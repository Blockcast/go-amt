//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

// registryAccounts returns the publisher and the accounts of
// txfeed/testdata/registry-accounts-v3.json, which channel-registry wrote.
func registryAccounts(t *testing.T) (txfeed.Pubkey, map[string][]byte) {
	t.Helper()
	b, err := os.ReadFile("../../txfeed/testdata/registry-accounts-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Publisher string
		Accounts  []struct {
			Name    string
			DataHex string `json:"data_hex"`
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	pub, err := txfeed.ParsePubkey(f.Publisher)
	if err != nil {
		t.Fatal(err)
	}
	accts := map[string][]byte{}
	for _, a := range f.Accounts {
		if accts[a.Name], err = hex.DecodeString(a.DataHex); err != nil {
			t.Fatal(err)
		}
	}
	return pub, accts
}

func mustChannel(t *testing.T, s string) txfeed.Channel {
	t.Helper()
	c, err := txfeed.ParseChannel(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// rpcServer answers getProgramAccounts with accounts, after checking that the
// request asks for what poll needs; or with reply, when it is not empty.
func rpcServer(t *testing.T, program, publisher txfeed.Pubkey, accounts [][]byte, reply string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string
			Params []json.RawMessage
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Method != "getProgramAccounts" || len(req.Params) != 2 {
			t.Errorf("request: %+v, %v", req, err)
		}
		var prog string
		var opts struct {
			Encoding  string
			DataSlice struct{ Offset, Length int }
			Filters   []struct {
				Memcmp struct {
					Offset int
					Bytes  string
				}
			}
		}
		_ = json.Unmarshal(req.Params[0], &prog)
		_ = json.Unmarshal(req.Params[1], &opts)
		wantFilters := [][2]any{{0, "3"}, {3, "2"}, {36, publisher.String()}} // base58 of 2, of 1, the publisher
		var gotFilters [][2]any
		for _, f := range opts.Filters {
			gotFilters = append(gotFilters, [2]any{f.Memcmp.Offset, f.Memcmp.Bytes})
		}
		if prog != program.String() || opts.Encoding != "base64" || opts.DataSlice.Offset != 0 || opts.DataSlice.Length != txfeed.RegistryChannelPrefix || !slices.Equal(gotFilters, wantFilters) {
			t.Errorf("getProgramAccounts %s %+v; want program %s, base64, the first %d bytes, filters %v", prog, opts, program, txfeed.RegistryChannelPrefix, wantFilters)
		}
		if reply != "" {
			w.Write([]byte(reply))
			return
		}
		type acct struct {
			Pubkey  string `json:"pubkey"`
			Account struct {
				Data []string `json:"data"`
			} `json:"account"`
		}
		res := []acct{}
		for _, d := range accounts {
			var a acct
			a.Pubkey = "11111111111111111111111111111111"
			a.Account.Data = []string{base64.StdEncoding.EncodeToString(d), "base64"}
			if d == nil {
				a.Account.Data = []string{"not base64!", "base64"}
			}
			res = append(res, a)
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": res})
	}))
}

func TestRegistryPoll(t *testing.T) {
	pub, accts := registryAccounts(t)
	program := mustChannel(t, "program:H5d1TLJhopVLCRAyotADAraH8iQS7HBz7fqQdifDQ8f2").Key
	jup := accts["channel-program-jupiter-active"]
	edit := func(f func([]byte)) []byte { d := slices.Clone(jup); f(d); return d }
	vote := edit(func(d []byte) { // a channel the program refuses (HotKey), forged with a correct group
		copy(d[4:36], txfeed.VoteProgram[:])
		g := txfeed.ChannelGroup(txfeed.ChannelProgram, txfeed.VoteProgram).As16()
		copy(d[100:116], g[:])
	})
	sent := []txfeed.Channel{mustChannel(t, "program:JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")}
	srv := rpcServer(t, program, pub, [][]byte{
		jup[:txfeed.RegistryChannelPrefix], // what the RPC's dataSlice returns
		jup,                                // the same channel again: sent once, not skipped
		accts["channel-account-usdc-pending"],
		accts["channel-program-token-revoked"],
		edit(func(d []byte) { d[115] ^= 1 }), // stored group differs from spec v1
		edit(func(d []byte) { d[40] ^= 1 }),  // another publisher's channel
		edit(func(d []byte) { binary.LittleEndian.PutUint16(d[116:], 5004) }), // another port
		vote,
		nil, // not base64
	}, "")
	defer srv.Close()
	r := &registry{url: srv.URL, program: program, publisher: pub, port: 5003}
	chans, skipped, err := r.poll(context.Background())
	if err != nil || !slices.Equal(chans, sent) || skipped != 7 {
		t.Errorf("poll = %v, %d skipped, %v; want %v, 7 skipped", chans, skipped, err, sent)
	}

	for _, reply := range []string{
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32010,"message":"excluded from account secondary indexes"}}`,
		`{"jsonrpc":"2.0","id":1,"result":`, // cut short
	} {
		srv := rpcServer(t, program, pub, nil, reply)
		r.url = srv.URL
		if chans, _, err := r.poll(context.Background()); err == nil {
			t.Errorf("reply %s: poll = %v; want an error", reply, chans)
		}
		srv.Close()
	}
}

func TestNextChannels(t *testing.T) {
	ch := func(n byte) txfeed.Channel { return txfeed.Channel{Kind: txfeed.ChannelAccount, Key: txfeed.Pubkey{n}} }
	a, b, c, d, e, f := ch(1), ch(2), ch(3), ch(4), ch(5), ch(6)
	for _, tc := range []struct {
		static, current, polled []txfeed.Channel
		addMax, limit           int
		next, added, dropped    []txfeed.Channel
	}{
		// c stays, b stops, and two of d, e, f start: the add limit.
		{[]txfeed.Channel{a}, []txfeed.Channel{b, c}, []txfeed.Channel{c, d, e, f}, 2, 8,
			[]txfeed.Channel{a, c, d, e}, []txfeed.Channel{d, e}, []txfeed.Channel{b}},
		// -channel-max stops the adds.
		{[]txfeed.Channel{a}, nil, []txfeed.Channel{b, c, d}, 4, 3,
			[]txfeed.Channel{a, b, c}, []txfeed.Channel{b, c}, nil},
		// A static channel the registry also has is sent once, as a static one.
		{[]txfeed.Channel{a}, nil, []txfeed.Channel{a, b}, 4, 8,
			[]txfeed.Channel{a, b}, []txfeed.Channel{b}, nil},
		// An empty poll (or a stale registry) stops every registry channel.
		{[]txfeed.Channel{a}, []txfeed.Channel{b, c}, nil, 4, 8,
			[]txfeed.Channel{a}, nil, []txfeed.Channel{b, c}},
	} {
		next, added, dropped := nextChannels(tc.static, tc.current, tc.polled, tc.addMax, tc.limit)
		if !slices.Equal(next, tc.next) || !slices.Equal(added, tc.added) || !slices.Equal(dropped, tc.dropped) {
			t.Errorf("nextChannels(%v, %v, %v, %d, %d) = %v, +%v, -%v; want %v, +%v, -%v",
				tc.static, tc.current, tc.polled, tc.addMax, tc.limit, next, added, dropped, tc.next, tc.added, tc.dropped)
		}
	}
}

func TestNewRegistry(t *testing.T) {
	const prog, pub = "H5d1TLJhopVLCRAyotADAraH8iQS7HBz7fqQdifDQ8f2", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
	if r, err := newRegistry("", "", "", 5003, time.Second, 1, time.Second); r != nil || err != nil {
		t.Errorf("no -registry-rpc: %v, %v; want nil, nil", r, err)
	}
	if r, err := newRegistry("http://rpc", prog, pub, 5003, 30*time.Second, 4, 2*time.Minute); err != nil || r.program.String() != prog || r.publisher.String() != pub {
		t.Errorf("newRegistry = %+v, %v", r, err)
	}
	for _, tc := range []struct {
		url, prog, pub string
		poll           time.Duration
		add            int
		stale          time.Duration
		want           string
	}{
		{"", prog, "", time.Second, 1, time.Second, "need -registry-rpc"},
		{"http://rpc", "x", pub, time.Second, 1, time.Second, "-registry-program"},
		{"http://rpc", prog, "", time.Second, 1, time.Second, "-registry-publisher"},
		{"http://rpc", prog, pub, 0, 1, time.Second, "positive poll"},
		{"http://rpc", prog, pub, time.Minute, 1, time.Second, "positive poll"},
		{"http://rpc", prog, pub, time.Second, 0, time.Second, "positive poll"},
	} {
		if _, err := newRegistry(tc.url, tc.prog, tc.pub, 5003, tc.poll, tc.add, tc.stale); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("newRegistry(%q, %q, %q, %v, %d, %v): err %v; want one containing %q", tc.url, tc.prog, tc.pub, tc.poll, tc.add, tc.stale, err, tc.want)
		}
	}
}
