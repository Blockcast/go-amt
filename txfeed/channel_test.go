package txfeed

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestChannelVectors checks ChannelGroup and RefusedKeys against
// testdata/channel-vectors.json, which testdata/channel-vectors.py writes with
// Python's standard library alone. The registry program, the Rust tools and
// the JS page are to assert the same file.
func TestChannelVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/channel-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Domain  string
		Kinds   map[string]ChannelKind
		Refused []struct{ Name, Key string }
		Vectors []struct {
			Name, Kind, Key, Group string
			GroupHex               string `json:"group_hex"`
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Domain != channelDomain || len(f.Kinds) != 2 || f.Kinds["program"] != ChannelProgram || f.Kinds["account"] != ChannelAccount {
		t.Errorf("the file has domain %q, kinds %v; want %q, program 1 and account 2", f.Domain, f.Kinds, channelDomain)
	}
	if len(f.Refused) != len(RefusedKeys) {
		t.Errorf("the file refuses %d keys, RefusedKeys %d", len(f.Refused), len(RefusedKeys))
	}
	for i, r := range f.Refused {
		if i < len(RefusedKeys) && (r.Name != RefusedKeys[i].Name || r.Key != RefusedKeys[i].ID.String()) {
			t.Errorf("refused %d: the file has %s %s, RefusedKeys %s %s", i, r.Name, r.Key, RefusedKeys[i].Name, RefusedKeys[i].ID)
		}
	}
	if len(f.Vectors) < 6 {
		t.Fatalf("%d vectors, want at least 6", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		c, err := ParseChannel(v.Kind + ":" + v.Key)
		if err != nil || c.String() != v.Kind+":"+v.Key {
			t.Errorf("%s: ParseChannel = %s, %v", v.Name, c, err)
			continue
		}
		if g := ChannelGroup(c.Kind, c.Key); g.String() != v.Group || hex.EncodeToString(g.AsSlice()) != v.GroupHex {
			t.Errorf("%s: ChannelGroup(%s) = %s, want %s", v.Name, c, g, v.Group)
		}
	}
}

// pub is the public key of key(seed).
func pub(seed byte) Pubkey { return Pubkey(key(seed).Public().(ed25519.PublicKey)) }

func TestMatchChannels(t *testing.T) {
	prog := func(p Pubkey) Channel { return Channel{ChannelProgram, p} }
	acct := func(p Pubkey) Channel { return Channel{ChannelAccount, p} }
	twice := testTx{signers: []ed25519.PrivateKey{key(1)}, extra: []Pubkey{memo, memo}, ixs: []ix{{program: 2}}}
	for _, c := range []struct {
		name         string
		tx           testTx
		active, want []Channel
	}{
		// legacyTx invokes system and memo, and lists key(1), key(2), system
		// and memo.
		{"the programs it invokes, not a key it only lists", legacyTx,
			[]Channel{prog(memo), prog(system), prog(jupiter), prog(pub(2))}, []Channel{prog(system), prog(memo)}},
		{"the static keys it lists, a signer's included", legacyTx,
			[]Channel{acct(memo), acct(pub(2)), acct(jupiter)}, []Channel{acct(pub(2)), acct(memo)}},
		// v1Tx invokes jupiter and token, and lists key(5), key(6), jupiter
		// and token.
		{"several channels, programs first", v1Tx,
			[]Channel{acct(jupiter), prog(token), acct(pub(6)), prog(jupiter), prog(memo), acct(memo)},
			[]Channel{prog(jupiter), prog(token), acct(pub(6)), acct(jupiter)}},
		{"a vote matches as any transaction does", voteTx,
			[]Channel{acct(pub(4)), prog(token)}, []Channel{acct(pub(4))}},
		// v0Tx lists key(3), the compute budget program and jupiter, and loads
		// accounts from the lookup table at token.
		{"static keys only: not a lookup table's address", v0Tx,
			[]Channel{acct(token), acct(pub(3))}, []Channel{acct(pub(3))}},
		{"a key listed twice matches once", twice, []Channel{acct(memo), prog(memo)}, []Channel{prog(memo), acct(memo)}},
		{"no active channels", v1Tx, nil, nil},
	} {
		tx, _, err := ParseTx(c.tx.build())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		active := map[Channel]bool{}
		for _, a := range c.active {
			active[a] = true
		}
		if got := MatchChannels(tx, active); !slices.Equal(got, c.want) {
			t.Errorf("%s: MatchChannels = %v, want %v", c.name, got, c.want)
		}
	}
}
