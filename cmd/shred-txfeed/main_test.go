//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

func TestParsePrograms(t *testing.T) {
	if got, err := parsePrograms(nil); err != nil || len(got) != len(txfeed.DefaultPrograms) {
		t.Errorf("no -program: %d programs, %v; want the defaults", len(got), err)
	}
	got, err := parsePrograms([]string{"jup=JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "memo=MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"})
	if err != nil || len(got) != 2 || got[0].Name != "jup" || got[1].ID != txfeed.DefaultPrograms[4].ID {
		t.Errorf("parsePrograms = %v, %v; want jup then memo, replacing the defaults", got, err)
	}
	for _, specs := range [][]string{
		{"JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"},                                          // no name
		{"=JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"},                                         // empty name
		{"x=JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV"},                                         // 31 bytes
		strings.Fields(strings.Repeat("s=11111111111111111111111111111111 ", txfeed.NumNamed+1)), // too many
	} {
		if _, err := parsePrograms(specs); err == nil {
			t.Errorf("parsePrograms(%q): want an error", specs)
		}
	}
}

// recorder stands in for an output's socket: it keeps what it is sent.
type recorder map[netip.AddrPort][][]byte

func (r recorder) WriteToUDPAddrPort(b []byte, dst netip.AddrPort) (int, error) {
	r[dst] = append(r[dst], bytes.Clone(b))
	return len(b), nil
}

// capture returns the txframes of the 2026-10-13 capture (txfeed/testdata).
func capture(t *testing.T) [][]byte {
	zf, err := os.Open("../../txfeed/testdata/txframes-2026-10-13.bin.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()
	zr, err := gzip.NewReader(zf)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	for len(all) >= 2 {
		n := 2 + int(binary.LittleEndian.Uint16(all))
		frames = append(frames, all[2:n])
		all = all[n:]
	}
	return frames
}

// partitionGroups returns the groups under base on port 5003, by partition.
func partitionGroups(base string) []netip.AddrPort {
	var dst []netip.AddrPort
	for p := range txfeed.PartBucketBase + txfeed.NumBuckets {
		g, _ := txfeed.Group(netip.MustParseAddr(base), p)
		dst = append(dst, netip.AddrPortFrom(g, 5003))
	}
	return dst
}

func defaultIDs() []txfeed.Pubkey {
	ids := make([]txfeed.Pubkey, len(txfeed.DefaultPrograms))
	for i, n := range txfeed.DefaultPrograms {
		ids[i] = n.ID
	}
	return ids
}

// reassembles checks dgs, the datagrams one group got for a transaction: none
// over limit bytes, they reassemble, in order, into exactly frame.
func reassembles(dgs [][]byte, limit int, frame []byte) error {
	r := txfeed.NewReassembler(time.Second, 1)
	for j, d := range dgs {
		if len(d) > limit {
			return fmt.Errorf("datagram %d of %d is %d bytes, over %d", j, len(dgs), len(d), limit)
		}
		c, err := txfeed.ParseFrame(d)
		if err != nil {
			return fmt.Errorf("datagram %d: %v", j, err)
		}
		if whole, ok := r.Add(c, time.Unix(0, 0)); ok != (j == len(dgs)-1) {
			return fmt.Errorf("datagram %d of %d whole = %t", j, len(dgs), ok)
		} else if ok && !bytes.Equal(txfeed.AppendFrame(nil, whole), frame) {
			return errors.New("reassembled a frame other than the live feed's")
		}
	}
	return nil
}

// TestPublishNeverExceedsMaxDatagram publishes every transaction of the
// 2026-10-13 capture (txfeed/testdata) on both address families. No datagram
// is over txfeed.MaxDatagram, and every group of each transaction receives
// all of its datagrams, in order, reassembling into exactly the frame the
// live feed sent.
func TestPublishNeverExceedsMaxDatagram(t *testing.T) {
	ids := defaultIDs()
	var txs, chunked int
	for _, frame := range capture(t) {
		txs++

		f, err := txfeed.ParseFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		tx, _, err := txfeed.ParseTx(f.Tx)
		if err != nil {
			t.Fatalf("transaction %d: %v", txs, err)
		}
		rec := recorder{}
		var outs []*output
		for _, base := range []string{"232.0.3.0", "ff3e::232:300"} {
			outs = append(outs, &output{conn: rec, dst: partitionGroups(base)})
		}
		sent, failed, dgs := publish(outs, ids, txfeed.Batch{Slot: f.Slot, StartIndex: f.BatchStart, ShredTs: f.ShredTs}, int(f.Index), tx)
		if dgs > 1 {
			chunked++
		}
		groups := 2 * len(txfeed.Partitions(tx, ids))
		if len(rec) != groups || sent != uint64(groups*dgs) || failed != 0 {
			t.Fatalf("transaction %d: %d groups, %d sent, %d failed; want %d groups, %d datagrams each", txs, len(rec), sent, failed, groups, dgs)
		}
		for dst, got := range rec {
			if err := reassembles(got, txfeed.MaxDatagram, frame); err != nil {
				t.Fatalf("transaction %d to %s: %v", txs, dst, err)
			}
		}
	}
	if txs != 900 || chunked != 144 {
		t.Errorf("published %d transactions, %d chunked; want 900 and 144", txs, chunked)
	}
}

func TestParseChannels(t *testing.T) {
	const jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
	got, err := parseChannels([]string{"program:" + jup, "account:" + jup, "program:" + jup}, 2)
	want := []txfeed.Channel{
		{Kind: txfeed.ChannelProgram, Key: txfeed.DefaultPrograms[5].ID},
		{Kind: txfeed.ChannelAccount, Key: txfeed.DefaultPrograms[5].ID},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("parseChannels = %v, %v; want %v, the repeat dropped", got, err, want)
	}
	var full []string // 256 distinct channels, -channel-max's default
	for i := range 256 {
		full = append(full, "account:"+txfeed.Pubkey{byte(i)}.String())
	}
	if got, err := parseChannels(full, 256); err != nil || len(got) != 256 {
		t.Errorf("256 channels under -channel-max 256: %d channels, %v", len(got), err)
	}
	for _, c := range []struct {
		name  string
		specs []string
	}{
		{"a bad kind", []string{"programs:" + jup}},
		{"no kind", []string{jup}},
		{"bad base58", []string{"program:JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV0"}}, // 0 is not a base58 digit
		{"a 31-byte key", []string{"account:JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV"}},
		{"over the cap", append(full, "program:"+jup)},
	} {
		if _, err := parseChannels(c.specs, 256); err == nil {
			t.Errorf("%s: parseChannels accepted it", c.name)
		}
	}
	// A hot key, of either kind, would carry the whole feed.
	for _, key := range []string{"Vote111111111111111111111111111111111111111", "ComputeBudget111111111111111111111111111111"} {
		for _, kind := range []string{"program", "account"} {
			if _, err := parseChannels([]string{kind + ":" + key}, 256); err == nil || !strings.Contains(err.Error(), "whole feed") {
				t.Errorf("parseChannels(%s:%s) = %v; want it refused as the whole feed", kind, key, err)
			}
		}
	}
}

// -group-base6 and -channel6 each need -src6, an IPv6 address.
func TestSource6(t *testing.T) {
	const s6 = "2602:f74d:1:5::57"
	for _, c := range []struct {
		src6, base6 string
		channels    int
		want        string // empty for an error
	}{
		{"", "", 0, "invalid IP"}, // no IPv6 output
		{s6, "", 1, s6},
		{s6, "ff3e::232:300", 0, s6},
		{"", "", 1, ""},              // -channel6 without -src6
		{"", "ff3e::232:300", 0, ""}, // -group-base6 without -src6
		{"69.25.95.57", "", 1, ""},
	} {
		got, err := source6(c.src6, c.base6, c.channels)
		if (err == nil) != (c.want != "") || err == nil && got.String() != c.want {
			t.Errorf("source6(%q, %q, %d) = %s, %v; want %q", c.src6, c.base6, c.channels, got, err, c.want)
		}
	}
}

// keys returns tx's static account keys.
func keys(tx txfeed.Tx) []txfeed.Pubkey {
	var ks []txfeed.Pubkey
	for k := range slices.Chunk(tx.Keys, 32) {
		ks = append(ks, txfeed.Pubkey(k))
	}
	return ks
}

// TestPublishChannels publishes every transaction of the capture to two filter
// channels, from an IPv6 output without partition groups (-channel6 alone)
// and with them (-group-base6 too). Each transaction reaches each channel it
// matches, once, and no other group but its partitions; a channel's
// datagrams are at most txfeed.MaxChannelDatagram, a partition's
// txfeed.MaxDatagram, and they reassemble into exactly the captured frame.
func TestPublishChannels(t *testing.T) {
	ids := defaultIDs()
	jup, token := txfeed.DefaultPrograms[5].ID, txfeed.DefaultPrograms[0].ID
	prog := txfeed.Channel{Kind: txfeed.ChannelProgram, Key: jup}
	acct := txfeed.Channel{Kind: txfeed.ChannelAccount, Key: token}
	chans := map[txfeed.Channel]netip.AddrPort{}
	for _, c := range []txfeed.Channel{prog, acct} {
		chans[c] = netip.AddrPortFrom(txfeed.ChannelGroup(c.Kind, c.Key), 5003)
	}
	frames := capture(t)
	for _, base := range []string{"", "ff3e::232:300"} {
		var invoking, listing, cpiOnly, chunked int
		for i, frame := range frames {
			f, err := txfeed.ParseFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			tx, _, err := txfeed.ParseTx(f.Tx)
			if err != nil {
				t.Fatal(err)
			}
			rec := recorder{}
			o := &output{conn: rec, chans: chans}
			limits := map[netip.AddrPort]int{} // the groups tx belongs to, and their datagram limits
			if base != "" {
				o.dst = partitionGroups(base)
				for _, p := range txfeed.Partitions(tx, ids) {
					limits[o.dst[p]] = txfeed.MaxDatagram
				}
			}
			if slices.Contains(tx.Programs, jup) {
				limits[chans[prog]] = txfeed.MaxChannelDatagram
				invoking++
			}
			if slices.Contains(keys(tx), token) {
				limits[chans[acct]] = txfeed.MaxChannelDatagram
				listing++
				if !slices.Contains(tx.Programs, token) {
					cpiOnly++
				}
			}
			publish([]*output{o}, ids, txfeed.Batch{Slot: f.Slot, StartIndex: f.BatchStart, ShredTs: f.ShredTs}, int(f.Index), tx)
			if len(rec) != len(limits) {
				t.Fatalf("-group-base6 %q, transaction %d: sent to %d groups, want %d", base, i, len(rec), len(limits))
			}
			for dst, dgs := range rec {
				limit, ok := limits[dst]
				if !ok {
					t.Fatalf("-group-base6 %q, transaction %d: sent to %s, a group it does not belong to", base, i, dst)
				}
				if err := reassembles(dgs, limit, frame); err != nil {
					t.Fatalf("-group-base6 %q, transaction %d to %s: %v", base, i, dst, err)
				}
				if limit == txfeed.MaxChannelDatagram && len(dgs) > 1 {
					chunked++
				}
			}
		}
		// 496 list the Token program, 168 of them without invoking it: they
		// reach it by CPI, which only the account kind sees. Of the 803
		// channel sends, 202 are chunked at MaxChannelDatagram; 160 would be
		// at MaxDatagram.
		if invoking != 307 || listing != 496 || cpiOnly != 168 || chunked != 202 {
			t.Errorf("%d invoke Jupiter v6, %d list Token, %d of them without invoking it, %d channel sends chunked; want 307, 496, 168 and 202",
				invoking, listing, cpiOnly, chunked)
		}
	}
}
