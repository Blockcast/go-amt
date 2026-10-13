//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
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

// TestPublishNeverExceedsMaxDatagram publishes every transaction of the
// 2026-10-13 capture (txfeed/testdata) on both address families. No datagram
// is over txfeed.MaxDatagram, and every group of each transaction receives
// all of its datagrams, in order, reassembling into exactly the frame the
// live feed sent.
func TestPublishNeverExceedsMaxDatagram(t *testing.T) {
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
	ids := make([]txfeed.Pubkey, len(txfeed.DefaultPrograms))
	for i, n := range txfeed.DefaultPrograms {
		ids[i] = n.ID
	}
	var txs, chunked int
	for len(all) >= 2 {
		n := 2 + int(binary.LittleEndian.Uint16(all))
		frame := all[2:n]
		all = all[n:]
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
			o := &output{conn: rec}
			for p := range txfeed.PartBucketBase + txfeed.NumBuckets {
				g, _ := txfeed.Group(netip.MustParseAddr(base), p)
				o.dst = append(o.dst, netip.AddrPortFrom(g, 5003))
			}
			outs = append(outs, o)
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
			r := txfeed.NewReassembler(time.Second, 1)
			for j, d := range got {
				if len(d) > txfeed.MaxDatagram {
					t.Fatalf("transaction %d: a %d-byte datagram to %s, over txfeed.MaxDatagram", txs, len(d), dst)
				}
				c, err := txfeed.ParseFrame(d)
				if err != nil {
					t.Fatalf("transaction %d: datagram %d to %s: %v", txs, j, dst, err)
				}
				if whole, ok := r.Add(c, time.Unix(0, 0)); ok != (j == len(got)-1) {
					t.Fatalf("transaction %d to %s: datagram %d of %d whole = %t", txs, dst, j, len(got), ok)
				} else if ok && !bytes.Equal(txfeed.AppendFrame(nil, whole), frame) {
					t.Fatalf("transaction %d to %s: reassembled a frame other than the live feed's", txs, dst)
				}
			}
		}
	}
	if txs != 900 || chunked != 144 {
		t.Errorf("published %d transactions, %d chunked; want 900 and 144", txs, chunked)
	}
}
