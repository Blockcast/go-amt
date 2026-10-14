//go:build linux

package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

func TestChannelCaps(t *testing.T) {
	a := txfeed.Channel{Kind: txfeed.ChannelProgram, Key: txfeed.Pubkey{1}}
	b := txfeed.Channel{Kind: txfeed.ChannelProgram, Key: txfeed.Pubkey{2}}
	t0 := time.Unix(1_800_000_000, 0)
	clock := t0
	cc := newChannelCaps(0.008, 0.012) // 1000 B/s each, 1500 B/s in all
	cc.now = func() time.Time { return clock }
	for i, step := range []struct {
		at   time.Duration
		c    txfeed.Channel
		n    int
		want bool
	}{
		{0, a, 600, true},
		{0, a, 600, false}, // a has 400 left
		{0, b, 600, true},  // the total has 300 left
		{0, b, 400, false}, // b has 400, but the total only 300
		{0, b, 300, true},
		{500 * time.Millisecond, a, 700, true},  // a refills to 900, the total to 750
		{500 * time.Millisecond, b, 200, false}, // b has 600, but the total only 50
		{10 * time.Second, a, 1000, true},       // a bucket holds at most one second
		{10 * time.Second, a, 1, false},
	} {
		clock = t0.Add(step.at)
		if got := cc.take(step.c, step.n); got != step.want {
			t.Errorf("step %d: take(%v, %d) at +%v = %t, want %t", i, step.c.Key[0], step.n, step.at, got, step.want)
		}
	}
	if cc.capped != 4 {
		t.Errorf("capped = %d, want 4", cc.capped)
	}

	// 0 is no cap: per channel, or in all.
	unlimited := newChannelCaps(0, 0)
	unlimited.now = func() time.Time { return t0 }
	for range 100 {
		if !unlimited.take(a, 1<<20) {
			t.Fatal("no caps: a send was refused")
		}
	}
	totalOnly := newChannelCaps(0, 0.008)
	totalOnly.now = func() time.Time { return t0 }
	if !totalOnly.take(a, 600) || !totalOnly.take(b, 400) || totalOnly.take(a, 1) {
		t.Error("a total cap alone: want 1000 B in all, from any channels")
	}
}

// TestPublishChannelCaps replays the 2026-10-13 capture with a clock that does
// not move, so no bucket refills. A tight cap sends the Token account channel
// only its first transactions, each whole; the default caps send both
// channels every transaction they match.
func TestPublishChannelCaps(t *testing.T) {
	ids := defaultIDs()
	jup, token := txfeed.DefaultPrograms[5].ID, txfeed.DefaultPrograms[0].ID
	prog := txfeed.Channel{Kind: txfeed.ChannelProgram, Key: jup}
	acct := txfeed.Channel{Kind: txfeed.ChannelAccount, Key: token}
	frames := capture(t)
	run := func(cc *channelCaps, cs ...txfeed.Channel) recorder {
		now := time.Unix(1_800_000_000, 0)
		cc.now = func() time.Time { return now }
		chans := map[txfeed.Channel]netip.AddrPort{}
		for _, c := range cs {
			chans[c] = netip.AddrPortFrom(txfeed.ChannelGroup(c.Kind, c.Key), 5003)
		}
		rec := recorder{}
		o := &output{conn: rec, chans: chans, caps: cc}
		for _, frame := range frames {
			f, err := txfeed.ParseFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			tx, _, err := txfeed.ParseTx(f.Tx)
			if err != nil {
				t.Fatal(err)
			}
			publish([]*output{o}, ids, txfeed.Batch{Slot: f.Slot, StartIndex: f.BatchStart, ShredTs: f.ShredTs}, int(f.Index), tx)
		}
		return rec
	}
	group := func(c txfeed.Channel) netip.AddrPort {
		return netip.AddrPortFrom(txfeed.ChannelGroup(c.Kind, c.Key), 5003)
	}

	const capBytes = 40_000 // one second's worth at 0.32 Mbit/s
	tight := newChannelCaps(capBytes*8/1e6, 0)
	dgs := run(tight, acct)[group(acct)]
	sentBytes := 0
	for _, d := range dgs {
		sentBytes += len(d)
	}
	if n := txs(t, dgs); n == 0 || n+int(tight.capped) != 496 || sentBytes > capBytes {
		t.Errorf("Token channel capped at %d bytes: %d transactions (%d bytes) sent and %d capped; want some sent within the cap, and sent + capped = the 496 that list Token",
			capBytes, n, sentBytes, tight.capped)
	}

	defaults := newChannelCaps(8, 64)
	rec := run(defaults, prog, acct)
	if p, a := txs(t, rec[group(prog)]), txs(t, rec[group(acct)]); p != 307 || a != 496 || defaults.capped != 0 {
		t.Errorf("default caps: Jupiter %d, Token %d transactions, %d capped; want 307, 496 and 0", p, a, defaults.capped)
	}
}

// txs counts the transactions in a channel's datagrams, and fails the test if
// any was sent in part: a chunked transaction arrives with every chunk or
// none.
func txs(t *testing.T, dgs [][]byte) int {
	t.Helper()
	type key struct {
		slot  uint64
		batch uint32
		index uint16
	}
	got, want := map[key]int{}, map[key]int{}
	for _, d := range dgs {
		f, err := txfeed.ParseFrame(d)
		if err != nil {
			t.Fatal(err)
		}
		k := key{f.Slot, f.BatchStart, f.Index}
		got[k]++
		want[k] = max(1, int(f.Chunks))
	}
	for k, n := range got {
		if n != want[k] {
			t.Errorf("transaction %v: %d of %d datagrams sent", k, n, want[k])
		}
	}
	return len(got)
}
