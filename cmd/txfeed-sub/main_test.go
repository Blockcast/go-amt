//go:build linux

package main

import (
	"net/netip"
	"testing"

	"github.com/blockcast/go-amt/txfeed"
)

func TestJoinFiltersOnlyProgramBuckets(t *testing.T) {
	src := netip.MustParseAddr("69.25.95.57")
	bucket := netip.MustParseAddrPort("232.0.3.72:5003")
	jup, token := txfeed.DefaultPrograms[5].ID, txfeed.DefaultPrograms[0].ID
	subs := join(nil, "bucket", src, bucket, &jup)
	subs = join(subs, "nonvote", src, netip.MustParseAddrPort("232.0.3.1:5003"), nil)
	if len(subs) != 2 || !subs[0].keeps(txfeed.Tx{Programs: []txfeed.Pubkey{token, jup}}) || subs[0].keeps(txfeed.Tx{Programs: []txfeed.Pubkey{token}}) {
		t.Fatal("a -program group must keep only transactions invoking the program")
	}
	if !subs[1].keeps(txfeed.Tx{}) {
		t.Error("a -nonvote group must keep every transaction")
	}
	// A raw join of the same channel takes every frame of it.
	if subs = join(subs, "ssm", src, bucket, nil); len(subs) != 2 || !subs[0].keeps(txfeed.Tx{Programs: []txfeed.Pubkey{token}}) {
		t.Error("joining a filtered group unfiltered must widen it, not join it twice")
	}
}

func TestPercentile(t *testing.T) {
	l := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for p, want := range map[int]float64{0: 1, 50: 6, 90: 10, 99: 10} {
		if got := percentile(l, p); got != want {
			t.Errorf("percentile(1..10, %d) = %v, want %v", p, got, want)
		}
	}
	if percentile(nil, 50) != 0 {
		t.Error("the percentile of nothing is 0")
	}
}
