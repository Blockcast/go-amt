package amt

import (
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TestControlFlagsAreTheDocumentedSets pins what ControlFlags4/ControlFlags6
// MEAN, which the call-site guards deliberately do not.
//
// control_flags_conn_test.go and control_flags_managed_test.go both compare the
// argument a join site passes AGAINST the constant, so they follow the constant
// wherever it goes. That is the right shape for the drift BLO-34983 targets — a
// consumer sizing from len(ipv4.NewControlMessage(amt.ControlFlags4)) follows it
// too — but it leaves the set's membership unpinned: dropping FlagDst here would
// be consistently sized everywhere and silently stop requesting the cmsg the
// consumer filters on. Same silent failure as undersizing the buffer, reached
// from the other direction, and multicast's lct group filter discards every
// datagram that arrives without Dst.
//
// So editing a constant is allowed; editing one by accident is not. A flag
// added upstream costs one line here and nothing at any consumer, which is the
// trade this file is buying.
//
// Untagged, like control_flags.go: the constants are what callers on any
// platform size a buffer from, so the guard must not be deselectable by a tag
// the thing it guards does not carry. Nothing in ci.yml asserts its selection
// for that reason — there is no tag set that can drop it.
func TestControlFlagsAreTheDocumentedSets(t *testing.T) {
	if want := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL; ControlFlags4 != want {
		t.Errorf("ControlFlags4 = %v, want %v: if FlagDst was dropped, every consumer "+
			"still sizes its OOB buffer correctly and the kernel simply never sends "+
			"the destination cmsg, so a group filter discards all traffic with no error",
			ControlFlags4, want)
	}
	if want := ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagHopLimit; ControlFlags6 != want {
		t.Errorf("ControlFlags6 = %v, want %v: same silent loss as v4, on the family "+
			"multicast's receiver has no headroom on", ControlFlags6, want)
	}
}
