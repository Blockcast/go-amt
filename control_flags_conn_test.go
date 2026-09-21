//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// errCaptureBind is what the capturing seams below return. Failing the bind is
// deliberate: the flag set is read at the call site, before the socket exists,
// so nothing after it is part of the property — and refusing keeps the test off
// IP_ADD_MEMBERSHIP, which a stock runner cannot satisfy anyway.
var errCaptureBind = errors.New("control-flag capture: bind refused")

// TestOpenPassesTheExportedControlFlags pins that MulticastConn.Open hands its
// listen calls exactly ControlFlags4 / ControlFlags6.
//
// Exporting the sets is only half the fix. The other half is that nothing here
// keeps a second copy, and the compiler cannot help: before BLO-34983 all three
// join sites built the set from ipv4.Flag* / ipv6.Flag* locals, so a caller
// sizing an OOB buffer from a hand-mirrored copy drifted the moment a flag was
// added — no build break, because there was no shared symbol, and no test break
// either, because the caller's guard was sized from the same assumption as the
// thing it guarded.
//
// So this asserts the ARGUMENT, not the outcome. Re-introducing a local set at
// the call site, or OR-ing one extra flag onto the constant there, is the exact
// mutation that costs multicast's v6 receiver its Dst cmsg, and it is the one
// this test must fail on. Asserting anything observable after the bind would
// not: every flag set produces a working socket.
//
// The seams are package state, so no t.Parallel.
func TestOpenPassesTheExportedControlFlags(t *testing.T) {
	var got4 ipv4.ControlFlags
	var seen4 bool
	orig4 := listenMulticastUDP4
	listenMulticastUDP4 = func(_ string, _ *net.Interface, _ netip.Addr, _ *net.UDPAddr,
		_ []bpf.RawInstruction, _ bool, _ int, flags ipv4.ControlFlags, _, _ int) (*ipv4.PacketConn, error) {
		got4, seen4 = flags, true
		return nil, errCaptureBind
	}
	t.Cleanup(func() { listenMulticastUDP4 = orig4 })

	var got6 ipv6.ControlFlags
	var seen6 bool
	orig6 := listenMulticastUDP6
	listenMulticastUDP6 = func(_ string, _ *net.Interface, _ netip.Addr, _ *net.UDPAddr,
		_ []bpf.RawInstruction, _ bool, _ int, flags ipv6.ControlFlags, _, _ int) (*ipv6.PacketConn, error) {
		got6, seen6 = flags, true
		return nil, errCaptureBind
	}
	t.Cleanup(func() { listenMulticastUDP6 = orig6 })

	// No RelayAddr, so planProbe returns the zero plan: attemptNative is true
	// and TunnelOnFailure is false, which is the shortest path through Open that
	// still reaches a native join — no probe goroutine, no gateway.
	for _, tc := range []struct{ name, src, group string }{
		{"v4", "10.0.0.1", "232.0.0.1"},
		{"v6", "fe80::1", "ff3e::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mc := &MulticastConn{
				GroupAddr: netip.MustParseAddr(tc.group),
				GroupPort: 1234,
				SrcAddr:   netip.MustParseAddr(tc.src),
				IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
			}
			if err := mc.Open(); !errors.Is(err, errCaptureBind) {
				t.Fatalf("Open() = %v, want the capturing seam's error: if the bind "+
					"did not come through the seam this test observed nothing", err)
			}
		})
	}

	if !seen4 {
		t.Fatal("Open never called the v4 listen seam, so the v4 assertion below is vacuous")
	}
	if got4 != ControlFlags4 {
		t.Errorf("Open passed v4 flags %v, want ControlFlags4 (%v): the call site has a "+
			"copy again, so a caller sizing its OOB buffer from the exported constant "+
			"will undersize it and the kernel will truncate Dst away silently",
			got4, ControlFlags4)
	}

	if !seen6 {
		t.Fatal("Open never called the v6 listen seam, so the v6 assertion below is vacuous")
	}
	if got6 != ControlFlags6 {
		t.Errorf("Open passed v6 flags %v, want ControlFlags6 (%v): v6 is the family with "+
			"no headroom — 40 pktinfo + 24 hop limit + 32 timestamp is exactly the 96-byte "+
			"buffer multicast allocates — so a drift here takes the receiver dark on IPv6",
			got6, ControlFlags6)
	}
}
