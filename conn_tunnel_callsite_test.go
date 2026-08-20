//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// countBindAttempts wraps the v4 bind seam for one test and returns a pointer to
// the attempt count.
//
// It delegates to the real ListenMulticastUDP4 rather than stubbing it, so a
// counted attempt is a real attempt and what these tests measure is Open's own
// behaviour. Restored by t.Cleanup. The seam is package state, so a test using
// it must not call t.Parallel.
func countBindAttempts(t *testing.T) *int {
	t.Helper()

	orig := listenMulticastUDP4
	var attempts int
	listenMulticastUDP4 = func(network string, ifi *net.Interface, saddr netip.Addr,
		gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, ttl int,
		flags4 ipv4.ControlFlags, rcvBufBytes, sndBufBytes int) (*ipv4.PacketConn, error) {
		attempts++
		return orig(network, ifi, saddr, gaddr, f, timestamp, ttl, flags4, rcvBufBytes, sndBufBytes)
	}
	t.Cleanup(func() { listenMulticastUDP4 = orig })

	return &attempts
}

// TestTunnelModeSkipsTheNativeBindAtTheCallSite pins that MulticastConn.Open
// actually *consults* the plan, not merely that planProbe computes it correctly.
//
// The policy tests in probe_policy_test.go pin attemptNative across all six
// mode x relay shapes, but mutating conn.go from `if plan.attemptNative()` to
// `if true` leaves every one of them green — nothing there exercises either
// Open. That is precisely the defect class this PR exists to fix: the finding was
// a call site ignoring a correct plan, and the one before it was a call site
// carrying its own copy of the policy.
//
// It asserts the bind was not ATTEMPTED, which is the actual property, rather
// than inferring it from the bind having failed. The earlier version inferred,
// and was vacuous on the only platform CI runs: under `if true` on linux the
// bogus interface binds successfully, the tunnel-handover path then closes the
// socket and sets mc.conn4 back to nil, and Open fails at the gateway instead —
// so "the error mentions failed to create conn" and "conn4 is still set" both
// came out false either way, and the mutation passed. See listenMulticastUDP4
// for why no after-the-fact observation can substitute for counting.
func TestTunnelModeSkipsTheNativeBindAtTheCallSite(t *testing.T) {
	binds := countBindAttempts(t)

	mc := &MulticastConn{
		GroupAddr: netip.MustParseAddr("232.0.0.1"),
		GroupPort: 1234,
		SrcAddr:   netip.MustParseAddr("10.0.0.1"),
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
		// TEST-NET-1 (RFC 5737): routable nowhere, so the handshake fails rather
		// than hanging on a real relay.
		RelayAddr: net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2268},
		// At or above MinRelayHandshakeTimeout so gatewayOpenTimeout keeps it and
		// Gateway.Open bounds itself rather than falling back to 10s.
		Timeout: MinRelayHandshakeTimeout,
		Mode:    AMTModeTunnel,
	}

	err := mc.Open()
	if err == nil {
		t.Fatal("Open against an unroutable relay must fail")
	}

	if *binds != 0 {
		t.Fatalf("AMTModeTunnel attempted %d native bind(s), want 0: planProbe "+
			"returns attemptNative()==false for this mode with a relay configured, "+
			"so Open must reach the gateway without touching the socket. Binding "+
			"first is what made the mode fail closed on exactly the hosts where an "+
			"operator selects it.", *binds)
	}

	if mc.conn4 != nil {
		t.Error("AMTModeTunnel left a native v4 socket bound; the group should never " +
			"have been joined on this path")
	}
}

// TestTunnelModeWithoutARelayStillBinds is the other half, and it is what stops
// the guard above from being satisfied by an Open that never binds at all.
//
// AMTModeTunnel without a relay is documented to degrade to native, so the bind
// must still be attempted. Asserting the attempt rather than its outcome is what
// makes this host-independent: whether a bogus interface makes the join fail is
// platform-specific — darwin rejects it, linux binds the unspecified index — and
// that difference has nothing to do with the question being asked.
func TestTunnelModeWithoutARelayStillBinds(t *testing.T) {
	binds := countBindAttempts(t)

	mc := &MulticastConn{
		GroupAddr: netip.MustParseAddr("232.0.0.1"),
		GroupPort: 1234,
		SrcAddr:   netip.MustParseAddr("10.0.0.1"),
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
		// No RelayAddr: nothing to fall back to.
		Timeout: time.Second,
		Mode:    AMTModeTunnel,
	}

	err := mc.Open()

	if *binds != 1 {
		t.Fatalf("AMTModeTunnel without a relay attempted %d native bind(s), want 1: "+
			"with no relay to fall back to it must degrade to native rather than "+
			"skipping the bind", *binds)
	}

	// Whether that attempt succeeded is the host-specific part and not what this
	// test is about, so both outcomes are accepted — but a success must have left
	// a socket behind, since nothing else in Open creates conn4.
	if err == nil {
		if mc.conn4 == nil {
			t.Error("Open succeeded with no native socket bound")
		} else {
			mc.conn4.Close()
		}
	}
}
