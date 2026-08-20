//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestTunnelModeSkipsTheNativeBindAtTheCallSite pins that MulticastConn.Open
// actually *consults* the plan, not merely that planProbe computes it correctly.
//
// This closes a real gap rather than adding belt-and-braces. The policy tests in
// probe_policy_test.go pin attemptNative across all six mode x relay shapes, but
// mutating the call site at conn.go from `if plan.attemptNative()` to `if true`
// leaves every one of them green — there was no test that exercised either Open.
// That is precisely the defect class this PR exists to fix: the finding was a
// call site ignoring a correct plan, and the one before it was a call site
// carrying its own copy of the policy (Ally review on go-amt#49).
//
// The discrimination has to work on any host, so the bind is forced to fail
// rather than assumed to: a non-existent interface makes ListenMulticastUDP4
// fail everywhere, including a runner that does have a multicast route. With the
// plan consulted, AMTModeTunnel never touches the socket and the failure comes
// from the gateway; with the call site mutated, the bind runs first and the
// error is conn.go's "failed to create conn". The two are textually distinct.
func TestTunnelModeSkipsTheNativeBindAtTheCallSite(t *testing.T) {
	mc := &MulticastConn{
		GroupAddr: netip.MustParseAddr("232.0.0.1"),
		GroupPort: 1234,
		SrcAddr:   netip.MustParseAddr("10.0.0.1"),
		// Guaranteed absent, so the native bind cannot succeed on any host.
		IFace: &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
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

	if strings.Contains(err.Error(), "failed to create conn") {
		t.Fatalf("AMTModeTunnel bound the native socket before consulting the plan: %v\n"+
			"planProbe returns attemptNative()==false for this mode with a relay "+
			"configured, so Open must reach the gateway without touching the socket — "+
			"binding first is what made the mode fail closed on exactly the hosts "+
			"where an operator selects it", err)
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
// must still be attempted. It deliberately accepts EITHER outcome of that
// attempt, because whether a bogus interface makes ListenMulticastUDP4 fail is
// host-dependent: on darwin it fails, on linux an unspecified index binds
// successfully. An earlier version of this test asserted the failure and was
// green on darwin while red on CI. Both outcomes prove the same thing — that the
// call site did not skip the bind — so assert that, not the errno.
func TestTunnelModeWithoutARelayStillBinds(t *testing.T) {
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

	if err == nil {
		// The bind succeeded on this host, which is itself proof it was
		// attempted: nothing else in Open creates conn4.
		if mc.conn4 == nil {
			t.Error("Open succeeded with no native socket bound; AMTModeTunnel without " +
				"a relay must degrade to native rather than skipping the bind")
		} else {
			mc.conn4.Close()
		}
		return
	}

	if !strings.Contains(err.Error(), "failed to create conn") {
		t.Fatalf("AMTModeTunnel without a relay must degrade to native and attempt the "+
			"bind, so a failure here should come from ListenMulticastUDP4; got: %v", err)
	}
}
