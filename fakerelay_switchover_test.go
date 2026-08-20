//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net"
	"testing"
	"time"
)

// MulticastConn switchover, driven against fakeRelay and fakeNativeSource.
//
// WHY THIS FILE IS SEPARATE FROM fakenative_flows_test.go. MulticastConn is the
// live path and it reaches AMT through Gateway directly, not through
// RelayManager — and both conn.go and gateway.go are tagged
// `cgo && !purego`, so this file can only be selected in the cgo-test lane.
// The ManagedConn half of the same story is in fakenative_flows_test.go, which is
// `linux || darwin` and therefore runs in every lane. Two files rather than one
// because a single file would have to carry the narrower tag and would take the
// ManagedConn coverage out of the CGO_ENABLED=0 lane with it.
//
// Both arbiters are covered on purpose. probe.go's header records why: they are
// selected by different tag sets, and when only one was exercised, ManagedConn
// kept the BLO-28640 defect after MulticastConn was fixed. The issue that asked
// for this harness (BLO-29196) named the same shape — asserting only ManagedConn
// would leave the MulticastConn arbiter, which is the live path, asserted by
// nothing.

// newMulticastConnUnderTest builds a MulticastConn in the only mode whose
// delivery path is actually in question: Auto, with a relay configured.
//
// The interface does not exist. The fake native source substitutes the join seam
// before the name is resolved, so this is deliberate — a real interface would
// invite the native leg to pass because of a genuine local multicast join rather
// than because the harness delivered.
func newMulticastConnUnderTest(t *testing.T, fr *fakeRelay) *MulticastConn {
	t.Helper()

	mc := &MulticastConn{
		SrcAddr:   testHarnessSource,
		GroupAddr: testHarnessGroup,
		GroupPort: testHarnessPort,
		RelayAddr: fr.Addr(),
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
		// At or above MinRelayHandshakeTimeout so gatewayOpenTimeout keeps it as
		// the AMT handshake bound rather than dropping it to DefaultOpenTimeout.
		Timeout: 2 * time.Second,
		Mode:    AMTModeAuto,
	}
	t.Cleanup(func() { _ = mc.Close() })
	return mc
}

// TestMulticastConnKeepsNativeWhenBothPathsAreLive is the "native and relay both
// live" case on the live path: a reachable relay must not displace a native join
// that is delivering.
//
// The relay-side count is what gives this force. !IsUsingTunnel alone would also
// hold if the arbiter had chosen native for a bad reason; a relay that was never
// even sent a discovery datagram proves no part of Open went looking for a tunnel
// it did not need.
func TestMulticastConnKeepsNativeWhenBothPathsAreLive(t *testing.T) {
	fr := newFakeRelay(t)
	nat := installFakeNativeSource(t)
	nat.Enable(testHarnessGroup)

	mc := newMulticastConnUnderTest(t, fr)
	if err := mc.Open(); err != nil {
		t.Fatalf("Open with native delivering: %v", err)
	}

	if nat.Binds() != 1 {
		t.Fatalf("native joins through the seam = %d, want 1: the fake was not "+
			"reached, so nothing below is testing native delivery", nat.Binds())
	}
	if mc.IsUsingTunnel() {
		t.Fatal("MulticastConn chose the AMT tunnel while native was delivering; " +
			"the probe should have been satisfied inside the window")
	}

	payload, err := readOne(mc, 3*time.Second)
	if err != nil {
		t.Fatalf("read after choosing native: %v", err)
	}
	if got := provenanceOf(payload); got != nativeProvenanceTag {
		t.Errorf("payload %q has provenance %q, want %q: the connection reports "+
			"native but the bytes did not come from the native source",
			payload, got, nativeProvenanceTag)
	}

	if n := fr.advertised.Load(); n != 0 {
		t.Errorf("relay answered %d discovery message(s), want 0: native was "+
			"delivering, so Open should never have reached the relay", n)
	}
}

// TestMulticastConnHandsOverToTheRelayWhenNativeIsSilent is the fallback leg: the
// probe concludes native is not deliverable, the native join is released, and the
// group is handed to an AMT tunnel through Gateway — the production path.
//
// THE UNCONDITIONAL CLAIM is that the handover reached the relay: fakeRelay
// received a Relay Discovery and answered it. That is what "reaching AMT via
// Gateway as production does" means here, and it holds whether or not the
// handshake then completes.
//
// Whether it completes is deliberately NOT asserted either way, because it is
// not yet known. Every Gateway test in this repository drives Open to failure —
// a silent relay (gateway_timeout_test.go), an unroutable address
// (conn_tunnel_callsite_test.go), a logging assertion (gateway_logging_test.go) —
// so no test has ever completed a Gateway handshake against fakeRelay, and
// Gateway's handshake is decoded by the Rust amt_protocol library rather than by
// this package's Go decoders. fakeRelay's advertisement is hand-built to what
// HandleAdvertisement accepts (see its buildQuery note), and whether the Rust
// side is equally permissive is an open question that cannot be answered on a
// host without cgo. The branch is logged so the cgo-test lane answers it, after
// which this test should be tightened to assert the outcome unconditionally.
//
// What keeps that honest is that the logged branch is not the assertion. The
// discovery count below is checked on both branches, so this test cannot pass by
// taking a path that asserts nothing.
func TestMulticastConnHandsOverToTheRelayWhenNativeIsSilent(t *testing.T) {
	fr := newFakeRelay(t)
	nat := installFakeNativeSource(t)
	// Never enabled: native delivery is off by default, so silence is the
	// harness's resting state rather than something arranged here.

	mc := newMulticastConnUnderTest(t, fr)

	start := time.Now()
	err := mc.Open()
	t.Logf("Open with native silent took %s (probe window floor is %s), err=%v",
		time.Since(start).Round(time.Millisecond), MinUsefulProbeWindow, err)

	if nat.Binds() != 1 {
		t.Fatalf("native joins through the seam = %d, want 1: the handover did not "+
			"follow a failed probe, it skipped native altogether", nat.Binds())
	}
	if nat.Delivered() != 0 {
		t.Fatalf("native source delivered %d datagram(s) despite never being "+
			"enabled; this test is not exercising a silent native path", nat.Delivered())
	}

	// The claim. Gateway sends Relay Discovery as the first leg of Open, so a
	// relay that answered one necessarily saw the gateway come up.
	if n := fr.advertised.Load(); n < 1 {
		t.Fatalf("relay received no Relay Discovery (advertisements sent = %d): the "+
			"probe timed out but the group was never handed to an AMT gateway", n)
	}

	if err != nil {
		t.Logf("Gateway.Open did not complete against fakeRelay: %v. The handover "+
			"reached the relay, which is what this test asserts. Completing the "+
			"handshake needs fakeRelay to satisfy the Rust amt_protocol decoder; "+
			"tighten this once the lane confirms either way.", err)
		return
	}

	if !mc.IsUsingTunnel() {
		t.Fatal("Open succeeded with native silent but the connection does not " +
			"report tunnelling; the group is on neither path")
	}
	t.Log("Gateway.Open COMPLETED against fakeRelay — the tunnel data leg below " +
		"is live, and this test can be tightened to require it")

	const burst = 8
	for i := 1; i <= burst; i++ {
		fr.SendData(testHarnessSource, testHarnessGroup, 4000, testHarnessPort, tunnelPayload(i))
	}
	for i := 1; i <= burst; i++ {
		payload, err := readOne(mc, 3*time.Second)
		if err != nil {
			t.Fatalf("tunnel read %d/%d: %v", i, burst, err)
		}
		if got := provenanceOf(payload); got != tunnelProvenanceTag {
			t.Fatalf("packet %d has provenance %q, want %q: native is silent, so "+
				"anything arriving must have come through the tunnel",
				i, got, tunnelProvenanceTag)
		}
	}
}

// TestMulticastConnPicksNativeAgainAfterItRecovers is the recovery leg: once the
// native source delivers again, a fresh Open must choose native over the relay.
//
// A fresh connection because Open is one-shot — the arbiter re-decides per Open,
// and that is the shape a reconnect actually takes. The first Open is what makes
// this a recovery rather than a repeat of the both-live case: it establishes that
// this group had already been given up on.
func TestMulticastConnPicksNativeAgainAfterItRecovers(t *testing.T) {
	fr := newFakeRelay(t)
	nat := installFakeNativeSource(t)

	// Leg 1: native silent, so the group is handed away.
	givenUp := newMulticastConnUnderTest(t, fr)
	_ = givenUp.Open() // outcome asserted by the handover test above
	if n := fr.advertised.Load(); n < 1 {
		t.Fatalf("relay received no discovery on the first open (advertisements = %d); "+
			"the group was never given up, so there is nothing to recover from", n)
	}
	_ = givenUp.Close()

	// Leg 2: native comes back.
	nat.Enable(testHarnessGroup)
	recovered := newMulticastConnUnderTest(t, fr)
	if err := recovered.Open(); err != nil {
		t.Fatalf("Open after native recovered: %v", err)
	}
	if recovered.IsUsingTunnel() {
		t.Fatal("still tunnelling after native recovered; a fresh Open must " +
			"re-decide and choose the native join")
	}

	payload, err := readOne(recovered, 3*time.Second)
	if err != nil {
		t.Fatalf("read after native recovered: %v", err)
	}
	if got := provenanceOf(payload); got != nativeProvenanceTag {
		t.Errorf("payload %q has provenance %q, want %q", payload, got, nativeProvenanceTag)
	}
}
