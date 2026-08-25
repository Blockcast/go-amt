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

func waitForRelayDiscovery(t *testing.T, fr *fakeRelay) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for fr.advertised.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

func TestMulticastConnNativeSelectionCancelsInFlightTunnel(t *testing.T) {
	mc := &MulticastConn{wantTunnel: true, activeTunnel: true}

	// This models the native probe winning while openTunnel is still between
	// Gateway.Open and its pathMu publication section.
	mc.setActiveTunnel(false)

	mc.pathMu.RLock()
	wantTunnel, activeTunnel := mc.wantTunnel, mc.activeTunnel
	mc.pathMu.RUnlock()
	if wantTunnel {
		t.Fatal("native selection left the in-flight tunnel intent enabled")
	}
	if activeTunnel {
		t.Fatal("native selection left AMT active")
	}
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
// probe concludes native is not deliverable, the native join is released, the
// group is handed to an AMT tunnel through Gateway — the production path — and
// data arrives through that tunnel with tunnel provenance.
//
// THE CLAIM IS NOW END-TO-END. It used to stop at "the relay saw a discovery",
// because the handshake could not complete and the test pinned that failure to
// its timeout shape. BLO-29437 found why, and the cause was NOT the one that
// ticket assumed. fakeRelay's advertisement was never wrong: its 12 bytes are
// byte-for-byte what amt-protocol's own RelayAdvertisement encoder emits for
// IPv4. The defect was in gateway.go, which discarded the read length and handed
// the Rust decoder the whole MTU-sized buffer. Relay Advertisement is the one
// AMT message decoded by EXACT length (messages.rs:213 — 12 for IPv4, 24 for
// IPv6, error otherwise), so it failed on every handshake, against every relay,
// real or fake. The cgo AMT path had never completed a handshake at all.
//
// So this test now asserts what it could not before, and there is no timeout
// branch to fall back to: a timeout here is a failure, which is the only way the
// completed-path assertions below can carry weight.
func TestMulticastConnHandsOverToTheRelayWhenNativeIsSilent(t *testing.T) {
	// Pin the query interval high (0x7f = 12.7s) so the keepalive cannot fire
	// during the burst below. Two distinct hazards, both real:
	//
	//   - A keepalive Request draws a second Membership Query, and send_update
	//     is single-shot per query on the Rust path (BLO-28805): the second call
	//     re-enters gateway.rs:252 in state Active, fails the guard and returns
	//     InvalidState, which ReadBatch would surface mid-burst.
	//   - fakeRelay's default code is 0x0a = 1s, which is well inside the time
	//     this test spends reading, so that is not a theoretical window.
	//
	// This pins the relay's advertised interval rather than
	// RelayManagerConfig.KeepaliveInterval because the handshake overwrites the
	// latter — see withQueryIntervalCode.
	fr := newFakeRelay(t, withQueryIntervalCode(0x7f))
	nat := installFakeNativeSource(t)
	// Never enabled: native delivery is off by default, so silence is the
	// harness's resting state rather than something arranged here.

	mc := newMulticastConnUnderTest(t, fr)

	start := time.Now()
	err := mc.Open()
	elapsed := time.Since(start)
	t.Logf("Open with native silent took %s (probe window floor is %s), err=%v",
		elapsed.Round(time.Millisecond), MinUsefulProbeWindow, err)

	if nat.Binds() != 1 {
		t.Fatalf("native joins through the seam = %d, want 1: the handover did not "+
			"follow a failed probe, it skipped native altogether", nat.Binds())
	}
	if nat.Delivered() != 0 {
		t.Fatalf("native source delivered %d datagram(s) despite never being "+
			"enabled; this test is not exercising a silent native path", nat.Delivered())
	}

	// The handover reached the relay. Gateway sends Relay Discovery as the first
	// leg of Open, so a relay that answered one necessarily saw the gateway come
	// up. Kept as a separate, earlier assertion than the handshake result: if
	// this one fails the group never reached AMT at all, which is a different
	// diagnosis from a handshake that started and then broke.
	waitForRelayDiscovery(t, fr)
	if n := fr.advertised.Load(); n < 1 {
		t.Fatalf("relay received no Relay Discovery (advertisements sent = %d): the "+
			"probe timed out but the group was never handed to an AMT gateway", n)
	}

	// Both legs are bounded, and this is the only test that covers them in
	// series. gateway_timeout_test.go bounds the handshake from a bare Gateway;
	// here the probe window runs first, so a regression that made either leg
	// unbounded — the #29 hang, or a probe deadline that outlived its window —
	// shows up as an overrun rather than a slow pass.
	if elapsed >= MinUsefulProbeWindow {
		t.Errorf("Open took %s, want return before the native probe window %s", elapsed, MinUsefulProbeWindow)
	}
	if bound := 2*time.Second + 8*time.Second; elapsed > bound {
		t.Errorf("Open took %s, over the %s bound (probe window + handshake timeout "+
			"+ slack): one of the two legs is not bounding itself", elapsed, bound)
	}

	// No timeout branch. A handshake that does not complete is the BLO-29437
	// regression returning, and the burst below is what proves the tunnel
	// carries data rather than merely having been constructed.
	if err != nil {
		t.Fatalf("Gateway.Open did not complete against fakeRelay: %v. The relay "+
			"answered the discovery, so this is the handshake breaking after it "+
			"started. If this is an i/o timeout, suspect the advertisement decode "+
			"first: BLO-29437 was gateway.go handing the Rust decoder a full-MTU "+
			"buffer for a message whose decoder matches on exact length.", err)
	}

	if !mc.IsUsingTunnel() {
		t.Fatal("Open succeeded with native silent but the connection does not " +
			"report tunnelling; the group is on neither path")
	}
	// The log line the cgo-test lane greps for. A bare --- PASS is not evidence
	// on its own: that is what the old timeout branch produced too, so CI
	// asserts on this string specifically.
	t.Log("Gateway.Open COMPLETED against fakeRelay")

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
			t.Fatalf("packet %d (%q) has provenance %q, want %q: native is silent, so "+
				"anything arriving must have come through the tunnel",
				i, payload, got, tunnelProvenanceTag)
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
	waitForRelayDiscovery(t, fr)
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
