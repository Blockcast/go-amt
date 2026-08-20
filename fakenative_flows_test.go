//go:build linux || darwin

package amt

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests exercise the fakeNativeSource harness and then use it, together
// with fakeRelay, to drive a real delivery-path switchover.
//
// They run in BOTH the CGO_ENABLED=0 `test` lane and the `cgo-test` lane,
// because ManagedConn's native path (managed_conn_native.go, `linux || darwin`)
// and its tunnel path (relay_manager.go, untagged) both compile without cgo.
// MulticastConn cannot: conn.go and gateway.go are `cgo && !purego`, so the same
// switchover against MulticastConn/Gateway lives in fakerelay_switchover_test.go
// and is cgo-only. Between them the two files cover both arbiters; ci.yml
// asserts each file is selected in the lane it claims.
//
// RUNTIME. Any test here that needs the probe to CONCLUDE native is dead pays
// MinUsefulProbeWindow, which is a const 10s floor that no configuration can
// lower — planProbe raises anything shorter rather than believing it. The
// switchover story is therefore written as one test with subtests, so the suite
// pays that window once rather than once per assertion.

// parseNativeSeq extracts the sequence number from a tagged payload.
func parseNativeSeq(t *testing.T, payload []byte) int {
	t.Helper()
	_, rest, ok := strings.Cut(string(payload), "|")
	if !ok {
		t.Fatalf("payload %q carries no sequence number", payload)
	}
	seq, err := strconv.Atoi(rest)
	if err != nil {
		t.Fatalf("payload %q sequence: %v", payload, err)
	}
	return seq
}

// newManagedConnUnderTest builds a ManagedConn pointed at a fake relay, in the
// mode where the delivery path is actually in question.
//
// AMTModeAuto with a relay configured is the only shape that probes: Native
// keeps the join unconditionally and Tunnel skips it, so neither can switch over.
// The interface is deliberately one that does not exist — the fake native source
// substitutes the seam before the name is ever resolved, and using a real
// interface would only invite the test to pass because of a genuine local join.
func newManagedConnUnderTest(t *testing.T, fr *fakeRelay) *ManagedConn {
	t.Helper()

	mc := &ManagedConn{
		SrcAddr:   testHarnessSource,
		GroupAddr: testHarnessGroup,
		GroupPort: testHarnessPort,
		RelayAddr: fr.Addr(),
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
		// At or above MinRelayHandshakeTimeout so gatewayOpenTimeout keeps it as
		// the handshake bound instead of falling back to DefaultOpenTimeout.
		Timeout: 2 * time.Second,
		Mode:    AMTModeAuto,
	}

	t.Cleanup(func() {
		_ = mc.Close()
		// RelayManagers live in a process-global registry keyed by relay address.
		// Ephemeral relay ports mean no two tests collide, but leaving a live
		// manager behind leaks its keepalive goroutine and socket for the rest of
		// the binary.
		_ = CloseRelayManager(fr.Addr())
	})

	return mc
}

// waitTunnelReady blocks until the connection's relay subscription is Active,
// which is when the tunnel can actually deliver.
//
// Open does NOT guarantee this. It returns as soon as rm.Subscribe does, and
// Subscribe only queues into pendingJoins — a debounced batch timer sends the
// Membership Update and promotes the subscription afterwards. Until then
// routeDataToSubscription drops every packet on the floor
// (relay_manager.go:885), silently: no error, no counter, nothing the caller can
// observe. So a test that opens and immediately reads sees an empty tunnel and
// blames the relay. fakerelay_test.go's subscribeActive documents the same race
// for a directly-driven RelayManager; this is the ManagedConn-shaped version of
// it, and the harness has to expose it or every tunnel assertion built on Open
// alone is timing-dependent.
func waitTunnelReady(t *testing.T, mc *ManagedConn, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sub := mc.Subscription()
		if sub != nil && sub.State() == SubscriptionStateActive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	state := "<no subscription>"
	if sub := mc.Subscription(); sub != nil {
		state = sub.State().String()
	}
	t.Fatalf("relay subscription never became active within %s (state %s); the "+
		"tunnel cannot deliver until it does", timeout, state)
}

// assertNativeIsTheDeliveryPath opens the connection and asserts the arbiter
// chose native AND that the bytes delivered actually came from the native source.
//
// Both halves are the point. IsUsingTunnel alone says which path was selected,
// not that it works; a payload alone says something arrived, not by which route.
// A switchover assertion needs to tell "still working" from "working via the
// path we expected", and only the pair does that.
//
// Reported through a reporter rather than *testing.T so the negative control can
// run this exact body and require it to fail.
func assertNativeIsTheDeliveryPath(r reporter, mc *ManagedConn, readTimeout time.Duration) {
	r.Helper()

	if err := mc.Open(); err != nil {
		r.Errorf("Open: %v", err)
		return
	}
	if mc.IsUsingTunnel() {
		r.Errorf("arbiter chose the AMT tunnel, want native: the native source was " +
			"delivering, so the probe should have been satisfied inside the window")
		return
	}

	payload, err := readOne(mc, readTimeout)
	if err != nil {
		r.Errorf("read after choosing native: %v", err)
		return
	}
	if got := provenanceOf(payload); got != nativeProvenanceTag {
		r.Errorf("delivered payload %q has provenance %q, want %q: the connection "+
			"reports native but the bytes did not come from the native source",
			payload, got, nativeProvenanceTag)
	}
}

// TestFakeNativeSourceDeliversOnlyWhileEnabled pins the harness switch itself,
// in both directions, before anything relies on it.
//
// It drives the seam directly rather than through a conn type, so a failure here
// is unambiguously the harness and not the arbiter. Both directions matter: a
// source that cannot be silenced makes every fallback test vacuous, and one that
// cannot be started makes every native test vacuous.
func TestFakeNativeSourceDeliversOnlyWhileEnabled(t *testing.T) {
	nat := installFakeNativeSource(t)

	group := &net.UDPAddr{IP: net.IP(testHarnessGroup.AsSlice()), Port: testHarnessPort}
	conn, err := listenMulticastUDP4("udp4", nil, testHarnessSource, group, nil, false, 1, 0, 0, 0)
	if err != nil {
		t.Fatalf("seam join: %v", err)
	}
	defer conn.Close()

	if got := nat.Binds(); got != 1 {
		t.Fatalf("seam calls = %d, want 1: the fake was not installed, so every "+
			"delivery assertion built on it would pass for the wrong reason", got)
	}

	// Off by default.
	if _, err := readOne(nativeSocketReader{conn}, 250*time.Millisecond); err == nil {
		t.Fatal("received a datagram while native delivery was disabled; the switch " +
			"does not gate anything and a fallback test using it would be vacuous")
	}

	nat.Enable(testHarnessGroup)
	payload, err := readOne(nativeSocketReader{conn}, 2*time.Second)
	if err != nil {
		t.Fatalf("no datagram after enabling native delivery: %v", err)
	}
	if got := provenanceOf(payload); got != nativeProvenanceTag {
		t.Errorf("provenance = %q, want %q", got, nativeProvenanceTag)
	}

	// Back off again. Drain what is already in the socket buffer first, or the
	// backlog from the enabled phase reads as a live source.
	nat.Disable(testHarnessGroup)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := readOne(nativeSocketReader{conn}, 50*time.Millisecond); err != nil {
			break
		}
	}
	if _, err := readOne(nativeSocketReader{conn}, 250*time.Millisecond); err == nil {
		t.Error("still receiving datagrams after disabling native delivery; the " +
			"source cannot be silenced on demand")
	}
}

// TestFakeNativeSourceIsolatesGroups pins that the switch is per-group, which is
// what lets a test silence the group under test without silencing everything.
func TestFakeNativeSourceIsolatesGroups(t *testing.T) {
	nat := installFakeNativeSource(t)

	other := testHarnessGroup.Next()
	watched := &net.UDPAddr{IP: net.IP(testHarnessGroup.AsSlice()), Port: testHarnessPort}
	ignored := &net.UDPAddr{IP: net.IP(other.AsSlice()), Port: testHarnessPort}

	watchedConn, err := listenMulticastUDP4("udp4", nil, testHarnessSource, watched, nil, false, 1, 0, 0, 0)
	if err != nil {
		t.Fatalf("seam join (watched): %v", err)
	}
	defer watchedConn.Close()

	ignoredConn, err := listenMulticastUDP4("udp4", nil, testHarnessSource, ignored, nil, false, 1, 0, 0, 0)
	if err != nil {
		t.Fatalf("seam join (ignored): %v", err)
	}
	defer ignoredConn.Close()

	nat.Enable(other)

	if _, err := readOne(nativeSocketReader{ignoredConn}, 2*time.Second); err != nil {
		t.Fatalf("enabled group received nothing: %v", err)
	}
	if _, err := readOne(nativeSocketReader{watchedConn}, 250*time.Millisecond); err == nil {
		t.Error("a group that was never enabled received traffic; the switch is " +
			"global rather than per-group, so a test cannot silence one group alone")
	}
}

// TestProvenanceOfNamesEachDeliveryPath pins the provenance decoder, including
// that foreign bytes are neither path.
//
// The third case is the one that matters: treating "not native" as "tunnel"
// would let a corrupted or unrelated datagram be reported as a successful
// switchover.
func TestProvenanceOfNamesEachDeliveryPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{"native", nativePayload(7), nativeProvenanceTag},
		{"tunnel", tunnelPayload(7), tunnelProvenanceTag},
		{"untagged", []byte("hello"), unknownProvenanceTag},
		{"foreign tag", []byte("relay|7"), unknownProvenanceTag},
		{"empty", nil, unknownProvenanceTag},
	} {
		if got := provenanceOf(tc.payload); got != tc.want {
			t.Errorf("provenanceOf(%q) = %q, want %q", tc.payload, got, tc.want)
		} else {
			t.Logf("%s: provenanceOf(%q) = %q", tc.name, tc.payload, got)
		}
	}
}

// TestManagedConnKeepsNativeWhenBothPathsAreLive is the "native and relay both
// live" case: with a relay configured AND reachable, a delivering native join
// must still win.
//
// The relay-side assertion is what gives this force. Asserting only
// !IsUsingTunnel would also pass if the arbiter had picked native for a bad
// reason; asserting the relay was never even discovered proves no part of Open
// went looking for a tunnel it did not need.
func TestManagedConnKeepsNativeWhenBothPathsAreLive(t *testing.T) {
	fr := newFakeRelay(t)
	nat := installFakeNativeSource(t)
	nat.Enable(testHarnessGroup)

	mc := newManagedConnUnderTest(t, fr)
	assertNativeIsTheDeliveryPath(t, mc, 2*time.Second)

	if n := fr.advertised.Load(); n != 0 {
		t.Errorf("relay answered %d discovery message(s), want 0: native was "+
			"delivering, so Open should never have reached the relay at all", n)
	}
	if nat.Delivered() == 0 {
		t.Error("native source delivered nothing, yet the connection reports native; " +
			"the assertion above cannot have been testing what it claims")
	}
}

// TestManagedConnSwitchesFromNativeToRelayAndBack is the switchover story, in the
// order it happens in production, as subtests over one shared setup.
//
// Written as one test because the first leg pays MinUsefulProbeWindow — a 10s
// const floor no configuration can lower — and splitting the legs would pay it
// per test rather than once.
func TestManagedConnSwitchesFromNativeToRelayAndBack(t *testing.T) {
	fr := newFakeRelay(t)
	nat := installFakeNativeSource(t)

	// Native is silent from the start: delivery defaults to off, so this is the
	// harness's default rather than something arranged.
	silent := newManagedConnUnderTest(t, fr)

	t.Run("native silent falls back to the relay", func(t *testing.T) {
		start := time.Now()
		if err := silent.Open(); err != nil {
			t.Fatalf("Open with native silent: %v", err)
		}
		t.Logf("Open took %s (probe window is %s)", time.Since(start).Round(time.Millisecond), MinUsefulProbeWindow)

		if !silent.IsUsingTunnel() {
			t.Fatal("connection kept native even though the native source never " +
				"delivered; the probe cannot have concluded anything")
		}
		if nat.Binds() == 0 {
			t.Error("no native join was attempted, so the fallback did not follow a " +
				"failed probe — it skipped native altogether")
		}
	})

	t.Run("relay delivers under load while native stays silent", func(t *testing.T) {
		if !silent.IsUsingTunnel() {
			t.Skip("previous subtest did not reach the tunnel")
		}

		// The tunnel is selected but not yet able to deliver; see waitTunnelReady.
		waitTunnelReady(t, silent, 5*time.Second)

		// Sent from THIS goroutine, not a background one. fakeRelay.SendData
		// reports failures with t.Fatalf, and Fatalf from a non-test goroutine
		// calls runtime.Goexit on the wrong stack: the test hangs or reports
		// nothing instead of failing. The whole burst is emitted before the first
		// read, which is a stronger load shape anyway — it has to survive being
		// queued rather than being consumed as fast as it arrives. The relay
		// manager's per-subscription channel is 100 deep (DataChannelSize), so 16
		// is comfortably inside it and a drop here would be a real defect rather
		// than the harness overrunning its own buffer.
		const burst = 16
		for i := 1; i <= burst; i++ {
			fr.SendData(testHarnessSource, testHarnessGroup, 4000, testHarnessPort, tunnelPayload(i))
		}

		prev := 0
		for i := 1; i <= burst; i++ {
			payload, err := readOne(silent, 3*time.Second)
			if err != nil {
				t.Fatalf("tunnel read %d/%d: %v", i, burst, err)
			}
			if got := provenanceOf(payload); got != tunnelProvenanceTag {
				t.Fatalf("packet %d has provenance %q, want %q: native is silent, so "+
					"anything arriving must have come through the tunnel", i, got, tunnelProvenanceTag)
			}
			if seq := parseNativeSeq(t, payload); seq <= prev {
				t.Errorf("packet %d carries sequence %d, not greater than %d: the "+
					"tunnel reordered the burst", i, seq, prev)
			} else {
				prev = seq
			}
		}
	})

	t.Run("native recovers and a fresh open picks it again", func(t *testing.T) {
		nat.Enable(testHarnessGroup)

		// A fresh connection, because Open is one-shot: the arbiter re-decides per
		// Open, and Close marks the old connection permanently closed. This is the
		// shape a reconnect actually takes.
		recovered := newManagedConnUnderTest(t, fr)
		assertNativeIsTheDeliveryPath(t, recovered, 2*time.Second)
	})
}

// TestNativeDeliveryAssertionFailsWhenNativeNeverDelivers is the negative
// control the harness is worthless without.
//
// It runs assertNativeIsTheDeliveryPath — the SAME function the positive tests
// use, not a paraphrase — with the native switch forced off for the whole test,
// and requires it to report a failure. If it passed here, it would be asserting
// nothing there: a harness whose native-recovery assertion is green whether or
// not native ever delivered cannot distinguish a working switchover from a
// broken one.
//
// This is why assertNativeIsTheDeliveryPath reports through a reporter and uses
// Errorf rather than Fatalf: Fatalf would unwind this goroutine instead of
// handing the failure back to be checked.
func TestNativeDeliveryAssertionFailsWhenNativeNeverDelivers(t *testing.T) {
	fr := newFakeRelay(t)
	nat := installFakeNativeSource(t)

	// Deliberately never Enable. Assert the switch really is off rather than
	// trusting the default.
	if nat.Delivered() != 0 {
		t.Fatalf("native source delivered %d datagram(s) before being enabled; the "+
			"control cannot force native off", nat.Delivered())
	}

	mc := newManagedConnUnderTest(t, fr)
	rec := &failureRecorder{}
	assertNativeIsTheDeliveryPath(rec, mc, 2*time.Second)

	if !rec.failed() {
		t.Fatal("assertNativeIsTheDeliveryPath PASSED with native delivery forced " +
			"off for the whole test. It is therefore not testing native delivery, " +
			"and every positive result from it is meaningless.")
	}
	t.Logf("negative control: assertion failed as required (%s)", rec.report())

	if nat.Delivered() != 0 {
		t.Errorf("native source delivered %d datagram(s) despite never being enabled", nat.Delivered())
	}
	if !mc.IsUsingTunnel() {
		t.Error("connection did not fall back to the tunnel, so the assertion above " +
			"may have failed for an unrelated reason")
	}
}
