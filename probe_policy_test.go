package amt

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestAttemptNativeIsTheSamePredicateOnBothTypes is the regression guard for the
// asymmetry BLO-28640's fix left behind: planManagedOpen declined the native
// bind for AMTModeTunnel while MulticastConn.Open bound unconditionally, so the
// same Mode value produced two different behaviours depending on which type the
// caller held.
//
// The parity assertion is the point. Asserting only the truth table would let a
// future edit re-diverge the two call sites while each stayed internally
// consistent, which is exactly how the defect survived its first repair.
func TestAttemptNativeIsTheSamePredicateOnBothTypes(t *testing.T) {
	modes := []struct {
		name string
		mode AMTMode
	}{
		{"Auto", AMTModeAuto},
		{"Native", AMTModeNative},
		{"Tunnel", AMTModeTunnel},
	}
	timeouts := []time.Duration{0, 50 * time.Millisecond, time.Second, time.Minute}

	for _, m := range modes {
		for _, hasRelay := range []bool{false, true} {
			for _, timeout := range timeouts {
				plan := planProbe(m.mode, hasRelay, timeout)
				managed := planManagedOpen(m.mode, hasRelay, false, timeout)
				if plan.attemptNative() != managed.AttemptNative {
					t.Errorf("mode=%s hasRelay=%v timeout=%s: MulticastConn would attemptNative=%v but ManagedConn AttemptNative=%v — the two types must not disagree about the same Mode",
						m.name, hasRelay, timeout, plan.attemptNative(), managed.AttemptNative)
				}
			}
		}
	}
}

func TestTimeoutBoundsRemainIndependent(t *testing.T) {
	probeWindow, handshakeTimeout := resolveTimeouts(0, 60*time.Second, 2*time.Second)

	probe := planProbe(AMTModeAuto, true, probeWindow)
	if probe.Window != 60*time.Second {
		t.Fatalf("probe window = %v, want 1m", probe.Window)
	}
	if got := gatewayOpenTimeout(handshakeTimeout); got != 2*time.Second {
		t.Fatalf("handshake timeout = %v, want 2s", got)
	}
}

func TestLegacyTimeoutSeedsUnsetBoundsIndependently(t *testing.T) {
	probeWindow, handshakeTimeout := resolveTimeouts(7*time.Second, 0, 0)
	if probeWindow != 7*time.Second || handshakeTimeout != 7*time.Second {
		t.Fatalf("legacy timeout resolved to probe=%v handshake=%v, want both 7s", probeWindow, handshakeTimeout)
	}

	probeWindow, handshakeTimeout = resolveTimeouts(7*time.Second, 60*time.Second, 0)
	if probeWindow != 60*time.Second || handshakeTimeout != 7*time.Second {
		t.Fatalf("partial explicit config resolved to probe=%v handshake=%v, want 60s/7s", probeWindow, handshakeTimeout)
	}
}

// TestOnlyDeliberateTunnelModeDeclinesTheNativeBind pins the truth table itself,
// so a change that keeps both call sites consistent while making the predicate
// wrong is still caught.
//
// The case that matters is the last one: AMTModeTunnel with a relay is the only
// shape that declines the bind. If any other row flipped to false, a mode that
// needs the native socket would stop binding it; if the last row flipped to
// true, the escape hatch would go back to failing closed on precisely the hosts
// where an operator selects it.
func TestOnlyDeliberateTunnelModeDeclinesTheNativeBind(t *testing.T) {
	cases := []struct {
		name          string
		mode          AMTMode
		hasRelay      bool
		attemptNative bool
	}{
		{"Auto without a relay keeps native, since there is nothing to fall back to", AMTModeAuto, false, true},
		{"Auto with a relay binds, because it must probe before deciding", AMTModeAuto, true, true},
		{"Native without a relay binds", AMTModeNative, false, true},
		{"Native with a relay binds and never tunnels", AMTModeNative, true, true},
		{"Tunnel without a relay degrades to native, so it binds", AMTModeTunnel, false, true},
		{"Tunnel with a relay goes straight to the tunnel and never binds", AMTModeTunnel, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planProbe(tc.mode, tc.hasRelay, time.Second).attemptNative()
			if got != tc.attemptNative {
				t.Errorf("attemptNative() = %v, want %v", got, tc.attemptNative)
			}
		})
	}
}

// probeConnStub satisfies nativeConn without a socket, so the shared probe
// machinery can be exercised on a host with no multicast route.
//
// clearErr, when set, fails only the deadline-CLEARING call (the zero-time one),
// which is the single failure the success path has to handle distinctly.
type probeConnStub struct {
	deadlines []time.Time
	clearErr  error
}

func (c *probeConnStub) Close() error                     { return nil }
func (c *probeConnStub) LocalAddr() net.Addr              { return nil }
func (c *probeConnStub) SetDeadline(t time.Time) error    { return nil }
func (c *probeConnStub) SetWriteDeadline(time.Time) error { return nil }
func (c *probeConnStub) SetReadDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	if t.IsZero() {
		return c.clearErr
	}
	return nil
}

// TestProbeClampsNonPositiveMTU covers an interface reporting MTU 0, which
// otherwise makes a zero-length buffer and reads into nothing.
//
// The clamp is asserted here, in the shared implementation, because that is what
// makes it cover all three call sites at once: both conn.go branches pass
// mc.IFace.MTU straight through, and managed_conn_native.go's own default only
// handles a nil IFace rather than a present one reporting zero.
func TestProbeClampsNonPositiveMTU(t *testing.T) {
	for _, mtu := range []int{0, -1, -1500} {
		var got int
		conn := &probeConnStub{}
		_, native, err := probeNativeTraffic(conn, time.Second, mtu, func(b []byte) (int, error) {
			got = len(b)
			return 0, nil
		})
		if err != nil {
			t.Fatalf("mtu=%d: unexpected error: %v", mtu, err)
		}
		if !native {
			t.Fatalf("mtu=%d: probe should report native traffic when the read succeeds", mtu)
		}
		if got <= 0 {
			t.Errorf("mtu=%d: probe read into a %d-byte buffer; a non-positive MTU must be clamped, not trusted", mtu, got)
		}
	}
}

// TestProbePassesThroughAPlausibleMTU guards the other direction: the clamp must
// not overwrite a real MTU, including a small-but-legitimate one.
func TestProbePassesThroughAPlausibleMTU(t *testing.T) {
	for _, mtu := range []int{576, 1500, 9000} {
		var got int
		conn := &probeConnStub{}
		if _, _, err := probeNativeTraffic(conn, time.Second, mtu, func(b []byte) (int, error) {
			got = len(b)
			return 0, nil
		}); err != nil {
			t.Fatalf("mtu=%d: unexpected error: %v", mtu, err)
		}
		if got != mtu {
			t.Errorf("mtu=%d: probe read into a %d-byte buffer, want %d", mtu, got, mtu)
		}
	}
}

// TestProbeClearsItsDeadlineOnSuccess pins the second half of the BLO-28640
// shape: a probe that returned a socket still carrying its expired deadline
// would fail every subsequent read instantly.
func TestProbeClearsItsDeadlineOnSuccess(t *testing.T) {
	conn := &probeConnStub{}
	if _, _, err := probeNativeTraffic(conn, time.Second, 1500, func([]byte) (int, error) { return 0, nil }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(conn.deadlines) != 2 {
		t.Fatalf("expected the probe to set then clear a read deadline, got %d calls", len(conn.deadlines))
	}
	if !conn.deadlines[1].IsZero() {
		t.Errorf("probe left a read deadline of %v on the socket; it must be cleared", conn.deadlines[1])
	}
}

// TestProbeYieldsNoPacketWhenClearingTheDeadlineFails pins the contract that an
// error return never carries a datagram.
//
// The success path reads a packet and then clears the deadline, so it is the one
// place that can hold a real packet at the moment an error appears. Returning
// (pkt, true, err) there would be unactionable: every call site tests the error
// and returns before it looks at the bool, so the datagram would be consumed by
// the probe and discarded by the caller — the exact defect this PR closes,
// re-entering through the signature rather than through the predicate.
//
// Asserting the bool as well as the packet is deliberate. A future call site
// that checked native before err would otherwise read a nil packet as a
// zero-length datagram, which is a distinction this file works to preserve
// everywhere else.
func TestProbeYieldsNoPacketWhenClearingTheDeadlineFails(t *testing.T) {
	wantErr := errors.New("use of closed network connection")
	conn := &probeConnStub{clearErr: wantErr}

	pkt, native, err := probeNativeTraffic(conn, time.Second, 1500, func(b []byte) (int, error) {
		copy(b, []byte("slt"))
		return 3, nil
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("probe returned error %v, want %v", err, wantErr)
	}
	if pkt != nil {
		t.Errorf("probe returned a %d-byte packet alongside an error; no caller reads it, so the datagram is silently discarded", len(pkt))
	}
	if native {
		t.Errorf("probe reported native=true alongside an error; the bool must carry no information on the error path")
	}
}
