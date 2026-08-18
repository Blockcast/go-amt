package amt

import (
	"testing"
	"time"
)

// The two production configurations from BLO-28640, pinned as named cases so a
// future change to planProbe cannot quietly restore either of them.
//
// Both took the live multicast receiver down on 2026-08-18: the native socket was
// bound, the group was joined, and then the probe closed both because it had
// asked a 5s-cadence stream to answer inside 50ms (or, with the timeout unset,
// inside no time at all).
func TestPlanProbeRejectsWindowsThatCannotBeEvidence(t *testing.T) {
	t.Run("unset timeout does not discard the native join", func(t *testing.T) {
		// Previously: SetReadDeadline(now+0) — a deadline already in the past, so
		// ReadFrom timed out immediately and conn4.Close() ran 100% of the time.
		plan := planProbe(AMTModeAuto, true, 0)

		if !plan.Probe {
			t.Fatal("want a probe, got none: an unset timeout is a missing config value, not a decision to drop native")
		}
		if plan.Window < MinUsefulProbeWindow {
			t.Errorf("window %v is shorter than the %v a 5s signalling cadence needs", plan.Window, MinUsefulProbeWindow)
		}
	})

	t.Run("production 50ms is raised, not believed", func(t *testing.T) {
		plan := planProbe(AMTModeAuto, true, 50*time.Millisecond)

		if plan.Window != MinUsefulProbeWindow {
			t.Errorf("window = %v, want %v: 50ms against a 5s cadence catches a packet ~1%% of the time", plan.Window, MinUsefulProbeWindow)
		}
	})
}

func TestPlanProbe(t *testing.T) {
	tests := []struct {
		name            string
		mode            AMTMode
		relayConfigured bool
		timeout         time.Duration
		wantProbe       bool
		wantWindow      time.Duration
		wantTunnel      bool
	}{
		{
			// The overwhelmingly common case: trafficcontrol always allocates an
			// AMTRelay struct, but with an empty address, so ParseIP yields nil and
			// no relay is configured. Nothing to fall back to, so nothing to probe.
			name:      "no relay stays native without probing",
			mode:      AMTModeAuto,
			wantProbe: false,
		},
		{
			name:            "auto with relay probes and may tunnel",
			mode:            AMTModeAuto,
			relayConfigured: true,
			timeout:         30 * time.Second,
			wantProbe:       true,
			wantWindow:      30 * time.Second,
			wantTunnel:      true,
		},
		{
			// A window longer than the floor is the operator's call and is honoured.
			name:            "auto honours a window longer than the floor",
			mode:            AMTModeAuto,
			relayConfigured: true,
			timeout:         MinUsefulProbeWindow + time.Second,
			wantProbe:       true,
			wantWindow:      MinUsefulProbeWindow + time.Second,
			wantTunnel:      true,
		},
		{
			name:            "auto floors a too-short window",
			mode:            AMTModeAuto,
			relayConfigured: true,
			timeout:         50 * time.Millisecond,
			wantProbe:       true,
			wantWindow:      MinUsefulProbeWindow,
			wantTunnel:      true,
		},
		{
			name:            "auto floors an unset window",
			mode:            AMTModeAuto,
			relayConfigured: true,
			timeout:         0,
			wantProbe:       true,
			wantWindow:      MinUsefulProbeWindow,
			wantTunnel:      true,
		},
		{
			// A negative duration is as meaningless as zero and must not be
			// forwarded to SetReadDeadline as a past deadline.
			name:            "auto floors a negative window",
			mode:            AMTModeAuto,
			relayConfigured: true,
			timeout:         -time.Second,
			wantProbe:       true,
			wantWindow:      MinUsefulProbeWindow,
			wantTunnel:      true,
		},
		{
			// The escape hatch for the production incident: a relay address that was
			// inherited by profile clone must not cost the operator native multicast.
			name:            "native mode ignores a configured relay",
			mode:            AMTModeNative,
			relayConfigured: true,
			timeout:         50 * time.Millisecond,
			wantProbe:       false,
			wantTunnel:      false,
		},
		{
			// An operator who asked for the tunnel has already answered the question
			// the probe exists to ask, so do not spend MinUsefulProbeWindow re-asking.
			name:            "tunnel mode skips the probe entirely",
			mode:            AMTModeTunnel,
			relayConfigured: true,
			timeout:         30 * time.Second,
			wantProbe:       false,
			wantTunnel:      true,
		},
		{
			// Tunnel mode is not actionable without somewhere to tunnel to.
			name:            "tunnel mode without a relay degrades to native",
			mode:            AMTModeTunnel,
			relayConfigured: false,
			wantProbe:       false,
			wantTunnel:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := planProbe(tt.mode, tt.relayConfigured, tt.timeout)

			if got.Probe != tt.wantProbe {
				t.Errorf("Probe = %v, want %v", got.Probe, tt.wantProbe)
			}
			if got.TunnelOnFailure != tt.wantTunnel {
				t.Errorf("TunnelOnFailure = %v, want %v", got.TunnelOnFailure, tt.wantTunnel)
			}
			if tt.wantProbe && got.Window != tt.wantWindow {
				t.Errorf("Window = %v, want %v", got.Window, tt.wantWindow)
			}
		})
	}
}

// Whatever the inputs, Open must never be handed a deadline it cannot act on: a
// probe with a zero or negative window is the exact shape of the outage.
func TestPlanProbeNeverYieldsAnUnusableWindow(t *testing.T) {
	modes := []AMTMode{AMTModeAuto, AMTModeNative, AMTModeTunnel}
	timeouts := []time.Duration{-time.Hour, -time.Nanosecond, 0, time.Nanosecond, 50 * time.Millisecond, time.Hour}

	for _, mode := range modes {
		for _, relay := range []bool{false, true} {
			for _, timeout := range timeouts {
				plan := planProbe(mode, relay, timeout)
				if plan.Probe && plan.Window < MinUsefulProbeWindow {
					t.Errorf("planProbe(%v, %v, %v) probes with window %v, shorter than %v",
						mode, relay, timeout, plan.Window, MinUsefulProbeWindow)
				}
			}
		}
	}
}

// A probe is only ever worth running when there is a tunnel to fall back to.
func TestPlanProbeOnlyProbesWhenFallbackExists(t *testing.T) {
	for _, mode := range []AMTMode{AMTModeAuto, AMTModeNative, AMTModeTunnel} {
		if plan := planProbe(mode, false, time.Minute); plan.Probe || plan.TunnelOnFailure {
			t.Errorf("planProbe(%v, no relay, …) = %+v, want a plain native join", mode, plan)
		}
	}
}

func TestGatewayOpenTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			// The production value. Handing 50ms to the relay handshake guarantees it
			// fails, so the tunnel that just replaced native cannot come up either.
			// Dropping it to 0 lets Gateway.Open use DefaultOpenTimeout.
			name:    "production 50ms defers to the gateway default",
			timeout: 50 * time.Millisecond,
			want:    0,
		},
		{
			name:    "unset defers to the gateway default",
			timeout: 0,
			want:    0,
		},
		{
			name:    "negative defers to the gateway default",
			timeout: -time.Second,
			want:    0,
		},
		{
			name:    "a plausible bound is honoured",
			timeout: 5 * time.Second,
			want:    5 * time.Second,
		},
		{
			name:    "the threshold itself is honoured",
			timeout: MinRelayHandshakeTimeout,
			want:    MinRelayHandshakeTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gatewayOpenTimeout(tt.timeout); got != tt.want {
				t.Errorf("gatewayOpenTimeout(%v) = %v, want %v", tt.timeout, got, tt.want)
			}
		})
	}
}

// Gateway.Open treats a non-positive Timeout as "use DefaultOpenTimeout", so the
// adapter must never emit a positive-but-useless value: that would be honoured
// literally and fail the handshake.
func TestGatewayOpenTimeoutNeverEmitsAnUnusableBound(t *testing.T) {
	for _, timeout := range []time.Duration{-time.Hour, -time.Nanosecond, 0, time.Nanosecond, time.Millisecond, 999 * time.Millisecond} {
		if got := gatewayOpenTimeout(timeout); got != 0 {
			t.Errorf("gatewayOpenTimeout(%v) = %v, want 0 so Gateway.Open applies DefaultOpenTimeout", timeout, got)
		}
	}
}
