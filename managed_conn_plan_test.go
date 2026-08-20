package amt

import (
	"testing"
	"time"
)

// modeIsSettableUnderEveryBuildConfiguration is a compile-time assertion, not a
// runtime one: it exists so that assigning Mode fails the build here rather than
// in a consumer.
//
// This file carries no build tags, so `GOOS=android go vet ./...` (and ios,
// nocgo, purego, js) type-checks it. That matters because go-amt has THREE
// MulticastConn definitions — conn.go (cgo), conn_nocgo.go, conn_mobile.go — and
// the mobile one shipped without Mode while conn_nocgo.go's comment claimed
// callers "can set it under any build configuration without tag-specific code"
// (Ally review on go-amt#49).
//
// Note that `GOOS=android go build ./...` does NOT catch that: a struct missing a
// field compiles perfectly well on its own. Only an assignment does, which is why
// this is a test rather than a CI build step.
func modeIsSettableUnderEveryBuildConfiguration() {
	var mc MulticastConn
	mc.Mode = AMTModeNative
	mc.Mode = AMTModeTunnel
	mc.Mode = AMTModeAuto

	// ManagedConn is the path conn_mobile.go delegates to, so mobile inherits its
	// policy. It needs the same field for the delegation to carry the operator's
	// choice rather than silently dropping it.
	var managed ManagedConn
	managed.Mode = AMTModeNative
}

var _ = modeIsSettableUnderEveryBuildConfiguration

// TestPlanManagedOpenRejectsTheOutageConfigurations pins the BLO-28640 shapes on
// the ManagedConn path specifically.
//
// ManagedConn carried an independent copy of the same defect after conn.go was
// fixed: managed_conn_native.go honoured mc.Timeout literally and closed the
// socket, and managed_conn.go gated the native attempt on `mc.Timeout > 0` so an
// unset timeout skipped native altogether. Neither had a test, which is how the
// copy survived the first fix.
func TestPlanManagedOpenRejectsTheOutageConfigurations(t *testing.T) {
	t.Run("unset timeout still attempts native", func(t *testing.T) {
		// Previously: `hasRelay && mc.Timeout > 0` was false, so ManagedConn went
		// straight to the tunnel and never bound the native socket at all — the
		// "unset is worse than 50ms" case.
		plan := planManagedOpen(AMTModeAuto, true, false, 0)

		if !plan.AttemptNative {
			t.Fatal("want a native attempt: an unset timeout is a missing config value, not a decision to skip native")
		}
		if !plan.Probe.Probe {
			t.Error("want a probe to decide native-vs-tunnel")
		}
		if plan.Probe.Window < MinUsefulProbeWindow {
			t.Errorf("window %v is shorter than the %v a 5s signalling cadence needs", plan.Probe.Window, MinUsefulProbeWindow)
		}
	})

	t.Run("production 50ms does not destroy the native join", func(t *testing.T) {
		// Previously: SetReadDeadline(now+50ms) against a 5s cadence, then
		// conn.Close() on the inevitable timeout.
		plan := planManagedOpen(AMTModeAuto, true, false, 50*time.Millisecond)

		if !plan.AttemptNative {
			t.Fatal("want a native attempt")
		}
		if plan.Probe.Window != MinUsefulProbeWindow {
			t.Errorf("window = %v, want %v: 50ms against a 5s cadence catches a packet ~1%% of the time", plan.Probe.Window, MinUsefulProbeWindow)
		}
	})
}

func TestPlanManagedOpen(t *testing.T) {
	tests := []struct {
		name          string
		mode          AMTMode
		hasRelay      bool
		enableDRIAD   bool
		timeout       time.Duration
		wantDRIAD     bool
		wantNative    bool
		wantProbe     bool
		wantTunnel    bool
		wantWindowMin time.Duration
	}{
		{
			name:       "no relay, no DRIAD: native only, nothing to fall back to",
			mode:       AMTModeAuto,
			timeout:    30 * time.Second,
			wantNative: true,
		},
		{
			name:        "DRIAD with no relay address: discovery decides, no native attempt",
			mode:        AMTModeAuto,
			enableDRIAD: true,
			timeout:     30 * time.Second,
			wantDRIAD:   true,
		},
		{
			name:        "explicit relay wins over DRIAD",
			mode:        AMTModeAuto,
			hasRelay:    true,
			enableDRIAD: true,
			timeout:     30 * time.Second,
			wantNative:  true, wantProbe: true, wantTunnel: true,
			wantWindowMin: MinUsefulProbeWindow,
		},
		{
			name:       "AMTModeNative keeps the join and never tunnels",
			mode:       AMTModeNative,
			hasRelay:   true,
			timeout:    50 * time.Millisecond,
			wantNative: true,
		},
		{
			name:       "AMTModeTunnel goes straight to the tunnel without paying a probe window",
			mode:       AMTModeTunnel,
			hasRelay:   true,
			timeout:    30 * time.Second,
			wantNative: false, wantTunnel: true,
		},
		{
			name:       "a generous timeout is honoured, not clamped down",
			mode:       AMTModeAuto,
			hasRelay:   true,
			timeout:    60 * time.Second,
			wantNative: true, wantProbe: true, wantTunnel: true,
			wantWindowMin: 60 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := planManagedOpen(tc.mode, tc.hasRelay, tc.enableDRIAD, tc.timeout)

			if got.UseDRIAD != tc.wantDRIAD {
				t.Errorf("UseDRIAD = %v, want %v", got.UseDRIAD, tc.wantDRIAD)
			}
			if got.AttemptNative != tc.wantNative {
				t.Errorf("AttemptNative = %v, want %v", got.AttemptNative, tc.wantNative)
			}
			if got.Probe.Probe != tc.wantProbe {
				t.Errorf("Probe.Probe = %v, want %v", got.Probe.Probe, tc.wantProbe)
			}
			if got.Probe.TunnelOnFailure != tc.wantTunnel {
				t.Errorf("Probe.TunnelOnFailure = %v, want %v", got.Probe.TunnelOnFailure, tc.wantTunnel)
			}
			if tc.wantWindowMin > 0 && got.Probe.Window < tc.wantWindowMin {
				t.Errorf("Probe.Window = %v, want >= %v", got.Probe.Window, tc.wantWindowMin)
			}
		})
	}
}

// TestManagedTunnelHandshakeBoundIsFiltered covers the third part of the
// ManagedConn finding: managed_conn.go passed raw mc.Timeout into
// TransportConfig.Timeout, so the doubled-timeout defect survived here even
// after conn.go started filtering it. The production 50ms destroyed the native
// join and then gave the replacement handshake 50ms to complete a round trip.
func TestManagedTunnelHandshakeBoundIsFiltered(t *testing.T) {
	if got := gatewayOpenTimeout(50 * time.Millisecond); got != 0 {
		t.Errorf("gatewayOpenTimeout(50ms) = %v, want 0 so Gateway.Open applies DefaultOpenTimeout", got)
	}
	if got := gatewayOpenTimeout(30 * time.Second); got != 30*time.Second {
		t.Errorf("gatewayOpenTimeout(30s) = %v, want it honoured", got)
	}
}
