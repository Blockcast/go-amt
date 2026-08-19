package amt

import "time"

// AMTMode selects how MulticastConn.Open chooses between a native multicast
// join and an AMT tunnel.
//
// This file deliberately carries no build tags. The decision it encodes is pure
// policy — no sockets, no cgo — so it compiles and is unit-tested under every
// build configuration, including the CGO_ENABLED=0 and purego CI jobs that
// deselect conn.go entirely.
type AMTMode int

const (
	// AMTModeAuto keeps the historical inference: a configured relay makes the
	// native join provisional, and Open falls back to an AMT tunnel when the
	// native path produces no traffic inside the probe window. This is the zero
	// value, so callers that do not set Mode keep the previous behaviour.
	AMTModeAuto AMTMode = iota

	// AMTModeNative never tunnels. The native join is kept unconditionally and a
	// configured relay address is treated as "a relay exists here", not "use it".
	// Use this when the operator knows native multicast is deliverable.
	AMTModeNative

	// AMTModeTunnel goes straight to the AMT tunnel without probing, because a
	// probe cannot tell the operator anything they have not already decided.
	// A relay address is required; without one this degrades to native.
	AMTModeTunnel
)

// MinUsefulProbeWindow is the shortest read window that can distinguish "native
// multicast does not work here" from "the next packet has not arrived yet".
//
// The signalling sender emits the SLT once per interval and floors that interval
// at 5s (multicast/lls/server.go:29-31). A window shorter than one full interval
// therefore proves nothing: it expires in the gap between two packets of a
// perfectly healthy stream. Two intervals gives a healthy native path a second
// chance to be seen if the first packet is missed.
//
// The latency this can add is only ever paid when native is genuinely dead: a
// working native path answers the probe as soon as its next packet arrives, and
// content channels carry data far faster than the signalling cadence.
const MinUsefulProbeWindow = 10 * time.Second

// MinRelayHandshakeTimeout is the shortest value of the operator's relay timeout
// that is plausibly a handshake bound rather than a typo.
//
// amt_relay_timeout is an overloaded knob: it sized the native probe window and
// was also handed to Gateway.Timeout as the AMT relay handshake bound. The
// production 50ms therefore did double damage — it destroyed the native join and
// then gave the relay handshake 50ms to complete a round trip, so the tunnel that
// replaced native could not come up either.
const MinRelayHandshakeTimeout = time.Second

// gatewayOpenTimeout adapts the operator's relay timeout for use as the AMT
// handshake bound. A value too short to complete a round trip to the relay is
// dropped rather than honoured, which lets Gateway.Open apply its own
// DefaultOpenTimeout instead of failing every handshake.
func gatewayOpenTimeout(timeout time.Duration) time.Duration {
	if timeout < MinRelayHandshakeTimeout {
		return 0
	}
	return timeout
}

// probePlan is the decision Open acts on, separated from the act of opening so
// it can be tested without a multicast-capable host.
type probePlan struct {
	// Probe reports whether Open should spend Window waiting for native traffic
	// before deciding anything.
	Probe bool

	// Window is how long to wait for native traffic. Only meaningful when Probe
	// is true, and never shorter than MinUsefulProbeWindow.
	Window time.Duration

	// TunnelOnFailure reports whether the native join should be torn down in
	// favour of an AMT tunnel — either because the probe timed out, or, when
	// Probe is false, because the caller asked for the tunnel outright.
	TunnelOnFailure bool
}

// planProbe decides whether to probe the native join, for how long, and whether
// a failure should hand over to an AMT tunnel.
//
// Two historical behaviours are deliberately not preserved, because neither is
// defensible (BLO-28640):
//
//   - A zero timeout used to mean "set a read deadline in the past", so the
//     native socket was closed 100% of the time, with no window at all. An
//     unset timeout is a missing configuration value, not an instruction to
//     discard a working multicast path.
//   - A sub-second timeout (production ran 50ms against a 5s cadence) used to be
//     honoured literally, so the probe timed out essentially always. Such a
//     window is not evidence, so it is raised to MinUsefulProbeWindow rather
//     than believed.
//
// Both now yield a window that a healthy native path can actually answer, while
// still tunnelling when it does not — so deployments that genuinely need AMT
// keep their fallback.
func planProbe(mode AMTMode, relayConfigured bool, timeout time.Duration) probePlan {
	// No relay means there is nothing to fall back to, so there is nothing a
	// probe could decide. Keep the native join.
	if !relayConfigured {
		return probePlan{}
	}

	switch mode {
	case AMTModeNative:
		return probePlan{}

	case AMTModeTunnel:
		return probePlan{TunnelOnFailure: true}

	default: // AMTModeAuto
		window := timeout
		if window < MinUsefulProbeWindow {
			window = MinUsefulProbeWindow
		}
		return probePlan{Probe: true, Window: window, TunnelOnFailure: true}
	}
}

// managedPlan is the decision ManagedConn.Open acts on. ManagedConn reaches the
// AMT tunnel through RelayManager rather than Gateway directly, so it needs one
// extra branch MulticastConn does not have (DRIAD discovery) — but the
// native-vs-tunnel policy underneath is the same planProbe.
type managedPlan struct {
	// UseDRIAD reports whether the relay address must be discovered via DNS
	// (RFC 8777) instead of being taken from RelayAddr.
	UseDRIAD bool

	// AttemptNative reports whether to bind the native socket at all. Only a
	// deliberate AMTModeTunnel skips it: an operator who has already decided to
	// tunnel should not pay a probe window to be told so.
	AttemptNative bool

	// Probe carries the native-join policy, and is meaningful only when
	// AttemptNative is true.
	Probe probePlan
}

// planManagedOpen decides how ManagedConn.Open should approach a group.
//
// Extracted as a pure function for the same reason planProbe was: ManagedConn's
// native path needs a multicast-capable host to exercise, so the decision has to
// be separable from the act to be testable at all. It was untested when it
// carried the BLO-28640 defect (Ally review on go-amt#49).
func planManagedOpen(mode AMTMode, hasRelay, enableDRIAD bool, timeout time.Duration) managedPlan {
	// DRIAD means the relay address is not known yet. Discovery is the whole
	// point of the mode, so there is no local native-vs-tunnel decision to make
	// and the native socket is not attempted. Preserved as-is; the BLO-28640
	// defect was never on this branch.
	if enableDRIAD && !hasRelay {
		return managedPlan{UseDRIAD: true}
	}

	plan := planProbe(mode, hasRelay, timeout)

	return managedPlan{
		AttemptNative: plan.Probe || !plan.TunnelOnFailure,
		Probe:         plan,
	}
}
