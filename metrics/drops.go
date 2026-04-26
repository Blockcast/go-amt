// Package metrics exposes the AMT relay drop counter contract.
// Spec: runbooks/amt-relay-drops-spec.md (BLO-563).
//
// The four-reason CounterVec materializes at startup with all series at 0
// (via InitDropCounters), so dashboards consuming amt_relay_drops_total
// render with the correct shape before any drop fires. Callers in the
// relay process import this package, call InitDropCounters(relayID) once
// during startup, and call the per-reason Inc helpers at the four drop
// call sites described in the spec.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// AMT relay drop reasons. Cardinality is fixed at 4; do not add new reasons
// without a substrate-spec revision (see runbooks/amt-relay-drops-spec.md).
const (
	DropReasonSocketOverrun    = "socket_overrun"
	DropReasonNoDownstreamSub  = "no_downstream_subscriber"
	DropReasonGatewayTableMiss = "gateway_table_miss"
	DropReasonRateLimit        = "rate_limit"
)

// AMTRelayDropsTotal is the canonical AMT relay drop counter.
//
// Labels:
//   - reason: one of the four DropReason* values above.
//   - relay:  relay instance identifier (PTR record like "sfo12.bcast.id" or
//     anycast unicast like "69.25.95.1"), matching the rest of the
//     relay-side metrics' "relay" label.
//
// Cardinality: 4 reasons * N relay instances; bounded.
var AMTRelayDropsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "amt_relay_drops_total",
		Help: "AMT relay drops by reason. See runbooks/amt-relay-drops-spec.md.",
	},
	[]string{"reason", "relay"},
)

// Cached counter handles for the four hot drop sites. Caching removes a
// per-packet map lookup on the saturation hot path.
var (
	dropsSocketOverrun    prometheus.Counter
	dropsNoDownstreamSub  prometheus.Counter
	dropsGatewayTableMiss prometheus.Counter
	dropsRateLimit        prometheus.Counter
)

// InitDropCounters initializes the cached per-reason counter handles for
// the given relay identifier and forces all four series to be emitted with
// value 0 immediately, so dashboards render with the correct shape before
// the first drop fires. Calling it multiple times is safe.
func InitDropCounters(relayID string) {
	dropsSocketOverrun = AMTRelayDropsTotal.WithLabelValues(DropReasonSocketOverrun, relayID)
	dropsNoDownstreamSub = AMTRelayDropsTotal.WithLabelValues(DropReasonNoDownstreamSub, relayID)
	dropsGatewayTableMiss = AMTRelayDropsTotal.WithLabelValues(DropReasonGatewayTableMiss, relayID)
	dropsRateLimit = AMTRelayDropsTotal.WithLabelValues(DropReasonRateLimit, relayID)

	dropsSocketOverrun.Add(0)
	dropsNoDownstreamSub.Add(0)
	dropsGatewayTableMiss.Add(0)
	dropsRateLimit.Add(0)
}

// IncSocketOverrun records `n` drops at the kernel UDP socket layer. Pass
// the SO_RXQ_OVFL delta from the recvmsg ancillary cmsg, not 1.
func IncSocketOverrun(n uint32) {
	if n == 0 {
		return
	}
	dropsSocketOverrun.Add(float64(n))
}

// IncNoDownstreamSub records one drop at the PIM/IGMP gateway adjacency
// layer (no live downstream join when replicating out).
func IncNoDownstreamSub() {
	dropsNoDownstreamSub.Inc()
}

// IncGatewayTableMiss records one drop at the AMT data-tunnel demux layer
// (no gateway table entry for the inbound (gateway-IP, gateway-port) tuple).
func IncGatewayTableMiss() {
	dropsGatewayTableMiss.Inc()
}

// IncRateLimit records one drop at the ATSS / per-(S,G) shaping layer
// (token bucket refused the packet because the configured pps/bps cap was
// exceeded).
func IncRateLimit() {
	dropsRateLimit.Inc()
}
