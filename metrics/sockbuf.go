package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Socket buffer clamp kinds. Cardinality is fixed at 2; do not add new kinds
// without re-thinking what "clamped" means.
const (
	BufferKindReceive = "receive"
	BufferKindSend    = "send"
)

// SocketBufferClampedTotal counts events where amt.SetForcedReceiveBuffer
// or amt.SetForcedSendBuffer requested a buffer larger than what the kernel
// granted — typically because the process lacks CAP_NET_ADMIN (SO_*FORCE
// returned EPERM) AND net.core.{r,w}mem_max is below the requested size.
//
// The counter is paired with a slog.Warn at the same call site. The metric
// exists so operators with log filtering / sampling can still alert on
// silent under-provisioning of UDP socket buffers — the original BLO-3856
// regression mode.
//
// Labels:
//   - kind: "receive" or "send" (see BufferKind* constants).
//
// Cardinality: 2.
var SocketBufferClampedTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "amt_socket_buffer_clamped_total",
		Help: "Socket buffer FORCE+RCVBUF/SNDBUF clamps by kind. See amt.BufferClampedError.",
	},
	[]string{"kind"},
)

// IncSocketBufferClamped records one clamp event for the given kind.
// Safe to call from any goroutine.
func IncSocketBufferClamped(kind string) {
	SocketBufferClampedTotal.WithLabelValues(kind).Inc()
}
