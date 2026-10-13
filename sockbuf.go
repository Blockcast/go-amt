package amt

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/blockcast/go-amt/metrics"
)

// BufferClampedError reports that a socket buffer size request was accepted
// but clamped below what was asked for — typically because the process lacks
// CAP_NET_ADMIN (so SO_RCVBUFFORCE/SO_SNDBUFFORCE returned EPERM) AND
// net.core.rmem_max / net.core.wmem_max is below the request.
// Callers can errors.As to detect this and log a warning while continuing.
//
// Requested is the setsockopt input. Got is the raw getsockopt readback,
// which on Linux is TWICE the accepted input — so Got can exceed Requested
// and still be a clamp. EffectiveCeiling unhalves it into the same units as
// Requested, which is the number an operator compares against rmem_max.
//
// Darwin has no FORCE variant. Its kernel clamps an oversized
// SO_RCVBUF/SO_SNDBUF to kern.ipc.maxsockbuf without an error on macOS 14.4
// and later, and refuses it with ENOBUFS on earlier releases.
// setXNUBufferAtLeast handles both and reads the size back, and returns this
// error with Got set to that readback. Darwin's getsockopt does not double, so
// there EffectiveCeiling is Got itself.
type BufferClampedError struct {
	Requested int
	Got       int

	// ceiling, when non-zero, is the accepted setsockopt input, for errors
	// whose Got is not a doubled Linux readback (Darwin).
	ceiling int
}

// EffectiveCeiling is the accepted setsockopt input implied by the readback —
// i.e. the net.core.{r,w}mem_max (Linux) or kern.ipc.maxsockbuf-derived
// (Darwin) limit the kernel held the request to — in the same units as
// Requested.
func (e *BufferClampedError) EffectiveCeiling() int {
	if e.ceiling != 0 {
		return e.ceiling
	}
	return e.Got / 2
}

func (e *BufferClampedError) Error() string {
	return fmt.Sprintf("socket buffer clamped: requested %d bytes, kernel allocated %d (effective ceiling %d; raise net.core.rmem_max/wmem_max or grant CAP_NET_ADMIN on Linux, kern.ipc.maxsockbuf on macOS)",
		e.Requested, e.Got, e.EffectiveCeiling())
}

// applyForcedBuffers raises the receive and send buffers on the given socket
// fd, treating *BufferClampedError as a non-fatal warning (logged via slog).
// Real syscall errors (EBADF, ENOTSOCK, etc.) are returned to the caller and
// should abort socket setup.
func applyForcedBuffers(fd, rcvBufBytes, sndBufBytes int) error {
	if err := SetForcedReceiveBuffer(fd, rcvBufBytes); err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			return fmt.Errorf("could not set socket receive buffer: %w", err)
		}
		slog.Warn("amt: udp receive buffer clamped",
			"requested", clamp.Requested, "allocated", clamp.Got,
			"effective_ceiling", clamp.EffectiveCeiling())
		metrics.IncSocketBufferClamped(metrics.BufferKindReceive)
	}
	if err := SetForcedSendBuffer(fd, sndBufBytes); err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			return fmt.Errorf("could not set socket send buffer: %w", err)
		}
		slog.Warn("amt: udp send buffer clamped",
			"requested", clamp.Requested, "allocated", clamp.Got,
			"effective_ceiling", clamp.EffectiveCeiling())
		metrics.IncSocketBufferClamped(metrics.BufferKindSend)
	}
	return nil
}
