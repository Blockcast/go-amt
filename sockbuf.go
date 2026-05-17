package amt

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/blockcast/go-amt/metrics"
)

// BufferClampedError reports that a socket buffer size request was honored
// but the resulting buffer is smaller than requested — typically because the
// process lacks CAP_NET_ADMIN (so SO_RCVBUFFORCE/SO_SNDBUFFORCE returned
// EPERM) AND net.core.rmem_max / net.core.wmem_max is below the request.
// Callers can errors.As to detect this and log a warning while continuing.
//
// On Darwin this type exists but is never returned, since Darwin has no
// FORCE variant — SO_RCVBUF/SO_SNDBUF is the only mechanism and any clamp
// is invisible to userspace.
type BufferClampedError struct {
	Requested int
	Got       int
}

func (e *BufferClampedError) Error() string {
	return fmt.Sprintf("socket buffer clamped: requested %d bytes, got %d (raise net.core.rmem_max/wmem_max or grant CAP_NET_ADMIN)",
		e.Requested, e.Got)
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
			"requested", clamp.Requested, "got", clamp.Got)
		metrics.IncSocketBufferClamped(metrics.BufferKindReceive)
	}
	if err := SetForcedSendBuffer(fd, sndBufBytes); err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			return fmt.Errorf("could not set socket send buffer: %w", err)
		}
		slog.Warn("amt: udp send buffer clamped",
			"requested", clamp.Requested, "got", clamp.Got)
		metrics.IncSocketBufferClamped(metrics.BufferKindSend)
	}
	return nil
}
