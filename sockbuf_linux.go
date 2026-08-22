//go:build linux

package amt

import (
	"errors"
	"fmt"
	"syscall"
)

// SetForcedReceiveBuffer raises the socket receive buffer so the kernel
// accepts a setsockopt input of at least bytes. It is a no-op when bytes <= 0
// or when the socket already holds that much.
//
// It first tries SO_RCVBUFFORCE, which bypasses net.core.rmem_max but
// requires CAP_NET_ADMIN in the socket's network namespace user namespace.
// On EPERM it falls back to SO_RCVBUF (capped at net.core.rmem_max).
// If the fallback is clamped below the request, the error is a
// *BufferClampedError so callers can choose to warn-and-continue.
func SetForcedReceiveBuffer(fd int, bytes int) error {
	return setBufferAtLeast(fd, bytes,
		syscall.SO_RCVBUF, syscall.SO_RCVBUFFORCE)
}

// SetForcedSendBuffer is the send-side counterpart of SetForcedReceiveBuffer.
func SetForcedSendBuffer(fd int, bytes int) error {
	return setBufferAtLeast(fd, bytes,
		syscall.SO_SNDBUF, syscall.SO_SNDBUFFORCE)
}

// bufferHolds reports whether a getsockopt readback of got bytes means a
// setsockopt request of want bytes was satisfied.
//
// The two values are in DIFFERENT UNITS and must not be compared directly.
// Linux stores twice the accepted setsockopt input and getsockopt returns
// that stored value (sock_setsockopt: `sk_rcvbuf = max(val*2, SOCK_MIN_RCVBUF)`
// after `val = min(val, rmem_max)`). So a satisfied request of `want` reads
// back as 2*want, while one clamped to rmem_max reads back as 2*rmem_max.
//
// Comparing the doubled readback against the undoubled request — as this
// code did until BLO-29351 — only flags a clamp when rmem_max < want/2, so
// every clamp in [want/2, want) passed silently. That blind zone is what let
// the staging receiver request 7500000, land on an rmem_max of 4194304, read
// back 8388608, and emit no warning: 8388608 >= 7500000, so the old check saw
// a satisfied request where the effective ceiling was 56% of the ask.
//
// Halving `got` rather than doubling `want` keeps this overflow-free for any
// int the caller can pass.
func bufferHolds(got, want int) bool {
	return got/2 >= want
}

func setBufferAtLeast(fd, want, getOpt, forceOpt int) error {
	if want <= 0 {
		return nil
	}
	// Don't shrink: if the socket already holds `want`, leave it alone.
	cur, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, getOpt)
	if err != nil {
		return fmt.Errorf("getsockopt baseline: %w", err)
	}
	if bufferHolds(cur, want) {
		return nil
	}

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, forceOpt, want)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EPERM) {
		return err
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, getOpt, want); err != nil {
		return err
	}
	got, gerr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, getOpt)
	if gerr != nil {
		return fmt.Errorf("getsockopt verify after fallback: %w", gerr)
	}
	if !bufferHolds(got, want) {
		return &BufferClampedError{Requested: want, Got: got}
	}
	return nil
}
