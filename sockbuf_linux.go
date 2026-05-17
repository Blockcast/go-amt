//go:build linux

package amt

import (
	"errors"
	"fmt"
	"syscall"
)

// SetForcedReceiveBuffer raises the socket receive buffer so getsockopt(SO_RCVBUF)
// reports at least bytes. It is a no-op when bytes <= 0 or when the kernel
// already reports an allocation >= bytes (the kernel doubles the last
// setsockopt input, so getsockopt usually shows 2× the requested value).
//
// It first tries SO_RCVBUFFORCE, which bypasses net.core.rmem_max but
// requires CAP_NET_ADMIN in the socket's network namespace user namespace.
// On EPERM it falls back to SO_RCVBUF (capped at 2*net.core.rmem_max).
// If the fallback returns a buffer smaller than requested, the error is a
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

func setBufferAtLeast(fd, want, getOpt, forceOpt int) error {
	if want <= 0 {
		return nil
	}
	// Don't shrink. getsockopt returns the kernel-allocated size (typically
	// 2x the last setsockopt value due to internal doubling). If we already
	// have at least `want` bytes allocated, leave it alone.
	cur, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, getOpt)
	if err != nil {
		return fmt.Errorf("getsockopt baseline: %w", err)
	}
	if cur >= want {
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
	if got < want {
		return &BufferClampedError{Requested: want, Got: got}
	}
	return nil
}
