//go:build darwin

package amt

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// SetForcedReceiveBuffer raises the socket receive buffer to at least bytes.
// Darwin has no SO_RCVBUFFORCE, so this is plain SO_RCVBUF. A request above
// the kern.ipc.maxsockbuf ceiling is retried at the ceiling and reported as
// *BufferClampedError (see retryAtMaxsockbuf). No-op when bytes <= 0 or when
// the current buffer is already at least bytes.
func SetForcedReceiveBuffer(fd int, bytes int) error {
	return setBufferAtLeast(fd, bytes, syscall.SO_RCVBUF)
}

// SetForcedSendBuffer is the send-side counterpart of SetForcedReceiveBuffer.
func SetForcedSendBuffer(fd int, bytes int) error {
	return setBufferAtLeast(fd, bytes, syscall.SO_SNDBUF)
}

func setBufferAtLeast(fd, want, opt int) error {
	if want <= 0 {
		return nil
	}
	if cur, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, opt); err == nil && cur >= want {
		return nil
	}
	return retryAtMaxsockbuf(want,
		func(n int) error { return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, opt, n) },
		func() (uint32, error) { return unix.SysctlUint32("kern.ipc.maxsockbuf") })
}
