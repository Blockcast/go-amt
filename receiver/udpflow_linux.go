//go:build linux

package receiver

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func bindToInterface(fd int, name string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
}

func setUDPFlowReceiveBuffer(conn *net.UDPConn, want int) (int, bool, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var got int
	var setErr error
	if err := raw.Control(func(fd uintptr) {
		got, setErr = setUDPFlowReceiveBufferFD(int(fd), want)
	}); err != nil {
		return 0, false, err
	}
	if setErr != nil {
		return 0, false, setErr
	}
	return got, got < want, nil
}

func setUDPFlowReceiveBufferFD(fd, want int) (int, error) {
	got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return 0, fmt.Errorf("read UDP feed receive buffer: %w", err)
	}
	if got >= want {
		return got, nil
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, want); err != nil {
		if !errors.Is(err, unix.EPERM) {
			return 0, err
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, want); err != nil {
			return 0, err
		}
	}
	got, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return 0, fmt.Errorf("verify UDP feed receive buffer: %w", err)
	}
	return got, nil
}
