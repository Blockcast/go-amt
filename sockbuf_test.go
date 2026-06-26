//go:build linux || darwin

package amt

import (
	"errors"
	"syscall"
	"testing"
)

func newUDPSocket(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

func TestSetForcedReceiveBufferZero(t *testing.T) {
	fd := newUDPSocket(t)
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err := SetForcedReceiveBuffer(fd, 0); err != nil {
		t.Fatalf("SetForcedReceiveBuffer(0): want nil, got %v", err)
	}
	if err := SetForcedReceiveBuffer(fd, -1); err != nil {
		t.Fatalf("SetForcedReceiveBuffer(-1): want nil, got %v", err)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if before != after {
		t.Errorf("buffer changed despite no-op: before=%d after=%d", before, after)
	}
}

func TestSetForcedReceiveBufferDoesNotShrink(t *testing.T) {
	fd := newUDPSocket(t)
	// Set baseline first.
	if err := SetForcedReceiveBuffer(fd, 1<<20); err != nil { // 1 MB
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("baseline set: %v", err)
		}
		// Clamped is OK for baseline; use whatever we got.
	}
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	// Request a smaller buffer; helper should skip (don't shrink).
	if err := SetForcedReceiveBuffer(fd, 1024); err != nil {
		t.Fatalf("no-shrink call: %v", err)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if after < before {
		t.Errorf("buffer was shrunk: before=%d after=%d", before, after)
	}
}

func TestSetForcedReceiveBufferGrows(t *testing.T) {
	fd := newUDPSocket(t)
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	// Pick a target somewhat above the default (212992*2 = ~425KB on most
	// kernels) but well below typical rmem_max (often >= 7.5MB on modern
	// systems, or whatever the test environment has).
	want := before * 2
	if want < 1<<20 {
		want = 1 << 20
	}
	err := SetForcedReceiveBuffer(fd, want)
	if err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("unexpected error: %v", err)
		}
		// On a low-rmem_max host without NET_ADMIN, the kernel clamps below
		// `want`. The helper reports this via BufferClampedError; the buffer
		// still grew (just not to the full request).
		t.Logf("got clamp (expected on low-rmem_max env w/o NET_ADMIN): %v", clamp)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if after <= before {
		t.Errorf("buffer did not grow: before=%d after=%d want=%d", before, after, want)
	}
}

func TestSetForcedReceiveBufferBadFD(t *testing.T) {
	if err := SetForcedReceiveBuffer(-1, 1<<20); err == nil {
		t.Fatal("expected error on bad fd, got nil")
	}
}

func TestBufferClampedErrorMessage(t *testing.T) {
	e := &BufferClampedError{Requested: 7500000, Got: 425984}
	if msg := e.Error(); msg == "" {
		t.Fatal("empty error message")
	}
}

func TestSetForcedSendBufferGrows(t *testing.T) {
	fd := newUDPSocket(t)
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	want := before * 2
	if want < 1<<20 {
		want = 1 << 20
	}
	err := SetForcedSendBuffer(fd, want)
	if err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Logf("got clamp (expected on low-wmem_max env w/o NET_ADMIN): %v", clamp)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if after <= before {
		t.Errorf("send buffer did not grow: before=%d after=%d want=%d", before, after, want)
	}
}

func TestSetForcedSendBufferDoesNotShrink(t *testing.T) {
	fd := newUDPSocket(t)
	if err := SetForcedSendBuffer(fd, 1<<20); err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("baseline set: %v", err)
		}
	}
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err := SetForcedSendBuffer(fd, 1024); err != nil {
		t.Fatalf("no-shrink call: %v", err)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if after < before {
		t.Errorf("send buffer was shrunk: before=%d after=%d", before, after)
	}
}
