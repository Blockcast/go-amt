//go:build linux || darwin

package main

import (
	"net"
	"strings"
	"syscall"
	"testing"
)

// rcvBuf reads a socket's SO_RCVBUF as the kernel reports it.
func rcvBuf(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		got, getErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	}); err != nil {
		t.Fatal(err)
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	return got
}

// TestUnicastFeedGetsReceiveBuffer: a --feed socket used to keep the kernel
// default, and at the union feed's burst rate a receiver on that default dropped
// 1–4% of its datagrams at the socket (BLO-41705). openFeed must ask for more.
// Without CAP_NET_ADMIN the kernel caps the request at net.core.rmem_max, so the
// assertion is "more than the default", which holds even under that cap.
func TestUnicastFeedGetsReceiveBuffer(t *testing.T) {
	control, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	const want = 1 << 20
	kernelDefault := rcvBuf(t, control)
	if kernelDefault >= 2*want {
		t.Skipf("kernel default SO_RCVBUF %d already holds a %d-byte request", kernelDefault, want)
	}

	conn, err := openFeed(feed{name: "tap", address: "127.0.0.1:0", rcvbuf: want})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := rcvBuf(t, conn.(*net.UDPConn)); got <= kernelDefault {
		t.Fatalf("feed SO_RCVBUF = %d, want more than the kernel default %d", got, kernelDefault)
	}

	unset, err := openFeed(feed{name: "tap", address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	defer unset.Close()
	if got := rcvBuf(t, unset.(*net.UDPConn)); got != kernelDefault {
		t.Fatalf("--rcvbuf 0 feed SO_RCVBUF = %d, want the kernel default %d", got, kernelDefault)
	}
}

func TestNegativeRcvbufIsRejected(t *testing.T) {
	err := run([]string{"--rcvbuf", "-1", "--http-addr", ""})
	if err == nil || !strings.Contains(err.Error(), "--rcvbuf must not be negative") {
		t.Fatalf("run(--rcvbuf -1) error = %v, want a --rcvbuf validation error", err)
	}
}
