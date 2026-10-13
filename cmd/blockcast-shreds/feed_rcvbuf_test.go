//go:build linux || darwin

package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// TestRaisedHostDefaultIsNotShrunk: install.md used to have operators raise
// net.core.rmem_default to 128 MiB. Linux allocates twice a setsockopt request,
// so on such a host the 8 MiB request would shrink every feed socket. openFeed
// must leave a default that already covers the request alone.
func TestRaisedHostDefaultIsNotShrunk(t *testing.T) {
	const want = 1 << 20
	fake := filepath.Join(t.TempDir(), "rmem_default")
	defer func(old string) { rmemDefaultFile = old }(rmemDefaultFile)
	rmemDefaultFile = fake
	setDefault := func(v string) {
		t.Helper()
		if err := os.WriteFile(fake, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	setDefault("134217728\n")
	control, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	kernelDefault := rcvBuf(t, control)
	conn, err := openFeed(feed{name: "tap", address: "127.0.0.1:0", rcvbuf: want})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := rcvBuf(t, conn.(*net.UDPConn)); got != kernelDefault {
		t.Fatalf("feed SO_RCVBUF = %d under a raised rmem_default, want the default %d left alone", got, kernelDefault)
	}

	// The threshold is what the request would allocate, twice its size.
	for v, wantReq := range map[string]int{
		strconv.Itoa(2 * want):   0,
		strconv.Itoa(2*want - 1): want,
		"not a number":           want,
	} {
		setDefault(v)
		if got := feedRcvBuf(want); got != wantReq {
			t.Errorf("rmem_default %q: feedRcvBuf(%d) = %d, want %d", v, want, got, wantReq)
		}
	}
	rmemDefaultFile = filepath.Join(t.TempDir(), "absent")
	if got := feedRcvBuf(want); got != want {
		t.Errorf("no rmem_default file: feedRcvBuf(%d) = %d, want the request sent", want, got)
	}
}

func TestNegativeRcvbufIsRejected(t *testing.T) {
	err := run([]string{"--rcvbuf", "-1", "--http-addr", ""})
	if err == nil || !strings.Contains(err.Error(), "--rcvbuf must not be negative") {
		t.Fatalf("run(--rcvbuf -1) error = %v, want a --rcvbuf validation error", err)
	}
}
