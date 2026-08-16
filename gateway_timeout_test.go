//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"errors"
	"net"
	"testing"
	"time"
)

// A relay that never answers must not hang the caller.
//
// Regression: Open sent discovery and then read from the socket in an unbounded
// loop with no deadline, so an unreachable or silent relay blocked it forever.
// The only thing that ever ended it was the Go test binary's own 10-minute
// panic, which is what this test exists to prevent recurring.
func TestGatewayOpenTimesOutAgainstSilentRelay(t *testing.T) {
	// A real, bound UDP socket that accepts the discovery datagram and never
	// replies — a black hole rather than an unreachable address, so the failure
	// is the missing advertisement and not an ICMP error or a routing quirk.
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind silent relay: %v", err)
	}
	defer silent.Close()

	relay := silent.LocalAddr().(*net.UDPAddr)
	gw := &Gateway{
		RelayAddr:  relay,
		GroupAddr:  net.ParseIP("232.0.0.1"),
		SourceAddr: net.ParseIP("192.0.2.1"),
		MTU:        1500,
		Timeout:    2 * time.Second,
	}

	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- gw.Open() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open succeeded against a relay that never answered")
		}
		elapsed := time.Since(started)
		if elapsed > 10*time.Second {
			t.Fatalf("Open took %s to fail; the deadline is not bounding it", elapsed)
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Logf("Open failed with a non-timeout error (acceptable, still bounded): %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Open did not return within 30s — it is still unbounded")
	}
}

// Zero Timeout must fall back to DefaultOpenTimeout rather than meaning
// "no deadline", which would reintroduce the hang for every existing caller
// that does not set the field.
func TestGatewayOpenZeroTimeoutUsesDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("takes DefaultOpenTimeout to complete")
	}
	silent, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind silent relay: %v", err)
	}
	defer silent.Close()

	gw := &Gateway{
		RelayAddr: silent.LocalAddr().(*net.UDPAddr),
		GroupAddr: net.ParseIP("232.0.0.1"),
		MTU:       1500,
	}
	done := make(chan error, 1)
	go func() { done <- gw.Open() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Open succeeded against a relay that never answered")
		}
	case <-time.After(DefaultOpenTimeout + 20*time.Second):
		t.Fatalf("Open did not return within DefaultOpenTimeout (%s) plus slack", DefaultOpenTimeout)
	}
}
