//go:build linux && !android

package amt

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/net/ipv4"
)

// countOpenFDs reports how many descriptors this process currently holds.
func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// TestListenMulticastUDP4ClosesFDOnErrorPaths pins the descriptor leak in
// ListenMulticastUDP4. Every early return between socket(2) and a successful
// return owns that descriptor; a return that skips the close burns one fd per
// call, which on a gateway retrying a failing join is unbounded.
//
// The failure is driven through a non-existent interface, which fails at
// SetMulticastInterface -- after the raw socket has been wrapped into an
// ipv4.PacketConn, so it covers the post-wrap paths as well as the raw ones.
func TestListenMulticastUDP4ClosesFDOnErrorPaths(t *testing.T) {
	bogus := &net.Interface{Index: 999999, Name: "amt-nonexistent0"}
	gaddr := &net.UDPAddr{IP: net.IPv4(232, 10, 10, 10), Port: 5555}
	saddr := netip.MustParseAddr("10.11.12.13")

	// One warm-up call so any lazily-initialised runtime state is already open
	// and does not count as growth.
	if conn, err := ListenMulticastUDP4("udp4", bogus, saddr, gaddr, nil, false, 1, 0, 0, 0); err == nil {
		_ = conn.Close()
		t.Skip("expected a failure against a non-existent interface; environment permits it")
	}

	before := countOpenFDs(t)

	const iterations = 50
	for i := 0; i < iterations; i++ {
		conn, err := ListenMulticastUDP4("udp4", bogus, saddr, gaddr, nil, false, 1, 0, 0, 0)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("iteration %d unexpectedly succeeded against a non-existent interface", i)
		}
	}

	after := countOpenFDs(t)

	// Allow a small slack for unrelated runtime activity; a genuine leak grows
	// by one descriptor per iteration.
	if after-before > iterations/10 {
		t.Errorf("descriptor leak: %d fds before, %d after %d failed calls (grew %d)",
			before, after, iterations, after-before)
	}
}

// TestListenMulticastUDP4RejectsNonIPv4Group covers the guard that runs before
// any descriptor is allocated.
func TestListenMulticastUDP4RejectsNonIPv4Group(t *testing.T) {
	before := countOpenFDs(t)

	gaddr := &net.UDPAddr{IP: net.ParseIP("ff3e::4321:1234"), Port: 5555}
	conn, err := ListenMulticastUDP4("udp4", nil, netip.Addr{}, gaddr, nil, false, 1, ipv4.ControlFlags(0), 0, 0)
	if err == nil {
		_ = conn.Close()
		t.Fatal("accepted an IPv6 group address")
	}

	if after := countOpenFDs(t); after > before {
		t.Errorf("descriptor leaked on the validation path: %d -> %d", before, after)
	}
}
