//go:build linux && !android

package amt

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
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

// TestListenMulticastUDP6ClosesFDOnErrorPaths is the IPv6 twin of
// TestListenMulticastUDP4ClosesFDOnErrorPaths. A filter the kernel rejects
// fails before the raw socket is wrapped; a non-existent interface fails at
// SetMulticastInterface, after it. Each case checks it failed at that step, so
// it cannot pass by failing somewhere that allocates nothing.
func TestListenMulticastUDP6ClosesFDOnErrorPaths(t *testing.T) {
	// Port 0, so the bind succeeds and the interface case reaches the wrap.
	gaddr := &net.UDPAddr{IP: net.ParseIP("ff3e::4321:1234")}
	for _, tc := range []struct {
		name string
		ifi  *net.Interface
		f    []bpf.RawInstruction
		step string
	}{
		{"raw socket", nil, []bpf.RawInstruction{{Op: 0xffff}}, "failed to set bpf"},
		{"wrapped conn", &net.Interface{Index: 999999, Name: "amt-nonexistent0"}, nil, "set multicast interface"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listen := func() error {
				c, err := ListenMulticastUDP6("udp6", tc.ifi, netip.Addr{}, gaddr, tc.f, false, 0, 0, 0, 0)
				if err == nil {
					_ = c.Close()
				}
				return err
			}

			// The warm-up call also opens any lazily-initialised runtime state.
			err := listen()
			switch {
			case err == nil:
				t.Skip("expected a failure; environment permits the call")
			case strings.Contains(err.Error(), "could not get socket"):
				t.Skipf("no IPv6 sockets: %v", err)
			case !strings.Contains(err.Error(), tc.step):
				t.Fatalf("failed at the wrong step, want %q: %v", tc.step, err)
			}

			before := countOpenFDs(t)
			const iterations = 50
			for i := 0; i < iterations; i++ {
				if listen() == nil {
					t.Fatalf("iteration %d unexpectedly succeeded", i)
				}
			}
			if grew := countOpenFDs(t) - before; grew > iterations/10 {
				t.Errorf("descriptor leak: grew %d over %d failed calls", grew, iterations)
			}
		})
	}
}

// loopbackInterface returns the host's loopback interface. The tests below join
// and send on it, so no IGMP report or datagram reaches a real network.
func loopbackInterface(t *testing.T) *net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skipf("list interfaces: %v", err)
	}
	for i := range ifs {
		if ifs[i].Flags&net.FlagLoopback != 0 && ifs[i].Flags&net.FlagUp != 0 {
			return &ifs[i]
		}
	}
	t.Skip("no loopback interface is up")
	return nil
}

// TestListenMulticastUDP4ReceivesOnlyItsOwnGroup pins IP_MULTICAST_ALL=0. Two
// listeners share a port, as blockcast-shreds' one --feed per layer does, each
// joined to its own group. Under the kernel default each also read the other's
// group, so every layer arrived once per feed (BLO-41383). The sender uses TTL
// 0 with loopback, so nothing leaves the host.
func TestListenMulticastUDP4ReceivesOnlyItsOwnGroup(t *testing.T) {
	lo := loopbackInterface(t)
	// The first listener binds port 0, so the kernel picks a free port, and
	// the second shares it with SO_REUSEPORT. Probing for a free port and
	// closing the probe would leave a gap another socket could take it in,
	// and the skip that followed would fail CI's PASS-line step.
	groups := []*net.UDPAddr{
		{IP: net.IPv4(239, 255, 41, 1)},
		{IP: net.IPv4(239, 255, 41, 2)},
	}
	var listeners []*ipv4.PacketConn
	for _, g := range groups {
		c, err := ListenMulticastUDP4("udp4", lo, netip.Addr{}, g, nil, false, 0, 0, 0, 0)
		if err != nil {
			// Failing to clear the option is the regression itself, not an
			// environment gap.
			if strings.Contains(err.Error(), "MULTICAST_ALL") {
				t.Fatalf("join %v on %s: %v", g.IP, lo.Name, err)
			}
			t.Skipf("join %v on %s: %v", g.IP, lo.Name, err)
		}
		defer c.Close()
		listeners = append(listeners, c)
		if g.Port == 0 {
			port := c.LocalAddr().(*net.UDPAddr).Port
			groups[0].Port, groups[1].Port = port, port
		}
	}

	tx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	ptx := ipv4.NewPacketConn(tx)
	if err := ptx.SetMulticastInterface(lo); err != nil {
		t.Skipf("send on %s: %v", lo.Name, err)
	}
	if err := ptx.SetMulticastTTL(0); err != nil {
		t.Fatal(err)
	}
	if err := ptx.SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	for i, g := range groups {
		if _, err := tx.WriteToUDP([]byte{byte('A' + i)}, g); err != nil {
			t.Skipf("send to %v: %v", g.IP, err)
		}
	}

	for i, c := range listeners {
		var got []byte
		buf := make([]byte, 64)
		if err := c.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		for {
			n, _, _, err := c.ReadFrom(buf)
			if err != nil {
				break
			}
			got = append(got, buf[:n]...)
		}
		if len(got) == 0 {
			t.Skipf("multicast loopback delivered nothing to %v on %s", groups[i].IP, lo.Name)
		}
		if want := string(rune('A' + i)); string(got) != want {
			t.Errorf("listener joined to %v read %q, want only %q", groups[i].IP, got, want)
		}
	}
}

// TestListenMulticastUDP6ClearsMulticastAll pins the IPv6 half,
// IPV6_MULTICAST_ALL=0. IPv6 multicast has no route on lo, so it cannot be
// sent there; this reads the option back off the joined socket instead.
func TestListenMulticastUDP6ClearsMulticastAll(t *testing.T) {
	lo := loopbackInterface(t)
	// Port 0: the kernel picks a free one, with no probe-then-close gap.
	g := &net.UDPAddr{IP: net.ParseIP("ff15::4113:1")}
	c, err := ListenMulticastUDP6("udp6", lo, netip.Addr{}, g, nil, false, 0, 0, 0, 0)
	if err != nil {
		if strings.Contains(err.Error(), "MULTICAST_ALL") {
			t.Fatalf("join %v on %s: %v", g.IP, lo.Name, err)
		}
		t.Skipf("join %v on %s: %v", g.IP, lo.Name, err)
	}
	defer c.Close()

	raw, err := c.PacketConn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var getErr error
	if err := raw.Control(func(fd uintptr) {
		value, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_ALL)
	}); err != nil {
		t.Fatal(err)
	}
	if errors.Is(getErr, unix.ENOPROTOOPT) {
		t.Skip("IPV6_MULTICAST_ALL unsupported here (ENOPROTOOPT): a kernel before 4.20, or a sandbox without it")
	}
	if getErr != nil {
		t.Fatal(getErr)
	}
	if value != 0 {
		t.Errorf("IPV6_MULTICAST_ALL = %d, want 0", value)
	}
}
