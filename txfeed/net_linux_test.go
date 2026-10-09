package txfeed

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// Loopback only: the joins are on lo, and TTL 0 with loop never transmits.
func TestSSMOnLoopback(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	g1, g2 := netip.MustParseAddr("232.0.3.251"), netip.MustParseAddr("232.0.3.252")
	a, err := ListenSSM(lo, g1, 0, lo, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	port := a.LocalAddr().(*net.UDPAddr).Port
	b, err := ListenSSM(lo, g2, port, lo, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	e, err := EmitSocket(lo, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	// g2 goes first: a socket that took every group on the port would read it.
	for _, g := range []netip.Addr{g2, g1} {
		if _, err := e.WriteToUDPAddrPort([]byte(g.String()), netip.AddrPortFrom(g, uint16(port))); err != nil {
			t.Fatal(err)
		}
	}
	for c, want := range map[*net.UDPConn]netip.Addr{a: g1, b: g2} {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil || string(buf[:n]) != want.String() {
			t.Errorf("the socket joined to %s read %q, %v", want, buf[:n], err)
		}
	}
}
