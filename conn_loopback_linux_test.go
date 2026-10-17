//go:build linux && !android && cgo && !purego

package amt

import (
	"net/netip"
	"testing"
)

// A send-only caller turns IP_MULTICAST_LOOP off after Open, so its own sends
// are not copied back into a joined socket nothing reads (BLO-47236). Open must
// still turn it on, which receivers on the same host rely on.
func TestMulticastConnSetMulticastLoopback(t *testing.T) {
	mc := &MulticastConn{
		GroupAddr: netip.MustParseAddr("239.47.236.1"),
		GroupPort: 47236,
		IFace:     loopbackInterface(t),
		TTL:       1,
		Mode:      AMTModeNative,
	}
	if err := mc.SetMulticastLoopback(false); err == nil {
		t.Fatal("SetMulticastLoopback before Open = nil, want an error")
	}
	if err := mc.Open(); err != nil {
		t.Skipf("native join unavailable here: %v", err)
	}
	defer mc.Close()

	read := func() bool {
		t.Helper()
		on, err := mc.conn4.MulticastLoopback()
		if err != nil {
			t.Fatalf("getsockopt IP_MULTICAST_LOOP: %v", err)
		}
		return on
	}
	if !read() {
		t.Fatal("IP_MULTICAST_LOOP off after Open, want on: same-host receivers depend on it")
	}
	if err := mc.SetMulticastLoopback(false); err != nil {
		t.Fatalf("SetMulticastLoopback(false): %v", err)
	}
	if read() {
		t.Fatal("IP_MULTICAST_LOOP still on after SetMulticastLoopback(false)")
	}
	if err := mc.SetMulticastLoopback(true); err != nil || !read() {
		t.Fatalf("SetMulticastLoopback(true) = %v, loop on = %v", err, read())
	}
}
