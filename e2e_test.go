//go:build (linux || darwin) && cgo

package amt

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

const (
	testRelayAddr   = "69.25.95.1"
	testRelayPort   = 2268
	testSource      = "69.25.95.10"
	testGroup       = "232.0.0.1"
	testGroupPort   = 1234
	testDataTimeout = 30 * time.Second
)

func TestE2E_ReceiveMulticastData(t *testing.T) {
	// Skip if CGO is not available (this test requires the Rust-backed MulticastConn)
	caps := GetPlatformCapabilities()
	if !caps.SupportsCGO {
		t.Skip("Skipping E2E test: CGO not available (Rust backend required)")
	}

	t.Log("Testing AMT gateway with Rust backend")
	t.Logf("Relay: %s:%d", testRelayAddr, testRelayPort)
	t.Logf("Source: %s, Group: %s:%d", testSource, testGroup, testGroupPort)

	// Get default interface
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		// Try to get any interface
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 {
				iface = &i
				break
			}
		}
	}
	if iface == nil {
		t.Fatal("No suitable network interface found")
	}
	t.Logf("Using interface: %s (MTU: %d)", iface.Name, iface.MTU)

	// Create multicast connection with AMT relay
	mc := &MulticastConn{
		RelayAddr: net.UDPAddr{
			IP:   net.ParseIP(testRelayAddr),
			Port: testRelayPort,
		},
		SrcAddr:   netip.MustParseAddr(testSource),
		GroupAddr: netip.MustParseAddr(testGroup),
		GroupPort: testGroupPort,
		IFace:     iface,
		Timeout:   5 * time.Second,
		TTL:       255,
	}

	// Open connection (will use AMT tunnel)
	if err := mc.Open(); err != nil {
		t.Fatalf("Failed to open connection: %v", err)
	}
	defer mc.Close()

	if !mc.IsUsingTunnel() {
		t.Log("Warning: Not using AMT tunnel (native multicast available)")
	} else {
		t.Log("Using AMT tunnel as expected")
	}

	// Try to receive data
	buf := make([]byte, iface.MTU)
	packetsReceived := 0

	// Set read deadline
	if err := mc.SetReadDeadline(time.Now().Add(testDataTimeout)); err != nil {
		t.Fatalf("Failed to set read deadline: %v", err)
	}

	for i := 0; i < 5; i++ {
		n, addr, err := mc.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Log("Read timeout - no more data")
				break
			}
			t.Fatalf("Read error: %v", err)
		}
		packetsReceived++
		t.Logf("Received packet %d: %d bytes from %v", packetsReceived, n, addr)
	}

	if packetsReceived == 0 {
		t.Error("No multicast packets received")
	} else {
		t.Logf("Successfully received %d multicast packets via AMT", packetsReceived)
	}
}

func TestVersion(t *testing.T) {
	v := Version()
	if v == "" {
		t.Error("Version() returned empty string")
	}
	t.Logf("AMT Protocol Library Version: %s", v)
}
