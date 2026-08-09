//go:build (linux || darwin) && !ios && !android

package amt

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
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
	if os.Getenv("AMT_E2E") == "" {
		t.Skip("set AMT_E2E=1 to run the live AMT test")
	}

	relayAddr := testRelayAddr
	if override := os.Getenv("AMT_TEST_RELAY"); override != "" {
		relayAddr = override
	}
	sourceAddr := testSource
	if override := os.Getenv("AMT_TEST_SOURCE"); override != "" {
		sourceAddr = override
	}
	groupAddr := testGroup
	if override := os.Getenv("AMT_TEST_GROUP"); override != "" {
		groupAddr = override
	}
	groupPort := uint16(testGroupPort)
	if override := os.Getenv("AMT_TEST_PORT"); override != "" {
		port, err := strconv.ParseUint(override, 10, 16)
		if err != nil || port == 0 {
			t.Fatalf("AMT_TEST_PORT = %q, want 1..65535", override)
		}
		groupPort = uint16(port)
	}

	t.Log("Testing AMT gateway through RelayManager")
	t.Logf("Relay: %s:%d", relayAddr, testRelayPort)
	t.Logf("Source: %s, Group: %s:%d", sourceAddr, groupAddr, groupPort)

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

	config := DefaultRelayManagerConfig(net.UDPAddr{
		IP:   net.ParseIP(relayAddr),
		Port: testRelayPort,
	})
	manager := NewRelayManager(config)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := manager.Open(ctx); err != nil {
		t.Fatalf("Failed to open relay manager: %v", err)
	}
	defer manager.Close()

	if _, ok := manager.protocol.(*PureGoProtocol); !ok {
		t.Fatalf("Protocol = %T, want *PureGoProtocol; run with CGO_ENABLED=0", manager.protocol)
	}

	subscription, err := manager.Subscribe(SubscriptionKey{
		Source: netip.MustParseAddr(sourceAddr),
		Group:  netip.MustParseAddr(groupAddr),
		Port:   groupPort,
	}, SubscriptionCallbacks{})
	if err != nil {
		t.Fatalf("Failed to subscribe: %v", err)
	}

	started := time.Now()
	dataTimeout := time.NewTimer(testDataTimeout)
	defer dataTimeout.Stop()
	for packetsReceived := 0; packetsReceived < 5; {
		select {
		case packet := <-subscription.DataChan():
			packetsReceived++
			t.Logf("Received packet %d: %d bytes from %v", packetsReceived, len(packet.Data), packet.Source)
		case <-dataTimeout.C:
			stats := subscription.Stats()
			t.Fatalf("Data timeout after %s: state=%s packets=%d bytes=%d", time.Since(started), stats.State, stats.PacketsReceived, stats.BytesReceived)
		}
	}

	stats := subscription.Stats()
	elapsed := time.Since(started)
	t.Logf("AMT data pass: packets=%d bytes=%d elapsed=%s packet_rate=%.2f/s", stats.PacketsReceived, stats.BytesReceived, elapsed, float64(stats.PacketsReceived)/elapsed.Seconds())
}
