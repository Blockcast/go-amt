package amt

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func multicastDataPacket(t *testing.T, payload []byte) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      1,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.0.2.1").To4(),
		DstIP:    net.ParseIP("239.0.0.1").To4(),
	}
	udp := &layers.UDP{SrcPort: 4000, DstPort: 5000}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	serialized := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(serialized, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}

	packet := make([]byte, m.DataMsgHdrLen+len(serialized.Bytes()))
	copy(packet[m.DataMsgHdrLen:], serialized.Bytes())
	return packet
}

func TestSubscriptionKey_String(t *testing.T) {
	key := SubscriptionKey{
		Source: netip.MustParseAddr("192.168.1.1"),
		Group:  netip.MustParseAddr("239.0.0.1"),
		Port:   5000,
	}

	expected := "(192.168.1.1,239.0.0.1):5000"
	if got := key.String(); got != expected {
		t.Errorf("SubscriptionKey.String() = %q, want %q", got, expected)
	}
}

func TestRelayState_String(t *testing.T) {
	tests := []struct {
		state RelayState
		want  string
	}{
		{RelayStateIdle, "Idle"},
		{RelayStateDiscovering, "Discovering"},
		{RelayStateRequesting, "Requesting"},
		{RelayStateQuerying, "Querying"},
		{RelayStateActive, "Active"},
		{RelayStateReconnecting, "Reconnecting"},
		{RelayStateClosed, "Closed"},
		{RelayStateError, "Error"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("RelayState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestSubscriptionState_String(t *testing.T) {
	tests := []struct {
		state SubscriptionState
		want  string
	}{
		{SubscriptionStateInitializing, "Initializing"},
		{SubscriptionStateJoining, "Joining"},
		{SubscriptionStateActive, "Active"},
		{SubscriptionStateSuspended, "Suspended"},
		{SubscriptionStateClosed, "Closed"},
		{SubscriptionStateError, "Error"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("SubscriptionState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestDefaultRelayManagerConfig(t *testing.T) {
	addr := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2268}
	cfg := DefaultRelayManagerConfig(addr)

	if cfg.RelayAddr.String() != addr.String() {
		t.Errorf("RelayAddr = %v, want %v", cfg.RelayAddr, addr)
	}
	if cfg.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", cfg.MTU)
	}
	if cfg.DataChannelSize != 100 {
		t.Errorf("DataChannelSize = %d, want 100", cfg.DataChannelSize)
	}
}

func TestNewRelayManager(t *testing.T) {
	addr := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2268}
	cfg := DefaultRelayManagerConfig(addr)
	rm := NewRelayManager(cfg)

	if rm.State() != RelayStateIdle {
		t.Errorf("Initial state = %v, want Idle", rm.State())
	}
}

func TestRouteDataToSubscriptionCopiesPayload(t *testing.T) {
	rm := NewRelayManager(DefaultRelayManagerConfig(net.UDPAddr{}))
	key := SubscriptionKey{
		Source: netip.MustParseAddr("192.0.2.1"),
		Group:  netip.MustParseAddr("239.0.0.1"),
		Port:   5000,
	}
	sub := &Subscription{key: key, dataChan: make(chan *DataPacket, 1)}
	sub.state.Store(SubscriptionStateActive)
	rm.subscriptions.Store(key, sub)

	want := []byte("first-payload")
	packet := multicastDataPacket(t, want)
	rm.routeDataToSubscription(packet)
	got := <-sub.dataChan

	for i := range packet {
		packet[i] = 0xff
	}
	if !bytes.Equal(got.Data, want) {
		t.Fatalf("queued payload changed after receive buffer reuse: got %q, want %q", got.Data, want)
	}
}

func TestManagedConnOpenRejectsNonIPv4Subscription(t *testing.T) {
	tests := []struct {
		name    string
		source  netip.Addr
		group   netip.Addr
		wantErr string
	}{
		{name: "IPv6 source", source: netip.MustParseAddr("2001:db8::1"), group: netip.MustParseAddr("239.0.0.1"), wantErr: "source address must be IPv4"},
		{name: "IPv6 group", source: netip.MustParseAddr("192.0.2.1"), group: netip.MustParseAddr("ff3e::1"), wantErr: "group address must be IPv4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &ManagedConn{
				RelayAddr: net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: m.DefaultPort},
				SrcAddr:   tt.source,
				GroupAddr: tt.group,
				GroupPort: 5000,
				Timeout:   time.Second,
			}
			err := mc.Open()
			if err == nil {
				t.Fatal("Open() succeeded for a non-IPv4 AMT subscription")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Open() error = %q, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPlatformCapabilities(t *testing.T) {
	caps := GetPlatformCapabilities()

	// UDP should always be available
	if !caps.SupportsUDP {
		t.Error("SupportsUDP should always be true")
	}

	// Platform should not be unknown on common platforms
	t.Logf("Platform: %s", caps.Platform)
	t.Logf("Capabilities: UDP=%v, CGO=%v, BPF=%v, Timestamp=%v",
		caps.SupportsUDP, caps.SupportsCGO, caps.SupportsBPF, caps.SupportsTimestamp)
}

func TestAMTState_String(t *testing.T) {
	tests := []struct {
		state AMTState
		want  string
	}{
		{AMTStateIdle, "Idle"},
		{AMTStateDiscovering, "Discovering"},
		{AMTStateRequesting, "Requesting"},
		{AMTStateQuerying, "Querying"},
		{AMTStateActive, "Active"},
		{AMTStateClosed, "Closed"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("AMTState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestTransportConfig_Defaults(t *testing.T) {
	addr := net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 2268}
	cfg := DefaultTransportConfig(addr)

	if cfg.RelayAddr.String() != addr.String() {
		t.Errorf("RelayAddr = %v, want %v", cfg.RelayAddr, addr)
	}
	if cfg.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", cfg.MTU)
	}
	if !cfg.EnableTimestamp {
		t.Error("EnableTimestamp should be true by default")
	}
}

func TestPlatformInfo(t *testing.T) {
	info := PlatformInfo()
	t.Logf("Platform info: %s", info)
	if info == "" {
		t.Error("PlatformInfo() returned empty string")
	}
}
