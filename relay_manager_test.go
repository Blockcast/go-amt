package amt

import (
	"net"
	"net/netip"
	"testing"
)

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
