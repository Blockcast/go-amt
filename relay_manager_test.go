package amt

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
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

func TestPureGoProtocolCreatesLeaveCompatibleIGMPv3Report(t *testing.T) {
	protocol, err := NewPureGoProtocol()
	if err != nil {
		t.Fatal(err)
	}

	report, err := protocol.CreateIGMPLeaveReport(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("239.0.0.1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	// Offsets are relative to the end of the IPv4 header, which carries the
	// Router Alert option and so is igmpIPHeaderLen rather than a bare 20.
	const igmp = igmpIPHeaderLen
	if len(report) != igmp+16 {
		t.Fatalf("leave report length = %d, want %d", len(report), igmp+16)
	}
	if report[igmp] != m.IGMPv3TypeMembershipReport {
		t.Fatalf("IGMP type = %#x, want %#x", report[igmp], m.IGMPv3TypeMembershipReport)
	}
	if report[igmp+7] != 1 {
		t.Fatalf("group record count = %d, want 1", report[igmp+7])
	}
	if report[igmp+8] != m.IGMPv3ChangeToIncludeMode {
		t.Fatalf("record type = %d, want change-to-include", report[igmp+8])
	}
	if report[igmp+10] != 0 || report[igmp+11] != 0 {
		t.Fatalf("leave record has sources: count bytes %#x %#x", report[igmp+10], report[igmp+11])
	}
}

func TestPureGoProtocolCreatesSourceSpecificLeaveReport(t *testing.T) {
	protocol, err := NewPureGoProtocol()
	if err != nil {
		t.Fatal(err)
	}

	report, err := protocol.CreateIGMPSourceLeaveReport(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("239.0.0.1"),
	)
	if err != nil {
		t.Fatal(err)
	}
	const igmp = igmpIPHeaderLen
	if len(report) != igmp+20 {
		t.Fatalf("source-specific leave report length = %d, want %d", len(report), igmp+20)
	}
	if report[igmp+8] != m.IGMPv3BlockOldSources {
		t.Fatalf("record type = %d, want block-old-sources", report[igmp+8])
	}
	if report[igmp+10] != 0 || report[igmp+11] != 1 {
		t.Fatalf("source count bytes = %#x %#x, want 0x00 0x01", report[igmp+10], report[igmp+11])
	}
	if !bytes.Equal(report[igmp+16:igmp+20], net.IPv4(192, 0, 2, 1).To4()) {
		t.Fatalf("source = %v, want 192.0.2.1", net.IP(report[igmp+16:igmp+20]))
	}
}

func TestManagedConnCloseUnblocksTunnelReads(t *testing.T) {
	tests := []struct {
		name string
		read func(*ManagedConn) error
	}{
		{
			name: "ReadFrom",
			read: func(mc *ManagedConn) error {
				_, _, err := mc.ReadFrom(make([]byte, 1500))
				return err
			},
		},
		{
			name: "ReadFromWithControlMessage",
			read: func(mc *ManagedConn) error {
				_, _, _, err := mc.ReadFromWithControlMessage(make([]byte, 1500))
				return err
			},
		},
		{
			name: "ReadBatch",
			read: func(mc *ManagedConn) error {
				messages := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1500)}}}
				_, err := mc.ReadBatch(messages, 0)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := &ManagedConn{
				usingTunnel: true,
				readBuffer:  make(chan *DataPacket),
				done:        make(chan struct{}),
			}

			readResult := make(chan error, 1)
			go func() {
				readResult <- tt.read(mc)
			}()

			select {
			case err := <-readResult:
				t.Fatalf("read returned before Close: %v", err)
			case <-time.After(20 * time.Millisecond):
			}

			closeResult := make(chan error, 1)
			go func() {
				closeResult <- mc.Close()
			}()

			select {
			case err := <-closeResult:
				if err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close blocked behind an idle read")
			}

			select {
			case err := <-readResult:
				if err == nil || !strings.Contains(err.Error(), "connection closed") {
					t.Fatalf("read error = %v, want connection closed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("read did not unblock after Close")
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

// TestRelayManagerOpenFallsOverToNextDRIADCandidate drives Open against a real
// AMTRELAY answer listing an unreachable relay ahead of a working one.
//
// Stopping at the first relay is what turned one dead relay into a dead
// subscription: the source had published a second relay and nothing ever tried
// it. The transport factory stands in for that relay being unreachable, so the
// failover is observed in milliseconds rather than after handshakeTimeout.
func TestRelayManagerOpenFallsOverToNextDRIADCandidate(t *testing.T) {
	fr := newFakeRelay(t)
	t.Cleanup(fr.Close)

	const deadRelay = "192.0.2.10"
	resolver, _ := startFakeDRIADResolver(t,
		"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 10 0 1 "+deadRelay,
		fmt.Sprintf("1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 20 0 1 %s", fr.Addr().IP),
	)

	cfg := DefaultRelayManagerConfigWithDRIAD(driadTestSource)
	cfg.DNSServers = []string{resolver}
	cfg.DNSTimeout = 5 * time.Second
	cfg.TransportConfig.Timeout = 2 * time.Second
	cfg.InitialBackoff = 10 * time.Millisecond
	cfg.MaxBackoff = 100 * time.Millisecond

	var tried []string
	cfg.TransportFactory = func(tc TransportConfig) (Transport, error) {
		tried = append(tried, tc.RelayAddr.IP.String())
		if tc.RelayAddr.IP.String() == deadRelay {
			return nil, fmt.Errorf("simulated unreachable relay %s", tc.RelayAddr.IP)
		}
		// DRIAD hands out m.DefaultPort, which is right on the wire and wrong
		// for a fake relay on an ephemeral port. The IP is what the candidate
		// list decides, and that is what this test is about.
		tc.RelayAddr = fr.Addr()
		return CreatePlatformTransport(tc)
	}

	rm := NewRelayManager(cfg)
	t.Cleanup(func() { _ = rm.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open did not fail over past %s: %v", deadRelay, err)
	}

	want := []string{deadRelay, fr.Addr().IP.String()}
	if !slices.Equal(tried, want) {
		t.Fatalf("relays tried = %v, want %v (lowest precedence first, then the next candidate)", tried, want)
	}
	if got := rm.config.RelayAddr.IP.String(); got != fr.Addr().IP.String() {
		t.Fatalf("manager settled on relay %s, want the reachable one %s", got, fr.Addr().IP)
	}
	if rm.State() != RelayStateActive {
		t.Fatalf("state after failover = %s, want Active", rm.State())
	}
}

// TestRelayManagerOpenReportsLastCandidateWhenAllFail keeps the all-dead case
// an error rather than a silent success on an unopened manager.
func TestRelayManagerOpenReportsLastCandidateWhenAllFail(t *testing.T) {
	resolver, _ := startFakeDRIADResolver(t,
		"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 10 0 1 192.0.2.10",
		"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 20 0 1 192.0.2.20",
	)

	cfg := DefaultRelayManagerConfigWithDRIAD(driadTestSource)
	cfg.DNSServers = []string{resolver}
	cfg.DNSTimeout = 5 * time.Second

	var tried []string
	cfg.TransportFactory = func(tc TransportConfig) (Transport, error) {
		tried = append(tried, tc.RelayAddr.IP.String())
		return nil, fmt.Errorf("simulated unreachable relay %s", tc.RelayAddr.IP)
	}

	rm := NewRelayManager(cfg)
	t.Cleanup(func() { _ = rm.Close() })

	err := rm.Open(context.Background())
	if err == nil {
		t.Fatal("Open succeeded with every relay unreachable")
	}
	if !strings.Contains(err.Error(), "192.0.2.20") {
		t.Fatalf("Open error %q does not name the last relay tried", err)
	}
	if want := []string{"192.0.2.10", "192.0.2.20"}; !slices.Equal(tried, want) {
		t.Fatalf("relays tried = %v, want %v", tried, want)
	}
}
