package amt

import (
	"net/netip"
	"testing"
)

func TestBuildDRIADQuery_IPv4(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:     "simple IPv4",
			source:   "192.0.2.1",
			expected: "1.2.0.192.in-addr.arpa.",
		},
		{
			name:     "all zeros",
			source:   "0.0.0.0",
			expected: "0.0.0.0.in-addr.arpa.",
		},
		{
			name:     "all 255s",
			source:   "255.255.255.255",
			expected: "255.255.255.255.in-addr.arpa.",
		},
		{
			name:     "typical multicast source",
			source:   "162.250.138.201",
			expected: "201.138.250.162.in-addr.arpa.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.source)
			got, err := BuildDRIADQuery(addr)
			if err != nil {
				t.Fatalf("BuildDRIADQuery() error = %v", err)
			}
			if got != tt.expected {
				t.Errorf("BuildDRIADQuery() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBuildDRIADQuery_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name:   "simple IPv6",
			source: "2001:db8::1",
			// 2001:0db8:0000:0000:0000:0000:0000:0001 reversed nibbles
			expected: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.source)
			got, err := BuildDRIADQuery(addr)
			if err != nil {
				t.Fatalf("BuildDRIADQuery() error = %v", err)
			}
			if got != tt.expected {
				t.Errorf("BuildDRIADQuery() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBuildDRIADQuery_Invalid(t *testing.T) {
	var invalid netip.Addr
	_, err := BuildDRIADQuery(invalid)
	if err == nil {
		t.Error("BuildDRIADQuery() expected error for invalid address")
	}
}

func TestParseAMTRelayRdata_IPv4(t *testing.T) {
	// AMTRELAY RDATA: precedence=10, D=0, type=1 (IPv4), relay=192.0.2.1
	rdata := []byte{
		0x0A,       // precedence = 10
		0x01,       // D=0, type=1 (IPv4)
		192, 0, 2, 1, // relay IP
	}

	record, err := ParseAMTRelayRdata(rdata)
	if err != nil {
		t.Fatalf("ParseAMTRelayRdata() error = %v", err)
	}

	if record.Precedence != 10 {
		t.Errorf("Precedence = %d, want 10", record.Precedence)
	}
	if record.DFlag {
		t.Error("DFlag = true, want false")
	}
	if record.RelayType != 1 {
		t.Errorf("RelayType = %d, want 1", record.RelayType)
	}
	if record.RelayAddr != "192.0.2.1" {
		t.Errorf("RelayAddr = %q, want %q", record.RelayAddr, "192.0.2.1")
	}
	if !record.ResolvedAddr.IsValid() || record.ResolvedAddr.String() != "192.0.2.1" {
		t.Errorf("ResolvedAddr = %v, want 192.0.2.1", record.ResolvedAddr)
	}
}

func TestParseAMTRelayRdata_IPv4_WithDFlag(t *testing.T) {
	// AMTRELAY RDATA: precedence=5, D=1, type=1 (IPv4), relay=10.0.0.1
	rdata := []byte{
		0x05,       // precedence = 5
		0x81,       // D=1, type=1 (IPv4)
		10, 0, 0, 1, // relay IP
	}

	record, err := ParseAMTRelayRdata(rdata)
	if err != nil {
		t.Fatalf("ParseAMTRelayRdata() error = %v", err)
	}

	if record.Precedence != 5 {
		t.Errorf("Precedence = %d, want 5", record.Precedence)
	}
	if !record.DFlag {
		t.Error("DFlag = false, want true")
	}
	if record.RelayType != 1 {
		t.Errorf("RelayType = %d, want 1", record.RelayType)
	}
	if record.RelayAddr != "10.0.0.1" {
		t.Errorf("RelayAddr = %q, want %q", record.RelayAddr, "10.0.0.1")
	}
}

func TestParseAMTRelayRdata_IPv6(t *testing.T) {
	// AMTRELAY RDATA: precedence=20, D=0, type=2 (IPv6), relay=2001:db8::1
	rdata := []byte{
		0x14, // precedence = 20
		0x02, // D=0, type=2 (IPv6)
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // 2001:db8::1
	}

	record, err := ParseAMTRelayRdata(rdata)
	if err != nil {
		t.Fatalf("ParseAMTRelayRdata() error = %v", err)
	}

	if record.Precedence != 20 {
		t.Errorf("Precedence = %d, want 20", record.Precedence)
	}
	if record.RelayType != 2 {
		t.Errorf("RelayType = %d, want 2", record.RelayType)
	}
	if record.RelayAddr != "2001:db8::1" {
		t.Errorf("RelayAddr = %q, want %q", record.RelayAddr, "2001:db8::1")
	}
}

func TestParseAMTRelayRdata_Empty(t *testing.T) {
	// AMTRELAY RDATA: precedence=0, D=0, type=0 (empty/no relay)
	rdata := []byte{
		0x00, // precedence = 0
		0x00, // D=0, type=0 (empty)
	}

	record, err := ParseAMTRelayRdata(rdata)
	if err != nil {
		t.Fatalf("ParseAMTRelayRdata() error = %v", err)
	}

	if record.RelayType != 0 {
		t.Errorf("RelayType = %d, want 0", record.RelayType)
	}
}

func TestParseAMTRelayRdata_TooShort(t *testing.T) {
	rdata := []byte{0x00} // Only 1 byte, need at least 2
	_, err := ParseAMTRelayRdata(rdata)
	if err == nil {
		t.Error("ParseAMTRelayRdata() expected error for too short RDATA")
	}
}

func TestBuildAMTRelayRdata_IPv4(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	rdata := BuildAMTRelayRdata(10, false, addr)

	expected := []byte{
		0x0A,       // precedence = 10
		0x01,       // D=0, type=1 (IPv4)
		192, 0, 2, 1, // relay IP
	}

	if len(rdata) != len(expected) {
		t.Fatalf("len(rdata) = %d, want %d", len(rdata), len(expected))
	}

	for i := range expected {
		if rdata[i] != expected[i] {
			t.Errorf("rdata[%d] = %02x, want %02x", i, rdata[i], expected[i])
		}
	}
}

func TestBuildAMTRelayRdata_IPv4_WithDFlag(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	rdata := BuildAMTRelayRdata(5, true, addr)

	if rdata[0] != 5 {
		t.Errorf("precedence = %d, want 5", rdata[0])
	}
	if rdata[1] != 0x81 {
		t.Errorf("flags = %02x, want 0x81 (D=1, type=1)", rdata[1])
	}
}

func TestBuildAMTRelayRdata_IPv6(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	rdata := BuildAMTRelayRdata(20, false, addr)

	if rdata[0] != 20 {
		t.Errorf("precedence = %d, want 20", rdata[0])
	}
	if rdata[1] != 0x02 {
		t.Errorf("flags = %02x, want 0x02 (D=0, type=2)", rdata[1])
	}
	if len(rdata) != 18 { // 1 + 1 + 16
		t.Errorf("len(rdata) = %d, want 18", len(rdata))
	}
}

func TestDefaultDRIADConfig(t *testing.T) {
	addr := netip.MustParseAddr("192.0.2.1")
	config := DefaultDRIADConfig(addr)

	if config.SourceAddr != addr {
		t.Errorf("SourceAddr = %v, want %v", config.SourceAddr, addr)
	}
	if config.Timeout != DefaultDNSDTimeout {
		t.Errorf("Timeout = %v, want %v", config.Timeout, DefaultDNSDTimeout)
	}
	if len(config.DNSServers) != 0 {
		t.Errorf("DNSServers = %v, want empty", config.DNSServers)
	}
}
