package amt

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/miekg/dns"
	"go.uber.org/atomic"
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
		0x0A,         // precedence = 10
		0x01,         // D=0, type=1 (IPv4)
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
		0x05,        // precedence = 5
		0x81,        // D=1, type=1 (IPv4)
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
		0x0A,         // precedence = 10
		0x01,         // D=0, type=1 (IPv4)
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

func TestOrderRelays_PrecedenceFirstAndEqualPrecedenceSpread(t *testing.T) {
	// RFC 8777 §3.1.2: lowest precedence first, and a non-deterministic choice
	// among equal precedence so several listed relays share the load.
	records := []AMTRelayRecord{
		{Precedence: 20, RelayAddr: "backup.example.com"},
		{Precedence: 10, RelayAddr: "relay1.example.com"},
		{Precedence: 10, RelayAddr: "relay2.example.com"},
	}
	rng := rand.New(rand.NewPCG(8777, 7450))
	leaders := map[string]bool{}
	for range 64 {
		ordered := OrderRelays(records, rng.Shuffle)
		if len(ordered) != 3 || ordered[0].Precedence != 10 || ordered[1].Precedence != 10 || ordered[2].RelayAddr != "backup.example.com" {
			t.Fatalf("order %+v: want both precedence-10 relays before the precedence-20 backup", ordered)
		}
		leaders[ordered[0].RelayAddr] = true
	}
	if !leaders["relay1.example.com"] || !leaders["relay2.example.com"] {
		t.Fatalf("leaders %v: both equal-precedence relays must lead some orderings", leaders)
	}
	if records[0].RelayAddr != "backup.example.com" {
		t.Fatalf("OrderRelays modified its input: %+v", records)
	}
}

func TestParseAMTRelayRR_NativeMiekgType(t *testing.T) {
	// miekg/dns decodes TYPE260 as *dns.AMTRELAY, which is what a real
	// resolver answer yields; the parser must accept it, not only RFC 3597.
	cases := []struct {
		rr   string
		want AMTRelayRecord
	}{
		{"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 10 0 3 relay.example.com.",
			AMTRelayRecord{Precedence: 10, RelayType: 3, RelayAddr: "relay.example.com."}},
		{"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 20 1 1 192.0.2.7",
			AMTRelayRecord{Precedence: 20, DFlag: true, RelayType: 1, RelayAddr: "192.0.2.7", ResolvedAddr: netip.MustParseAddr("192.0.2.7")}},
		{"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 30 0 2 2001:db8::7",
			AMTRelayRecord{Precedence: 30, RelayType: 2, RelayAddr: "2001:db8::7", ResolvedAddr: netip.MustParseAddr("2001:db8::7")}},
	}
	for _, tc := range cases {
		rr, err := dns.NewRR(tc.rr)
		if err != nil {
			t.Fatalf("NewRR(%q): %v", tc.rr, err)
		}
		if _, native := rr.(*dns.AMTRELAY); !native {
			t.Fatalf("miekg/dns returned %T, want *dns.AMTRELAY", rr)
		}
		got, ok := parseAMTRelayRR(rr)
		if !ok || got != tc.want {
			t.Fatalf("parseAMTRelayRR(%q) = %+v, %v; want %+v, true", tc.rr, got, ok, tc.want)
		}
	}
}

// driadTestSource is the source whose reverse name the fixtures below answer:
// BuildDRIADQuery(69.25.95.1) == "1.95.25.69.in-addr.arpa.".
var driadTestSource = netip.MustParseAddr("69.25.95.1")

// startFakeDRIADResolver answers AMTRELAY queries for driadTestSource with rrs,
// over UDP on 127.0.0.1, and reports whether the query carried an EDNS0 OPT
// record. The answer leaves through dns.Msg.Pack and arrives through the normal
// miekg/dns decode, so a caller exercises the same wire path a real resolver
// gives it rather than a hand-built RR.
func startFakeDRIADResolver(t *testing.T, rrs ...string) (addr string, sawEDNS0 *atomic.Bool) {
	t.Helper()

	answer := make([]dns.RR, 0, len(rrs))
	for _, text := range rrs {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatalf("NewRR(%q): %v", text, err)
		}
		answer = append(answer, rr)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen resolver socket: %v", err)
	}

	sawEDNS0 = atomic.NewBool(false)
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if req.IsEdns0() != nil {
			sawEDNS0.Store(true)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = answer
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return pc.LocalAddr().String(), sawEDNS0
}

func TestParseAMTRelayRR_PackedWireAnswer(t *testing.T) {
	// The acceptance case: an AMTRELAY RR that has been through dns.Msg.Pack
	// and back, which is what every real answer is. Before parseAMTRelayRR
	// learned *dns.AMTRELAY this yielded no records at all, and DiscoverRelay
	// reported "no AMTRELAY records found" for a source that had published one.
	rr, err := dns.NewRR("1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 10 0 1 192.0.2.7")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	msg := new(dns.Msg)
	msg.SetQuestion("1.95.25.69.in-addr.arpa.", DNSTypeAMTRELAY)
	msg.Answer = []dns.RR{rr}

	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	unpacked := new(dns.Msg)
	if err := unpacked.Unpack(wire); err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	var records []AMTRelayRecord
	for _, answer := range unpacked.Answer {
		if record, ok := parseAMTRelayRR(answer); ok {
			records = append(records, record)
		}
	}
	if len(records) != 1 {
		t.Fatalf("parsed %d records from a packed AMTRELAY answer, want 1", len(records))
	}
	want := AMTRelayRecord{Precedence: 10, RelayType: 1, RelayAddr: "192.0.2.7", ResolvedAddr: netip.MustParseAddr("192.0.2.7")}
	if records[0] != want {
		t.Fatalf("record = %+v, want %+v", records[0], want)
	}
}

func TestDiscoverRelays_OrdersWireAnswerAndSendsEDNS0(t *testing.T) {
	resolver, sawEDNS0 := startFakeDRIADResolver(t,
		"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 30 0 1 192.0.2.30",
		"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 10 0 1 192.0.2.10",
		"1.95.25.69.in-addr.arpa. 300 IN AMTRELAY 20 0 2 2001:db8::20",
	)

	relays, err := DiscoverRelays(context.Background(), DRIADConfig{
		SourceAddr: driadTestSource,
		DNSServers: []string{resolver},
		Timeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DiscoverRelays: %v", err)
	}

	// Every advertised relay comes back, not just the winner, so a caller can
	// fail over; distinct precedences make the order total.
	got := make([]string, 0, len(relays))
	for _, relay := range relays {
		got = append(got, relay.IP.String())
	}
	want := []string{"192.0.2.10", "2001:db8::20", "192.0.2.30"}
	if !slices.Equal(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for _, relay := range relays {
		if relay.Port != m.DefaultPort {
			t.Fatalf("relay %s port = %d, want %d", relay.IP, relay.Port, m.DefaultPort)
		}
	}

	// An RRset listing several relays, or a relay named rather than numbered,
	// outgrows the 512-byte floor; without EDNS0 the answer is truncated and the
	// extra relays are exactly what gets dropped.
	if !sawEDNS0.Load() {
		t.Fatal("DRIAD query carried no EDNS0 OPT record")
	}
}

func TestSystemDNSServerReadsResolvConf(t *testing.T) {
	// Hardcoding systemd-resolved's stub made DRIAD fail outright wherever that
	// stub is not listening -- a container pointed at a cluster DNS service, a
	// host on plain resolvconf -- so a published AMTRELAY RRset looked like a
	// source with no relays.
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 10.96.0.10\nsearch svc.cluster.local\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Cleanup(func(old string) func() { return func() { resolvConfPath = old } }(resolvConfPath))
	resolvConfPath = path

	if got := systemDNSServer(); got != "10.96.0.10:53" {
		t.Fatalf("systemDNSServer() = %q, want the resolv.conf nameserver 10.96.0.10:53", got)
	}

	// An unreadable resolv.conf still has to yield something dialable.
	resolvConfPath = filepath.Join(t.TempDir(), "absent")
	if _, _, err := net.SplitHostPort(systemDNSServer()); err != nil {
		t.Fatalf("fallback %q is not host:port: %v", systemDNSServer(), err)
	}
}
