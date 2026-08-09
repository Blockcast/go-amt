package amt

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestPureGoIGMPReportIncludesRouterAlert(t *testing.T) {
	protocol, err := NewPureGoProtocol()
	if err != nil {
		t.Fatal(err)
	}

	report, err := protocol.CreateIGMPJoinReport(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("232.0.0.1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if got := report[0] & 0x0f; got != 6 {
		t.Fatalf("IPv4 IHL = %d, want 6 for Router Alert option", got)
	}
	if got := report[20:24]; string(got) != string([]byte{0x94, 0x04, 0x00, 0x00}) {
		t.Fatalf("IPv4 options = %x, want Router Alert 94040000", got)
	}
	if got := binary.BigEndian.Uint16(report[2:4]); got != uint16(len(report)) {
		t.Fatalf("IPv4 total length = %d, want %d", got, len(report))
	}
	if got := protocol.calculateIPChecksum(report[:24]); got != 0 {
		t.Fatalf("IPv4 checksum validation = %#04x, want 0", got)
	}
}
