package amt

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestIGMPReportsIncludeRouterAlert pins the IPv4 envelope on every IGMPv3
// report this package emits. RFC 3376 requires the Router Alert option on all of
// them, and relays that enforce it silently drop reports that omit it -- a
// failure that looks like "the join worked but no data arrived", so it is worth
// catching here rather than on a live relay.
//
// Every builder is covered, not just the join. The join path and the leave path
// were once separate copies of the header code and only the join copy carried
// the option; enumerating the builders is what keeps a new one from repeating
// that.
func TestIGMPReportsIncludeRouterAlert(t *testing.T) {
	protocol, err := NewPureGoProtocol()
	if err != nil {
		t.Fatal(err)
	}

	source := netip.MustParseAddr("192.0.2.1")
	group := netip.MustParseAddr("232.0.0.1")

	for _, tc := range []struct {
		name  string
		build func() ([]byte, error)
	}{
		{"join", func() ([]byte, error) { return protocol.CreateIGMPJoinReport(source, group) }},
		{"join-multi", func() ([]byte, error) {
			return protocol.CreateIGMPJoinReportMulti(source, []netip.Addr{group})
		}},
		{"leave", func() ([]byte, error) { return protocol.CreateIGMPLeaveReport(source, group) }},
		{"source-leave", func() ([]byte, error) { return protocol.CreateIGMPSourceLeaveReport(source, group) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			if len(report) < igmpIPHeaderLen {
				t.Fatalf("report length = %d, want at least %d for the IPv4 header", len(report), igmpIPHeaderLen)
			}

			if got, want := report[0]&0x0f, byte(igmpIPHeaderLen/4); got != want {
				t.Errorf("IPv4 IHL = %d, want %d for Router Alert option", got, want)
			}
			if got := report[20:igmpIPHeaderLen]; string(got) != string(igmpRouterAlert[:]) {
				t.Errorf("IPv4 options = %x, want Router Alert %x", got, igmpRouterAlert)
			}
			if got := binary.BigEndian.Uint16(report[2:4]); got != uint16(len(report)) {
				t.Errorf("IPv4 total length = %d, want %d", got, len(report))
			}
			// A correct checksum re-checksums to zero over the whole header,
			// options included -- which also proves the option was written
			// before the checksum was computed.
			if got := protocol.calculateIPChecksum(report[:igmpIPHeaderLen]); got != 0 {
				t.Errorf("IPv4 checksum validation = %#04x, want 0", got)
			}
		})
	}
}
