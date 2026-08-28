//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net/netip"
	"testing"
)

func TestCGOProtocolJoinBuildersRejectNonIPv4WithoutPanicking(t *testing.T) {
	protocol := &CGOProtocol{state: AMTStateIdle}
	v6 := netip.MustParseAddr("2001:db8::1")
	v4 := netip.MustParseAddr("192.0.2.1")

	tests := []struct {
		name  string
		build func() ([]byte, error)
	}{
		{"join-source", func() ([]byte, error) { return protocol.CreateIGMPJoinReport(v6, v4) }},
		{"join-group", func() ([]byte, error) { return protocol.CreateIGMPJoinReport(v4, v6) }},
		{"join-multi-source", func() ([]byte, error) {
			return protocol.CreateIGMPJoinReportMulti(v6, []netip.Addr{v4})
		}},
		{"join-multi-group", func() ([]byte, error) {
			return protocol.CreateIGMPJoinReportMulti(v4, []netip.Addr{v6})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.build(); err == nil {
				t.Fatal("expected non-IPv4 address validation error")
			}
		})
	}
}
