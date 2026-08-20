package amt

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestIGMPEnvelopeParityAcrossImplementations pins the IPv4 envelope that the
// *selected* AMTProtocol implementation wraps around an IGMPv3 join report.
//
// TestIGMPReportsIncludeRouterAlert already covers this, but it constructs
// NewPureGoProtocol() explicitly, so it only ever exercises the pure-Go
// encoder. Production uses the cgo/Rust path (README.md:54), and that encoder
// lives in a different language in a different repository -- it had no envelope
// coverage here at all. This test goes through DefaultProtocol() so the same
// assertions land on whichever implementation the build actually selected:
// pure-Go under CGO_ENABLED=0, the Rust FFI under the cgo-test job.
//
// Scope is the two join builders on purpose. They are the only ones that cross
// the FFI: CreateIGMPLeaveReport and CreateIGMPSourceLeaveReport delegate to
// the shared Go helpers (protocol_cgo.go:257-263), so on the cgo path a leave
// report is already byte-identical to pure-Go by construction and asserting it
// here would prove nothing about the Rust encoder.
//
// This is also what makes BLO-28805's "all one guard" attribution falsifiable
// rather than a guess. The submodule bump that released three cgo-path tests
// carried a second, independent fix -- amt-protocol/src/igmp.rs switched the
// IPv4 options field from four zero pad bytes to a real Router Alert option --
// and an RA-less report is exactly what an RA-enforcing relay drops, which
// would present as "never became active" just as the send_update guard did.
// The reason it cannot be the cause here is that the fake-relay harness is
// blind to the option: handleUpdate (fakerelay_test.go:192) stores the update
// without parsing the IPv4 header, WaitForLeaveRecord derives its offset from
// igmpIPHeaderLen rather than reading the bytes, and both encodings are 4 bytes
// so no offset shifts. Nothing in the harness could distinguish them -- which
// is precisely why the RA convergence needs pinning explicitly, here, instead
// of being inferred from a green tick.
//
// The IPv4 destination is deliberately NOT asserted. It is the one envelope
// field the two implementations genuinely disagree on: the Rust encoder sends
// the multicast group address, pure-Go sends 224.0.0.22 per RFC 3376 §4.2.14.
// That is a real conformance gap, pre-existing and tracked in BLO-29419; add
// the assertion here when it closes.
func TestIGMPEnvelopeParityAcrossImplementations(t *testing.T) {
	protocol, err := DefaultProtocol()
	if err != nil {
		t.Fatalf("DefaultProtocol: %v", err)
	}
	defer protocol.Close()

	// Anti-vacuity. DefaultProtocol falls back to pure Go whenever the cgo
	// factory returns an error, so on a build where the FFI path is compiled in
	// this test would otherwise pass by silently re-testing pure Go -- the same
	// failure mode the cgo-test job's selection guard exists to catch. If the
	// cgo protocol is registered, it is what must be under test.
	if IsCGOAvailable() {
		if _, isPure := protocol.(*PureGoProtocol); isPure {
			t.Fatal("cgo protocol is registered but DefaultProtocol returned the pure-Go one; " +
				"this test would not have covered the FFI encoder")
		}
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			if len(report) < igmpIPHeaderLen {
				t.Fatalf("report length = %d, want at least %d for the IPv4 header",
					len(report), igmpIPHeaderLen)
			}

			if got, want := report[0]&0x0f, byte(igmpIPHeaderLen/4); got != want {
				t.Errorf("IPv4 IHL = %d, want %d for the Router Alert option", got, want)
			}
			if got := report[20:igmpIPHeaderLen]; string(got) != string(igmpRouterAlert[:]) {
				t.Errorf("IPv4 options = %x, want Router Alert %x", got, igmpRouterAlert)
			}
			if got := binary.BigEndian.Uint16(report[2:4]); got != uint16(len(report)) {
				t.Errorf("IPv4 total length = %d, want %d", got, len(report))
			}
			// A correct checksum re-checksums to zero over the whole header,
			// options included -- which also proves the option was written
			// before the checksum was computed rather than appended after.
			if got := ipChecksum(report[:igmpIPHeaderLen]); got != 0 {
				t.Errorf("IPv4 checksum validation = %#04x, want 0", got)
			}
		})
	}
}
