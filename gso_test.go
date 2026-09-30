package amt

import (
	"errors"
	"testing"
)

func TestSegmentCount(t *testing.T) {
	// The ceiling matters: GSO allows a single trailing short segment, and
	// undercounting it would let a batch one segment over the cap through the
	// pre-check to be rejected by the kernel instead.
	for _, tc := range []struct {
		name              string
		total, segmentSze int
		want              int
	}{
		{"exact multiple", 1200, 400, 3},
		{"short tail", 1300, 400, 4},
		{"one byte over", 401, 400, 2},
		{"single full", 400, 400, 1},
		{"smaller than one segment", 39, 400, 1},
		{"zero total", 0, 400, 0},
		{"zero segment size", 1200, 0, 0},
		{"negative segment size", 1200, -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := segmentCount(tc.total, tc.segmentSze); got != tc.want {
				t.Fatalf("segmentCount(%d, %d) = %d, want %d",
					tc.total, tc.segmentSze, got, tc.want)
			}
		})
	}
}

func TestCheckSegmentBatch(t *testing.T) {
	const mtu = 1500
	for _, tc := range []struct {
		name                    string
		total, segmentSize, mtu int
		wantErr                 bool
	}{
		// A DS 74 block: 12 x 1366. The shipping case, with headroom on both caps.
		{"ds74 block", 12 * 1366, 1366, mtu, false},
		{"short last segment", 11*1366 + 700, 1366, mtu, false},

		// Boundaries, each measured on the staging sender by bisection.
		{"at segment cap", UDPMaxSegments * 400, 400, mtu, false},
		{"one over segment cap", UDPMaxSegments*400 + 1, 400, mtu, true},
		{"at byte cap", maxSegmentedPayloadBytes, 1400, 0, false},
		{"one over byte cap", maxSegmentedPayloadBytes + 1, 1400, 0, true},
		{"segment exactly mtu minus headers", 3 * (mtu - 28), mtu - 28, mtu, false},
		{"segment one over mtu", 3 * (mtu - 27), mtu - 27, mtu, true},

		// An unknown mtu must not refuse the batch: guessing one would decline
		// sends the kernel would accept, and the kernel still fails closed.
		{"unknown mtu skips the mtu check", 3 * 9000, 9000, 0, false},
		{"negative mtu skips the mtu check", 3 * 9000, 9000, -1, false},

		{"zero segment size", 1200, 0, mtu, true},
		{"negative segment size", 1200, -1, mtu, true},
		{"empty buffer", 0, 400, mtu, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSegmentBatch(tc.total, tc.segmentSize, tc.mtu)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("checkSegmentBatch(%d, %d, %d) = nil, want an error",
						tc.total, tc.segmentSize, tc.mtu)
				}
				// Callers select the fallback with errors.Is, so every refusal
				// must carry the sentinel rather than a bare message.
				if !errors.Is(err, ErrSegmentsUnsupported) {
					t.Fatalf("error %v does not wrap ErrSegmentsUnsupported", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkSegmentBatch(%d, %d, %d) = %v, want nil",
					tc.total, tc.segmentSize, tc.mtu, err)
			}
		})
	}
}

// TestSegmentsPartialIsDistinctFromUnsupported pins the one distinction that
// decides whether a caller may retry: ErrSegmentsUnsupported means nothing was
// written (fall back), ErrSegmentsPartial means some of it was (do not).
// Collapsing them would put the accepted prefix on a live group twice.
func TestSegmentsPartialIsDistinctFromUnsupported(t *testing.T) {
	if errors.Is(ErrSegmentsPartial, ErrSegmentsUnsupported) {
		t.Fatal("ErrSegmentsPartial must not wrap ErrSegmentsUnsupported: a caller " +
			"falling back on it would duplicate the accepted datagrams")
	}
	if errors.Is(ErrSegmentsUnsupported, ErrSegmentsPartial) {
		t.Fatal("ErrSegmentsUnsupported must not wrap ErrSegmentsPartial")
	}
}
