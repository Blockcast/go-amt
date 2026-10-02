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

		// A segment larger than the buffer, with the mtu check skipped, is the
		// only way an out-of-range segmentSize reaches the uint16 narrowing in
		// writeSegments. 70000 wraps to 4464, so the kernel would emit 15
		// datagrams where the caller asked for one -- and report success.
		{"segment over the buffer wraps uint16", maxSegmentedPayloadBytes, 70000, 0, true},
		{"segment one over the buffer", 1200, 1201, 0, true},
		// The boundary stays open: one segment exactly filling the buffer is
		// the legitimate single-datagram batch and must not be refused.
		{"segment exactly fills the buffer", 1200, 1200, mtu, false},

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

// TestCheckSegmentBatchKeepsTheUint16NarrowingLossless is the invariant behind
// the "segment over the buffer" rows above, asserted as a property rather than
// at three chosen points.
//
// writeSegments narrows segmentSize to uint16 for the UDP_SEGMENT cmsg. That
// narrowing is the one step in this path that changes the wire silently: an
// out-of-range value does not error, it wraps, and the kernel then emits a
// different number of differently-sized datagrams than the caller asked for and
// reports success. checkSegmentBatch is the only thing standing in front of it,
// so what must hold is not "these three inputs are refused" but "nothing this
// function accepts can wrap".
//
// mtu is 0 throughout on purpose: an unknown mtu skips the per-segment check by
// design, which is exactly the configuration in which the other bounds have to
// carry this alone.
func TestCheckSegmentBatchKeepsTheUint16NarrowingLossless(t *testing.T) {
	for _, total := range []int{1, 400, 1366, 12 * 1366, maxSegmentedPayloadBytes} {
		for _, segmentSize := range []int{
			1, 400, 1366, total - 1, total, total + 1,
			1 << 16, 1<<16 + 1, 70000, 1 << 20, // all wrap
		} {
			if segmentSize <= 0 {
				continue // covered by its own table row
			}
			if err := checkSegmentBatch(total, segmentSize, 0); err != nil {
				continue // refused, so it never reaches the narrowing
			}
			if got := int(uint16(segmentSize)); got != segmentSize {
				t.Fatalf("checkSegmentBatch(%d, %d, 0) accepted a segment size that "+
					"narrows to %d: the kernel would emit ceil(%d/%d)=%d datagrams "+
					"instead of %d, and the call would return success",
					total, segmentSize, got, total, got,
					segmentCount(total, got), segmentCount(total, segmentSize))
			}
		}
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

// TestMaxSegmentsPerSendIsTheLargestBatchWriteSegmentsAccepts pins the helper
// to checkSegmentBatch rather than to its own arithmetic: at each size the
// batch it reports must be accepted and one segment more must be refused.
// Asserting it against min(UDPMaxSegments, maxSegmentedPayloadBytes/size)
// would only restate the implementation, so a drift in either bound would move
// both sides together and assert nothing.
//
// The sizes are chosen so each bound binds on its own: at 400B the count binds
// (163 segments would fit in 65,507B, the kernel takes 128) and at 1366B the
// aggregate binds (128 segments would be 174,848B, the kernel takes 47). So
// dropping either arm of the min fails this test somewhere in the sweep.
func TestMaxSegmentsPerSendIsTheLargestBatchWriteSegmentsAccepts(t *testing.T) {
	for _, segmentSize := range []int{1, 2, 64, 400, 511, 512, 513, 1024, 1366, 1448, 8192, 32768, 65506, 65507} {
		n := MaxSegmentsPerSend(segmentSize)
		if n < 1 {
			t.Fatalf("MaxSegmentsPerSend(%d) = %d, want at least 1 -- "+
				"a size that fits the aggregate limit must allow one segment", segmentSize, n)
		}
		if err := checkSegmentBatch(n*segmentSize, segmentSize, 0); err != nil {
			t.Errorf("checkSegmentBatch rejected a full batch of %d x %dB = %dB: %v",
				n, segmentSize, n*segmentSize, err)
		}
		if err := checkSegmentBatch((n+1)*segmentSize, segmentSize, 0); err == nil {
			t.Errorf("checkSegmentBatch accepted %d x %dB = %dB, one segment past "+
				"MaxSegmentsPerSend(%d) = %d -- the helper understates the limit",
				n+1, segmentSize, (n+1)*segmentSize, segmentSize, n)
		}
	}
}

// TestMaxSegmentsPerSendRefusesUnsegmentableSizes covers the 0 return, which a
// caller must read as "do not segment" and not as a count: a non-positive size,
// and a size that alone exceeds the aggregate limit so that not even one
// segment fits.
func TestMaxSegmentsPerSendRefusesUnsegmentableSizes(t *testing.T) {
	for _, segmentSize := range []int{-1, 0, maxSegmentedPayloadBytes + 1, 1 << 20} {
		if n := MaxSegmentsPerSend(segmentSize); n != 0 {
			t.Errorf("MaxSegmentsPerSend(%d) = %d, want 0", segmentSize, n)
		}
	}
}
