package amt

import (
	"errors"
	"fmt"
)

// ErrSegmentsUnsupported reports that a segmented (UDP GSO) write cannot be
// attempted for this connection or this batch. It is the caller's signal to
// fall back to WriteBatch or per-datagram WriteTo; it never means the write
// half-happened. Every refusal below returns an error wrapping this sentinel,
// so callers select the fallback with errors.Is rather than by string match.
var ErrSegmentsUnsupported = errors.New("amt: segmented write unsupported")

// ErrSegmentsPartial reports that the kernel accepted only part of a segmented
// buffer. It is NOT retryable: the accepted prefix is already on the wire, so
// re-sending the same buffer would duplicate those datagrams on a live group.
// A caller seeing this must surface it, not fall back.
//
// No probe on kernel 6.18 has produced this — sendmsg(2) on a datagram socket
// is all-or-nothing — but the analogous partial accept on sendmmsg(2) is real
// (a count and an error can be returned together), so this is reported as its
// own condition rather than silently rounded to success.
var ErrSegmentsPartial = errors.New("amt: segmented write partially accepted")

const (
	// UDPMaxSegments is the kernel's cap on segments per GSO send. Measured on
	// the staging sender node (Talos, kernel 6.18) by bisecting the boundary:
	// 128 x 400B succeeded in one call, 129 x 400B returned EINVAL. Linux has
	// historically documented 64; do not substitute that value without
	// re-measuring.
	//
	// A kernel whose real cap is lower stays correct: its EINVAL is classified
	// as ErrSegmentsUnsupported and the caller falls back, with nothing on the
	// wire either time. But it is not free -- every batch above its real cap
	// then pays a doomed syscall before falling back, which is the per-packet
	// syscall cost this whole path exists to remove. That is why
	// TestUDPMaxSegmentsMatchesKernel asserts this value against the running
	// kernel in both directions and fails rather than skipping: a silently
	// overstated cap is a permanent slow path that no other test can see.
	UDPMaxSegments = 128

	// maxSegmentedPayloadBytes is the total size a single segmented send may
	// carry: the 16-bit IPv4 total-length field minus the headers the kernel
	// accounts against the aggregate, i.e. 65535 - 20 (IP) - 8 (UDP) = 65507.
	// It is written against udpIPv4HeaderOverhead because it is the same 28
	// bytes for the same reason, so a correction to one must move the other.
	//
	// Bisected against the running kernel at segment sizes 512, 1024 and 1366:
	// 65507 accepted, 65508 EMSGSIZE, identically at all three -- so the bound
	// is on the aggregate buffer, not on how it is segmented.
	//
	// Overstating this costs exactly what overstating UDPMaxSegments costs:
	// correctness is unaffected (the kernel's EMSGSIZE is classified as
	// ErrSegmentsUnsupported and nothing reaches the wire either time), but
	// every batch above the real ceiling pays a doomed syscall before falling
	// back, which is the per-packet syscall cost this path exists to remove.
	// The table tests express their bounds in terms of this constant and so
	// move with it; TestMaxSegmentedPayloadBytesMatchesKernel is what pins it
	// to the kernel in both directions, and it fails rather than skipping.
	maxSegmentedPayloadBytes = 65535 - udpIPv4HeaderOverhead

	// udpIPv4HeaderOverhead is the IPv4 (20) + UDP (8) header cost added to each
	// emitted segment. A segment of exactly MTU-28 succeeded in probing; one
	// byte more returned EMSGSIZE.
	udpIPv4HeaderOverhead = 28
)

// segmentCount returns how many datagrams the kernel emits for a buffer of
// total bytes at segmentSize, i.e. ceil(total/segmentSize). GSO requires every
// segment to be segmentSize except the last, which may be shorter; a trailing
// short segment costs no extra call.
func segmentCount(total, segmentSize int) int {
	if segmentSize <= 0 || total <= 0 {
		return 0
	}
	n := total / segmentSize
	if total%segmentSize != 0 {
		n++
	}
	return n
}

// checkSegmentBatch rejects a batch the kernel would refuse anyway, so the
// caller can fall back without paying for a doomed syscall.
//
// This is an optimization, not the correctness boundary. The kernel remains the
// authority: a rejected segmented sendmsg emits zero frames (measured), so
// falling back after an EMSGSIZE/EINVAL cannot duplicate traffic. That is why
// an unknown mtu (<= 0) skips the per-segment check rather than refusing the
// batch -- guessing an MTU would decline sends the kernel would have accepted.
func checkSegmentBatch(total, segmentSize, mtu int) error {
	if segmentSize <= 0 {
		return fmt.Errorf("%w: segment size %d must be positive", ErrSegmentsUnsupported, segmentSize)
	}
	if total <= 0 {
		return fmt.Errorf("%w: nothing to send", ErrSegmentsUnsupported)
	}
	if total > maxSegmentedPayloadBytes {
		return fmt.Errorf("%w: %d bytes exceeds the %d-byte limit",
			ErrSegmentsUnsupported, total, maxSegmentedPayloadBytes)
	}
	// Ordering is load-bearing. total is now known to fit in 16 bits, so
	// refusing a segment larger than the buffer is also what keeps the
	// uint16(segmentSize) narrowing in writeSegments lossless -- and that
	// narrowing is the one place an out-of-range value changes the wire
	// silently instead of erroring: segmentSize 70000 wraps to 4464, so the
	// kernel emits 15 datagrams where the caller asked for one, and the call
	// returns success. The mtu check above cannot be relied on to catch it,
	// because an unknown mtu skips that check by design.
	//
	// Refusing costs nothing real: a segment larger than the buffer is a
	// degenerate GSO request either way -- the caller wanted a single
	// datagram, which the fallback sends directly.
	if segmentSize > total {
		return fmt.Errorf("%w: segment size %d exceeds the %d-byte buffer",
			ErrSegmentsUnsupported, segmentSize, total)
	}
	if mtu > 0 && segmentSize+udpIPv4HeaderOverhead > mtu {
		return fmt.Errorf("%w: segment %d + %d header exceeds mtu %d",
			ErrSegmentsUnsupported, segmentSize, udpIPv4HeaderOverhead, mtu)
	}
	if n := segmentCount(total, segmentSize); n > UDPMaxSegments {
		return fmt.Errorf("%w: %d segments exceeds the %d-segment limit",
			ErrSegmentsUnsupported, n, UDPMaxSegments)
	}
	return nil
}
