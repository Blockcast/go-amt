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
	// re-measuring, and note that a kernel with a lower cap still fails closed
	// via the EINVAL retry path rather than emitting a short batch.
	UDPMaxSegments = 128

	// maxSegmentedPayloadBytes is the total size a single segmented send may
	// carry, bounded by the 16-bit IP payload length. Measured: 45 x 1366 =
	// 61470B succeeded, 48 x 1366 = 65568B returned EMSGSIZE.
	maxSegmentedPayloadBytes = 65535

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
