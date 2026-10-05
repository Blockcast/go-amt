//go:build !linux

package amt

import (
	"fmt"
	"net"
	"runtime"
)

// enableGRO is unavailable off Linux: UDP_GRO is a Linux socket option with no
// portable equivalent. Callers read datagram-per-slot on ErrGROUnsupported, so
// this is a capability report, not a failure.
func enableGRO(pc net.PacketConn) error {
	return fmt.Errorf("%w: UDP_GRO is not available on %s", ErrGROUnsupported, runtime.GOOS)
}

// segmentSizeFromOOB reports no coalescing off Linux. 0 is the correct answer
// rather than a refusal: without UDP_GRO the kernel never coalesces, so every
// slot really does hold exactly one datagram.
func segmentSizeFromOOB(oob []byte) int { return 0 }
