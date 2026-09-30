//go:build !linux

package amt

import (
	"fmt"
	"net"
	"runtime"

	"golang.org/x/net/ipv4"
)

// writeSegments is unavailable off Linux: UDP_SEGMENT is a Linux socket option
// with no portable equivalent. Callers fall back to WriteBatch or per-datagram
// WriteTo on ErrSegmentsUnsupported, so this is a capability report, not a
// failure.
func writeSegments(pc *ipv4.PacketConn, b []byte, segmentSize int, oob []byte, dst *net.UDPAddr) (int, error) {
	return 0, fmt.Errorf("%w: UDP_SEGMENT is not available on %s", ErrSegmentsUnsupported, runtime.GOOS)
}
