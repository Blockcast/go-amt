//go:build linux

package amt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// appendUDPSegmentCmsg appends a SOL_UDP/UDP_SEGMENT control message carrying
// segmentSize to oob and returns the grown buffer.
//
// This is the whole reason a segmented write cannot be expressed through
// x/net's ipv4.ControlMessage: that type marshals IP-level options only, and
// UDP_SEGMENT sits at IPPROTO_UDP. The IP-level half (IP_PKTINFO, giving the
// source address and egress interface) still comes from cm.Marshal(); this
// function only adds the UDP-level cmsg alongside it.
func appendUDPSegmentCmsg(oob []byte, segmentSize uint16) []byte {
	off := len(oob)
	oob = append(oob, make([]byte, unix.CmsgSpace(2))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[off]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[off+unix.CmsgLen(0):], segmentSize)
	return oob
}

// writeSegments performs the segmented sendmsg(2) on pc's underlying socket.
//
// oob must already carry the IP-level control message; the UDP_SEGMENT cmsg is
// appended here. The write goes through RawConn.Write rather than a bare
// unix.SendmsgN so it keeps the runtime's poller semantics: write deadlines are
// honoured and EAGAIN blocks for writability instead of surfacing as an error.
func writeSegments(pc *ipv4.PacketConn, b []byte, segmentSize int, oob []byte, dst *net.UDPAddr) (int, error) {
	udp, ok := pc.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, fmt.Errorf("%w: underlying conn is %T, not *net.UDPConn", ErrSegmentsUnsupported, pc.PacketConn)
	}
	ip := dst.IP.To4()
	if ip == nil {
		return 0, fmt.Errorf("%w: destination %s is not IPv4", ErrSegmentsUnsupported, dst.IP)
	}
	sa := &unix.SockaddrInet4{Port: dst.Port}
	copy(sa.Addr[:], ip)

	rc, err := udp.SyscallConn()
	if err != nil {
		return 0, err
	}
	oob = appendUDPSegmentCmsg(oob, uint16(segmentSize))

	var n int
	var opErr error
	if err := rc.Write(func(fd uintptr) bool {
		n, opErr = unix.SendmsgN(int(fd), b, oob, sa, 0)
		// false parks until the socket is writable and calls back.
		return !errors.Is(opErr, unix.EAGAIN)
	}); err != nil {
		return 0, err
	}
	return classifySendResult(n, len(b), opErr)
}

// classifySendResult maps a segmented sendmsg outcome onto the caller contract.
// It is split out because one of its two branches cannot be reached through a
// real socket: sendmsg(2) on a datagram socket is all-or-nothing, so no kernel
// produces the short accept that ErrSegmentsPartial reports. Keeping the
// classification pure is what lets that branch be tested at all -- and it must
// be tested, because getting it wrong is the difference between surfacing a
// partial send and silently duplicating the accepted datagrams on a live group.
func classifySendResult(n, total int, opErr error) (int, error) {
	if opErr != nil {
		// EMSGSIZE (total or per-segment too large) and EINVAL (too many
		// segments, or no GSO support on this path) are both refusals, and a
		// refused segmented sendmsg emits zero frames -- measured by bisecting
		// each boundary on the staging sender, and re-asserted against the
		// running kernel by TestWriteSegmentsRejectionEmitsNothing. Marking
		// them retryable is what makes the fallback duplicate-free.
		if errors.Is(opErr, unix.EMSGSIZE) || errors.Is(opErr, unix.EINVAL) {
			return 0, fmt.Errorf("%w: %v", ErrSegmentsUnsupported, opErr)
		}
		return 0, opErr
	}
	if n != total {
		return n, fmt.Errorf("%w: accepted %d of %d bytes", ErrSegmentsPartial, n, total)
	}
	return n, nil
}
