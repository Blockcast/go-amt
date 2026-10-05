//go:build linux

package amt

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// groCmsgPayloadBytes is the size of the UDP_GRO control message payload the
// kernel emits on a coalesced datagram.
//
// 4, not 2, and the asymmetry with the send side is the trap this constant
// exists to name: UDP_SEGMENT is set with a uint16 (see appendUDPSegmentCmsg),
// but udp_cmsg_recv reports the size back with `int gso_size`, so the receive
// payload is sizeof(int). Reading it as a uint16 yields the right answer on a
// little-endian machine for every segment size under 65536 and the wrong one on
// big-endian, which is the sort of bug that survives every test run on amd64.
//
// Measured against the running kernel by TestGROCmsgPayloadIsFourBytes rather
// than trusted: a payload-width change would otherwise be read as a segment
// size silently.
const groCmsgPayloadBytes = 4

// enableGRO sets UDP_GRO on pc's underlying socket, so the kernel coalesces
// consecutive same-size datagrams from one source into a single read.
//
// It takes net.PacketConn rather than *ipv4.PacketConn because UDP_GRO is an
// IPPROTO_UDP option with no address-family component: the v4 and v6 sockets
// take it identically, and both x/net wrappers expose the underlying conn as a
// net.PacketConn. Nothing here needs to know which family it has.
func enableGRO(pc net.PacketConn) error {
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("%w: underlying conn is %T, not *net.UDPConn", ErrGROUnsupported, pc)
	}
	rc, err := udp.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	}); err != nil {
		return err
	}
	if opErr != nil {
		// ENOPROTOOPT is a kernel too old to know the option; EOPNOTSUPP is a
		// path that cannot do it. Both mean "read datagram-per-slot", which is
		// the behaviour the socket already has, so the socket is left usable
		// and the caller just does not walk segments.
		return fmt.Errorf("%w: %v", ErrGROUnsupported, opErr)
	}
	return nil
}

// segmentSizeFromOOB walks one slot's control buffer for the UDP_GRO cmsg.
// See SegmentSize in gro.go for the contract; this is only the parse.
func segmentSizeFromOOB(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		// A buffer that does not parse cannot be shown to be free of a GRO
		// cmsg, and "no cmsg" is the answer that frames the slot as a single
		// datagram. Refusing is the safe direction; see SegmentSizeUnreadable.
		return SegmentSizeUnreadable
	}
	for _, c := range cmsgs {
		if c.Header.Level != unix.IPPROTO_UDP || c.Header.Type != unix.UDP_GRO {
			continue
		}
		if len(c.Data) < groCmsgPayloadBytes {
			return SegmentSizeUnreadable
		}
		n := int(int32(binary.NativeEndian.Uint32(c.Data[:groCmsgPayloadBytes])))
		if n <= 0 {
			// The kernel does not emit this -- the cmsg exists because a
			// coalesce happened, so the size is positive. Refusing rather than
			// returning it keeps a non-positive value from reaching a caller
			// that would use it as a loop stride, where 0 does not misbehave,
			// it hangs.
			return SegmentSizeUnreadable
		}
		return n
	}
	return 0
}
