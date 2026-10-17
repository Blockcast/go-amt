//go:build linux

package amt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
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
	// oob[:off:off] caps the slice at its length so append must allocate and
	// copy instead of writing into whatever backing array the caller owns.
	// Every caller today passes a fresh cm.Marshal(), but this function takes
	// oob with no stated ownership contract, and the natural optimization on
	// this path -- hoisting a scratch oob out of a per-block send loop, which
	// is exactly the sort of per-packet allocation one-syscall sends exist to
	// remove -- would otherwise have it scribble the UDP cmsg into a buffer
	// the caller reuses.
	return putUDPSegmentCmsg(oob[:off:off], segmentSize)
}

// putUDPSegmentCmsg is appendUDPSegmentCmsg for a caller that owns dst's spare
// capacity: it appends in place, so a reused scratch costs no allocation once
// it has grown. segSend is that caller (BLO-47267).
func putUDPSegmentCmsg(dst []byte, segmentSize uint16) []byte {
	off := len(dst)
	dst = append(dst, make([]byte, unix.CmsgSpace(2))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&dst[off]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(dst[off+unix.CmsgLen(0):], segmentSize)
	return dst
}

// writeSegments performs the segmented sendmsg(2) on pc's underlying socket.
//
// oob must already carry the IP-level control message; the UDP_SEGMENT cmsg is
// appended here. The write goes through RawConn.Write rather than a bare
// unix.SendmsgN so it keeps the runtime's poller semantics: write deadlines are
// honoured and EAGAIN blocks for writability instead of surfacing as an error.
func writeSegments(pc *ipv4.PacketConn, b []byte, segmentSize int, oob []byte, dst *net.UDPAddr) (int, error) {
	return sendSegments(pc, b, segmentSize, oob, nil, dst)
}

// writeSegmentsCM is writeSegments with the IP-level control message given
// unmarshalled. Its marshalled bytes are cached on the pooled segSend and
// reused while cm's fields are unchanged, which is every send of a channel's
// hoisted control message: cm.Marshal allocated a fresh buffer per call
// (BLO-47267).
func writeSegmentsCM(pc *ipv4.PacketConn, b []byte, segmentSize int, cm *ipv4.ControlMessage, dst *net.UDPAddr) (int, error) {
	return sendSegments(pc, b, segmentSize, nil, cm, dst)
}

// sendSegments is the shared body. oob, if any, is the caller's marshalled
// IP-level control message; cm, if non-nil, is marshalled through the cache
// instead. At most one of them is set.
func sendSegments(pc *ipv4.PacketConn, b []byte, segmentSize int, oob []byte, cm *ipv4.ControlMessage, dst *net.UDPAddr) (int, error) {
	udp, ok := pc.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, fmt.Errorf("%w: underlying conn is %T, not *net.UDPConn", ErrSegmentsUnsupported, pc.PacketConn)
	}
	ip := dst.IP.To4()
	if ip == nil {
		return 0, fmt.Errorf("%w: destination %s is not IPv4", ErrSegmentsUnsupported, dst.IP)
	}
	s := takeSegSend()
	defer s.put()
	if s.udp != udp {
		rc, err := udp.SyscallConn()
		if err != nil {
			return 0, err
		}
		s.udp, s.rc = udp, rc
	}
	s.sa = unix.SockaddrInet4{Port: dst.Port}
	copy(s.sa.Addr[:], ip)
	if cm != nil {
		oob = s.marshalCM(cm)
	}
	s.oob = putUDPSegmentCmsg(append(s.oob[:0], oob...), uint16(segmentSize))
	s.b = b
	if err := s.rc.Write(s.fn); err != nil {
		return 0, err
	}
	return classifySendResult(s.n, len(b), s.opErr)
}

// segSend is one segmented send's state, pooled (BLO-47267). Built per call,
// the destination sockaddr, the cmsg buffer, the RawConn and the write
// closure with its two captured results were nine allocations per DS 74 block
// on the sender's hottest loop. Pooled, they are none once warm: fn is bound
// to its segSend once, at construction, and every other field is overwritten
// before the send reads it.
//
// rc is cached against the *net.UDPConn it came from. SyscallConn returns an
// immutable wrapper of that conn's fd, so reusing it for the same conn is the
// same call; a different conn takes a new one.
type segSend struct {
	udp   *net.UDPConn
	rc    syscall.RawConn
	sa    unix.SockaddrInet4
	oob   []byte
	b     []byte
	n     int
	opErr error
	fn    func(fd uintptr) bool

	// The last control message marshalled, and the fields it was marshalled
	// from. Compared byte for byte, so a changed source or interface is
	// re-marshalled rather than sent stale.
	cmOOB        []byte
	cmTTL, cmIf  int
	cmSrc, cmDst []byte
	cmValid      bool
}

func (s *segSend) marshalCM(cm *ipv4.ControlMessage) []byte {
	if !s.cmValid || cm.TTL != s.cmTTL || cm.IfIndex != s.cmIf ||
		!bytes.Equal(cm.Src, s.cmSrc) || !bytes.Equal(cm.Dst, s.cmDst) {
		s.cmOOB = append(s.cmOOB[:0], cm.Marshal()...)
		s.cmTTL, s.cmIf = cm.TTL, cm.IfIndex
		s.cmSrc = append(s.cmSrc[:0], cm.Src...)
		s.cmDst = append(s.cmDst[:0], cm.Dst...)
		s.cmValid = true
	}
	return s.cmOOB
}

var segSends sync.Pool

func takeSegSend() *segSend {
	if s, _ := segSends.Get().(*segSend); s != nil {
		return s
	}
	s := new(segSend)
	s.fn = s.write
	return s
}

// write is the RawConn.Write callback. false parks until the socket is
// writable and calls back.
func (s *segSend) write(fd uintptr) bool {
	s.n, s.opErr = unix.SendmsgN(int(fd), s.b, s.oob, &s.sa, 0)
	return !retrySegmentedSend(s.opErr)
}

// put drops the payload and the result before pooling, so a pooled segSend
// pins neither the caller's buffer nor an error.
func (s *segSend) put() {
	s.b, s.n, s.opErr = nil, 0, nil
	segSends.Put(s)
}

// retrySegmentedSend reports whether a sendmsg outcome should be reissued
// rather than surfaced. It is split out for the same reason classifySendResult
// is: the decision is not observable through a real socket (EAGAIN needs a full
// send buffer, EINTR needs a signal landing mid-call), so a table test is the
// only way to assert it.
//
// Both cases are safe to reissue because sendmsg(2) on a datagram socket is
// all-or-nothing: neither put a byte on the wire, so a retry cannot duplicate.
// EINTR is included because unix.SendmsgN is a bare syscall wrapper, not one of
// internal/poll's own send paths, so nothing else retries it -- and without this
// a signal mid-send surfaces as a bare error that does not wrap
// ErrSegmentsUnsupported, so the caller fails the send instead of falling back.
// Rare (Go installs its handlers with SA_RESTART), but free to close.
func retrySegmentedSend(opErr error) bool {
	return errors.Is(opErr, unix.EAGAIN) || errors.Is(opErr, unix.EINTR)
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
