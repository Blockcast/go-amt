//go:build linux && !android && cgo && !purego

// Tagged exactly like gso_linux_test.go, whose loopbackPair these tests reuse.
// A bare `linux` tag also selects android -- the GOOS satisfies that
// constraint -- which puts this file in the mobile typecheck job without the
// file that defines the helper, so `GOOS=android go vet` fails to compile the
// package. Keeping the two tag sets identical is what lets the helper be
// shared instead of copied.

package amt

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// TestGROControlMessageLenMatchesTheABI checks the literal 24 against the
// kernel ABI rather than against another copy of itself, exactly as
// TestTimestampControlMessageLenMatchesTheABI does for the SOL_SOCKET term.
//
// GROControlMessageLen has to be a plain constant for the same reason: the
// option is IPPROTO_UDP, so there is no x/net control-flag accessor to compute
// it from. Over-allocating is the only safe direction, so this failing on a
// 32-bit ABI is correct -- the constant would genuinely be wrong there.
func TestGROControlMessageLenMatchesTheABI(t *testing.T) {
	if got := unix.CmsgSpace(groCmsgPayloadBytes); got != GROControlMessageLen {
		t.Errorf("the UDP_GRO cmsg occupies CmsgSpace(%d) = %d, but "+
			"GROControlMessageLen is %d. ControlMessageOOBLen is built from that "+
			"constant, so every caller's OOB buffer is off by %d bytes per slot "+
			"-- and a short one is silent: MSG_CTRUNC, Dst dropped, group filter "+
			"discards everything",
			groCmsgPayloadBytes, got, GROControlMessageLen, got-GROControlMessageLen)
	}
}

// TestGROCmsgPayloadIsFourBytes pins groCmsgPayloadBytes against the C type the
// kernel reports the segment size with.
//
// udp_cmsg_recv does put_cmsg(..., sizeof(gso_size), &gso_size) on an `int`, so
// the receive payload is sizeof(int) -- NOT the uint16 the send side sets
// UDP_SEGMENT with. That asymmetry is the whole hazard: reading 2 bytes gives
// the right answer on little-endian for every segment size under 65536 and the
// wrong one on big-endian, so no amd64 test run would ever show it.
// TestGROReadsCoalescedSegmentsOverLoopback measures the width against the
// running kernel; this one only guards the constant against being edited to 2.
//
// It is deliberately not a measurement, and the distinction is worth keeping
// straight: unsafe.Sizeof(int32(0)) is 4 on every Go platform by language
// definition, so unlike control_oob_len_abi_test.go's unix.Timespec{} -- whose
// width genuinely moves between ABIs -- this cannot vary by target. No
// measurement is available to write instead. C int is 4 bytes on both ILP32 and
// LP64, so there is no Go-reachable Linux ABI where groCmsgPayloadBytes should
// differ, and nothing in Go tracks the C type to assert against.
func TestGROCmsgPayloadIsFourBytes(t *testing.T) {
	if got := int(unsafe.Sizeof(int32(0))); got != groCmsgPayloadBytes {
		t.Errorf("the kernel reports gso_size as an int (%d bytes), but "+
			"groCmsgPayloadBytes is %d", got, groCmsgPayloadBytes)
	}
}

// groDial returns a receiving *net.UDPConn and a sender, reusing the existing
// loopbackPair rather than a second copy of it. The receiver is re-typed
// because the GRO tests need ReadMsgUDP, which net.PacketConn does not carry.
func groDial(t *testing.T) (rx *net.UDPConn, tx *ipv4.PacketConn, dst *net.UDPAddr) {
	t.Helper()
	pc, tx, dst := loopbackPair(t)
	rx, ok := pc.(*net.UDPConn)
	if !ok {
		t.Fatalf("loopbackPair receiver is %T, not *net.UDPConn", pc)
	}
	return rx, tx, dst
}

// sendGSO writes b to dst as one segmented sendmsg. It goes through the
// package's own writeSegments so the test exercises the real send path rather
// than a second hand-built cmsg -- the receive side is what is under test, and
// a bug shared by both would otherwise cancel out.
func sendGSO(t *testing.T, tx *ipv4.PacketConn, b []byte, segmentSize int, dst *net.UDPAddr) {
	t.Helper()
	n, err := writeSegments(tx, b, segmentSize, nil, dst)
	if err != nil {
		t.Fatalf("segmented send of %d bytes at %d: %v", len(b), segmentSize, err)
	}
	if n != len(b) {
		t.Fatalf("segmented send accepted %d of %d bytes", n, len(b))
	}
}

// readSlot performs one recvmsg with an OOB buffer sized the way a caller is
// told to size it, and returns the payload and the parsed segment size.
func readSlot(t *testing.T, rx *net.UDPConn) ([]byte, int) {
	t.Helper()
	if err := rx.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	p := make([]byte, 65535)
	// Exactly what ControlMessageOOBLen promises a caller is enough. Sizing the
	// test's buffer generously instead would hide the term this change added.
	oob := make([]byte, ControlMessageOOBLen())
	n, oobn, flags, _, err := rx.ReadMsgUDP(p, oob)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		t.Fatalf("kernel set MSG_CTRUNC on a buffer of ControlMessageOOBLen() = %d, "+
			"so a cmsg was dropped. This is the silent-truncation failure the "+
			"exported length exists to prevent", ControlMessageOOBLen())
	}
	return p[:n], SegmentSize(oob[:oobn])
}

// TestGROReadsCoalescedSegmentsOverLoopback is the end-to-end check: a block
// sent as one segmented sendmsg must come back coalesced, with a segment size
// that frames it back into the datagrams that were sent.
//
// The short trailing datagram is the case worth having: GRO permits the last
// segment to be shorter, so a walker using the segment size as a fixed stride
// has to clamp the final chunk. A block of 12 equal datagrams alone would pass
// against a walker that reads past the end of the buffer on the last one.
func TestGROReadsCoalescedSegmentsOverLoopback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		segment int
		full    int // number of full-size datagrams
		tail    int // bytes in the short trailing datagram, 0 for none
	}{
		{"block of 12, exact", 400, 12, 0},
		{"block of 12 plus a short last", 400, 12, 137},
		{"single segment size, short last", 1366, 5, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx, tx, dst := groDial(t)
			if err := enableGRO(rx); err != nil {
				if errors.Is(err, ErrGROUnsupported) {
					t.Skipf("UDP_GRO unavailable here: %v", err)
				}
				t.Fatalf("enable gro: %v", err)
			}

			total := tc.segment*tc.full + tc.tail
			b := make([]byte, total)
			for i := range b {
				b[i] = byte(i)
			}
			sendGSO(t, tx, b, tc.segment, dst)

			// Read until the whole block is accounted for. Coalescing is a
			// kernel decision, not a guarantee -- it may hand back one slot or
			// several -- so the assertion is on the FRAMING of whatever comes
			// back, not on the slot count. Asserting one slot would make this
			// test fail on a correct kernel that chose to split.
			var got []byte
			slots := 0
			for len(got) < total {
				payload, seg := readSlot(t, rx)
				slots++
				switch {
				case seg == SegmentSizeUnreadable:
					t.Fatalf("slot %d: SegmentSize reported the GRO cmsg unreadable", slots)
				case seg == 0:
					// No coalescing on this slot: it is exactly one datagram.
					if len(payload) > tc.segment {
						t.Fatalf("slot %d carries %d bytes with no GRO cmsg, but a "+
							"single datagram here is at most %d. The slot was "+
							"coalesced and the segment size was lost, so a caller "+
							"would read several datagrams as one",
							slots, len(payload), tc.segment)
					}
				default:
					if seg != tc.segment {
						t.Fatalf("slot %d: SegmentSize = %d, want the %d the sender "+
							"segmented at", slots, seg, tc.segment)
					}
					// Every segment but the last must be exactly seg bytes, so
					// an interior short one means the framing is wrong.
					for off := 0; off < len(payload); off += seg {
						end := min(off+seg, len(payload))
						if end-off != seg && end != len(payload) {
							t.Fatalf("slot %d: interior segment at %d is %d bytes, not %d",
								slots, off, end-off, seg)
						}
					}
				}
				got = append(got, payload...)
				if slots > tc.full+2 {
					t.Fatalf("read %d slots for %d datagrams without reassembling "+
						"%d bytes (have %d)", slots, tc.full, total, len(got))
				}
			}

			if len(got) != total {
				t.Fatalf("reassembled %d bytes, sent %d", len(got), total)
			}
			for i := range got {
				if got[i] != byte(i) {
					t.Fatalf("payload differs at byte %d: got %d, want %d", i, got[i], byte(i))
				}
			}
			t.Logf("%d bytes in %d datagrams arrived in %d slot(s)", total, tc.full+btoi(tc.tail > 0), slots)
		})
	}
}

// TestGRODisabledDeliversOneDatagramPerSlot is the control for the test above.
// Without it a SegmentSize that always returned 0 would pass every assertion
// there -- the reassembly loop accepts uncoalesced slots by design -- so this
// is what makes the coalescing claim falsifiable: the same traffic on a socket
// with GRO off must arrive as separate slots, which is only observable as a
// difference against the enabled run.
func TestGRODisabledDeliversOneDatagramPerSlot(t *testing.T) {
	rx, tx, dst := groDial(t)
	// Deliberately no enableGRO.

	const segment, full = 400, 12
	b := make([]byte, segment*full)
	sendGSO(t, tx, b, segment, dst)

	for i := range full {
		payload, seg := readSlot(t, rx)
		if seg != 0 {
			t.Fatalf("slot %d reported segment size %d on a socket with GRO off; "+
				"the kernel only attaches that cmsg when it coalesced", i, seg)
		}
		if len(payload) != segment {
			t.Fatalf("slot %d carries %d bytes, want one %d-byte datagram",
				i, len(payload), segment)
		}
	}
}

// TestEnableGROIsObservableOnTheSocket pins that EnableGRO's success actually
// reached the socket, rather than the call merely returning nil. Without this
// an enableGRO that did nothing at all would still let the loopback test above
// pass on any kernel that happened not to coalesce.
func TestEnableGROIsObservableOnTheSocket(t *testing.T) {
	rx, _, _ := groDial(t)
	if err := enableGRO(rx); err != nil {
		if errors.Is(err, ErrGROUnsupported) {
			t.Skipf("UDP_GRO unavailable here: %v", err)
		}
		t.Fatalf("enable gro: %v", err)
	}
	rc, err := rx.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	var v int
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		v, opErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
	}); err != nil {
		t.Fatalf("control: %v", err)
	}
	if opErr != nil {
		t.Fatalf("getsockopt UDP_GRO: %v", opErr)
	}
	if v != 1 {
		t.Errorf("UDP_GRO reads back %d after EnableGRO, want 1", v)
	}
}

// TestEnableGROOnNonUDPIsUnsupported pins the fallback classification: a
// connection with no UDP socket behind it must report ErrGROUnsupported so the
// caller keeps reading datagram-per-slot, not a bare error it would surface.
func TestEnableGROOnNonUDPIsUnsupported(t *testing.T) {
	err := enableGRO(notAUDPConn{})
	if !errors.Is(err, ErrGROUnsupported) {
		t.Errorf("enableGRO on a non-UDP conn = %v, want an error wrapping "+
			"ErrGROUnsupported so errors.Is selects the fallback", err)
	}
}

// TestSegmentSizeReadsTheLiveKernelLayout builds the UDP_GRO cmsg the way the
// kernel does and checks SegmentSize against it, including a value that would
// be read wrong by a 2-byte parse. The loopback test cannot reach this: the
// kernel will not coalesce at a segment size above 65535, so the one input that
// distinguishes a 4-byte read from a 2-byte one is only constructible here.
func TestSegmentSizeReadsTheLiveKernelLayout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value int32
		want  int
	}{
		{"typical segment size", 1366, 1366},
		{"small segment size", 400, 400},
		// 65536 is 0x00010000: its low 16 bits are zero, so a uint16 read
		// returns 0 and a caller using that as a stride hangs rather than
		// mis-framing. This is the input that proves the width.
		{"above the 16-bit range", 65536, 65536},
		{"kernel reported nothing usable", 0, SegmentSizeUnreadable},
		{"kernel reported a negative size", -1, SegmentSizeUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SegmentSize(groCmsg(tc.value)); got != tc.want {
				t.Errorf("SegmentSize(gso_size=%d) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

// TestSegmentSizeIgnoresUnrelatedControlMessages pins that the walk selects on
// level AND type. A real slot carries IP_PKTINFO and often a timestamp
// alongside, and matching on type alone would read one of those as a segment
// size -- SCM_TIMESTAMPNS is SOL_SOCKET type 35, but IP_PKTINFO is IPPROTO_IP
// type 8 and nothing stops a future UDP type colliding with an IP one.
func TestSegmentSizeIgnoresUnrelatedControlMessages(t *testing.T) {
	// Same type number, wrong level.
	wrongLevel := groCmsg(1366)
	(*unix.Cmsghdr)(unsafe.Pointer(&wrongLevel[0])).Level = unix.IPPROTO_IP
	if got := SegmentSize(wrongLevel); got != 0 {
		t.Errorf("SegmentSize read a cmsg at IPPROTO_IP as a segment size (%d); "+
			"the walk must select on level as well as type", got)
	}

	// Right level, wrong type.
	wrongType := groCmsg(1366)
	(*unix.Cmsghdr)(unsafe.Pointer(&wrongType[0])).Type = unix.UDP_SEGMENT
	if got := SegmentSize(wrongType); got != 0 {
		t.Errorf("SegmentSize read a UDP_SEGMENT cmsg as a GRO segment size (%d)", got)
	}

	// Present, but behind an unrelated cmsg: the walk must not stop at the
	// first entry.
	prefixed := append(timestampCmsg(), groCmsg(1366)...)
	if got := SegmentSize(prefixed); got != 1366 {
		t.Errorf("SegmentSize = %d with the GRO cmsg second in the buffer, want 1366; "+
			"a real slot always carries IP_PKTINFO first", got)
	}
}

// TestSegmentSizeOnAbsentAndMalformedBuffers pins the two answers that are not
// a size, and they are different answers on purpose: 0 frames the slot as one
// datagram, SegmentSizeUnreadable refuses to frame it at all.
func TestSegmentSizeOnAbsentAndMalformedBuffers(t *testing.T) {
	if got := SegmentSize(nil); got != 0 {
		t.Errorf("SegmentSize(nil) = %d, want 0 -- no cmsg means one datagram", got)
	}
	if got := SegmentSize(timestampCmsg()); got != 0 {
		t.Errorf("SegmentSize with only unrelated cmsgs = %d, want 0", got)
	}
	// A header claiming more payload than the buffer holds. ParseSocketControlMessage
	// rejects it, and the refusal must not degrade to 0.
	truncated := groCmsg(1366)
	truncated = truncated[:len(truncated)-8]
	if got := SegmentSize(truncated); got != SegmentSizeUnreadable {
		t.Errorf("SegmentSize on a truncated control buffer = %d, want "+
			"SegmentSizeUnreadable (%d). Returning 0 would frame a coalesced "+
			"slot as a single oversized datagram with no error anywhere",
			got, SegmentSizeUnreadable)
	}
}

// groCmsg builds one UDP_GRO control message carrying v, laid out the way
// put_cmsg does.
func groCmsg(v int32) []byte {
	b := make([]byte, unix.CmsgSpace(groCmsgPayloadBytes))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_GRO
	h.SetLen(unix.CmsgLen(groCmsgPayloadBytes))
	binary.NativeEndian.PutUint32(b[unix.CmsgLen(0):], uint32(v))
	return b
}

// timestampCmsg builds a plausible unrelated control message for the walk tests.
func timestampCmsg() []byte {
	b := make([]byte, unix.CmsgSpace(16))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = unix.SOL_SOCKET
	h.Type = unix.SCM_TIMESTAMPNS
	h.SetLen(unix.CmsgLen(16))
	return b
}

type notAUDPConn struct{ net.PacketConn }

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
