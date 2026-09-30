//go:build linux

package amt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// loopbackPair returns a receiving socket and an ipv4.PacketConn to send from.
// The sender binds the wildcard address so a control message may override the
// source address; tests that do not set one are unaffected.
func loopbackPair(t *testing.T) (net.PacketConn, *ipv4.PacketConn, *net.UDPAddr) {
	t.Helper()
	rx, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen rx: %v", err)
	}
	t.Cleanup(func() { rx.Close() })
	tx, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen tx: %v", err)
	}
	t.Cleanup(func() { tx.Close() })
	return rx, ipv4.NewPacketConn(tx), rx.LocalAddr().(*net.UDPAddr)
}

// readDatagrams drains exactly want datagrams, then asserts none follow.
func readDatagrams(t *testing.T, rx net.PacketConn, want int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, want)
	buf := make([]byte, 1<<16)
	for i := 0; i < want; i++ {
		if err := rx.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		n, _, err := rx.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d of %d: %v", i, want, err)
		}
		out = append(out, append([]byte(nil), buf[:n]...))
	}
	assertNoMoreDatagrams(t, rx)
	return out
}

func assertNoMoreDatagrams(t *testing.T, rx net.PacketConn) {
	t.Helper()
	if err := rx.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	buf := make([]byte, 1<<16)
	n, _, err := rx.ReadFrom(buf)
	if err == nil {
		t.Fatalf("unexpected extra datagram of %d bytes", n)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("want a read timeout, got %v", err)
	}
}

// TestAppendUDPSegmentCmsg pins the wire form of the control message, parsed
// back through the kernel's own header layout. This is the piece that cannot
// be expressed via ipv4.ControlMessage, so nothing else would catch a wrong
// level, type, or length -- the kernel would simply ignore an unrecognised
// cmsg and emit one jumbo datagram instead of N, which looks like success.
func TestAppendUDPSegmentCmsg(t *testing.T) {
	got := appendUDPSegmentCmsg(nil, 1366)
	msgs, err := unix.ParseSocketControlMessage(got)
	if err != nil {
		t.Fatalf("ParseSocketControlMessage: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d control messages, want 1", len(msgs))
	}
	h := msgs[0].Header
	if h.Level != unix.IPPROTO_UDP {
		t.Errorf("Level = %d, want IPPROTO_UDP (%d)", h.Level, unix.IPPROTO_UDP)
	}
	if h.Type != unix.UDP_SEGMENT {
		t.Errorf("Type = %d, want UDP_SEGMENT (%d)", h.Type, unix.UDP_SEGMENT)
	}
	if int(h.Len) != unix.CmsgLen(2) {
		t.Errorf("Len = %d, want CmsgLen(2) = %d", h.Len, unix.CmsgLen(2))
	}
	if v := binary.NativeEndian.Uint16(msgs[0].Data); v != 1366 {
		t.Errorf("segment size = %d, want 1366", v)
	}
}

// TestAppendUDPSegmentCmsgPreservesExisting proves the UDP cmsg is appended
// beside the IP-level one rather than overwriting it. Losing IP_PKTINFO would
// silently change the source address and egress interface of every segment.
func TestAppendUDPSegmentCmsgPreservesExisting(t *testing.T) {
	cm := &ipv4.ControlMessage{IfIndex: 1, TTL: 8}
	got := appendUDPSegmentCmsg(cm.Marshal(), 800)
	msgs, err := unix.ParseSocketControlMessage(got)
	if err != nil {
		t.Fatalf("ParseSocketControlMessage: %v", err)
	}
	if len(msgs) < 2 {
		t.Fatalf("got %d control messages, want the IP-level ones plus UDP_SEGMENT", len(msgs))
	}
	last := msgs[len(msgs)-1]
	if last.Header.Level != unix.IPPROTO_UDP || last.Header.Type != unix.UDP_SEGMENT {
		t.Fatalf("last cmsg is level %d type %d, want UDP_SEGMENT",
			last.Header.Level, last.Header.Type)
	}
	var sawIP bool
	for _, m := range msgs[:len(msgs)-1] {
		if m.Header.Level == unix.IPPROTO_IP {
			sawIP = true
		}
	}
	if !sawIP {
		t.Error("the IP-level control message did not survive the append")
	}
}

// TestWriteSegmentsEmitsSeparateDatagramsInOrder is the load-bearing test: one
// syscall must put N distinct, correctly sized datagrams on the wire, in order,
// byte-identical to the slices a per-datagram sender would have written.
func TestWriteSegmentsEmitsSeparateDatagramsInOrder(t *testing.T) {
	for _, tc := range []struct {
		name        string
		segmentSize int
		total       int
		wantSizes   []int
	}{
		{"short last segment", 1366, 11*1366 + 700, append(repeat(1366, 11), 700)},
		{"exact multiple", 400, 5 * 400, repeat(400, 5)},
		{"single segment", 400, 400, repeat(400, 1)},
		{"shorter than one segment", 400, 137, []int{137}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rx, pc, dst := loopbackPair(t)
			payload := make([]byte, tc.total)
			for i := range payload {
				payload[i] = byte(i % 251)
			}

			n, err := writeSegments(pc, payload, tc.segmentSize, nil, dst)
			if err != nil {
				t.Fatalf("writeSegments: %v", err)
			}
			if n != tc.total {
				t.Fatalf("wrote %d bytes, want %d", n, tc.total)
			}

			got := readDatagrams(t, rx, len(tc.wantSizes))
			var off int
			for i, want := range tc.wantSizes {
				if len(got[i]) != want {
					t.Fatalf("datagram %d is %d bytes, want %d", i, len(got[i]), want)
				}
				if !bytes.Equal(got[i], payload[off:off+want]) {
					t.Fatalf("datagram %d differs from payload[%d:%d]", i, off, off+want)
				}
				off += want
			}
			if off != tc.total {
				t.Fatalf("datagrams covered %d bytes of %d", off, tc.total)
			}
		})
	}
}

// TestWriteSegmentsCarriesControlMessage proves the IP-level control message is
// not merely accepted alongside UDP_SEGMENT but actually applied: every emitted
// segment leaves with the requested source address. Asserting only that the
// send did not error would pass with the control message dropped entirely,
// which on the sender would silently change the source of every packet.
//
// The source address is the observable because it is the field the multicast
// sender actually sets. TTL was tried first and is not usable here: a requested
// TTL of 7 came back as 64 on loopback.
func TestWriteSegmentsCarriesControlMessage(t *testing.T) {
	rx, pc, dst := loopbackPair(t)
	const wantSrc = "127.0.0.7"
	cm := &ipv4.ControlMessage{Src: net.ParseIP(wantSrc)}

	payload := bytes.Repeat([]byte("x"), 3*200)
	if _, err := writeSegments(pc, payload, 200, cm.Marshal(), dst); err != nil {
		t.Fatalf("writeSegments with control message: %v", err)
	}
	assertAllFrom(t, rx, 3, wantSrc)
}

// TestMulticastConnWriteSegmentsAppliesControlMessage is the method-level
// counterpart: it proves WriteSegments marshals the caller's control message
// rather than discarding it on the way to the syscall.
func TestMulticastConnWriteSegmentsAppliesControlMessage(t *testing.T) {
	rx, pc, dst := loopbackPair(t)
	mc := &MulticastConn{conn4: pc, IFace: &net.Interface{MTU: 1500}}
	const wantSrc = "127.0.0.9"

	payload := bytes.Repeat([]byte("y"), 4*300)
	if _, err := mc.WriteSegments(payload, 300, &ipv4.ControlMessage{Src: net.ParseIP(wantSrc)}, dst); err != nil {
		t.Fatalf("WriteSegments: %v", err)
	}
	assertAllFrom(t, rx, 4, wantSrc)
}

// assertAllFrom drains want datagrams and requires every one to originate from
// wantSrc, then requires that no more follow.
func assertAllFrom(t *testing.T, rx net.PacketConn, want int, wantSrc string) {
	t.Helper()
	buf := make([]byte, 1<<16)
	for i := 0; i < want; i++ {
		if err := rx.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		_, from, err := rx.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d of %d: %v", i, want, err)
		}
		host, _, err := net.SplitHostPort(from.String())
		if err != nil {
			t.Fatalf("parse %s: %v", from, err)
		}
		if host != wantSrc {
			t.Fatalf("datagram %d came from %s, want %s: the control message did "+
				"not reach the kernel", i, host, wantSrc)
		}
	}
	assertNoMoreDatagrams(t, rx)
}

// TestWriteSegmentsRejectionEmitsNothing is the test the fallback rests on.
// The whole duplicate-free fallback argument is that a refused segmented send
// puts ZERO frames on the wire, so re-sending the same buffer per datagram
// cannot double-deliver. If the kernel ever emitted a prefix before failing,
// the fallback would silently duplicate traffic on a live group -- so this
// asserts the atomicity directly rather than trusting the measurement.
func TestWriteSegmentsRejectionEmitsNothing(t *testing.T) {
	rx, pc, dst := loopbackPair(t)

	// Over the segment cap: measured to return EINVAL. writeSegments is called
	// directly so the pre-check cannot mask the kernel's behaviour.
	segments := UDPMaxSegments + 72
	payload := make([]byte, segments*100)

	n, err := writeSegments(pc, payload, 100, nil, dst)
	if err == nil {
		t.Fatalf("writeSegments accepted %d segments, want a refusal", segments)
	}
	if !errors.Is(err, ErrSegmentsUnsupported) {
		t.Fatalf("error %v does not wrap ErrSegmentsUnsupported, so the caller "+
			"would surface it instead of falling back", err)
	}
	if n != 0 {
		t.Fatalf("refused send reported %d bytes written, want 0", n)
	}
	assertNoMoreDatagrams(t, rx)
}

// TestUDPMaxSegmentsMatchesKernel pins the constant to the kernel's real cap
// instead of to itself. The table tests above all express their bounds in terms
// of UDPMaxSegments, so they move with the constant and cannot catch a wrong
// value -- "correcting" 128 to the widely-cited 64 left every one of them green
// while silently pushing 65..128-segment batches onto the slower fallback.
//
// So assert against the kernel: exactly UDPMaxSegments must be accepted, and one
// more must be refused. A failure here means the constant and the running kernel
// disagree -- if a newer kernel accepts more, the constant is stale and can be
// raised; if it accepts fewer, it must be lowered.
func TestUDPMaxSegmentsMatchesKernel(t *testing.T) {
	const segment = 100

	t.Run("cap is accepted", func(t *testing.T) {
		rx, pc, dst := loopbackPair(t)
		n, err := writeSegments(pc, make([]byte, UDPMaxSegments*segment), segment, nil, dst)
		if err != nil {
			t.Fatalf("kernel refused %d segments, which UDPMaxSegments claims is allowed: %v",
				UDPMaxSegments, err)
		}
		if n != UDPMaxSegments*segment {
			t.Fatalf("wrote %d bytes, want %d", n, UDPMaxSegments*segment)
		}
		readDatagrams(t, rx, UDPMaxSegments)
	})

	t.Run("one over the cap is refused", func(t *testing.T) {
		rx, pc, dst := loopbackPair(t)
		if _, err := writeSegments(pc, make([]byte, (UDPMaxSegments+1)*segment), segment, nil, dst); err == nil {
			t.Fatalf("kernel accepted %d segments, so UDPMaxSegments (%d) understates its "+
				"real cap and batches are falling back needlessly",
				UDPMaxSegments+1, UDPMaxSegments)
		}
		assertNoMoreDatagrams(t, rx)
	})
}

func TestWriteSegmentsRejectsNonIPv4Destination(t *testing.T) {
	_, pc, _ := loopbackPair(t)
	dst := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9}
	if _, err := writeSegments(pc, make([]byte, 100), 100, nil, dst); !errors.Is(err, ErrSegmentsUnsupported) {
		t.Fatalf("got %v, want an error wrapping ErrSegmentsUnsupported", err)
	}
}

// TestMulticastConnWriteSegmentsRefusals covers the paths where the method
// declines before touching a socket. Each must wrap ErrSegmentsUnsupported so
// the caller falls back rather than failing the send.
//
// Every fixture sets conn4, including the tunnel and v6 cases. That is
// deliberate: with conn4 nil the "not open" check refuses first and masks the
// guard under test, so deleting the tunnel or v6 branch entirely left this test
// green. Each case must be refused by its own branch.
func TestMulticastConnWriteSegmentsRefusals(t *testing.T) {
	_, pc, dst := loopbackPair(t)
	payload := make([]byte, 400)

	for _, tc := range []struct {
		name string
		conn *MulticastConn
		dst  net.Addr
	}{
		{"amt tunnel", &MulticastConn{conn4: pc, activeTunnel: true}, dst},
		{"native v6", &MulticastConn{conn4: pc, conn6: &ipv6.PacketConn{}}, dst},
		{"not open", &MulticastConn{}, dst},
		{"destination is not a udp addr", &MulticastConn{conn4: pc},
			&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := tc.conn.WriteSegments(payload, 200, nil, tc.dst)
			if !errors.Is(err, ErrSegmentsUnsupported) {
				t.Fatalf("got %v, want an error wrapping ErrSegmentsUnsupported", err)
			}
			if n != 0 {
				t.Fatalf("declined send reported %d bytes written, want 0", n)
			}
		})
	}
}

// TestClassifySendResult covers the branch no socket can reach. sendmsg(2) on a
// datagram socket is all-or-nothing, so the short-accept case is unreachable
// end-to-end -- but the analogous partial accept on sendmmsg(2) is real, and
// treating one as success would hide datagrams that never went out while
// treating it as retryable would duplicate the ones that did.
func TestClassifySendResult(t *testing.T) {
	for _, tc := range []struct {
		name            string
		n, total        int
		opErr           error
		wantN           int
		wantUnsupported bool
		wantPartial     bool
		wantRaw         error
	}{
		{name: "full accept", n: 1200, total: 1200, wantN: 1200},
		// n is deliberately non-zero on every error case: a failed send must
		// report 0 bytes written, or a caller that falls back would believe part
		// of the batch was already on the wire and skip it.
		{name: "emsgsize is retryable", n: 999, total: 1200, opErr: unix.EMSGSIZE, wantUnsupported: true},
		{name: "einval is retryable", n: 999, total: 1200, opErr: unix.EINVAL, wantUnsupported: true},
		{
			name: "short accept is partial, not success",
			n:    800, total: 1200, wantN: 800, wantPartial: true,
		},
		{
			name: "unrelated errno is surfaced, not swallowed",
			n:    999, total: 1200, opErr: unix.EPERM, wantRaw: unix.EPERM,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := classifySendResult(tc.n, tc.total, tc.opErr)
			if n != tc.wantN {
				t.Errorf("n = %d, want %d", n, tc.wantN)
			}
			switch {
			case tc.wantUnsupported:
				if !errors.Is(err, ErrSegmentsUnsupported) {
					t.Fatalf("got %v, want ErrSegmentsUnsupported so the caller falls back", err)
				}
			case tc.wantPartial:
				if !errors.Is(err, ErrSegmentsPartial) {
					t.Fatalf("got %v, want ErrSegmentsPartial", err)
				}
				if errors.Is(err, ErrSegmentsUnsupported) {
					t.Fatal("a partial accept must not read as retryable: falling back " +
						"would re-send the datagrams already on the wire")
				}
			case tc.wantRaw != nil:
				if !errors.Is(err, tc.wantRaw) {
					t.Fatalf("got %v, want %v", err, tc.wantRaw)
				}
				if errors.Is(err, ErrSegmentsUnsupported) {
					t.Fatal("an unrelated errno must not be classified as retryable")
				}
			default:
				if err != nil {
					t.Fatalf("got %v, want nil", err)
				}
			}
		})
	}
}

// TestMulticastConnWriteSegmentsUsesIFaceMTU proves the pre-check consults the
// interface MTU, and that it declines without a syscall rather than letting the
// kernel reject an oversized segment.
func TestMulticastConnWriteSegmentsUsesIFaceMTU(t *testing.T) {
	rx, pc, dst := loopbackPair(t)
	mc := &MulticastConn{conn4: pc, IFace: &net.Interface{MTU: 1500}}

	// 1473 + 28 > 1500.
	if _, err := mc.WriteSegments(make([]byte, 2*1473), 1473, nil, dst); !errors.Is(err, ErrSegmentsUnsupported) {
		t.Fatalf("oversized segment: got %v, want ErrSegmentsUnsupported", err)
	}
	assertNoMoreDatagrams(t, rx)

	// 1472 + 28 == 1500 exactly, which the staging probe measured as accepted.
	if _, err := mc.WriteSegments(make([]byte, 2*1472), 1472, nil, dst); err != nil {
		t.Fatalf("segment exactly at mtu-28: %v", err)
	}
	if got := readDatagrams(t, rx, 2); len(got) != 2 {
		t.Fatalf("got %d datagrams, want 2", len(got))
	}
}

// TestMulticastConnWriteSegmentsEndToEnd runs the exported method over a real
// socket on the shipping shape: a DS 74 block of 12 x 1366.
func TestMulticastConnWriteSegmentsEndToEnd(t *testing.T) {
	rx, pc, dst := loopbackPair(t)
	mc := &MulticastConn{conn4: pc, IFace: &net.Interface{MTU: 1500}}

	payload := make([]byte, 12*1366)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	n, err := mc.WriteSegments(payload, 1366, nil, dst)
	if err != nil {
		t.Fatalf("WriteSegments: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("wrote %d bytes, want %d", n, len(payload))
	}
	got := readDatagrams(t, rx, 12)
	for i, d := range got {
		if len(d) != 1366 {
			t.Fatalf("datagram %d is %d bytes, want 1366", i, len(d))
		}
		if !bytes.Equal(d, payload[i*1366:(i+1)*1366]) {
			t.Fatalf("datagram %d differs from its slice of the payload", i)
		}
	}
}

func repeat(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}
