//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"golang.org/x/net/ipv4"
)

// AmtResult codes from amt-protocol's FFI boundary (ffi.rs:34-53, mirrored in
// amt_protocol.h). handleRelayAdvertisement surfaces them numerically, so the
// test needs the two it discriminates between.
const (
	resultInvalidState = 2 // AMT_RESULT_INVALID_STATE
	resultDecodeError  = 5 // AMT_RESULT_DECODE_ERROR
)

// TestRelayAdvertisementMustBeDecodedAtItsReceivedLength is the negative control
// for BLO-29437, and it is the reason that bug can only come back deliberately.
//
// Relay Advertisement is the ONE AMT message whose Rust decoder matches on exact
// length rather than a minimum: messages.rs:213-224 selects IPv4 on
// `buf.len() == 12`, IPv6 on `== 24`, and errors on everything else. Every other
// decoder bound-checks with `<`. Gateway.Open used to discard the read length and
// pass the whole MTU-sized array, so the advertisement was the only leg that
// noticed — and it failed on every handshake the cgo path ever attempted, against
// real relays and fakeRelay alike, surfacing as a bare i/o timeout that named
// nothing.
//
// WHY THIS DISCRIMINATES rather than just asserting "padded fails". Both calls
// below fail, because a fresh gateway is in Idle and handle_advertisement
// requires Discovering (gateway.rs:167). The point is that they fail at DIFFERENT
// depths, and the codes say which:
//
//	exact 12 bytes -> decode SUCCEEDS, then the state guard rejects -> InvalidState
//	padded to MTU  -> decode FAILS before any state is consulted  -> DecodeError
//
// So InvalidState is positive evidence that the decoder accepted the length and
// got as far as protocol validation, and DecodeError is positive evidence that it
// did not. Asserting only that the padded form errors would also pass if the
// decoder had rejected both, which is the failure this test exists to tell apart.
//
// No socket and no discovery handshake are needed: handleRelayAdvertisement only
// reaches sendRequest after a successful handle, so both paths here return before
// anything touches g.conn.
func TestRelayAdvertisementMustBeDecodedAtItsReceivedLength(t *testing.T) {
	// A well-formed IPv4 Relay Advertisement, RFC 7450 section 5.1.2: type,
	// reserved, 2 reserved, 4-byte nonce, 4-byte relay address. Twelve bytes,
	// which is byte-for-byte what amt-protocol's own encoder emits
	// (messages.rs:110-122) and exactly what fakeRelay.handleDiscovery sends —
	// the harness was never the problem.
	advertisement := []byte{
		0x02,             // V=0, Type=2 (Relay Advertisement)
		0x00, 0x00, 0x00, // reserved
		0xde, 0xad, 0xbe, 0xef, // nonce
		127, 0, 0, 1, // relay address
	}
	if len(advertisement) != 12 {
		t.Fatalf("fixture is %d bytes, want 12: the IPv4 advertisement length is "+
			"the whole subject of this test", len(advertisement))
	}

	t.Run("exact length reaches protocol validation", func(t *testing.T) {
		g := newIdleRustGateway(t)
		err := g.handleRelayAdvertisement(advertisement)
		want := fmt.Sprintf("failed to handle advertisement: %d", resultInvalidState)
		if err == nil || err.Error() != want {
			t.Fatalf("handleRelayAdvertisement(12 bytes) = %v, want %q. InvalidState "+
				"means the decoder accepted the length and the STATE guard rejected "+
				"it, which is what proves a 12-byte advertisement decodes at all. A "+
				"DecodeError here would mean the wire format itself is wrong.", err, want)
		}
	})

	t.Run("zero-padded to MTU is rejected at decode", func(t *testing.T) {
		g := newIdleRustGateway(t)
		// Exactly what Gateway.Open used to hand the decoder: the message at the
		// front of a full MTU-sized read buffer, the remainder still zero.
		padded := make([]byte, 1500)
		copy(padded, advertisement)

		err := g.handleRelayAdvertisement(padded)
		want := fmt.Sprintf("failed to handle advertisement: %d", resultDecodeError)
		if err == nil || err.Error() != want {
			t.Fatalf("handleRelayAdvertisement(%d bytes) = %v, want %q. If this now "+
				"returns InvalidState the decoder has become length-tolerant "+
				"upstream, and the exact-length contract this test pins — along with "+
				"the reason Open must slice to n — no longer holds; if it returns nil "+
				"the padding is being accepted outright. Either way, re-read "+
				"amt-protocol/src/messages.rs before relaxing anything.",
				len(padded), err, want)
		}
	})
}

// TestZeroLengthDatagramIsNotDispatchedFromAStaleTypeByte pins the two facts that
// make ReadBatch's `n == 0` guard load-bearing — and that make its POSITION,
// before the type read rather than after, load-bearing too.
//
// A zero-length UDP datagram is legal and carries no type byte. ReadBatch reads
// into a reused ms[i].Buffers[0], so offset 0 still holds whatever the previous
// read left there. Reading the type from the UNSLICED buffer therefore
// misclassifies an empty datagram as whatever arrived last, and the control arms
// then hand a len-0 slice to handleRelayAdvertisement / handleMembershipQuery,
// both of which take &data[0] unconditionally to reach the FFI.
//
// Neither half is reachable from the harness tests: fakeRelay's message buffers
// are freshly zeroed, so a zero-length datagram reads type 0 and falls to
// default:. That is why this is a direct test of the mechanism rather than an
// end-to-end one.
func TestZeroLengthDatagramIsNotDispatchedFromAStaleTypeByte(t *testing.T) {
	// A buffer reused from an earlier read that carried a Relay Advertisement.
	buf := make([]byte, 1500)
	buf[0] = byte(m.RelayAdvertisementType)

	// 1. The stale tail really does misclassify. This is the reachability half of
	//    the defect and the half a future reader is most likely to doubt.
	if got := determineAMTmessageType(buf); got != m.RelayAdvertisementType {
		t.Fatalf("unsliced type read = %d, want %d: this test assumes a reused "+
			"buffer's stale offset-0 byte is what routes dispatch, which is the "+
			"whole reason the type must be read from buf[:n]",
			got, m.RelayAdvertisementType)
	}

	// 2. Slicing alone is NOT sufficient. At n == 0 there is no type byte to
	//    read, so the sliced read indexes past the end. This is why the guard has
	//    to come FIRST, and why "just slice the type read" is not the whole fix.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("determineAMTmessageType(buf[:0]) did not panic, which makes " +
					"ReadBatch's n == 0 guard look redundant — and someone will " +
					"delete it. It is not redundant: that guard is the only thing " +
					"keeping this index off a zero-length datagram.")
			}
		}()
		_ = determineAMTmessageType(buf[:0])
	}()
}

// TestProcessAMTBatchCompactsControlMessages proves that a control packet does
// not consume, duplicate, or hide a data packet from the same kernel batch.
//
// On Linux ReadBatch can receive both datagrams at once. The old compaction was
// a self-assignment, so [control, data] dispatched the control twice and
// returned no data. Merely changing that assignment is not enough: [data,
// control] then re-dispatches the tail control unless the loop's upper bound
// shrinks with the compacted range. Exercise both orders here.
func TestProcessAMTBatchCompactsControlMessages(t *testing.T) {
	advertisement := []byte{
		0x02, 0x00, 0x00, 0x00,
		0xde, 0xad, 0xbe, 0xef,
		127, 0, 0, 1,
	}

	for _, tt := range []struct {
		name  string
		first string
	}{
		{name: "control then data", first: "control"},
		{name: "data then control", first: "data"},
		{name: "zero length then data", first: "zero"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gw := newIdleRustGateway(t)
			mc := &MulticastConn{
				amtGw:     gw,
				GroupAddr: netip.MustParseAddr("239.0.0.1"),
			}

			want := []byte("batched-data")
			data := multicastDataPacket(t, want)
			data[0] = byte(m.MulticastDataType)
			controlMessage := ipv4.Message{Buffers: [][]byte{append([]byte(nil), advertisement...)}, N: len(advertisement)}
			if tt.first == "zero" {
				// Leave the stale advertisement type in the caller-owned buffer,
				// but report a legal zero-length datagram. The guard must compact
				// this slot exactly like the recognized control message above.
				controlMessage.N = 0
			}
			dataMessage := ipv4.Message{Buffers: [][]byte{data}, N: len(data)}
			messages := []ipv4.Message{controlMessage, dataMessage}
			if tt.first == "data" {
				messages[0], messages[1] = messages[1], messages[0]
			}

			n, err := mc.processAMTBatch(messages, len(messages))
			if n != 1 {
				t.Fatalf("processAMTBatch returned %d messages, want 1", n)
			}
			// The Idle Rust handle deliberately rejects the advertisement with
			// InvalidState. That is expected and proves the data delivery result
			// comes from compaction rather than a control handler succeeding.
			if tt.first == "zero" {
				if err != nil {
					t.Fatalf("processAMTBatch error = %v, want nil for dropped zero-length datagram", err)
				}
			} else if err == nil || err.Error() != fmt.Sprintf("failed to handle advertisement: %d", resultInvalidState) {
				t.Fatalf("processAMTBatch error = %v, want rejected advertisement", err)
			}
			if !bytes.Equal(messages[0].Buffers[0], want) {
				t.Fatalf("returned payload = %q, want %q", messages[0].Buffers[0], want)
			}
			if messages[0].N != len(want) {
				t.Fatalf("returned length = %d, want %d", messages[0].N, len(want))
			}
		})
	}
}

// newIdleRustGateway builds a Gateway with a live Rust handle in its initial Idle
// state, with no socket and no discovery sent.
//
// The handle is deliberately not freed: amt_gateway_free is a cgo call and cgo is
// not permitted in _test.go files, so there is no way to release it from here.
// One leaked handle per subtest is bounded and harmless for the lifetime of a
// test binary.
func newIdleRustGateway(t *testing.T) *Gateway {
	t.Helper()

	g := &Gateway{
		// Never connected to; createRustGateway only needs a parseable endpoint.
		RelayAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2268},
		MTU:       1500,
	}
	if err := g.createRustGateway(); err != nil {
		t.Fatalf("createRustGateway: %v", err)
	}
	return g
}

// TestRuntMulticastDataIsDroppedNotPanicked covers the half of the
// received-length invariant that the BLO-29437 zero-length guard left open.
//
// determineAMTmessageType reads exactly one byte, at index 0 (gateway.go:570),
// so once n >= 1 the type is decided by data the socket really delivered and
// slicing the buffer cannot change the classification. What the length still
// decides is whether the MulticastData arm's header slice is legal:
// [m.DataMsgHdrLen:n] at n == 1 is [2:1], low > high, which panics for the same
// reason n == 0 did. A single 1-byte 0x06 datagram reaches that arm.
//
// Both read paths are exercised because they slice differently and were fixed
// separately: the batch path must additionally COMPACT the runt, so a runt
// sharing a kernel batch with good data must not consume or hide it.
func TestRuntMulticastDataIsDroppedNotPanicked(t *testing.T) {
	// n == 1 is the panicking case (2:1). n == 0 is already covered above and
	// is included so the two guards are seen to agree at the boundary.
	for _, n := range []int{0, 1} {
		t.Run(fmt.Sprintf("batch/n=%d", n), func(t *testing.T) {
			gw := newIdleRustGateway(t)
			mc := &MulticastConn{amtGw: gw, GroupAddr: netip.MustParseAddr("239.0.0.1")}

			want := []byte("survives-the-runt")
			good := multicastDataPacket(t, want)
			good[0] = byte(m.MulticastDataType)

			// The runt keeps a full-MTU backing array: the bug is reading past
			// the reported length, so a short buffer would hide it.
			runtBuf := make([]byte, 1500)
			runtBuf[0] = byte(m.MulticastDataType)

			messages := []ipv4.Message{
				{Buffers: [][]byte{runtBuf}, N: n},
				{Buffers: [][]byte{good}, N: len(good)},
			}

			got, err := mc.processAMTBatch(messages, len(messages))
			if err != nil {
				t.Fatalf("processAMTBatch error = %v, want nil", err)
			}
			if got != 1 {
				t.Fatalf("processAMTBatch returned %d messages, want 1 (the runt must be compacted away, not counted)", got)
			}
			if !bytes.Equal(messages[0].Buffers[0], want) {
				t.Fatalf("returned payload = %q, want %q", messages[0].Buffers[0], want)
			}
		})
	}

	t.Run("single/n=1", func(t *testing.T) {
		// A real socket, not a fake: ReadFromWithControlMessage reads through a
		// concrete *ipv4.PacketConn, and the defect is in how it slices what the
		// kernel actually returned.
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket: %v", err)
		}
		defer pc.Close()

		gw := newIdleRustGateway(t)
		gw.conn = ipv4.NewPacketConn(pc)
		mc := &MulticastConn{amtGw: gw, GroupAddr: netip.MustParseAddr("239.0.0.1")}

		sender, err := net.Dial("udp4", pc.LocalAddr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer sender.Close()
		if _, err := sender.Write([]byte{byte(m.MulticastDataType)}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		// The runt is dropped and the loop reads again, so the call is expected
		// to end at the deadline. That timeout IS the pass condition: it proves
		// the datagram was neither delivered upward nor fatal.
		if err := gw.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		got, _, _, err := mc.ReadFromWithControlMessage(make([]byte, 1500))
		if got != 0 {
			t.Fatalf("ReadFromWithControlMessage returned n=%d, want 0: a 1-byte datagram is not deliverable multicast data", got)
		}
		// Assert the timeout through net.Error rather than a specific sentinel:
		// the error crosses x/net/ipv4 and is only guaranteed to stay a net.Error.
		var netErr net.Error
		if err == nil || !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("err = %v, want a read timeout after the runt was dropped", err)
		}
	})
}
