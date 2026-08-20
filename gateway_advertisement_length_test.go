//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"fmt"
	"net"
	"testing"
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
