package amt

import "errors"

// ErrGROUnsupported reports that UDP GRO could not be enabled on this
// connection. It is the caller's signal to read datagram-per-slot as it always
// has; it never means the socket was left in a half-configured state. Callers
// select that fallback with errors.Is rather than by string match, the same way
// ErrSegmentsUnsupported works on the send side.
//
// GRO is the receive-side counterpart of the UDP_SEGMENT write in gso.go and
// has the same justification: both are IPPROTO_UDP socket options, and x/net's
// ipv4.ControlMessage marshals IP-level options only, so neither can be
// expressed through the ReadBatch/WriteBatch signatures themselves.
var ErrGROUnsupported = errors.New("amt: udp gro unsupported")

// SegmentSizeUnreadable is returned by SegmentSize when a slot carries a
// UDP_GRO control message whose payload is not the size this package knows how
// to read.
//
// It is a distinct value from 0 because the two demand opposite handling and
// confusing them corrupts the stream silently. 0 means no GRO cmsg was present,
// so the buffer is one datagram and reading it whole is correct. This value
// means the kernel DID coalesce -- the buffer holds several datagrams
// back-to-back -- but the segment size could not be read, so reading it whole
// would hand the caller one oversized frame built from several real ones, with
// no error on any surface. A caller seeing this must fail the read, not fall
// back.
//
// Reaching it requires the kernel's cmsg payload to stop being a 4-byte int,
// which is an ABI change rather than a runtime condition;
// TestGROControlMessageLenMatchesTheABI and TestGROCmsgPayloadIsFourBytes pin
// both halves of that against the running kernel so the drift is caught in CI
// rather than here. It exists anyway because this is a parse of
// kernel-supplied bytes on the path that frames every received datagram, and
// the failure direction without it is silent.
const SegmentSizeUnreadable = -1

// SegmentSize reports the UDP GRO segment size for one ReadBatch slot, read
// from the control message the kernel attaches when it coalesced several
// datagrams into that slot. oob is the slot's control buffer truncated to the
// length the read reported, i.e. ms[i].OOB[:ms[i].NN].
//
// Returns 0 when the slot carries no GRO control message. That is the common
// case and it means exactly one datagram arrived, so the whole buffer is that
// datagram -- the kernel attaches the cmsg only when it actually coalesced.
// A caller therefore needs no "is GRO on" flag at the read site: 0 and
// "GRO disabled" are the same instruction.
//
// That reading of 0 holds only on a slot whose read did not set MSG_CTRUNC,
// and the caller must check ms[i].Flags for it. Truncation is reported out of
// band, never inside oob: the kernel drops whole control messages and shortens
// msg_controllen, so what survives still parses and a dropped GRO cmsg is
// indistinguishable here from one that was never attached. Acting on 0 after a
// truncated read frames a coalesced run as one oversized datagram -- the same
// silent corruption SegmentSizeUnreadable exists to prevent on the malformed
// payload path, reached by a route this parse cannot see. Sizing the buffer
// with ControlMessageOOBLen makes it unreachable; a caller that hand-mirrors
// that length is short by exactly GROControlMessageLen.
//
// A positive n means the slot holds ceil(len/n) datagrams laid out
// back-to-back, every one exactly n bytes except the last, which may be
// shorter. That is the same layout WriteSegments sends, by construction.
//
// Returns SegmentSizeUnreadable when a GRO cmsg is present but its payload is
// not readable; see that constant for why this is not folded into 0.
func SegmentSize(oob []byte) int { return segmentSizeFromOOB(oob) }
