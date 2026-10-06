//go:build linux

// Tagged like gro_linux.go, which defines the two constants under test, and
// unlike gro_linux_test.go, which is narrowed to `cgo && !purego && !android`
// because it drives real sockets through loopbackPair. These two need neither a
// socket nor cgo, and an ABI guard that does not run on the ABIs it guards is
// worth nothing -- control_oob_len_abi_test.go is tagged `linux || darwin` for
// the same reason.

package amt

import (
	"testing"
	"unsafe"

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
