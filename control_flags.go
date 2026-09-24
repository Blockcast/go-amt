package amt

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ControlFlags4 and ControlFlags6 are the control-message flag sets every
// native group join in this package requests. They are exported because a
// caller cannot size the OOB buffer it hands ReadBatch without them, and every
// listen call here consumes these constants rather than a local copy.
//
// Getting that buffer too small fails silently, which is why this is exported
// rather than documented: the kernel sets MSG_CTRUNC and drops whichever cmsgs
// did not fit. The first casualty is Dst, so a receiver filtering datagrams by
// destination group then discards all of them, with no error on any surface.
// Restating the sets at the caller works right up until a flag is added here —
// no build break, because there was never a shared symbol for the compiler to
// check. multicast's lct.ControlMessageOOBLen carried exactly that copy, and
// its v6 arm summed to 96 bytes against a 96-byte buffer: one more v6 cmsg
// upstream and IPv6 goes dark (BLO-34983).
//
// These are the IP-level cmsgs only. To size a buffer, use
// ControlMessageOOBLen, which adds the SOL_SOCKET term these flags cannot
// reach.
//
// Untagged on purpose. The listen calls that consume these are behind
// platform and cgo constraints, but the callers that must size a buffer are
// not, and a consumer whose own build tags do not line up with conn.go's would
// otherwise be pushed straight back to a local copy.
const (
	ControlFlags4 ipv4.ControlFlags = ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL
	ControlFlags6 ipv6.ControlFlags = ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagHopLimit
)

// TimestampControlMessageLen is the OOB space the one timestamp control message
// occupies on a socket opened with MulticastConfig.Timestamp set.
//
// It is a separate exported term, rather than another bit in the sets above,
// because it is structurally unreachable from them. The option this package
// sets is SOL_SOCKET — SO_TIMESTAMPNS with an SO_TIMESTAMP fallback on linux,
// SO_TIMESTAMP on darwin and mobile — while ipv4.ControlFlags and
// ipv6.ControlFlags are closed types carrying only IP-level bits (x/net/ipv6
// has exactly FlagTrafficClass, FlagHopLimit, FlagSrc, FlagDst, FlagInterface,
// FlagPathMTU). There is no value a caller could OR in to account for it, so a
// caller sizing from the flag sets alone is short by exactly this much and the
// kernel silently truncates — which is the failure BLO-34983 exists to close,
// surviving inside the fix for it until this term was exported too.
//
// 32 is CmsgSpace(16) on a 64-bit ABI: both options carry a 16-byte payload,
// timespec for SCM_TIMESTAMPNS and timeval for SCM_TIMESTAMP.
// TestTimestampControlMessageLenMatchesTheABI checks that against
// unix.CmsgSpace instead of trusting the literal, and
// TestTimestampSockoptsAreAllAccountedFor fails if a listen file starts setting
// one this number does not cover — SO_TIMESTAMPING is the live example, three
// timespecs at CmsgSpace(48) = 64.
const TimestampControlMessageLen = 32

// ControlMessageOOBLen returns the per-slot OOB buffer length a ReadBatch
// caller must allocate to receive everything a socket opened by this package
// can emit.
//
// This, not the flag sets, is what a caller should size from. Every term is
// owned here — the IP-level cmsgs by ControlFlags4/6 and the SOL_SOCKET one by
// TimestampControlMessageLen — so a cmsg added on either axis reaches the
// caller's buffer on its next pin bump with no edit at the caller, which is the
// whole point (BLO-34983). Exporting only the flag sets left the timestamp term
// as a hand-mirror at the caller, i.e. one instance of the drift class the
// export was meant to retire.
//
// The larger of the two families, because a caller allocating one buffer size
// for slots it will hand to either family cannot know the family in advance.
// v6's cmsgs are 8 bytes wider, so sizing from v4 alone truncates Dst on a v6
// datagram and a group filter then discards all of it.
//
// Unconditionally includes the timestamp term, even though Timestamp is
// per-config: over-allocating 32 bytes per slot costs nothing, and a length
// that varied by config would put the caller back in the business of tracking
// which options this package set.
//
// A function and not an exported var. It cannot be a const — len of a call is
// not constant — and an exported var is assignable by any importer, which is
// the one way a consumer silently un-sizes every OOB buffer in the process and
// lands back on the exact MSG_CTRUNC path this symbol exists to close. Nothing
// would catch that: not the compiler, not vet, not the guards in
// control_oob_len_test.go, which read the same var the assignment clobbered. A
// package that exports a length to stop a silent truncation does not get to
// leave a one-assignment hole into it.
func ControlMessageOOBLen() int { return controlMessageOOBLen }

var controlMessageOOBLen = max(
	len(ipv4.NewControlMessage(ControlFlags4)),
	len(ipv6.NewControlMessage(ControlFlags6)),
) + TimestampControlMessageLen
