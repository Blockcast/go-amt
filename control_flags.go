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
// Size from these, adding whatever the caller's own socket options contribute
// (SO_TIMESTAMPING is 32 bytes):
//
//	len(ipv4.NewControlMessage(amt.ControlFlags4))
//	len(ipv6.NewControlMessage(amt.ControlFlags6))
//
// Untagged on purpose. The listen calls that consume these are behind
// platform and cgo constraints, but the callers that must size a buffer are
// not, and a consumer whose own build tags do not line up with conn.go's would
// otherwise be pushed straight back to a local copy.
const (
	ControlFlags4 ipv4.ControlFlags = ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL
	ControlFlags6 ipv6.ControlFlags = ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagHopLimit
)
