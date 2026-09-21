//go:build linux || darwin

package amt

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestTimestampControlMessageLenMatchesTheABI checks the literal 32 against the
// kernel ABI rather than against another copy of itself.
//
// TimestampControlMessageLen has to be a plain constant: it is the one term of
// ControlMessageOOBLen with no x/net accessor to compute it from, because the
// option is SOL_SOCKET and the ipv4/ipv6 control-flag types are IP-level only.
// A hand-written number is what this package just finished removing from its
// consumer, so it does not get to keep one unchecked.
//
// CmsgSpace is the same alignment arithmetic the kernel uses to lay the control
// buffer out, so this fails on a 32-bit ABI — where the cmsghdr is 12 bytes and
// the space is 20, not 32 — as well as on a payload change. That is the correct
// outcome: the constant would genuinely be wrong there, and over-allocating is
// only safe in the direction it currently errs.
//
// Tagged, unlike the guards in control_oob_len_test.go, because unix.CmsgSpace
// exists only where there is a real ABI to ask. The untagged guards there cover
// what is asserted about source rather than about this machine.
func TestTimestampControlMessageLenMatchesTheABI(t *testing.T) {
	// SCM_TIMESTAMPNS carries a timespec, SCM_TIMESTAMP a timeval. Both are two
	// words, so both land on the same space — assert each, so a platform where
	// they diverge is caught rather than averaged.
	for _, tc := range []struct {
		opt     string
		payload int
	}{
		{"SO_TIMESTAMPNS/timespec", int(unsafe.Sizeof(unix.Timespec{}))},
		{"SO_TIMESTAMP/timeval", int(unsafe.Sizeof(unix.Timeval{}))},
	} {
		if got := unix.CmsgSpace(tc.payload); got != TimestampControlMessageLen {
			t.Errorf("%s occupies CmsgSpace(%d) = %d, but "+
				"TimestampControlMessageLen is %d. ControlMessageOOBLen is built "+
				"from that constant, so every caller's OOB buffer is off by %d "+
				"bytes per slot — and a short one is silent: MSG_CTRUNC, Dst "+
				"dropped, group filter discards everything",
				tc.opt, tc.payload, got, TimestampControlMessageLen,
				got-TimestampControlMessageLen)
		}
	}
}
