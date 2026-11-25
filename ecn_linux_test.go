//go:build linux

package amt

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestECNControlMessageLenMatchesTheABI(t *testing.T) {
	if got := unix.CmsgSpace(1); got != ECNControlMessageLen {
		t.Fatalf("CmsgSpace(1)=%d, ECNControlMessageLen=%d", got, ECNControlMessageLen)
	}
}

func cmsg(level, typ int32, data []byte) []byte {
	b := make([]byte, unix.CmsgSpace(len(data)))
	h := (*unix.Cmsghdr)(unsafePtrHdr(b))
	h.Level, h.Type = level, typ
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

func TestParseECN(t *testing.T) {
	for _, want := range []ECN{NotECT, ECT1, ECT0, CE} {
		// DSCP bits set alongside, which must be masked off.
		v4 := cmsg(unix.IPPROTO_IP, unix.IP_TOS, []byte{0xb8 | byte(want)})
		if got, ok := ParseECN(v4); !ok || got != want {
			t.Errorf("v4 %v: got %v ok=%v", want, got, ok)
		}
		tc := make([]byte, 4)
		binary.NativeEndian.PutUint32(tc, 0x28|uint32(want))
		v6 := cmsg(unix.IPPROTO_IPV6, unix.IPV6_TCLASS, tc)
		if got, ok := ParseECN(v6); !ok || got != want {
			t.Errorf("v6 %v: got %v ok=%v", want, got, ok)
		}
	}
	if _, ok := ParseECN(nil); ok {
		t.Error("empty oob must be unavailable, not Not-ECT")
	}
}
