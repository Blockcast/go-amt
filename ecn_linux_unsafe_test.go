//go:build linux

package amt

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func unsafePtrHdr(b []byte) unsafe.Pointer { _ = unix.Cmsghdr{}; return unsafe.Pointer(&b[0]) }
