//go:build linux || darwin

package amt

import (
	"errors"
	"fmt"
	"syscall"
)

// retryAtMaxsockbuf is Darwin's SO_RCVBUF/SO_SNDBUF set. It lives outside
// sockbuf_darwin.go, with the syscalls injected, so Linux CI can test it.
//
// XNU's sbreserve refuses any size above sb_max*MCLBYTES/(MSIZE+MCLBYTES),
// i.e. kern.ipc.maxsockbuf*2048/2304, and setsockopt turns that into ENOBUFS
// instead of clamping. On ENOBUFS this reads kern.ipc.maxsockbuf, retries at
// the largest size sbreserve accepts, and reports that as *BufferClampedError
// so callers warn and continue. With the default maxsockbuf of 8 MiB the
// ceiling is 7456540, below blockcast-shreds' default 8 MiB --rcvbuf.
func retryAtMaxsockbuf(want int, set func(int) error, maxsockbuf func() (uint32, error)) error {
	err := set(want)
	if !errors.Is(err, syscall.ENOBUFS) {
		return err
	}
	limit, merr := maxsockbuf()
	if merr != nil {
		return fmt.Errorf("%w (reading kern.ipc.maxsockbuf: %v)", err, merr)
	}
	ceiling := int(uint64(limit) * 2048 / 2304)
	if ceiling >= want {
		return err // the ENOBUFS has some other cause; a retry cannot help
	}
	if err := set(ceiling); err != nil {
		return err
	}
	return &BufferClampedError{Requested: want, Got: ceiling, ceiling: ceiling}
}
