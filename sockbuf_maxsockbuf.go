//go:build linux || darwin

package amt

import (
	"errors"
	"fmt"
	"syscall"
)

// setXNUBufferAtLeast is Darwin's SO_RCVBUF/SO_SNDBUF set. It lives outside
// sockbuf_darwin.go, with getsockopt, setsockopt and the kern.ipc.maxsockbuf
// sysctl injected, so Linux CI can test it.
//
// XNU's sbreserve treats a size above its limit in one of two ways:
//   - macOS 14.4 and later (xnu-10063 on): it clamps the size to
//     kern.ipc.maxsockbuf and setsockopt succeeds, so the clamp is silent.
//     It fails with ENOBUFS only when the buffer already sits at that limit.
//   - macOS 14.3 and earlier (xnu-10002 and before): it refuses any size
//     above kern.ipc.maxsockbuf*2048/2304 and setsockopt fails with ENOBUFS.
//     With the default 8 MiB maxsockbuf that ceiling is 7456540, below
//     blockcast-shreds' default 8 MiB --rcvbuf.
//
// A refused size leaves the buffer as it was. On ENOBUFS this retries at the
// older kernels' ceiling, unless that would shrink the buffer. It then reads
// the size back. Darwin's getsockopt does not double, so a readback below want
// is a clamp, and it is returned as *BufferClampedError for callers to warn on
// and continue. The readback is what reports the newer kernels' silent clamp.
func setXNUBufferAtLeast(want int, get func() (int, error), set func(int) error, maxsockbuf func() (uint32, error)) error {
	if want <= 0 {
		return nil
	}
	cur, gerr := get()
	if gerr == nil && cur >= want {
		return nil
	}
	if err := set(want); err != nil {
		if !errors.Is(err, syscall.ENOBUFS) {
			return err
		}
		if limit, merr := maxsockbuf(); merr == nil {
			if ceiling := int(uint64(limit) * 2048 / 2304); ceiling > cur && ceiling < want {
				_ = set(ceiling) // a refusal leaves the buffer as it was; the readback reports it
			}
		}
	}
	got, err := get()
	if err != nil {
		return fmt.Errorf("getsockopt verify: %w", err)
	}
	if got < want {
		return &BufferClampedError{Requested: want, Got: got, ceiling: got}
	}
	return nil
}
