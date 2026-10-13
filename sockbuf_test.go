//go:build linux || darwin

package amt

import (
	"errors"
	"slices"
	"syscall"
	"testing"
)

func newUDPSocket(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

func TestSetForcedReceiveBufferZero(t *testing.T) {
	fd := newUDPSocket(t)
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err := SetForcedReceiveBuffer(fd, 0); err != nil {
		t.Fatalf("SetForcedReceiveBuffer(0): want nil, got %v", err)
	}
	if err := SetForcedReceiveBuffer(fd, -1); err != nil {
		t.Fatalf("SetForcedReceiveBuffer(-1): want nil, got %v", err)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if before != after {
		t.Errorf("buffer changed despite no-op: before=%d after=%d", before, after)
	}
}

func TestSetForcedReceiveBufferDoesNotShrink(t *testing.T) {
	fd := newUDPSocket(t)
	// Set baseline first.
	if err := SetForcedReceiveBuffer(fd, 1<<20); err != nil { // 1 MB
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("baseline set: %v", err)
		}
		// Clamped is OK for baseline; use whatever we got.
	}
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	// Request a smaller buffer; helper should skip (don't shrink).
	if err := SetForcedReceiveBuffer(fd, 1024); err != nil {
		t.Fatalf("no-shrink call: %v", err)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if after < before {
		t.Errorf("buffer was shrunk: before=%d after=%d", before, after)
	}
}

func TestSetForcedReceiveBufferGrows(t *testing.T) {
	fd := newUDPSocket(t)
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	// Pick a target somewhat above the default (212992*2 = ~425KB on most
	// kernels) but well below typical rmem_max (often >= 7.5MB on modern
	// systems, or whatever the test environment has).
	want := before * 2
	if want < 1<<20 {
		want = 1 << 20
	}
	err := SetForcedReceiveBuffer(fd, want)
	if err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("unexpected error: %v", err)
		}
		// On a low-rmem_max host without NET_ADMIN, the kernel clamps below
		// `want`. The helper reports this via BufferClampedError; the buffer
		// still grew (just not to the full request).
		t.Logf("got clamp (expected on low-rmem_max env w/o NET_ADMIN): %v", clamp)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if after <= before {
		t.Errorf("buffer did not grow: before=%d after=%d want=%d", before, after, want)
	}
}

func TestSetForcedReceiveBufferBadFD(t *testing.T) {
	if err := SetForcedReceiveBuffer(-1, 1<<20); err == nil {
		t.Fatal("expected error on bad fd, got nil")
	}
}

func TestBufferClampedErrorMessage(t *testing.T) {
	e := &BufferClampedError{Requested: 7500000, Got: 425984}
	if msg := e.Error(); msg == "" {
		t.Fatal("empty error message")
	}
}

func TestSetForcedSendBufferGrows(t *testing.T) {
	fd := newUDPSocket(t)
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	want := before * 2
	if want < 1<<20 {
		want = 1 << 20
	}
	err := SetForcedSendBuffer(fd, want)
	if err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("unexpected error: %v", err)
		}
		t.Logf("got clamp (expected on low-wmem_max env w/o NET_ADMIN): %v", clamp)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if after <= before {
		t.Errorf("send buffer did not grow: before=%d after=%d want=%d", before, after, want)
	}
}

func TestSetForcedSendBufferDoesNotShrink(t *testing.T) {
	fd := newUDPSocket(t)
	if err := SetForcedSendBuffer(fd, 1<<20); err != nil {
		var clamp *BufferClampedError
		if !errors.As(err, &clamp) {
			t.Fatalf("baseline set: %v", err)
		}
	}
	before, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err := SetForcedSendBuffer(fd, 1024); err != nil {
		t.Fatalf("no-shrink call: %v", err)
	}
	after, _ := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if after < before {
		t.Errorf("send buffer was shrunk: before=%d after=%d", before, after)
	}
}

// TestRetryAtMaxsockbuf drives Darwin's ENOBUFS path with a fake setsockopt
// that, like XNU's sbreserve under the default 8 MiB kern.ipc.maxsockbuf,
// refuses anything above floor(8388608*2048/2304) = 7456540. The exact quotient
// is 7456540.44, so a wrong ratio or rounding lands on a size the fake refuses
// or on the wrong Got.
func TestRetryAtMaxsockbuf(t *testing.T) {
	const (
		defaultMaxsockbuf = 8 << 20 // macOS default kern.ipc.maxsockbuf
		ceiling           = 7456540 // largest size sbreserve accepts under it
		shredsRcvbuf      = 8 << 20 // blockcast-shreds' default --rcvbuf
	)
	for _, tc := range []struct {
		name       string
		want       int
		maxsockbuf uint32
		sysctlErr  error
		setErr     error // returned for every call instead of the sbreserve check
		wantCalls  []int
		wantGot    int   // non-zero: expect *BufferClampedError with this Got
		wantErr    error // otherwise: expect errors.Is(err, wantErr), or nil
	}{
		{
			name: "default rcvbuf on stock macOS clamps to the ceiling",
			want: shredsRcvbuf, maxsockbuf: defaultMaxsockbuf,
			wantCalls: []int{shredsRcvbuf, ceiling}, wantGot: ceiling,
		},
		{
			name: "request at the ceiling is accepted as is",
			want: ceiling, maxsockbuf: defaultMaxsockbuf,
			wantCalls: []int{ceiling},
		},
		{
			name: "other setsockopt errors pass through without a retry",
			want: shredsRcvbuf, maxsockbuf: defaultMaxsockbuf, setErr: syscall.EBADF,
			wantCalls: []int{shredsRcvbuf}, wantErr: syscall.EBADF,
		},
		{
			name: "unreadable maxsockbuf keeps the ENOBUFS",
			want: shredsRcvbuf, sysctlErr: syscall.ENOENT,
			wantCalls: []int{shredsRcvbuf}, wantErr: syscall.ENOBUFS,
		},
		{
			name: "ENOBUFS under a higher maxsockbuf is not a clamp",
			want: shredsRcvbuf, maxsockbuf: 2 * defaultMaxsockbuf,
			wantCalls: []int{shredsRcvbuf}, wantErr: syscall.ENOBUFS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []int
			set := func(n int) error {
				calls = append(calls, n)
				if tc.setErr != nil {
					return tc.setErr
				}
				if n > ceiling {
					return syscall.ENOBUFS
				}
				return nil
			}
			err := retryAtMaxsockbuf(tc.want, set,
				func() (uint32, error) { return tc.maxsockbuf, tc.sysctlErr })

			if !slices.Equal(calls, tc.wantCalls) {
				t.Errorf("setsockopt calls = %v, want %v", calls, tc.wantCalls)
			}
			var clamp *BufferClampedError
			if tc.wantGot != 0 {
				if !errors.As(err, &clamp) {
					t.Fatalf("want *BufferClampedError, got %v", err)
				}
				if clamp.Requested != tc.want || clamp.Got != tc.wantGot || clamp.EffectiveCeiling() != tc.wantGot {
					t.Errorf("clamp = {Requested %d, Got %d, EffectiveCeiling %d}, want {%d, %d, %d}",
						clamp.Requested, clamp.Got, clamp.EffectiveCeiling(), tc.want, tc.wantGot, tc.wantGot)
				}
				return
			}
			if errors.As(err, &clamp) {
				t.Fatalf("unexpected *BufferClampedError: %v", err)
			}
			if !errors.Is(err, tc.wantErr) { // errors.Is(err, nil) is err == nil
				t.Errorf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
