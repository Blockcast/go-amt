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

// fakeXNU is the sbreserve that setsockopt(SO_RCVBUF/SO_SNDBUF) calls, in
// both of its shapes:
//   - legacy (xnu-10002.81.5, macOS 14.3, and earlier) refuses any size above
//     sb_max*MCLBYTES/(MSIZE+MCLBYTES) = maxsockbuf*2048/2304;
//   - modern (xnu-10063.101.15, macOS 14.4, through xnu-12377) clamps a size
//     above sb_max to sb_max, and refuses only if the buffer is already there.
//
// Both refuse growth on an SB_LIMITED buffer. A refusal is ENOBUFS and leaves
// hiwat alone. getsockopt returns hiwat undoubled.
type fakeXNU struct {
	legacy  bool
	limited bool
	sbMax   int
	hiwat   int
	calls   []int
}

func (k *fakeXNU) set(cc int) error {
	k.calls = append(k.calls, cc)
	if k.legacy {
		if cc > k.sbMax*2048/2304 {
			return syscall.ENOBUFS
		}
	} else if cc > k.sbMax {
		if k.hiwat == k.sbMax {
			return syscall.ENOBUFS
		}
		cc = k.sbMax
	}
	if k.limited && cc > k.hiwat {
		return syscall.ENOBUFS
	}
	k.hiwat = cc
	return nil
}

// TestSetXNUBufferAtLeast drives Darwin's buffer set against both kernels. The
// legacy ceiling under the default 8 MiB maxsockbuf is
// floor(8388608*2048/2304) = 7456540; the exact quotient is 7456540.44, so a
// wrong ratio or rounding lands on a size the fake refuses or on the wrong Got.
func TestSetXNUBufferAtLeast(t *testing.T) {
	const (
		defaultMaxsockbuf = 8 << 20 // macOS default kern.ipc.maxsockbuf
		legacyCeiling     = 7456540 // largest size legacy sbreserve accepts under it
		udpRecvspace      = 786896  // macOS default UDP receive buffer
		shredsRcvbuf      = 8 << 20 // blockcast-shreds' default --rcvbuf
	)
	for _, tc := range []struct {
		name      string
		kernel    fakeXNU
		want      int
		sysctlErr error
		setErr    error // returned for every setsockopt instead of the fake
		getErr    error // returned for every getsockopt
		wantCalls []int
		wantGot   int   // non-zero: expect *BufferClampedError with this Got
		wantErr   error // otherwise: expect errors.Is(err, wantErr), or nil
		wantHiwat int   // the buffer size left behind
	}{
		{
			name:   "legacy: default rcvbuf retries at the ceiling and reports the clamp",
			kernel: fakeXNU{legacy: true, sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, wantCalls: []int{shredsRcvbuf, legacyCeiling},
			wantGot: legacyCeiling, wantHiwat: legacyCeiling,
		},
		{
			name:   "legacy: a request at the ceiling is accepted as is",
			kernel: fakeXNU{legacy: true, sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   legacyCeiling, wantCalls: []int{legacyCeiling}, wantHiwat: legacyCeiling,
		},
		{
			name:   "legacy: unreadable maxsockbuf reports the unchanged buffer as the clamp",
			kernel: fakeXNU{legacy: true, sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, sysctlErr: syscall.ENOENT,
			wantCalls: []int{shredsRcvbuf}, wantGot: udpRecvspace, wantHiwat: udpRecvspace,
		},
		{
			name:   "legacy: a refused retry reports the unchanged buffer as the clamp",
			kernel: fakeXNU{legacy: true, limited: true, sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, wantCalls: []int{shredsRcvbuf, legacyCeiling},
			wantGot: udpRecvspace, wantHiwat: udpRecvspace,
		},
		{
			name:   "ENOBUFS with the ceiling at or above the request is not retried",
			kernel: fakeXNU{legacy: true, limited: true, sbMax: 2 * defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, wantCalls: []int{shredsRcvbuf},
			wantGot: udpRecvspace, wantHiwat: udpRecvspace,
		},
		{
			name:   "modern: default rcvbuf equals maxsockbuf and is accepted in full",
			kernel: fakeXNU{sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, wantCalls: []int{shredsRcvbuf}, wantHiwat: shredsRcvbuf,
		},
		{
			name:   "modern: the silent clamp above maxsockbuf is reported",
			kernel: fakeXNU{sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   2 * shredsRcvbuf, wantCalls: []int{2 * shredsRcvbuf},
			wantGot: defaultMaxsockbuf, wantHiwat: defaultMaxsockbuf,
		},
		{
			name:   "modern: ENOBUFS at maxsockbuf does not shrink the buffer to the legacy ceiling",
			kernel: fakeXNU{sbMax: defaultMaxsockbuf, hiwat: defaultMaxsockbuf},
			want:   2 * shredsRcvbuf, wantCalls: []int{2 * shredsRcvbuf},
			wantGot: defaultMaxsockbuf, wantHiwat: defaultMaxsockbuf,
		},
		{
			name:   "a buffer already at least the request is left alone",
			kernel: fakeXNU{sbMax: 4 * defaultMaxsockbuf, hiwat: 2 * shredsRcvbuf},
			want:   shredsRcvbuf, wantHiwat: 2 * shredsRcvbuf,
		},
		{
			name:   "other setsockopt errors pass through without a retry",
			kernel: fakeXNU{legacy: true, sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, setErr: syscall.EBADF,
			wantCalls: []int{shredsRcvbuf}, wantErr: syscall.EBADF, wantHiwat: udpRecvspace,
		},
		{
			name:   "an unreadable size after the set is an error, not success",
			kernel: fakeXNU{sbMax: defaultMaxsockbuf, hiwat: udpRecvspace},
			want:   shredsRcvbuf, getErr: syscall.EBADF,
			wantCalls: []int{shredsRcvbuf}, wantErr: syscall.EBADF, wantHiwat: shredsRcvbuf,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := tc.kernel
			set := func(n int) error {
				if tc.setErr != nil {
					k.calls = append(k.calls, n)
					return tc.setErr
				}
				return k.set(n)
			}
			get := func() (int, error) { return k.hiwat, tc.getErr }
			err := setXNUBufferAtLeast(tc.want, get, set,
				func() (uint32, error) { return uint32(k.sbMax), tc.sysctlErr })

			if !slices.Equal(k.calls, tc.wantCalls) {
				t.Errorf("setsockopt calls = %v, want %v", k.calls, tc.wantCalls)
			}
			if k.hiwat != tc.wantHiwat {
				t.Errorf("buffer left at %d, want %d", k.hiwat, tc.wantHiwat)
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
