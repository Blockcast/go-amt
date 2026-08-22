//go:build linux

package amt

import (
	"errors"
	"syscall"
	"testing"
)

// TestBufferHoldsUnitMismatch pins the arithmetic that BLO-29351 turned up:
// getsockopt readbacks and setsockopt requests are in different units, and
// comparing them directly hides a whole class of clamps.
//
// The staging/production row is the one that actually bit us. A request of
// 7500000 against an rmem_max of 4194304 reads back as 8388608, and the old
// `got < want` check saw 8388608 >= 7500000 and reported success — while the
// socket was really capped at 56% of the ask, with no log line and no metric.
func TestBufferHoldsUnitMismatch(t *testing.T) {
	const (
		stagingRequest = 7500000 // MULTICAST_UDP_RCVBUF_BYTES on staging + prod
		poolRmemMax    = 4194304 // measured on the `data` pool (BLO-29361)
	)

	for _, tc := range []struct {
		name     string
		got      int // raw getsockopt readback (kernel-allocated, 2x accepted)
		want     int // setsockopt request
		holds    bool
		oldCheck bool // what the pre-fix `got >= want` comparison concluded
	}{
		{
			name:     "staging clamp the old check missed",
			got:      2 * poolRmemMax, // 8388608
			want:     stagingRequest,  // 7500000
			holds:    false,
			oldCheck: true, // <- the regression: silently "satisfied"
		},
		{
			name:     "request exactly honored",
			got:      2 * stagingRequest, // 15000000, as on the ARC runner
			want:     stagingRequest,
			holds:    true,
			oldCheck: true,
		},
		{
			name:     "catastrophic clamp both checks catch",
			got:      2 * 212992, // 425984, kernel default ceiling
			want:     stagingRequest,
			holds:    false,
			oldCheck: false,
		},
		{
			name:     "boundary: ceiling exactly half the request",
			got:      stagingRequest, // ceiling == want/2
			want:     stagingRequest,
			holds:    false,
			oldCheck: true,
		},
		{
			name:     "readback already above the request",
			got:      4 * stagingRequest,
			want:     stagingRequest,
			holds:    true,
			oldCheck: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bufferHolds(tc.got, tc.want); got != tc.holds {
				t.Errorf("bufferHolds(got=%d, want=%d) = %v, want %v",
					tc.got, tc.want, got, tc.holds)
			}
			// Guard the guard: assert each row really does distinguish the
			// fixed check from the broken one, so this table cannot rot into
			// a set of cases both implementations agree on.
			if oldCheck := tc.got >= tc.want; oldCheck != tc.oldCheck {
				t.Errorf("fixture drift: old check on (got=%d, want=%d) = %v, table says %v",
					tc.got, tc.want, oldCheck, tc.oldCheck)
			}
		})
	}
}

// TestBufferClampedErrorReportsCeiling checks the operator-facing arithmetic.
// "requested 7500000, allocated 8388608" reads like a success unless the
// effective ceiling is spelled out, which is precisely how the silent clamp
// survived review.
func TestBufferClampedErrorReportsCeiling(t *testing.T) {
	e := &BufferClampedError{Requested: 7500000, Got: 8388608}
	if got := e.EffectiveCeiling(); got != 4194304 {
		t.Fatalf("EffectiveCeiling() = %d, want 4194304", got)
	}
	if msg := e.Error(); msg == "" {
		t.Fatal("empty error message")
	}
}

// TestKernelDoublesSetsockoptInput pins the kernel contract bufferHolds is
// built on: Linux stores 2x the accepted setsockopt input. If a future kernel
// stops doubling, bufferHolds silently under-reports every buffer by half and
// this test is the thing that says so.
func TestKernelDoublesSetsockoptInput(t *testing.T) {
	fd := newUDPSocket(t)

	// Comfortably above the 212992 default so the no-shrink path cannot
	// short-circuit us, and small enough to clear any plausible rmem_max.
	const want = 262144

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, want); err != nil {
		t.Fatalf("setsockopt SO_RCVBUF %d: %v", want, err)
	}
	got, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatalf("getsockopt SO_RCVBUF: %v", err)
	}
	if got < want {
		t.Skipf("host clamps below %d (rmem_max too low, readback %d); doubling not observable", want, got)
	}
	if got != 2*want {
		t.Errorf("kernel doubling contract broken: setsockopt(%d) read back %d, want %d — bufferHolds() assumes 2x",
			want, got, 2*want)
	}
}

// TestSetForcedReceiveBufferReportsClampWhenUnprivileged exercises the real
// syscall path end to end. Without CAP_NET_ADMIN a request above rmem_max must
// now surface a *BufferClampedError instead of returning nil.
func TestSetForcedReceiveBufferReportsClampWhenUnprivileged(t *testing.T) {
	fd := newUDPSocket(t)

	// Find the host ceiling by asking for far more than any sane rmem_max.
	const probe = 1 << 30
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, probe); err != nil {
		t.Fatalf("probe setsockopt: %v", err)
	}
	readback, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		t.Fatalf("probe getsockopt: %v", err)
	}
	ceiling := readback / 2
	if ceiling >= probe {
		t.Skip("host has no effective rmem_max ceiling; nothing to clamp against")
	}

	// Ask for more than the ceiling on a fresh socket. If the process holds
	// CAP_NET_ADMIN (as the ARC runner does) SO_RCVBUFFORCE succeeds and there
	// is legitimately no clamp — skip rather than fail.
	fresh := newUDPSocket(t)
	over := ceiling * 2
	gotErr := SetForcedReceiveBuffer(fresh, over)
	if gotErr == nil {
		after, _ := syscall.GetsockoptInt(fresh, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		if after/2 >= over {
			t.Skipf("CAP_NET_ADMIN present: request %d honored via SO_RCVBUFFORCE", over)
		}
		t.Fatalf("request %d clamped to %d but no BufferClampedError returned", over, after/2)
	}
	var clamp *BufferClampedError
	if !errors.As(gotErr, &clamp) {
		t.Fatalf("want *BufferClampedError, got %v", gotErr)
	}
	if clamp.EffectiveCeiling() >= over {
		t.Errorf("reported ceiling %d should be below the %d request", clamp.EffectiveCeiling(), over)
	}
}
