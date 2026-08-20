//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"testing"
	"time"
)

// TestStopKeepaliveIsObservedByTheKeepaliveGoroutine guards the fix for the
// unsynchronised Gateway.leave field.
//
// It has teeth in three distinct ways, which is worth spelling out because a
// test over a concurrency fix can easily have none:
//
//  1. Reverting leave to a plain bool does not compile, because .Load()/.Store()
//     have no meaning on one. That is the primary guard and it is a build error
//     rather than a flake.
//  2. The read and the write genuinely run on different goroutines here, so if
//     leave were replaced by some other non-atomic mechanism that still
//     compiled, `go test -race` flags it. That only helps if CI runs these tests
//     under -race, which is why this change also adds -race to the cgo-test
//     job — before it, gateway.go had zero race coverage on CI (the only -race
//     job runs -tags purego, which deselects the file).
//  3. The assertion is the semantic that actually matters, not merely the
//     absence of a reported race: stopKeepalive exists so a failed Open does not
//     leak a goroutine reconnecting to a relay nobody is listening to, so the
//     signal has to be *observable* by that goroutine. An unsynchronised write
//     to a flag read in a bare for loop is not obliged to be.
func TestStopKeepaliveIsObservedByTheKeepaliveGoroutine(t *testing.T) {
	g := &Gateway{}

	observed := make(chan struct{})
	go func() {
		// Mirrors the shape of the real keepalive loop: a bare spin on the flag
		// with no synchronisation of its own, which is what made the plain-bool
		// version both a data race and potentially non-terminating.
		for {
			if g.leave.Load() {
				close(observed)
				return
			}
		}
	}()

	g.stopKeepalive()

	select {
	case <-observed:
	case <-time.After(10 * time.Second):
		t.Fatal("the keepalive goroutine never observed stopKeepalive; the signal must be " +
			"visible across goroutines or a failed Open leaks a goroutine that keeps " +
			"reconnecting to the relay")
	}
}
