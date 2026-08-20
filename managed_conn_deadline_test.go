package amt

import (
	"testing"
	"time"
)

// halfOpenConn returns a ManagedConn in the state Open leaves it in while the
// probe window is still running: openDone and done both allocated, neither
// closed, and no native socket installed yet.
//
// That window is where every finding on this file has lived. It exists at all
// because Open holds mc.mu only for short sections at each end — see the Open
// doc — so anything that reads or mutates connection state can now land inside
// it, which it could not when the lock spanned the whole call.
func halfOpenConn() *ManagedConn {
	return &ManagedConn{
		openDone: make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// The deadline setters are the three methods that mutate connection state
// without being part of the data plane. Driving all three from one table is
// deliberate: the bug was that some methods waited and these did not, so a
// per-method test invites the next method to be added without one.
var deadlineSetters = []struct {
	name string
	call func(*ManagedConn) error
}{
	{"SetDeadline", func(mc *ManagedConn) error { return mc.SetDeadline(time.Now().Add(time.Minute)) }},
	{"SetReadDeadline", func(mc *ManagedConn) error { return mc.SetReadDeadline(time.Now().Add(time.Minute)) }},
	{"SetWriteDeadline", func(mc *ManagedConn) error { return mc.SetWriteDeadline(time.Now().Add(time.Minute)) }},
}

// TestDeadlineSettersWaitForOpen pins that the deadline setters wait for Open
// rather than silently succeeding against a half-built connection.
//
// Without the wait, each takes mu.RLock during the probe window, finds
// !usingTunnel && nativeConn == nil, falls through to the tunnel branch and
// returns nil having set nothing. Open then installs the native socket with no
// deadline on it, so a caller that opened in a goroutine and set a deadline on
// the main path gets a socket that blocks forever on a group that goes idle. The
// nil return is the whole problem: there is nothing to retry on.
//
// This is a regression of the same shape and origin as the ReadFrom park that
// this PR's Critical fixed, not a pre-existing gap — before the lock was
// narrowed, mu.RLock here queued behind Open's full-length write lock, so the
// deadline always landed on the final socket.
//
// Note the direction of the timing assertion. If the setters wait correctly the
// call never returns and the 100ms elapses, so a slow or loaded runner cannot
// fail this test spuriously; it can only ever miss a detection. The positive half
// below — that the call DOES return once Open completes — is what stops the test
// being satisfied by a method that simply hangs.
func TestDeadlineSettersWaitForOpen(t *testing.T) {
	for _, setter := range deadlineSetters {
		t.Run(setter.name, func(t *testing.T) {
			mc := halfOpenConn()

			returned := make(chan error, 1)
			go func() { returned <- setter.call(mc) }()

			select {
			case <-returned:
				t.Fatalf("%s returned while Open was still in flight: racing Open it "+
					"finds nativeConn nil, falls through to the tunnel branch, and "+
					"reports success without setting anything", setter.name)
			case <-time.After(100 * time.Millisecond):
			}

			close(mc.openDone)

			select {
			case <-returned:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s never returned after Open completed; waiting must not "+
					"become hanging", setter.name)
			}
		})
	}
}

// TestWaitOpenIsReleasedByClose pins the `done` arm of waitOpen's select, which
// is the reason blocking is the right choice for these methods rather than a
// hang waiting to happen.
//
// A caller cannot wait for Open itself — openMu and openDone are unexported — so
// returning an ErrNotOpen-style error would export a spin loop into every
// consumer. Blocking is only defensible because the wait is bounded in the
// direction that matters: Close releases waiters without waiting out the probe
// window, which has no cancellation path.
//
// Nothing pinned that arm, and a refactor narrowing waitOpen to `<-openDone`
// alone would leave the whole suite green while turning every racing call into a
// park until Open finishes. openDone is deliberately left open here, so the done
// arm is the only thing that can release these calls.
func TestWaitOpenIsReleasedByClose(t *testing.T) {
	for _, setter := range deadlineSetters {
		t.Run(setter.name, func(t *testing.T) {
			mc := halfOpenConn()

			returned := make(chan error, 1)
			go func() { returned <- setter.call(mc) }()

			close(mc.done)

			select {
			case <-returned:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s stayed parked after Close signalled done, with Open still "+
					"in its probe window: a shutdown must not be held up for the "+
					"remainder of a window that cannot be cancelled", setter.name)
			}
		})
	}
}
