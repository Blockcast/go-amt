package amt

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// receiveOverlapTransport decorates a Transport and records the high-water mark
// of concurrent Receive calls. RelayManager has exactly two Receive call sites --
// performHandshake and readLoop -- and they must never be in flight together:
// they read one socket into separate buffers, so an overlap lets the reader
// consume the handshake's Relay Advertisement (or the reverse), which presents in
// the field as a handshake timing out against a relay that did in fact answer.
//
// Overlap is measured, not inferred. inFlight is incremented on entry and
// decremented on exit; maxSeen keeps the largest value ever observed.
//
// The naked counter is not enough on its own. Both guards that serialize these
// call sites -- waitLoops() before the reconnect handshake, and receiveMu around
// each Receive -- can be removed and the counter still never sees 2, because the
// reader is unblocked by transport.Close() and exits while the reconnecting
// goroutine is still doing socket setup. The race is real but far too narrow to
// land on. So this decorator can also *hold* one call inside Receive (see
// armHold), which pries the window open deterministically and turns a
// once-in-a-million interleaving into the default one.
type receiveOverlapTransport struct {
	Transport

	inFlight  atomic.Int32
	maxSeen   atomic.Int32
	calls     atomic.Int64
	deadlines atomic.Int64 // only performHandshake calls SetReadDeadline

	holdArmed   atomic.Bool
	holdEntered chan struct{} // closed once a call is parked inside Receive
	holdRelease chan struct{} // closed by the test to let that call out
	releaseOnce sync.Once
}

func newReceiveOverlapTransport(inner Transport) *receiveOverlapTransport {
	return &receiveOverlapTransport{
		Transport:   inner,
		holdEntered: make(chan struct{}),
		holdRelease: make(chan struct{}),
	}
}

func (t *receiveOverlapTransport) Receive(buf []byte) (int, net.Addr, error) {
	depth := t.inFlight.Add(1)
	t.calls.Add(1)
	for {
		prev := t.maxSeen.Load()
		if depth <= prev || t.maxSeen.CompareAndSwap(prev, depth) {
			break
		}
	}
	defer t.inFlight.Add(-1)

	n, addr, err := t.Transport.Receive(buf)

	// Park this call inside Receive, still counted in inFlight. Exactly one call
	// is ever held: the CAS disarms the hold as it fires.
	if t.holdArmed.CompareAndSwap(true, false) {
		close(t.holdEntered)
		<-t.holdRelease
	}
	return n, addr, err
}

func (t *receiveOverlapTransport) SetReadDeadline(deadline time.Time) error {
	t.deadlines.Add(1)
	return t.Transport.SetReadDeadline(deadline)
}

// armHold makes the next Receive to return from the underlying transport park
// inside Receive until releaseHold is called.
func (t *receiveOverlapTransport) armHold() { t.holdArmed.Store(true) }

func (t *receiveOverlapTransport) releaseHold() {
	t.releaseOnce.Do(func() { close(t.holdRelease) })
}

// newOverlapProbedManager wires a RelayManager to the fake relay through a
// receiveOverlapTransport, using the RelayManagerConfig.TransportFactory seam.
//
// The factory runs exactly once, inside Open, on the caller's goroutine -- and
// reconnection reuses that Transport rather than constructing a new one, so this
// single probe covers the initial handshake, every readLoop generation and every
// reconnect handshake.
func newOverlapProbedManager(t *testing.T, fr *fakeRelay) (*RelayManager, *receiveOverlapTransport) {
	t.Helper()

	cfg := DefaultRelayManagerConfig(fr.Addr())
	cfg.EnableDRIAD = false
	cfg.TransportConfig.RelayAddr = fr.Addr()
	cfg.TransportConfig.Timeout = 2 * time.Second
	cfg.InitialBackoff = 10 * time.Millisecond
	cfg.MaxBackoff = 100 * time.Millisecond
	// Stop the keepalive data-liveness check from firing a reconnect of its own;
	// this test drives reconnects itself and asserts on loop generations.
	cfg.KeepaliveInterval = 30 * time.Second

	var probe *receiveOverlapTransport
	cfg.TransportFactory = func(tc TransportConfig) (Transport, error) {
		inner, err := CreatePlatformTransport(tc)
		if err != nil {
			return nil, err
		}
		probe = newReceiveOverlapTransport(inner)
		return probe, nil
	}

	rm := NewRelayManager(cfg)
	// Release before Close: Close waits on the loops, which cannot exit while a
	// reader is parked in the hold.
	t.Cleanup(func() {
		if probe != nil {
			probe.releaseHold()
		}
		_ = rm.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}
	if probe == nil {
		t.Fatal("TransportFactory was never called: Open still builds its own transport")
	}
	return rm, probe
}

// waitFor polls cond until it holds or the deadline expires. Polling a condition
// is deliberate: the test must not synchronise on a fixed sleep, because a sleep
// long enough to be reliable would also be long enough to hide what it is
// looking for.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", timeout, what)
}

// TestReceiveIsSerializedAcrossHandshakeAndReadLoop pins defect 6: transport
// Receive must never be concurrent across performHandshake and readLoop.
//
// The test parks a reader inside Receive -- verified through the probe, not
// assumed -- and only then drives a reconnect, so the reconnect handshake runs
// with a reader demonstrably still inside Receive on the same socket. Any path
// that lets the handshake reach Receive in that state is an overlap and is
// reported.
//
// Two independent guards prevent it today and either one alone is sufficient, so
// this fails when the last of them is removed rather than the first. Revert
// matrix, measured:
//
//	receiveMu   waitLoops   result
//	   yes         yes      PASS (shipping configuration)
//	   no          yes      PASS -- waitLoops fences the reader out first
//	   yes         no       PASS -- the handshake blocks on receiveMu
//	   no          no       FAIL -- 2 concurrent Receive calls observed
func TestReceiveIsSerializedAcrossHandshakeAndReadLoop(t *testing.T) {
	fr := newFakeRelay(t)
	rm, probe := newOverlapProbedManager(t, fr)

	// The initial handshake ran on this goroutine and has returned, so anything
	// in flight now is the reader. Wait for it to actually park in Receive:
	// reconnecting before that leaves nothing to overlap with, and every
	// assertion below would pass vacuously.
	waitFor(t, 5*time.Second, func() bool {
		return probe.inFlight.Load() == 1
	}, "readLoop to enter Receive")

	rm.loopsMu.Lock()
	genBefore := rm.loopGeneration
	rm.loopsMu.Unlock()
	deadlinesBefore := probe.deadlines.Load()

	// Hold the reader inside Receive the moment transport.Close() unblocks it.
	probe.armHold()

	reconnectDone := make(chan struct{})
	go func() {
		defer close(reconnectDone)
		rm.reconnectWithBackoff()
	}()

	select {
	case <-probe.holdEntered:
	case <-time.After(10 * time.Second):
		probe.releaseHold()
		t.Fatal("no Receive was ever held: the reader never returned from Receive, " +
			"so the reconnect handshake never ran against a parked reader")
	}

	// The held call is the reader, not the handshake: the handshake announces
	// itself with SetReadDeadline, which readLoop never calls.
	if got := probe.deadlines.Load(); got != deadlinesBefore {
		probe.releaseHold()
		t.Fatalf("SetReadDeadline count moved %d -> %d before the hold engaged: "+
			"the held call is the handshake, not the reader", deadlinesBefore, got)
	}

	// A reader is now parked inside Receive and the reconnect is live. Give the
	// handshake a generous window to reach its own Receive. This bound is a
	// detection window, not a synchronisation point: no assertion depends on it
	// having elapsed, and lengthening it can only make a defect easier to catch,
	// never introduce a false failure. Poll so a real overlap fails fast.
	const detectionWindow = 500 * time.Millisecond
	deadline := time.Now().Add(detectionWindow)
	for time.Now().Before(deadline) && probe.maxSeen.Load() < 2 {
		time.Sleep(time.Millisecond)
	}

	overlap := probe.maxSeen.Load()
	probe.releaseHold()

	if overlap > 1 {
		t.Fatalf("observed %d concurrent transport.Receive calls, want at most 1: "+
			"performHandshake and readLoop overlapped on one socket, so each can "+
			"consume the datagram the other is waiting for", overlap)
	}

	select {
	case <-reconnectDone:
	case <-time.After(15 * time.Second):
		t.Fatal("reconnect did not complete after the held reader was released")
	}

	// Non-vacuity: the reconnect really did re-handshake and restart a generation.
	rm.loopsMu.Lock()
	genAfter := rm.loopGeneration
	rm.loopsMu.Unlock()
	if genAfter == genBefore {
		t.Fatalf("loop generation did not advance across reconnect (%d): nothing was exercised", genAfter)
	}
	if got := probe.deadlines.Load(); got <= deadlinesBefore {
		t.Fatalf("SetReadDeadline count did not move (%d): the reconnect handshake never ran", got)
	}
	if got := rm.State(); got != RelayStateActive {
		t.Fatalf("state after reconnect = %v, want %v", got, RelayStateActive)
	}

	// The reader must be delivering again on the new generation.
	key := SubscriptionKey{Source: testHarnessSource, Group: testHarnessGroup, Port: testHarnessPort}
	sub := subscribeActive(t, rm, key)
	fr.SendData(testHarnessSource, testHarnessGroup, 4321, testHarnessPort, []byte("post-reconnect"))
	select {
	case <-sub.dataChan:
	case <-time.After(5 * time.Second):
		t.Fatal("no data after reconnect: the reader did not restart")
	}

	if got := probe.maxSeen.Load(); got > 1 {
		t.Fatalf("observed %d concurrent transport.Receive calls after reconnect, want at most 1", got)
	}
}
