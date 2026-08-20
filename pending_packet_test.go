package amt

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// This file carries no build tags on purpose, mirroring probe.go and
// amtmode.go. The pending-packet seam is shared by MulticastConn (cgo only) and
// ManagedConn (linux||darwin, no cgo), so tagging these to the cgo lane would
// leave the ManagedConn half asserted by nothing in the ordinary `test` and
// `race` jobs — the deselection shape that let BLO-28640 ship.

// openedConn returns a ManagedConn in the state Open leaves it in on success:
// openDone closed, so the data-plane methods do not block in waitOpen, and no
// native socket, so a read that is NOT served from pending would fall through
// to the tunnel branch and park on readBuffer. That fall-through is what makes
// these assertions sharp — a regression hangs rather than quietly passing, so
// each read below is run under a timeout.
func openedConn() *ManagedConn {
	openDone := make(chan struct{})
	close(openDone)
	return &ManagedConn{
		openDone:   openDone,
		done:       make(chan struct{}),
		readBuffer: make(chan *DataPacket),
	}
}

// readResult is one data-plane return, captured off-goroutine so a read that
// wrongly falls through to readBuffer shows up as a timeout instead of wedging
// the test binary.
type readResult struct {
	n    int
	src  net.Addr
	cm   *ipv4.ControlMessage
	err  error
	buf  []byte
	sent bool
}

func readWithin(t *testing.T, d time.Duration, fn func() readResult) readResult {
	t.Helper()
	ch := make(chan readResult, 1)
	go func() { ch <- fn() }()
	select {
	case got := <-ch:
		return got
	case <-time.After(d):
		t.Fatalf("read did not return within %v; the pending packet was not delivered and the read fell through to the socket/tunnel path", d)
		return readResult{}
	}
}

var (
	probePayload = []byte("SLT-table-bytes")
	probeSrc     = &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 5004}
)

// TestPendingPacketIsDeliveredByReadFrom is the core BLO-28740 item-2
// assertion: the datagram the probe had to consume in order to conclude native
// multicast works is owed to the caller, not thrown away.
//
// Discarding it cost a full signalling interval (>=5s) of startup latency on the
// signalling channel, because the packet the probe ate WAS the SLT the receiver
// was waiting for.
func TestPendingPacketIsDeliveredByReadFrom(t *testing.T) {
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, src: probeSrc})

	buf := make([]byte, 1500)
	got := readWithin(t, 2*time.Second, func() readResult {
		n, src, err := mc.ReadFrom(buf)
		return readResult{n: n, src: src, err: err}
	})

	if got.err != nil {
		t.Fatalf("ReadFrom: %v", got.err)
	}
	if !bytes.Equal(buf[:got.n], probePayload) {
		t.Errorf("ReadFrom returned %q, want the probe packet %q", buf[:got.n], probePayload)
	}
	if got.src.String() != probeSrc.String() {
		t.Errorf("ReadFrom returned source %v, want %v", got.src, probeSrc)
	}
}

// TestPendingPacketIsDeliveredByReadFromWithControlMessage covers the second
// read entry point, and additionally pins that the v4 control message survives
// the handover. A caller that branches on cm (TTL, destination address) would
// otherwise see the probe packet arrive stripped of it.
func TestPendingPacketIsDeliveredByReadFromWithControlMessage(t *testing.T) {
	cm := &ipv4.ControlMessage{TTL: 12, Dst: net.IPv4(239, 1, 2, 3)}
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, cm: cm, src: probeSrc})

	buf := make([]byte, 1500)
	got := readWithin(t, 2*time.Second, func() readResult {
		n, gotCM, src, err := mc.ReadFromWithControlMessage(buf)
		return readResult{n: n, cm: gotCM, src: src, err: err}
	})

	if got.err != nil {
		t.Fatalf("ReadFromWithControlMessage: %v", got.err)
	}
	if !bytes.Equal(buf[:got.n], probePayload) {
		t.Errorf("returned %q, want the probe packet %q", buf[:got.n], probePayload)
	}
	if got.cm == nil || got.cm.TTL != cm.TTL {
		t.Errorf("control message did not survive the handover: got %+v, want TTL %d", got.cm, cm.TTL)
	}
}

// TestPendingPacketIsDeliveredByReadBatch covers the batch entry point, which a
// receiver in the hot path uses in preference to ReadFrom. A pending packet
// visible to one read entry point and not the others would make delivery depend
// on which API the caller happens to hold.
func TestPendingPacketIsDeliveredByReadBatch(t *testing.T) {
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, src: probeSrc})

	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1500)}}}
	type batchResult struct {
		n   int
		err error
	}
	ch := make(chan batchResult, 1)
	go func() {
		n, err := mc.ReadBatch(ms, 0)
		ch <- batchResult{n, err}
	}()

	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatalf("ReadBatch: %v", got.err)
		}
		if got.n != 1 {
			t.Fatalf("ReadBatch returned %d messages, want 1", got.n)
		}
		if !bytes.Equal(ms[0].Buffers[0][:ms[0].N], probePayload) {
			t.Errorf("ReadBatch returned %q, want the probe packet %q", ms[0].Buffers[0][:ms[0].N], probePayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadBatch did not return; the pending packet was not delivered")
	}
}

// TestPendingPacketIsDeliveredExactlyOnce is the no-duplicate half of the
// net.PacketConn correctness criterion. The store is drained with an atomic
// Swap precisely so a second read cannot see the same bytes again.
//
// Asserted through the public read path rather than on pendingStore directly:
// a take() that returned the packet twice and a ReadFrom that forgot to take at
// all are different bugs, and only the read path catches both.
func TestPendingPacketIsDeliveredExactlyOnce(t *testing.T) {
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, src: probeSrc})

	buf := make([]byte, 1500)
	first := readWithin(t, 2*time.Second, func() readResult {
		n, src, err := mc.ReadFrom(buf)
		return readResult{n: n, src: src, err: err}
	})
	if first.err != nil || !bytes.Equal(buf[:first.n], probePayload) {
		t.Fatalf("first read did not return the probe packet: n=%d err=%v", first.n, first.err)
	}

	// The second read must NOT be served from pending. With no native socket
	// installed it falls through to the tunnel branch and blocks on readBuffer,
	// so "still blocked" is the passing outcome and a prompt return is the bug.
	ch := make(chan readResult, 1)
	go func() {
		n, src, err := mc.ReadFrom(buf)
		ch <- readResult{n: n, src: src, err: err}
	}()
	select {
	case got := <-ch:
		t.Fatalf("second read returned n=%d err=%v; the pending packet was delivered twice", got.n, got.err)
	case <-time.After(250 * time.Millisecond):
	}
	close(mc.done) // release the parked reader so the test does not leak it
	<-ch
}

// TestPendingStoreTakeIsRaceFree pins the concurrent property the atomic Swap
// buys: many readers arriving together, exactly one packet handed out.
//
// This is the -race lane's assertion. MulticastConn has no mutex on its data
// plane by design, so a pendingStore built on a plain field would be a data
// race between whichever two goroutines called Read first.
func TestPendingStoreTakeIsRaceFree(t *testing.T) {
	const readers = 64
	var store pendingStore
	store.put(&pendingPacket{buf: probePayload})

	var wg sync.WaitGroup
	var mu sync.Mutex
	takes := 0
	start := make(chan struct{})

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if pkt := store.take(); pkt != nil {
				mu.Lock()
				takes++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if takes != 1 {
		t.Errorf("%d of %d concurrent readers took the packet; exactly 1 must", takes, readers)
	}
}

// TestClosedConnDoesNotServePendingPacket keeps the pending drain on the right
// side of the closed check. A connection that has been closed owes its caller an
// error; handing back a packet it happens to still be holding would serve a read
// from a torn-down path, which is exactly the net.PacketConn violation
// BLO-28740 asks the switchover not to commit.
func TestClosedConnDoesNotServePendingPacket(t *testing.T) {
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, src: probeSrc})
	mc.closed = true

	buf := make([]byte, 1500)
	got := readWithin(t, 2*time.Second, func() readResult {
		n, src, err := mc.ReadFrom(buf)
		return readResult{n: n, src: src, err: err}
	})
	if got.err == nil {
		t.Fatalf("ReadFrom on a closed conn returned n=%d and no error; it must not serve the pending packet", got.n)
	}
}

// TestReadBatchWithNoRoomKeepsPendingPacket covers the one path that could drop
// the packet silently: a caller passing a zero-length batch. Returning (0, nil)
// having consumed it would lose a datagram with nothing to show for it, so the
// packet is put back and the next call gets it.
func TestReadBatchWithNoRoomKeepsPendingPacket(t *testing.T) {
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, src: probeSrc})

	n, err := mc.ReadBatch(nil, 0)
	if err != nil {
		t.Fatalf("ReadBatch(nil): %v", err)
	}
	if n != 0 {
		t.Fatalf("ReadBatch(nil) returned %d, want 0", n)
	}

	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1500)}}}
	got, err := mc.ReadBatch(ms, 0)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if got != 1 || !bytes.Equal(ms[0].Buffers[0][:ms[0].N], probePayload) {
		t.Errorf("the packet was dropped by the zero-length batch: n=%d payload=%q", got, ms[0].Buffers[0][:ms[0].N])
	}
}

// TestNoRoomReadBatchNeverHidesThePendingPacket is the ordering half of the
// no-room path, and it is the reason that path peeks instead of taking.
//
// The obvious implementation — take the packet, notice there is nowhere to put
// it, put it back — is not atomic. Between the take and the put the store is
// empty, and an empty store is exactly the condition under which a concurrent
// reader falls through to the socket. So:
//
//	reader A (zero-length batch) takes packet #1   -> store empty
//	reader B takes nil, reads the socket           -> delivers packet #2
//	reader A puts #1 back                          -> #1 delivered later
//
// Net: #2 ahead of #1, the precise reordering the pending-first check exists to
// prevent (Ally review on go-amt#58). peek() cannot produce that window because
// it never mutates the store.
//
// The assertion is one-sided and therefore not flaky: observing the packet is
// always legal, so a pass is never spurious, while a single nil observation is a
// definite regression. Under -race this also pins that peek and the concurrent
// readers are properly synchronised.
func TestNoRoomReadBatchNeverHidesThePendingPacket(t *testing.T) {
	const iterations = 2000
	mc := openedConn()
	mc.pending.put(&pendingPacket{buf: probePayload, src: probeSrc})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Observer stands in for a concurrent reader deciding whether it is owed a
	// buffered packet. Every nil it sees is a read that would have gone to the
	// socket and delivered a later packet first.
	var mu sync.Mutex
	vanished := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if mc.pending.peek() == nil {
				mu.Lock()
				vanished++
				mu.Unlock()
			}
		}
	}()

	for i := 0; i < iterations; i++ {
		n, err := mc.ReadBatch(nil, 0)
		if err != nil {
			t.Fatalf("ReadBatch(nil) iteration %d: %v", i, err)
		}
		if n != 0 {
			t.Fatalf("ReadBatch(nil) iteration %d returned %d, want 0", i, n)
		}
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if vanished != 0 {
		t.Errorf("a no-room ReadBatch made the pending packet invisible %d times; a concurrent reader would read the socket and deliver a later packet ahead of it", vanished)
	}

	// And it is still deliverable afterwards.
	ms := []ipv4.Message{{Buffers: [][]byte{make([]byte, 1500)}}}
	got, err := mc.ReadBatch(ms, 0)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if got != 1 || !bytes.Equal(ms[0].Buffers[0][:ms[0].N], probePayload) {
		t.Errorf("the packet did not survive %d no-room calls: n=%d payload=%q", iterations, got, ms[0].Buffers[0][:ms[0].N])
	}
}

// TestProbeReturnsThePacketItRead asserts the producer half at the shared
// implementation, so it holds for all three call sites at once — both conn.go
// branches and managed_conn_native.go.
//
// The old signature could not express this: it returned only a bool, so the
// bytes had nowhere to go and every caller necessarily discarded them.
func TestProbeReturnsThePacketItRead(t *testing.T) {
	conn := &probeConnStub{}
	pkt, native, err := probeNativeTraffic(conn, time.Second, 1500, func(b []byte) (int, error) {
		return copy(b, probePayload), nil
	})
	if err != nil {
		t.Fatalf("probeNativeTraffic: %v", err)
	}
	if !native {
		t.Fatal("probe should report native traffic when the read succeeds")
	}
	if !bytes.Equal(pkt, probePayload) {
		t.Errorf("probe returned %q, want the packet it read, %q", pkt, probePayload)
	}
}

// TestProbeReturnsNoPacketOnTimeout is the negative control for the above: a
// timed-out probe consumed nothing, so it must hand back nothing. A non-nil
// slice here would make the caller install a zero-length phantom packet as
// pending and deliver an empty datagram the network never sent.
func TestProbeReturnsNoPacketOnTimeout(t *testing.T) {
	conn := &probeConnStub{}
	pkt, native, err := probeNativeTraffic(conn, time.Second, 1500, func([]byte) (int, error) {
		return 0, &net.OpError{Op: "read", Err: timeoutError{}}
	})
	if err != nil {
		t.Fatalf("a probe timeout is a decision, not an error, but got: %v", err)
	}
	if native {
		t.Error("probe reported native traffic after a timeout")
	}
	if pkt != nil {
		t.Errorf("probe returned %q on timeout; it consumed no packet and must return none", pkt)
	}
}

// TestProbeDistinguishesZeroLengthDatagramFromSilence pins why probeNativeTraffic
// reports success through a bool rather than through len(pkt). A zero-length UDP
// datagram is legal and is real evidence the native path delivers; conflating it
// with "nothing arrived" would tunnel a working join.
func TestProbeDistinguishesZeroLengthDatagramFromSilence(t *testing.T) {
	conn := &probeConnStub{}
	pkt, native, err := probeNativeTraffic(conn, time.Second, 1500, func([]byte) (int, error) {
		return 0, nil
	})
	if err != nil {
		t.Fatalf("probeNativeTraffic: %v", err)
	}
	if !native {
		t.Error("a zero-length datagram is delivery; the probe must report native traffic")
	}
	if pkt == nil || len(pkt) != 0 {
		t.Errorf("probe returned %v, want a non-nil empty slice for a zero-length datagram", pkt)
	}
}

// timeoutError is a net.Error reporting a timeout, which is how the probe
// distinguishes "the window elapsed" from a real read failure.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
