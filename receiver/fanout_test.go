package receiver

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestUDPFanoutWritesByteIdenticalPacketsToEveryDestination(t *testing.T) {
	listeners := make([]*net.UDPConn, 2)
	addresses := make([]string, 2)
	for i := range listeners {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = conn
		addresses[i] = conn.LocalAddr().String()
		defer conn.Close()
	}

	fanout, err := NewUDPFanout(addresses, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	packet := []byte{0xde, 0xad, 0xbe, 0xef}
	if fanout.Enqueue("feed", packet) != EnqueueAccepted {
		t.Fatal("Enqueue() dropped packet with an empty ring")
	}
	packet[0] = 0

	for _, listener := range listeners {
		if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		n, _, err := listener.ReadFromUDP(got)
		if err != nil {
			t.Fatal(err)
		}
		if want := []byte{0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(got[:n], want) {
			t.Fatalf("received %x, want %x", got[:n], want)
		}
	}
}

func TestFanoutCountsOverflowAtEnqueue(t *testing.T) {
	writer := newBlockingWriter()
	fanout, err := NewFanout([]io.WriteCloser{writer}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	if fanout.Enqueue("feed", []byte("first")) != EnqueueAccepted {
		t.Fatal("first packet dropped")
	}
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("fan-out worker did not enter writer")
	}
	if fanout.Enqueue("feed", []byte("second")) != EnqueueAccepted {
		t.Fatal("second packet did not fill ring")
	}
	if fanout.Enqueue("feed", []byte("overflow")) != EnqueueOverflow {
		t.Fatal("overflow packet was accepted")
	}

	stats := fanout.Stats()
	if stats.QueuedPackets != 2 || stats.DroppedPackets != 1 {
		t.Fatalf("Stats() = %+v, want queued=2 dropped=1", stats)
	}
	close(writer.release)
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	if got := writer.packetsCopy(); !equalPackets(got, [][]byte{[]byte("first"), []byte("second")}) {
		t.Fatalf("written packets = %q", got)
	}
	if got := fanout.Stats().EgressPackets; got != 2 {
		t.Fatalf("EgressPackets = %d, want 2", got)
	}
}

func TestFanoutCountsWriteErrorsPerDestination(t *testing.T) {
	good := &recordingWriter{}
	bad := &errorWriter{err: errors.New("destination unavailable")}
	fanout, err := NewFanout([]io.WriteCloser{good, bad}, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fanout.Enqueue("feed", []byte("packet")) != EnqueueAccepted {
		t.Fatal("packet dropped")
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	stats := fanout.Stats()
	if stats.EgressPackets != 1 || stats.WriteErrors != 1 {
		t.Fatalf("Stats() = %+v, want egress=1 write_errors=1", stats)
	}
}

// TestFanoutAttributesDeliveryToTheOriginatingFeed pins the attribution rule.
// One process-wide Fanout serves every feed, so the worker must charge each
// packet to the feed that enqueued it rather than to a global total or to
// whichever feed happened to enqueue last.
func TestFanoutAttributesDeliveryToTheOriginatingFeed(t *testing.T) {
	observer := &recordingObserver{}
	good := &recordingWriter{}
	bad := &errorWriter{err: errors.New("destination unavailable")}
	fanout, err := NewFanout([]io.WriteCloser{good, bad}, 4, observer)
	if err != nil {
		t.Fatal(err)
	}

	if fanout.Enqueue("feed-a", []byte("first")) != EnqueueAccepted {
		t.Fatal("feed-a packet dropped")
	}
	if fanout.Enqueue("feed-b", []byte("second")) != EnqueueAccepted {
		t.Fatal("feed-b packet dropped")
	}
	if fanout.Enqueue("feed-b", []byte("third")) != EnqueueAccepted {
		t.Fatal("second feed-b packet dropped")
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	// One good writer and one failing writer per packet: each packet yields
	// exactly one egress and one write error for its own feed.
	if got := observer.egressCopy(); got["feed-a"] != 1 || got["feed-b"] != 2 || len(got) != 2 {
		t.Fatalf("egress by feed = %v, want feed-a=1 feed-b=2", got)
	}
	if got := observer.writeErrorsCopy(); got["feed-a"] != 1 || got["feed-b"] != 2 || len(got) != 2 {
		t.Fatalf("write errors by feed = %v, want feed-a=1 feed-b=2", got)
	}

	// The process-wide totals stay consistent with the per-feed attribution.
	if stats := fanout.Stats(); stats.EgressPackets != 3 || stats.WriteErrors != 3 {
		t.Fatalf("Stats() = %+v, want egress=3 write_errors=3", stats)
	}
}

// TestFanoutSurvivesAnObserverThatRejectsTheFeed asserts that accounting never
// blocks or discards delivery work: an unknown feed loses attribution only.
func TestFanoutSurvivesAnObserverThatRejectsTheFeed(t *testing.T) {
	writer := &recordingWriter{}
	fanout, err := NewFanout([]io.WriteCloser{writer}, 2, rejectingObserver{})
	if err != nil {
		t.Fatal(err)
	}
	if fanout.Enqueue("unconfigured", []byte("packet")) != EnqueueAccepted {
		t.Fatal("packet dropped")
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	if got := writer.packets; !equalPackets(got, [][]byte{[]byte("packet")}) {
		t.Fatalf("written packets = %q, want the packet delivered despite observer rejection", got)
	}
	if stats := fanout.Stats(); stats.EgressPackets != 1 {
		t.Fatalf("Stats() = %+v, want egress=1", stats)
	}
}

func TestNewFanoutValidatesConfiguration(t *testing.T) {
	if _, err := NewFanout(nil, 1, nil); err == nil {
		t.Fatal("NewFanout() accepted no destinations")
	}
	if _, err := NewFanout([]io.WriteCloser{nil}, 1, nil); err == nil {
		t.Fatal("NewFanout() accepted a nil destination")
	}
	if _, err := NewFanout([]io.WriteCloser{&recordingWriter{}}, 0, nil); err == nil {
		t.Fatal("NewFanout() accepted zero queue capacity")
	}
}

type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	packets [][]byte
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
}

func (w *blockingWriter) Write(packet []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.mu.Lock()
	w.packets = append(w.packets, append([]byte(nil), packet...))
	w.mu.Unlock()
	return len(packet), nil
}

func (w *blockingWriter) Close() error { return nil }

func (w *blockingWriter) packetsCopy() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.packets...)
}

type recordingWriter struct {
	packets [][]byte
}

func (w *recordingWriter) Write(packet []byte) (int, error) {
	w.packets = append(w.packets, append([]byte(nil), packet...))
	return len(packet), nil
}

func (w *recordingWriter) Close() error { return nil }

type errorWriter struct {
	err error
}

func (w *errorWriter) Write([]byte) (int, error) { return 0, w.err }
func (w *errorWriter) Close() error              { return nil }

// recordingObserver captures per-feed egress attribution from the fan-out
// worker. The worker reports from its own goroutine, so access is guarded.
type recordingObserver struct {
	mu          sync.Mutex
	egress      map[string]uint64
	writeErrors map[string]uint64
}

func (o *recordingObserver) AddEgress(feedID string, count uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.egress == nil {
		o.egress = make(map[string]uint64)
	}
	o.egress[feedID] += count
	return nil
}

func (o *recordingObserver) AddWriteErrors(feedID string, count uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.writeErrors == nil {
		o.writeErrors = make(map[string]uint64)
	}
	o.writeErrors[feedID] += count
	return nil
}

func (o *recordingObserver) egressCopy() map[string]uint64 { return o.snapshot(o.egress) }

func (o *recordingObserver) writeErrorsCopy() map[string]uint64 { return o.snapshot(o.writeErrors) }

func (o *recordingObserver) snapshot(source map[string]uint64) map[string]uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make(map[string]uint64, len(source))
	for feedID, count := range source {
		result[feedID] = count
	}
	return result
}

// rejectingObserver models ReceiverMetrics rejecting an unconfigured feed.
type rejectingObserver struct{}

func (rejectingObserver) AddEgress(string, uint64) error      { return ErrUnknownFeed }
func (rejectingObserver) AddWriteErrors(string, uint64) error { return ErrUnknownFeed }

func equalPackets(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestFanoutRotatesDestinationOrder pins the ordering-fairness rule. An
// unrotated send loop hands a persistent ~4 microsecond-per-position latency
// advantage to whichever subscriber sits early in the destination list, which
// an auditable-SLA product cannot ship. Rotation must change the ORDER of each
// batch without ever changing its membership.
func TestFanoutRotatesDestinationOrder(t *testing.T) {
	const count = 4
	fanout := &Fanout{udpDest: make([]*net.UDPAddr, count)}
	for i := range fanout.udpDest {
		fanout.udpDest[i] = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000 + i}
	}

	packet := []byte{0x01, 0x02}
	leadCounts := make(map[int]int, count)
	for round := 0; round < count*3; round++ {
		messages := fanout.rotatedMessages(packet)
		if len(messages) != count {
			t.Fatalf("round %d produced %d messages, want %d", round, len(messages), count)
		}

		// Membership must be exactly the configured set, every time.
		seen := make(map[string]int, count)
		for _, message := range messages {
			seen[message.Addr.String()]++
		}
		if len(seen) != count {
			t.Fatalf("round %d addressed %d distinct destinations, want %d", round, len(seen), count)
		}
		for address, times := range seen {
			if times != 1 {
				t.Fatalf("round %d addressed %s %d times, want exactly 1", round, address, times)
			}
		}

		leadCounts[messages[0].Addr.(*net.UDPAddr).Port-20000]++
	}

	// Over 3 full cycles every destination should have led exactly 3 times.
	for index := 0; index < count; index++ {
		if leadCounts[index] != 3 {
			t.Fatalf("destination %d led %d times over 3 cycles, want 3; order is not rotating fairly (%v)",
				index, leadCounts[index], leadCounts)
		}
	}
}

// TestUDPFanoutDeliversEveryPacketExactlyOnceToEveryDestination is the
// acceptance criterion for the fan-out itself: N destinations each receive
// every shred exactly once. Rotation must not cause a drop or a duplicate.
func TestUDPFanoutDeliversEveryPacketExactlyOnceToEveryDestination(t *testing.T) {
	const destinations, packets = 5, 40

	listeners := make([]*net.UDPConn, destinations)
	addresses := make([]string, destinations)
	for i := range listeners {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetReadBuffer(1 << 20); err != nil {
			t.Logf("SetReadBuffer: %v", err)
		}
		listeners[i] = conn
		addresses[i] = conn.LocalAddr().String()
		defer conn.Close()
	}

	fanout, err := NewUDPFanout(addresses, packets*2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	for sequence := 0; sequence < packets; sequence++ {
		if fanout.Enqueue("feed", []byte{byte(sequence)}) != EnqueueAccepted {
			t.Fatalf("Enqueue dropped packet %d with a sized ring", sequence)
		}
	}

	for index, listener := range listeners {
		received := make(map[byte]int, packets)
		for count := 0; count < packets; count++ {
			if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 16)
			n, _, err := listener.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("destination %d received %d of %d packets: %v", index, count, packets, err)
			}
			if n != 1 {
				t.Fatalf("destination %d received a %d-byte packet, want 1", index, n)
			}
			received[buffer[0]]++
		}
		if len(received) != packets {
			t.Fatalf("destination %d received %d distinct packets, want %d", index, len(received), packets)
		}
		for sequence, times := range received {
			if times != 1 {
				t.Fatalf("destination %d received packet %d %d times, want exactly once", index, sequence, times)
			}
		}
	}

	if stats := fanout.Stats(); stats.EgressPackets != destinations*packets {
		t.Fatalf("EgressPackets = %d, want %d", stats.EgressPackets, destinations*packets)
	}
}

// TestEnqueueAfterCloseIsNotCountedAsOverflow separates the two rejection
// reasons. Both refuse the packet, but only a full ring means the receiver
// could not keep up; a closed fan-out means the process is shutting down while
// an ingress goroutine is still reading. Folding them together lets shutdown
// inflate DroppedPackets, which is documented as ring-full only.
func TestEnqueueAfterCloseIsNotCountedAsOverflow(t *testing.T) {
	fanout, err := NewFanout([]io.WriteCloser{&recordingWriter{}}, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	if got := fanout.Enqueue("feed", []byte("after close")); got != EnqueueClosed {
		t.Fatalf("Enqueue() after Close = %v, want %v", got, EnqueueClosed)
	}
	if got := fanout.Stats().DroppedPackets; got != 0 {
		t.Fatalf("DroppedPackets = %d after a post-close Enqueue, want 0; shutdown must not read as ring overflow", got)
	}
}
