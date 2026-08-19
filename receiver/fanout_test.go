package receiver

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
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
		messages, _ := fanout.rotatedMessages(packet)
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

// TestFanoutLedgerChargesEachDestinationSeparately is the per-destination
// accounting criterion: packets, bytes, and a counted drop site at every drop.
//
// The pre-existing TestFanoutCountsWriteErrorsPerDestination asserts only the
// process-wide Stats aggregate despite its name, so nothing pinned that a
// shortfall is attributable to the destination that caused it. A per-feed
// EgressObserver cannot close that gap either: one feed fans out to every
// subscriber, so feed-level counters are identical whichever destination broke.
func TestFanoutLedgerChargesEachDestinationSeparately(t *testing.T) {
	const packets = 5
	good := &recordingWriter{}
	bad := &errorWriter{err: errors.New("destination unavailable")}
	fanout, err := NewFanout([]io.WriteCloser{good, bad}, packets, nil)
	if err != nil {
		t.Fatal(err)
	}

	packet := []byte("shred-payload")
	for i := 0; i < packets; i++ {
		if fanout.Enqueue("feed", packet) != EnqueueAccepted {
			t.Fatalf("packet %d dropped with a sized ring", i)
		}
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	ledger := fanout.DestinationStats()
	if len(ledger) != 2 {
		t.Fatalf("ledger has %d entries, want 2", len(ledger))
	}

	wantBytes := uint64(packets * len(packet))
	if got := ledger[0]; got.Packets != packets || got.Bytes != wantBytes || got.Drops != 0 || got.WriteErrors != 0 {
		t.Errorf("healthy destination = %+v, want packets=%d bytes=%d drops=0 errors=0", got, packets, wantBytes)
	}
	if got := ledger[1]; got.Packets != 0 || got.Bytes != 0 || got.Drops != packets || got.WriteErrors != packets {
		t.Errorf("broken destination = %+v, want packets=0 bytes=0 drops=%d errors=%d", got, packets, packets)
	}
}

// TestFanoutLedgerHoldsThePacketsPlusDropsInvariant pins the property that
// makes the ledger auditable: every destination accounts for every packet the
// worker processed, as either a delivery or a drop. A per-destination
// shortfall therefore cannot hide as a process-wide average.
func TestFanoutLedgerHoldsThePacketsPlusDropsInvariant(t *testing.T) {
	const packets = 7
	writers := []io.WriteCloser{
		&recordingWriter{},
		&errorWriter{err: errors.New("down")},
		&recordingWriter{},
	}
	fanout, err := NewFanout(writers, packets, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < packets; i++ {
		if fanout.Enqueue("feed", []byte("x")) != EnqueueAccepted {
			t.Fatalf("packet %d dropped", i)
		}
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	for index, stat := range fanout.DestinationStats() {
		if total := stat.Packets + stat.Drops; total != packets {
			t.Errorf("destination %d: packets+drops = %d, want %d (%+v)", index, total, packets, stat)
		}
		if stat.WriteErrors > stat.Drops {
			t.Errorf("destination %d: write errors %d exceed drops %d", index, stat.WriteErrors, stat.Drops)
		}
	}
}

// TestUDPFanoutLedgerIsExactUnderRotation is the regression guard for the
// batch-slot-versus-destination-index mapping. rotatedMessages reorders each
// batch, so charging the ledger by batch slot would walk a destination's
// counts onto its neighbours one position per packet. With every destination
// healthy the smearing bug and the correct mapping differ only in that the
// buggy version misattributes, so exact equal counts are the assertion.
func TestUDPFanoutLedgerIsExactUnderRotation(t *testing.T) {
	const (
		destinations = 4
		packets      = destinations * 3
	)
	listeners := make([]*net.UDPConn, destinations)
	addresses := make([]string, destinations)
	for i := range listeners {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		listeners[i] = conn
		addresses[i] = conn.LocalAddr().String()
		defer conn.Close()
	}

	fanout, err := NewUDPFanout(addresses, packets, nil)
	if err != nil {
		t.Fatal(err)
	}

	packet := []byte{0xde, 0xad, 0xbe, 0xef}
	for i := 0; i < packets; i++ {
		if fanout.Enqueue("feed", packet) != EnqueueAccepted {
			t.Fatalf("packet %d dropped with a sized ring", i)
		}
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	wantBytes := uint64(packets * len(packet))
	for index, stat := range fanout.DestinationStats() {
		if stat.Destination != addresses[index] {
			t.Errorf("ledger entry %d names %q, want %q", index, stat.Destination, addresses[index])
		}
		if stat.Packets != packets || stat.Bytes != wantBytes || stat.Drops != 0 {
			t.Errorf("destination %d = %+v, want packets=%d bytes=%d drops=0", index, stat, packets, wantBytes)
		}
	}
}

// TestUDPFanoutLedgerLocalisesTheBrokenDestination is the real regression
// guard for the batch-slot-versus-destination-index mapping.
//
// It needs a PARTIAL send to bite. With every destination healthy each slot is
// charged once per batch and each destination appears once per batch, so
// slot-charging and destination-charging produce identical totals and a
// healthy-path test proves nothing. Only when sendmmsg stops early do the two
// diverge: charging by slot would report that the first slots always succeed
// and the last always drop — pinning blame to a fixed POSITION while rotation
// walks a different subscriber through that position every packet.
//
// Here destination 2 is the broken one. Correct attribution charges every
// write error to destination 2 whatever slot it occupied; the slot-charging
// bug spreads those errors across all four.
//
// The two subtests model the two DIFFERENT contracts a partial send can
// present, because they disagree on the error and only one of them is
// production on Linux:
//
//   - sendmmsg reports the count with errno 0, so ipv4.WriteBatch returns
//     (slot, nil). This is the Linux path. A blame rule that requires a
//     non-nil error is dead here — which is the defect this pair pins.
//   - the non-Linux writeUDPPacketBatch loop returns (slot, err) with the
//     failing message at index slot.
//
// Blame must localise to destination 2 under BOTH. Covering only the
// error-returning shape passes green while the Linux path silently records
// nothing.
func TestUDPFanoutLedgerLocalisesTheBrokenDestination(t *testing.T) {
	const (
		count  = 4
		broken = 2
		rounds = count * 3
	)

	for _, contract := range []struct {
		name string
		// err is what the batch writer returns alongside the short count.
		err error
	}{
		{name: "linux_sendmmsg_reports_count_with_no_error", err: nil},
		{name: "non_linux_loop_reports_count_with_error", err: errors.New("destination unavailable")},
	} {
		t.Run(contract.name, func(t *testing.T) {
			fanout := &Fanout{udpDest: make([]*net.UDPAddr, count)}
			// deliver branches on udpConn, so the UDP path needs a real socket
			// even though the stubbed sendBatch never writes to it.
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fanout.udpConn = ipv4.NewPacketConn(conn)

			names := make([]string, count)
			for i := range fanout.udpDest {
				fanout.udpDest[i] = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000 + i}
				names[i] = fanout.udpDest[i].String()
			}
			// Stop the batch at whichever slot carries the broken destination,
			// which is where both contracts agree the first failure lands.
			fanout.sendBatch = func(_ *ipv4.PacketConn, messages []ipv4.Message, _ bool) (int, error) {
				for slot, message := range messages {
					if message.Addr.(*net.UDPAddr).Port-20000 == broken {
						return slot, contract.err
					}
				}
				return len(messages), nil
			}
			fanout.initDestinations(names)

			for round := 0; round < rounds; round++ {
				fanout.deliver([]byte("shred"))
			}

			for index, stat := range fanout.DestinationStats() {
				if index == broken {
					if stat.WriteErrors != rounds {
						t.Errorf("broken destination %d took %d write errors over %d packets, want %d (%+v)",
							index, stat.WriteErrors, rounds, rounds, stat)
					}
					if stat.Packets != 0 {
						t.Errorf("broken destination %d was credited %d deliveries, want 0", index, stat.Packets)
					}
					continue
				}
				if stat.WriteErrors != 0 {
					t.Errorf("healthy destination %d took %d write errors; blame is following batch position, not destination (%+v)",
						index, stat.WriteErrors, stat)
				}
			}

			// The invariant still holds on the partial-send path: unattempted
			// destinations are dropped, just not blamed.
			for index, stat := range fanout.DestinationStats() {
				if total := stat.Packets + stat.Drops; total != rounds {
					t.Errorf("destination %d: packets+drops = %d, want %d (%+v)", index, total, rounds, stat)
				}
			}
		})
	}
}
