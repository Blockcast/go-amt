// Package receiver implements the unicast receive and fan-out path used by
// bcast-shred-gw.
package receiver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"golang.org/x/net/ipv4"
)

// FanoutStats is a point-in-time snapshot of the bounded fan-out path.
// EgressPackets and WriteErrors are process-wide totals across every feed and
// every destination; per-feed attribution is reported to an EgressObserver.
type FanoutStats struct {
	QueuedPackets  uint64
	DroppedPackets uint64
	EgressPackets  uint64
	WriteErrors    uint64
}

// EgressObserver receives the per-feed outcome of each fanned-out packet.
// Counts are per destination write, so one received packet reports up to one
// egress per configured destination. Implementations must be safe for
// concurrent use: the fan-out worker calls them from its own goroutine.
type EgressObserver interface {
	AddEgress(feedID string, count uint64) error
	AddWriteErrors(feedID string, count uint64) error
}

// queuedPacket carries the originating feed alongside the packet so the worker
// can attribute delivery to a feed. A single process-wide Fanout serves every
// feed, so the worker cannot infer the feed from the packet itself.
type queuedPacket struct {
	feedID string
	packet []byte
}

// Fanout copies packets into a bounded ring and writes each packet to every
// destination from a dedicated worker. Enqueue never blocks the ingress path.
//
// The UDP path uses ONE socket and a single batched send per packet, never a
// per-destination worker pool. Sharding the send across goroutines is a
// measured regression, not a speedup: on the fan-out harness at N=42 the
// single-socket loop holds p50 161 microseconds while 1-shard and 8-shard
// variants degrade to 276 and 283 microseconds respectively.
type Fanout struct {
	writers  []io.WriteCloser
	queue    chan queuedPacket
	observer EgressObserver

	udpConn *ipv4.PacketConn
	udpDest []*net.UDPAddr
	// next rotates which destination is served first. Without it the send
	// order is fixed, which hands a persistent ~4 microsecond-per-position
	// latency advantage to whichever subscriber sits early in the list. An
	// auditable-SLA product cannot ship a delivery order correlated with
	// subscriber index.
	next int

	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup

	queuedPackets  atomic.Uint64
	droppedPackets atomic.Uint64
	egressPackets  atomic.Uint64
	writeErrors    atomic.Uint64
}

// NewFanout starts a bounded fan-out worker for writers. The worker owns and
// closes the writers. queueCapacity must be positive. observer may be nil, in
// which case only the process-wide Stats counters are maintained.
func NewFanout(writers []io.WriteCloser, queueCapacity int, observer EgressObserver) (*Fanout, error) {
	if len(writers) == 0 {
		return nil, errors.New("fan-out requires at least one destination")
	}
	for i, writer := range writers {
		if writer == nil {
			return nil, fmt.Errorf("fan-out destination %d is nil", i)
		}
	}
	if queueCapacity <= 0 {
		return nil, errors.New("fan-out queue capacity must be positive")
	}

	f := &Fanout{
		writers:  append([]io.WriteCloser(nil), writers...),
		queue:    make(chan queuedPacket, queueCapacity),
		observer: observer,
	}
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// NewUDPFanout starts a bounded fan-out worker over a single UDP socket. Each
// packet is sent to every destination as one batch, with the destination order
// rotated per packet so no subscriber holds a fixed position advantage.
func NewUDPFanout(destinations []string, queueCapacity int, observer EgressObserver) (*Fanout, error) {
	if len(destinations) == 0 {
		return nil, errors.New("fan-out requires at least one destination")
	}
	if queueCapacity <= 0 {
		return nil, errors.New("fan-out queue capacity must be positive")
	}

	addresses := make([]*net.UDPAddr, 0, len(destinations))
	for _, destination := range destinations {
		address, err := net.ResolveUDPAddr("udp4", destination)
		if err != nil {
			return nil, fmt.Errorf("resolve UDP destination %q: %w", destination, err)
		}
		if address.IP == nil || address.IP.To4() == nil {
			return nil, fmt.Errorf("UDP destination %q is not IPv4", destination)
		}
		addresses = append(addresses, address)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("open fan-out UDP socket: %w", err)
	}

	f := &Fanout{
		queue:    make(chan queuedPacket, queueCapacity),
		observer: observer,
		udpConn:  ipv4.NewPacketConn(conn),
		udpDest:  addresses,
	}
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// Enqueue copies packet into the bounded ring, attributing it to feedID. It
// returns false when the ring is full or the fan-out has been closed. Only ring
// overflow increments the drop counter.
func (f *Fanout) Enqueue(feedID string, packet []byte) bool {
	owned := queuedPacket{feedID: feedID, packet: append([]byte(nil), packet...)}

	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return false
	}

	select {
	case f.queue <- owned:
		f.queuedPackets.Add(1)
		return true
	default:
		f.droppedPackets.Add(1)
		return false
	}
}

// Stats returns a lock-free snapshot of the fan-out counters.
func (f *Fanout) Stats() FanoutStats {
	return FanoutStats{
		QueuedPackets:  f.queuedPackets.Load(),
		DroppedPackets: f.droppedPackets.Load(),
		EgressPackets:  f.egressPackets.Load(),
		WriteErrors:    f.writeErrors.Load(),
	}
}

// Close drains the ring, closes every destination, and waits for the worker.
func (f *Fanout) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		close(f.queue)
		f.mu.Unlock()

		f.wg.Wait()
		if f.udpConn != nil {
			f.closeErr = f.udpConn.Close()
			return
		}
		var errs []error
		for _, writer := range f.writers {
			if err := writer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		f.closeErr = errors.Join(errs...)
	})
	return f.closeErr
}

func (f *Fanout) run() {
	defer f.wg.Done()
	for item := range f.queue {
		delivered, failed := f.deliver(item.packet)
		f.egressPackets.Add(delivered)
		f.writeErrors.Add(failed)
		f.report(item.feedID, delivered, failed)
	}
}

// deliver writes one packet to every destination and reports how many landed.
func (f *Fanout) deliver(packet []byte) (delivered, failed uint64) {
	if f.udpConn == nil {
		for _, writer := range f.writers {
			n, err := writer.Write(packet)
			if err != nil || n != len(packet) {
				failed++
				continue
			}
			delivered++
		}
		return delivered, failed
	}

	count := len(f.udpDest)
	messages := f.rotatedMessages(packet)

	written, err := writeUDPPacketBatch(f.udpConn, messages, runtime.GOOS == "linux")
	if written < 0 || written > count {
		written = 0
	}
	delivered = uint64(written)
	failed = uint64(count - written)
	// A batch can report every message written and still surface an error. Do
	// not let that pass as a clean send, or a persistent fault is invisible.
	if err != nil && failed == 0 {
		failed = 1
	}
	return delivered, failed
}

// report attributes one packet's delivery outcome to its originating feed.
// Observer errors are deliberately ignored: scoring and accounting must never
// block or discard delivery work, so an unknown feed loses attribution rather
// than stalling the egress path.
func (f *Fanout) report(feedID string, delivered, failed uint64) {
	if f.observer == nil || feedID == "" {
		return
	}
	if delivered > 0 {
		_ = f.observer.AddEgress(feedID, delivered)
	}
	if failed > 0 {
		_ = f.observer.AddWriteErrors(feedID, failed)
	}
}

// rotatedMessages builds the send batch for one packet and advances the
// rotation by exactly one position.
//
// Every destination appears exactly once per batch, so rotation changes the
// ORDER of a send, never its membership: no destination can be skipped or
// served twice. The batch is ordered starting at f.next, so across count
// consecutive packets each destination leads exactly once.
//
// The caller must be the single fan-out worker goroutine; f.next is
// deliberately unsynchronized because only that goroutine touches it.
func (f *Fanout) rotatedMessages(packet []byte) []ipv4.Message {
	count := len(f.udpDest)
	messages := make([]ipv4.Message, count)
	for i := range f.udpDest {
		index := (f.next + i) % count
		messages[i] = ipv4.Message{Buffers: [][]byte{packet}, Addr: f.udpDest[index]}
	}
	// Advance once per packet, not once per destination, so the starting
	// offset walks the destination list one position at a time.
	f.next = (f.next + 1) % count
	return messages
}

// writeUDPPacketBatch keeps one socket on every platform.
//
// x/net/ipv4 only implements WriteBatch as a real sendmmsg on Linux. Its
// fallback for other platforms writes the FIRST message and returns 1 with no
// error, which on a fan-out means every destination after the first is
// silently dropped while the counters report a clean send. So non-Linux builds
// must loop explicitly rather than trust the batch API.
func writeUDPPacketBatch(conn *ipv4.PacketConn, messages []ipv4.Message, useBatch bool) (int, error) {
	if useBatch {
		return conn.WriteBatch(messages, 0)
	}

	written := 0
	for _, message := range messages {
		if len(message.Buffers) == 0 {
			return written, errors.New("fan-out message has no payload")
		}
		payload := message.Buffers[0]
		if len(payload) == 0 {
			return written, errors.New("fan-out message has an empty payload")
		}
		n, err := conn.WriteTo(payload, nil, message.Addr)
		if err != nil {
			return written, err
		}
		if n != len(payload) {
			return written, io.ErrShortWrite
		}
		written++
	}
	return written, nil
}
