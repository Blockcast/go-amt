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

// EnqueueResult reports how the bounded ring handled a packet. It exists so the
// ingress caller can tell a real delivery drop (EnqueueOverflow) apart from a
// shutdown-time rejection (EnqueueClosed), which is not a drop.
type EnqueueResult int

const (
	// enqueueUnknown is the zero value and is never returned. It exists so a
	// zero-valued EnqueueResult — a forgotten assignment, or a struct field that
	// was never set — does not silently read as "delivered". Callers branch on
	// delivery outcomes, so the default must be a value that fails loudly rather
	// than the success case.
	enqueueUnknown EnqueueResult = iota
	// EnqueueAccepted means the packet was copied into the ring for delivery.
	EnqueueAccepted
	// EnqueueOverflow means the ring was full and the packet was lost. This is
	// the only outcome that counts toward the documented drop counters.
	EnqueueOverflow
	// EnqueueClosed means the fan-out was already shut down. The packet was not
	// delivered, but it is a shutdown artifact rather than receiver overload,
	// so it must not be charged to the ring-overflow counters.
	EnqueueClosed
)

// String renders the result for logs and test failures.
func (r EnqueueResult) String() string {
	switch r {
	case enqueueUnknown:
		return "unknown"
	case EnqueueAccepted:
		return "accepted"
	case EnqueueOverflow:
		return "overflow"
	case EnqueueClosed:
		return "closed"
	default:
		return fmt.Sprintf("EnqueueResult(%d)", int(r))
	}
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

	// Per-destination ledger, indexed by destination position. Only the worker
	// goroutine writes these; they are atomic because DestinationStats reads
	// them from the caller's goroutine.
	destNames   []string
	destPackets []atomic.Uint64
	destBytes   []atomic.Uint64
	destDrops   []atomic.Uint64
	destErrors  []atomic.Uint64

	// sendBatch is writeUDPPacketBatch in production. It is a field so tests
	// can drive partial sends, which is the only condition under which batch
	// slot and destination index diverge observably.
	sendBatch func(*ipv4.PacketConn, []ipv4.Message, bool) (int, error)
}

// DestinationStat is one destination's entry in the delivery ledger.
//
// Packets+Drops equals the number of packets the worker has processed,
// whatever each destination's outcome was. That is what makes the ledger
// auditable — a per-destination shortfall cannot hide as a process-wide
// average.
//
// The equality is exact per destination at any instant, but across
// destinations only once the worker is quiesced. DestinationStats loads each
// counter independently while deliver may be mid-batch, and deliver charges
// its delivered destinations before its dropped ones, so a live snapshot can
// catch some destinations charged for the current packet and others not. A
// reader sampling a running worker is eventually consistent and must not
// alert on a transient cross-destination mismatch.
//
// WriteErrors is a subset of Drops. A drop is "this destination did not get
// this packet"; a write error is the narrower "the write for this destination
// actively failed". They differ because a partial sendmmsg abandons the
// remaining messages in the batch: those destinations are dropped without ever
// being attempted, and blaming them for a fault they did not cause would point
// at the wrong subscriber.
type DestinationStat struct {
	Destination string
	Packets     uint64
	Bytes       uint64
	Drops       uint64
	WriteErrors uint64
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
	names := make([]string, len(writers))
	for i := range writers {
		names[i] = fmt.Sprintf("writer[%d]", i)
	}
	f.initDestinations(names)
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// initDestinations sizes the per-destination ledger. It must be called before
// the worker starts, because the worker indexes these slices without a lock.
func (f *Fanout) initDestinations(names []string) {
	f.destNames = names
	f.destPackets = make([]atomic.Uint64, len(names))
	f.destBytes = make([]atomic.Uint64, len(names))
	f.destDrops = make([]atomic.Uint64, len(names))
	f.destErrors = make([]atomic.Uint64, len(names))
	if f.sendBatch == nil {
		f.sendBatch = writeUDPPacketBatch
	}
}

// DestinationStats returns the per-destination delivery ledger, indexed in
// configured destination order.
//
// This is the per-subscriber accounting surface: process-wide Stats cannot
// answer "is destination 7 actually receiving its stream", and the per-feed
// EgressObserver cannot either, because one feed fans out to every subscriber.
func (f *Fanout) DestinationStats() []DestinationStat {
	stats := make([]DestinationStat, len(f.destNames))
	for i := range f.destNames {
		stats[i] = DestinationStat{
			Destination: f.destNames[i],
			Packets:     f.destPackets[i].Load(),
			Bytes:       f.destBytes[i].Load(),
			Drops:       f.destDrops[i].Load(),
			WriteErrors: f.destErrors[i].Load(),
		}
	}
	return stats
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
	names := make([]string, len(addresses))
	for i, address := range addresses {
		names[i] = address.String()
	}
	f.initDestinations(names)
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// Enqueue copies packet into the bounded ring, attributing it to feedID.
//
// The two rejection reasons are reported separately because only one of them is
// a delivery drop. A full ring means the receiver could not keep up and the
// packet was lost; a closed fan-out means the process is shutting down and the
// ingress goroutine has not stopped reading yet. Charging both to the same
// counter lets shutdown inflate the ring-overflow metric, which is documented
// as ring-full only and would then disagree with Stats().DroppedPackets.
func (f *Fanout) Enqueue(feedID string, packet []byte) EnqueueResult {
	owned := queuedPacket{feedID: feedID, packet: append([]byte(nil), packet...)}

	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return EnqueueClosed
	}

	select {
	case f.queue <- owned:
		f.queuedPackets.Add(1)
		return EnqueueAccepted
	default:
		f.droppedPackets.Add(1)
		return EnqueueOverflow
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
	size := uint64(len(packet))
	if f.udpConn == nil {
		for i, writer := range f.writers {
			n, err := writer.Write(packet)
			if err != nil || n != len(packet) {
				// This path attempts every writer, so a failure here is always
				// attributable to the destination that produced it.
				f.destDrops[i].Add(1)
				f.destErrors[i].Add(1)
				failed++
				continue
			}
			f.destPackets[i].Add(1)
			f.destBytes[i].Add(size)
			delivered++
		}
		return delivered, failed
	}

	count := len(f.udpDest)
	messages, offset := f.rotatedMessages(packet)

	written, err := f.sendBatch(f.udpConn, messages, runtime.GOOS == "linux")
	if written < 0 || written > count {
		written = 0
	}
	// Batch position is not destination index: rotatedMessages started this
	// batch at offset, so batch slot i carries destination (offset+i)%count.
	// Charging the ledger by slot would smear a single broken subscriber
	// across every destination as the rotation walks, which is precisely the
	// fault this ledger exists to localise.
	for i := 0; i < written; i++ {
		destination := (offset + i) % count
		f.destPackets[destination].Add(1)
		f.destBytes[destination].Add(size)
	}
	for i := written; i < count; i++ {
		f.destDrops[(offset+i)%count].Add(1)
	}
	// sendmmsg stops at the first failure and abandons the rest of the batch,
	// so exactly one destination earns the write error; the rest were never
	// attempted and are dropped without blame.
	//
	// written < count is itself the failure signal, and err is not. A partial
	// sendmmsg reports the count with errno 0, so the kernel's error is nil:
	// sendmmsg returns errnoErr(errno) (x/net internal/socket/sys_linux.go),
	// errnoErr(0) is nil (internal/socket/error_unix.go), and ipv4.WriteBatch
	// wraps in an OpError only when that error is non-nil. Gating this on err
	// left WriteErrors permanently zero on Linux — dead for exactly the fault
	// the ledger exists to localise. The clamp above keeps slot written in
	// range, and the non-Linux loop below also leaves the failing message at
	// index written, so this holds on both paths.
	if written < count {
		f.destErrors[(offset+written)%count].Add(1)
	}

	delivered = uint64(written)
	failed = uint64(count - written)
	// A batch can report every message written and still surface an error. Do
	// not let that pass as a clean send, or a persistent fault is invisible.
	// This is a process-wide safety net only: with every message written there
	// is no destination to charge, so the ledger stays exact and silent.
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

// rotatedMessages builds the send batch for one packet, returning the batch
// and the destination offset it starts at, and advances the rotation by
// exactly one position.
//
// Every destination appears exactly once per batch, so rotation changes the
// ORDER of a send, never its membership: no destination can be skipped or
// served twice. The batch is ordered starting at f.next, so across count
// consecutive packets each destination leads exactly once.
//
// The returned offset is what lets a caller map a batch slot back to the
// destination it carried; without it a partial send cannot be attributed.
//
// The caller must be the single fan-out worker goroutine; f.next is
// deliberately unsynchronized because only that goroutine touches it.
func (f *Fanout) rotatedMessages(packet []byte) ([]ipv4.Message, int) {
	count := len(f.udpDest)
	offset := f.next
	messages := make([]ipv4.Message, count)
	for i := range f.udpDest {
		index := (offset + i) % count
		messages[i] = ipv4.Message{Buffers: [][]byte{packet}, Addr: f.udpDest[index]}
	}
	// Advance once per packet, not once per destination, so the starting
	// offset walks the destination list one position at a time.
	f.next = (f.next + 1) % count
	return messages, offset
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
