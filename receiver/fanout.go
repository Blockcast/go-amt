// Package receiver implements the unicast receive and fan-out path used by
// bcast-shred-gw.
package receiver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
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
type Fanout struct {
	writers  []io.WriteCloser
	queue    chan queuedPacket
	observer EgressObserver

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

// NewUDPFanout dials each destination and starts a bounded fan-out worker.
func NewUDPFanout(destinations []string, queueCapacity int, observer EgressObserver) (*Fanout, error) {
	writers := make([]io.WriteCloser, 0, len(destinations))
	for _, destination := range destinations {
		conn, err := net.Dial("udp", destination)
		if err != nil {
			for _, writer := range writers {
				_ = writer.Close()
			}
			return nil, fmt.Errorf("dial UDP destination %q: %w", destination, err)
		}
		writers = append(writers, conn)
	}

	f, err := NewFanout(writers, queueCapacity, observer)
	if err != nil {
		for _, writer := range writers {
			_ = writer.Close()
		}
		return nil, err
	}
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
		var delivered, failed uint64
		for _, writer := range f.writers {
			n, err := writer.Write(item.packet)
			if err != nil || n != len(item.packet) {
				failed++
				continue
			}
			delivered++
		}
		f.egressPackets.Add(delivered)
		f.writeErrors.Add(failed)
		f.report(item.feedID, delivered, failed)
	}
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
