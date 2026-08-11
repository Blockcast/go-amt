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
type FanoutStats struct {
	QueuedPackets  uint64
	DroppedPackets uint64
	EgressPackets  uint64
	WriteErrors    uint64
}

// Fanout copies packets into a bounded ring and writes each packet to every
// destination from a dedicated worker. Enqueue never blocks the ingress path.
type Fanout struct {
	writers []io.WriteCloser
	queue   chan []byte

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
// closes the writers. queueCapacity must be positive.
func NewFanout(writers []io.WriteCloser, queueCapacity int) (*Fanout, error) {
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
		writers: append([]io.WriteCloser(nil), writers...),
		queue:   make(chan []byte, queueCapacity),
	}
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// NewUDPFanout dials each destination and starts a bounded fan-out worker.
func NewUDPFanout(destinations []string, queueCapacity int) (*Fanout, error) {
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

	f, err := NewFanout(writers, queueCapacity)
	if err != nil {
		for _, writer := range writers {
			_ = writer.Close()
		}
		return nil, err
	}
	return f, nil
}

// Enqueue copies packet into the bounded ring. It returns false when the ring
// is full or the fan-out has been closed. Only ring overflow increments the
// drop counter.
func (f *Fanout) Enqueue(packet []byte) bool {
	owned := append([]byte(nil), packet...)

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
	for packet := range f.queue {
		for _, writer := range f.writers {
			n, err := writer.Write(packet)
			if err != nil || n != len(packet) {
				f.writeErrors.Add(1)
				continue
			}
			f.egressPackets.Add(1)
		}
	}
}
