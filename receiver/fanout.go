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

	"golang.org/x/net/ipv4"
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
	udpConn *ipv4.PacketConn
	udpDest []*net.UDPAddr
	next    int

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
	f, err := newFanout(queueCapacity)
	if err != nil {
		return nil, err
	}
	f.writers = append([]io.WriteCloser(nil), writers...)
	return f, nil
}

func newFanout(queueCapacity int) (*Fanout, error) {
	if queueCapacity <= 0 {
		return nil, errors.New("fan-out queue capacity must be positive")
	}
	f := &Fanout{
		queue: make(chan []byte, queueCapacity),
	}
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// NewUDPFanout starts a bounded fan-out worker using one UDP socket. Packets
// are sent as one batch, with destination order rotated for each packet.
func NewUDPFanout(destinations []string, queueCapacity int) (*Fanout, error) {
	if len(destinations) == 0 {
		return nil, errors.New("fan-out requires at least one destination")
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
	f, err := newFanout(queueCapacity)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	f.udpConn = ipv4.NewPacketConn(conn)
	f.udpDest = addresses
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
	for packet := range f.queue {
		if f.udpConn != nil {
			count := len(f.udpDest)
			messages := make([]ipv4.Message, count)
			for i := range f.udpDest {
				index := (f.next + i) % count
				messages[i] = ipv4.Message{Buffers: [][]byte{packet}, Addr: f.udpDest[index]}
			}
			f.next = (f.next + 1) % count
			written, err := f.udpConn.WriteBatch(messages, 0)
			f.egressPackets.Add(uint64(written))
			if written != count {
				f.writeErrors.Add(uint64(count - written))
			}
			if err != nil && written == count {
				f.writeErrors.Add(1)
			}
			continue
		}
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
