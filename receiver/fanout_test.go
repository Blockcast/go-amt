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

	fanout, err := NewUDPFanout(addresses, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	packet := []byte{0xde, 0xad, 0xbe, 0xef}
	if !fanout.Enqueue(packet) {
		t.Fatal("Enqueue() dropped packet with an empty ring")
	}
	packet[0] = 0

	var sourcePort int
	for i, listener := range listeners {
		if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 64)
		n, source, err := listener.ReadFromUDP(got)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			sourcePort = source.Port
		} else if source.Port != sourcePort {
			t.Fatalf("destination %d saw source port %d, want shared source port %d", i, source.Port, sourcePort)
		}
		if want := []byte{0xde, 0xad, 0xbe, 0xef}; !bytes.Equal(got[:n], want) {
			t.Fatalf("received %x, want %x", got[:n], want)
		}
	}
}

func TestFanoutCountsOverflowAtEnqueue(t *testing.T) {
	writer := newBlockingWriter()
	fanout, err := NewFanout([]io.WriteCloser{writer}, 1)
	if err != nil {
		t.Fatal(err)
	}

	if !fanout.Enqueue([]byte("first")) {
		t.Fatal("first packet dropped")
	}
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("fan-out worker did not enter writer")
	}
	if !fanout.Enqueue([]byte("second")) {
		t.Fatal("second packet did not fill ring")
	}
	if fanout.Enqueue([]byte("overflow")) {
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
	fanout, err := NewFanout([]io.WriteCloser{good, bad}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !fanout.Enqueue([]byte("packet")) {
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

func TestNewFanoutValidatesConfiguration(t *testing.T) {
	if _, err := NewFanout(nil, 1); err == nil {
		t.Fatal("NewFanout() accepted no destinations")
	}
	if _, err := NewFanout([]io.WriteCloser{nil}, 1); err == nil {
		t.Fatal("NewFanout() accepted a nil destination")
	}
	if _, err := NewFanout([]io.WriteCloser{&recordingWriter{}}, 0); err == nil {
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
