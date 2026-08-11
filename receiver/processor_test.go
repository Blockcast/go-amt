package receiver

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
)

func TestNewProcessorRejectsMissingDependencies(t *testing.T) {
	tracker := newTestTracker(t)
	fanout, err := NewFanout([]io.WriteCloser{&packetRecorder{}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fanout.Close() })

	if _, err := NewProcessor(nil, tracker); err == nil {
		t.Fatal("NewProcessor(nil, tracker) succeeded")
	}
	if _, err := NewProcessor(fanout, nil); err == nil {
		t.Fatal("NewProcessor(fanout, nil) succeeded")
	}
}

func TestProcessorDeliversMalformedPacketAndCountsParseFailure(t *testing.T) {
	writer := &packetRecorder{}
	processor, fanout := newTestProcessor(t, writer)
	packet := []byte("not a shred")

	result := processor.Process(packet, time.Unix(100, 0))
	if !result.Enqueued || result.Parsed || result.Counted {
		t.Fatalf("result = %+v, want delivered-only outcome", result)
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	if got := writer.Packet(); string(got) != string(packet) {
		t.Fatalf("delivered packet = %q, want %q", got, packet)
	}
	if got := processor.Stats(); got != (ProcessorStats{IngressPackets: 1, ShredsUnparsed: 1}) {
		t.Fatalf("stats = %+v", got)
	}
}

func TestProcessorParsesAndDeduplicatesWithoutMutatingDelivery(t *testing.T) {
	writer := &packetRecorder{}
	processor, fanout := newTestProcessor(t, writer)
	packet := dataShredFixture(42, 100, 96)
	now := time.Unix(100, 0)

	first := processor.Process(packet, now)
	second := processor.Process(packet, now.Add(time.Millisecond))
	if first != (ProcessResult{Enqueued: true, Parsed: true, Counted: true}) {
		t.Fatalf("first result = %+v", first)
	}
	if second != (ProcessResult{Enqueued: true, Parsed: true, Counted: false}) {
		t.Fatalf("duplicate result = %+v", second)
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	packets := writer.Packets()
	if len(packets) != 2 {
		t.Fatalf("delivered %d packets, want 2", len(packets))
	}
	for i, got := range packets {
		if string(got) != string(packet) {
			t.Fatalf("packet %d changed during delivery", i)
		}
	}
	if got := processor.Stats(); got != (ProcessorStats{IngressPackets: 2}) {
		t.Fatalf("stats = %+v", got)
	}
}

func TestProcessorStillScoresWhenFanoutRejectsPacket(t *testing.T) {
	processor, fanout := newTestProcessor(t, &packetRecorder{})
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	result := processor.Process(dataShredFixture(42, 100, 96), time.Unix(100, 0))
	if result != (ProcessResult{Parsed: true, Counted: true}) {
		t.Fatalf("result = %+v, want scoring-only outcome", result)
	}
	if got := fanout.Stats().DroppedPackets; got != 0 {
		t.Fatalf("closed fan-out recorded %d overflow drops, want 0", got)
	}
}

func newTestProcessor(t *testing.T, writer io.WriteCloser) (*Processor, *Fanout) {
	t.Helper()
	fanout, err := NewFanout([]io.WriteCloser{writer}, 4)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(fanout, newTestTracker(t))
	if err != nil {
		t.Fatal(err)
	}
	return processor, fanout
}

func newTestTracker(t *testing.T) *erasure.Tracker {
	t.Helper()
	tracker, err := erasure.NewTracker(400*time.Millisecond, time.Unix(99, 0))
	if err != nil {
		t.Fatal(err)
	}
	return tracker
}

func dataShredFixture(slot uint64, index, fecSetIndex uint32) []byte {
	packet := make([]byte, 83)
	packet[64] = 0x90
	binary.LittleEndian.PutUint64(packet[65:73], slot)
	binary.LittleEndian.PutUint32(packet[73:77], index)
	binary.LittleEndian.PutUint32(packet[79:83], fecSetIndex)
	return packet
}

type packetRecorder struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *packetRecorder) Write(packet []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.packets = append(w.packets, append([]byte(nil), packet...))
	return len(packet), nil
}

func (w *packetRecorder) Close() error { return nil }

func (w *packetRecorder) Packet() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.packets) == 0 {
		return nil
	}
	return append([]byte(nil), w.packets[0]...)
}

func (w *packetRecorder) Packets() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	packets := make([][]byte, len(w.packets))
	for i, packet := range w.packets {
		packets[i] = append([]byte(nil), packet...)
	}
	return packets
}
