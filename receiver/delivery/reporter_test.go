package delivery

import (
	"errors"
	"strings"
	"testing"
)

// captureSink records everything shipped and can be told to fail.
type captureSink struct {
	shipped []Record
	failing bool
	err     error
}

func (c *captureSink) Ship(record Record) error {
	if c.failing {
		if c.err != nil {
			return c.err
		}
		return errors.New("sink unavailable")
	}
	c.shipped = append(c.shipped, record)
	return nil
}

func (c *captureSink) forDestination(destination string) []Record {
	var out []Record
	for _, record := range c.shipped {
		if record.SubscriberID == destination {
			out = append(out, record)
		}
	}
	return out
}

func newTestReporter(t *testing.T) (*Reporter, *captureSink) {
	t.Helper()
	tracker, err := NewTracker(NewMemorySeqStore())
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}
	sink := &captureSink{}
	reporter, err := NewReporter(tracker, sink)
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}
	return reporter, sink
}

// TestTickBillsLedgerTotalExactlyOnce is the regression test for the
// cumulative-versus-delta hazard. The ledger is cumulative, so a Reporter that
// forwarded it straight to Observe would bill 10+30+60 = 100 bytes for 60 bytes
// of traffic. Summed BytesOut must equal the final ledger reading exactly.
func TestTickBillsLedgerTotalExactlyOnce(t *testing.T) {
	reporter, sink := newTestReporter(t)

	ledger := []struct{ bytes, packets uint64 }{
		{10, 1},
		{30, 3},
		{60, 6},
	}
	for _, reading := range ledger {
		if err := reporter.Tick([]LedgerSample{
			{Destination: "10.0.0.1:8000", Bytes: reading.bytes, Packets: reading.packets},
		}); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}

	var billedBytes, billedPackets uint64
	for _, record := range sink.forDestination("10.0.0.1:8000") {
		billedBytes += record.BytesOut
		billedPackets += record.PacketsOut
	}
	if billedBytes != 60 {
		t.Errorf("summed bytes_out = %d, want 60 (the final ledger reading)", billedBytes)
	}
	if billedPackets != 6 {
		t.Errorf("summed packets_out = %d, want 6", billedPackets)
	}
}

// TestTickOpensOneSessionPerDestination pins that sessions follow the fan-out
// destination set and that each destination bills only its own traffic.
func TestTickOpensOneSessionPerDestination(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{Destination: "10.0.0.1:8000", Bytes: 100, Packets: 10},
		{Destination: "10.0.0.2:8000", Bytes: 250, Packets: 25},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	first := sink.forDestination("10.0.0.1:8000")
	second := sink.forDestination("10.0.0.2:8000")
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("records per destination = %d/%d, want 1/1", len(first), len(second))
	}
	if first[0].BytesOut != 100 {
		t.Errorf("first destination bytes_out = %d, want 100", first[0].BytesOut)
	}
	if second[0].BytesOut != 250 {
		t.Errorf("second destination bytes_out = %d, want 250", second[0].BytesOut)
	}
	if first[0].SessionID == second[0].SessionID {
		t.Error("both destinations share a session ID; sessions must be per destination")
	}
}

// TestRefusedRecordIsRetransmittedVerbatim pins Emit's retry contract. A
// refused record must come back byte-identical, and the interval it covers must
// not be re-emitted as a fresh record — that is the silent under-bill the
// contract warns about.
func TestRefusedRecordIsRetransmittedVerbatim(t *testing.T) {
	reporter, sink := newTestReporter(t)

	sink.failing = true
	err := reporter.Tick([]LedgerSample{{Destination: "10.0.0.1:8000", Bytes: 40, Packets: 4}})
	if err == nil {
		t.Fatal("Tick returned nil while the sink was refusing records")
	}
	if reporter.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1 after a refused shipment", reporter.Pending())
	}
	if len(sink.shipped) != 0 {
		t.Fatalf("sink accepted %d records while failing", len(sink.shipped))
	}

	// More traffic arrives while the sink is still down.
	if err := reporter.Tick([]LedgerSample{{Destination: "10.0.0.1:8000", Bytes: 90, Packets: 9}}); err == nil {
		t.Fatal("Tick returned nil while the sink was still refusing records")
	}
	if reporter.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1; a second record must not be emitted while one is owed", reporter.Pending())
	}

	// Sink recovers.
	sink.failing = false
	if err := reporter.Tick([]LedgerSample{{Destination: "10.0.0.1:8000", Bytes: 90, Packets: 9}}); err != nil {
		t.Fatalf("Tick after recovery: %v", err)
	}
	if reporter.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0 after recovery", reporter.Pending())
	}

	records := sink.forDestination("10.0.0.1:8000")
	var billed uint64
	for _, record := range records {
		billed += record.BytesOut
	}
	// 90 bytes moved; every one must be billed exactly once despite the outage.
	if billed != 90 {
		t.Errorf("summed bytes_out = %d, want 90 after a sink outage", billed)
	}
	if records[0].BytesOut != 40 {
		t.Errorf("retransmitted record bytes_out = %d, want the original 40", records[0].BytesOut)
	}
	if records[0].Seq != 1 {
		t.Errorf("retransmitted record seq = %d, want the original 1", records[0].Seq)
	}
}

// TestLedgerResetTakesCurrentValueAsDelta pins the underflow guard. A backwards
// counter must not wrap uint64 into an astronomical over-bill.
func TestLedgerResetTakesCurrentValueAsDelta(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{Destination: "d", Bytes: 500, Packets: 50}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// The ledger was rebuilt and now reads lower than the watermark.
	if err := reporter.Tick([]LedgerSample{{Destination: "d", Bytes: 20, Packets: 2}}); err != nil {
		t.Fatalf("Tick after ledger reset: %v", err)
	}

	records := sink.forDestination("d")
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[1].BytesOut != 20 {
		t.Errorf("bytes_out after reset = %d, want 20 (the new ledger's whole traffic)", records[1].BytesOut)
	}
	if records[1].PacketsOut != 2 {
		t.Errorf("packets_out after reset = %d, want 2", records[1].PacketsOut)
	}
}

// TestCloseAllEmitsFinalRecordWithTailDelta pins that shutdown does not discard
// the traffic delivered since the last periodic record.
func TestCloseAllEmitsFinalRecordWithTailDelta(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{Destination: "10.0.0.1:8000", Bytes: 100, Packets: 10},
		{Destination: "10.0.0.2:8000", Bytes: 100, Packets: 10},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// More traffic lands, then the process shuts down before the next tick.
	if err := reporter.CloseAll([]LedgerSample{
		{Destination: "10.0.0.1:8000", Bytes: 175, Packets: 17},
		{Destination: "10.0.0.2:8000", Bytes: 100, Packets: 10},
	}, CloseShutdown); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	first := sink.forDestination("10.0.0.1:8000")
	final := first[len(first)-1]
	if !final.Final {
		t.Error("last record for a closed session is not marked final")
	}
	if final.CloseReason != CloseShutdown {
		t.Errorf("close_reason = %q, want %q", final.CloseReason, CloseShutdown)
	}
	if final.BytesOut != 75 {
		t.Errorf("final bytes_out = %d, want the 75-byte tail delta", final.BytesOut)
	}

	var billed uint64
	for _, record := range first {
		billed += record.BytesOut
	}
	if billed != 175 {
		t.Errorf("summed bytes_out = %d, want 175", billed)
	}

	// A destination with no tail traffic still gets its terminating record.
	second := sink.forDestination("10.0.0.2:8000")
	if last := second[len(second)-1]; !last.Final || last.BytesOut != 0 {
		t.Errorf("idle destination final record = {final:%v bytes:%d}, want {true 0}", last.Final, last.BytesOut)
	}
}

// TestDurationIsCumulativeAndBytesAreDeltas pins the asymmetry the package doc
// calls load-bearing, from the Reporter's side.
func TestDurationIsCumulativeAndBytesAreDeltas(t *testing.T) {
	tracker, err := NewTracker(NewMemorySeqStore())
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}
	sink := &captureSink{}
	reporter, err := NewReporter(tracker, sink)
	if err != nil {
		t.Fatalf("NewReporter: %v", err)
	}

	for _, total := range []uint64{10, 20, 30} {
		if err := reporter.Tick([]LedgerSample{{Destination: "d", Bytes: total, Packets: 1}}); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}

	records := sink.forDestination("d")
	for i, record := range records {
		if record.BytesOut != 10 {
			t.Errorf("record %d bytes_out = %d, want the constant 10-byte delta", i, record.BytesOut)
		}
	}
	for i := 1; i < len(records); i++ {
		if records[i].DurationMS < records[i-1].DurationMS {
			t.Errorf("duration_ms went backwards at record %d; it must be cumulative", i)
		}
		if records[i].Seq <= records[i-1].Seq {
			t.Errorf("seq not strictly increasing at record %d", i)
		}
	}
}

// TestCloseDestinationRejectsInvalidReason keeps a malformed close reason off
// the wire rather than letting it reach a billing rollup.
func TestCloseDestinationRejectsInvalidReason(t *testing.T) {
	reporter, _ := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{Destination: "d", Bytes: 1, Packets: 1}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	err := reporter.CloseDestination(LedgerSample{Destination: "d", Bytes: 1, Packets: 1}, CloseReason("NOPE"))
	if err == nil || !strings.Contains(err.Error(), "invalid close reason") {
		t.Fatalf("CloseDestination error = %v, want an invalid close reason error", err)
	}
}

// TestObserveErrorLeavesDeltaForRetry pins that a rejected sample is not
// silently swallowed: the destination keeps its watermark so the bytes are
// re-offered rather than lost.
func TestObserveErrorLeavesDeltaForRetry(t *testing.T) {
	reporter, _ := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{Destination: "", Bytes: 10, Packets: 1}}); err == nil {
		t.Fatal("Tick accepted a sample with no destination")
	}
	if reporter.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0; nothing was emitted", reporter.Pending())
	}
}

// TestTickContinuesPastOneBadDestination pins that one failing destination does
// not stop the others from accounting for their traffic.
func TestTickContinuesPastOneBadDestination(t *testing.T) {
	reporter, sink := newTestReporter(t)

	err := reporter.Tick([]LedgerSample{
		{Destination: "", Bytes: 10, Packets: 1},
		{Destination: "10.0.0.2:8000", Bytes: 250, Packets: 25},
	})
	if err == nil {
		t.Fatal("Tick returned nil despite a bad destination")
	}
	if got := sink.forDestination("10.0.0.2:8000"); len(got) != 1 || got[0].BytesOut != 250 {
		t.Errorf("healthy destination records = %+v, want one record of 250 bytes", got)
	}
}
