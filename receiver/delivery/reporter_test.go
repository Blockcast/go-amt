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

func (c *captureSink) forTarget(targetID string) []Record {
	var out []Record
	for _, record := range c.shipped {
		if record.SubscriberID == targetID {
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
			{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: reading.bytes, Packets: reading.packets},
		}); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}

	var billedBytes, billedPackets uint64
	for _, record := range sink.forTarget("grant-a") {
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
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 100, Packets: 10},
		{TargetID: "grant-b", Destination: "10.0.0.2:8000", Bytes: 250, Packets: 25},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	first := sink.forTarget("grant-a")
	second := sink.forTarget("grant-b")
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
	err := reporter.Tick([]LedgerSample{{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 40, Packets: 4}})
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
	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 90, Packets: 9}}); err == nil {
		t.Fatal("Tick returned nil while the sink was still refusing records")
	}
	if reporter.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1; a second record must not be emitted while one is owed", reporter.Pending())
	}

	// Sink recovers.
	sink.failing = false
	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 90, Packets: 9}}); err != nil {
		t.Fatalf("Tick after recovery: %v", err)
	}
	if reporter.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0 after recovery", reporter.Pending())
	}

	records := sink.forTarget("grant-a")
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

	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 500, Packets: 50}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// The ledger was rebuilt and now reads lower than the watermark.
	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 20, Packets: 2}}); err != nil {
		t.Fatalf("Tick after ledger reset: %v", err)
	}

	records := sink.forTarget("grant-d")
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
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 100, Packets: 10},
		{TargetID: "grant-b", Destination: "10.0.0.2:8000", Bytes: 100, Packets: 10},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// More traffic lands, then the process shuts down before the next tick.
	if err := reporter.CloseAll([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 175, Packets: 17},
		{TargetID: "grant-b", Destination: "10.0.0.2:8000", Bytes: 100, Packets: 10},
	}, CloseShutdown); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	first := sink.forTarget("grant-a")
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
	second := sink.forTarget("grant-b")
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
		if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: total, Packets: 1}}); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}

	records := sink.forTarget("grant-d")
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

// TestRefusedFinalRecordIsRetriedOnNextClose is the regression test for the
// worst case of the retry contract. Tracker.Close removes the session, so a
// final record the sink refused can never be regenerated -- it is the one
// record with no possible replacement. If the retry path observes before it
// drains, Observe hits the removed session, returns ErrNoSession, and the
// retained record is stranded forever: the session's last interval and its
// close reason are both lost, silently.
func TestRefusedFinalRecordIsRetriedOnNextClose(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 100, Packets: 10}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// The sink dies exactly as the final record is shipped.
	sink.failing = true
	final := LedgerSample{TargetID: "grant-d", Destination: "d", Bytes: 150, Packets: 15}
	if err := reporter.CloseAll([]LedgerSample{final}, CloseShutdown); err == nil {
		t.Fatal("CloseAll returned nil while the sink was refusing records")
	}
	if reporter.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1 after a refused final record", reporter.Pending())
	}

	// The sink recovers and the caller retries.
	sink.failing = false
	if err := reporter.CloseAll([]LedgerSample{final}, CloseShutdown); err != nil {
		t.Fatalf("CloseAll after recovery: %v", err)
	}
	if reporter.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0; the retained final record was never retried", reporter.Pending())
	}

	records := sink.forTarget("grant-d")
	var finals int
	var billed uint64
	for _, record := range records {
		billed += record.BytesOut
		if record.Final {
			finals++
		}
	}
	if finals != 1 {
		t.Errorf("final records = %d, want exactly 1: the retry must retransmit the "+
			"original record, not emit a second closing interval", finals)
	}
	if billed != 150 {
		t.Errorf("summed bytes_out = %d, want 150; the final interval was lost or double-counted", billed)
	}
	if last := records[len(records)-1]; last.CloseReason != CloseShutdown {
		t.Errorf("retried final record close_reason = %q, want %q", last.CloseReason, CloseShutdown)
	}
}

// TestRefusedFinalRecordIsRetriedOnNextTick pins the same recovery through the
// periodic path, since a caller that keeps ticking after a failed shutdown
// close must not strand the record either.
func TestRefusedFinalRecordIsRetriedOnNextTick(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 100, Packets: 10}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	sink.failing = true
	if err := reporter.CloseDestination(LedgerSample{TargetID: "grant-d", Destination: "d", Bytes: 100, Packets: 10}, CloseShutdown); err == nil {
		t.Fatal("CloseDestination returned nil while the sink was refusing")
	}

	sink.failing = false
	// More traffic arrives and the caller ticks again.
	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 175, Packets: 17}}); err != nil {
		t.Fatalf("Tick after recovery: %v", err)
	}
	if reporter.Pending() != 0 {
		t.Fatalf("Pending() = %d, want 0", reporter.Pending())
	}

	records := sink.forTarget("grant-d")
	var billed uint64
	for _, record := range records {
		billed += record.BytesOut
	}
	if billed != 175 {
		t.Errorf("summed bytes_out = %d, want 175", billed)
	}
	// The closed session's record shipped, and the post-close traffic opened a
	// NEW session rather than being folded into the closed one.
	sessions := map[string]bool{}
	for _, record := range records {
		sessions[record.SessionID] = true
	}
	if len(sessions) != 2 {
		t.Errorf("distinct sessions = %d, want 2: traffic after a close belongs to a new session", len(sessions))
	}
}

// TestReopenAfterCloseDoesNotRebillFromProcessStart pins the watermark's
// survival across a close. The ledger is cumulative over the whole process and
// does not reset when a session ends, so a reopened session that took its
// baseline as zero would bill every byte since process start all over again.
func TestReopenAfterCloseDoesNotRebillFromProcessStart(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 1000, Packets: 100}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := reporter.CloseAll([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 1000, Packets: 100}}, CloseShutdown); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	// The same process keeps running and the destination comes back. The ledger
	// still reads cumulatively: 1000 already billed, 40 new bytes.
	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 1040, Packets: 104}}); err != nil {
		t.Fatalf("Tick after reopen: %v", err)
	}

	var billed uint64
	for _, record := range sink.forTarget("grant-d") {
		billed += record.BytesOut
	}
	if billed != 1040 {
		t.Errorf("summed bytes_out = %d, want 1040; a reopened session re-billed the cumulative ledger", billed)
	}
}

// TestCloseWithoutAnyTickBillsTheWholeRun pins the run-shorter-than-one-report-
// interval case. No periodic tick has fired, so no session has ever been
// opened; the close is the only record that run will ever produce and must
// therefore carry all of its traffic. A close path that treats "no open
// session" as "already closed" silently bills such a run at zero.
func TestCloseWithoutAnyTickBillsTheWholeRun(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.CloseAll([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 4400, Packets: 100},
	}, CloseShutdown); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	records := sink.forTarget("grant-a")
	if len(records) != 1 {
		t.Fatalf("records = %d, want exactly 1 (the final record)", len(records))
	}
	if records[0].BytesOut != 4400 || records[0].PacketsOut != 100 {
		t.Errorf("final record = %d bytes / %d packets, want 4400/100: a run that closed "+
			"before its first tick must still bill everything it delivered",
			records[0].BytesOut, records[0].PacketsOut)
	}
	if !records[0].Final || records[0].CloseReason != CloseShutdown {
		t.Errorf("final record = {final:%v reason:%q}, want {true %q}",
			records[0].Final, records[0].CloseReason, CloseShutdown)
	}
}

// TestCloseAllIsIdempotent pins that a second close does not manufacture a
// second terminating record for a session that already has one.
func TestCloseAllIsIdempotent(t *testing.T) {
	reporter, sink := newTestReporter(t)

	samples := []LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 500, Packets: 50}}
	if err := reporter.CloseAll(samples, CloseShutdown); err != nil {
		t.Fatalf("first CloseAll: %v", err)
	}
	if err := reporter.CloseAll(samples, CloseShutdown); err != nil {
		t.Fatalf("second CloseAll: %v", err)
	}

	records := sink.forTarget("grant-d")
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1; a repeated close emitted a duplicate record", len(records))
	}
	var billed uint64
	for _, record := range records {
		billed += record.BytesOut
	}
	if billed != 500 {
		t.Errorf("summed bytes_out = %d, want 500", billed)
	}
}

// TestCloseDestinationRejectsInvalidReason keeps a malformed close reason off
// the wire rather than letting it reach a billing rollup.
func TestCloseDestinationRejectsInvalidReason(t *testing.T) {
	reporter, _ := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{{TargetID: "grant-d", Destination: "d", Bytes: 1, Packets: 1}}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	err := reporter.CloseDestination(LedgerSample{TargetID: "grant-d", Destination: "d", Bytes: 1, Packets: 1}, CloseReason("NOPE"))
	if err == nil || !strings.Contains(err.Error(), "invalid close reason") {
		t.Fatalf("CloseDestination error = %v, want an invalid close reason error", err)
	}
}

// TestObserveErrorLeavesDeltaForRetry pins that a rejected sample is not
// silently swallowed: the target keeps its watermark so the bytes are
// re-offered rather than lost. The sample carries a perfectly good address —
// it is rejected for having no IDENTITY, which is the only thing that may key
// billing state.
func TestObserveErrorLeavesDeltaForRetry(t *testing.T) {
	reporter, _ := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{TargetID: "", Destination: "10.0.0.1:8000", Bytes: 10, Packets: 1},
	}); err == nil {
		t.Fatal("Tick accepted a sample with no target ID")
	}
	if reporter.Pending() != 0 {
		t.Errorf("Pending() = %d, want 0; nothing was emitted", reporter.Pending())
	}
}

// TestTickContinuesPastOneBadDestination pins that one failing target does not
// stop the others from accounting for their traffic.
func TestTickContinuesPastOneBadDestination(t *testing.T) {
	reporter, sink := newTestReporter(t)

	err := reporter.Tick([]LedgerSample{
		{TargetID: "", Destination: "10.0.0.1:8000", Bytes: 10, Packets: 1},
		{TargetID: "grant-b", Destination: "10.0.0.2:8000", Bytes: 250, Packets: 25},
	})
	if err == nil {
		t.Fatal("Tick returned nil despite a sample with no target ID")
	}
	if got := sink.forTarget("grant-b"); len(got) != 1 || got[0].BytesOut != 250 {
		t.Errorf("healthy target records = %+v, want one record of 250 bytes", got)
	}
}

// TestTargetSurvivesAddressChangeOnOneSession is the regression test for the
// first of the two mis-bills that address-keying produces: a subscriber
// re-granted to a new endpoint mid-session.
//
// Keyed by address, the new address is an unseen key: a SECOND session opens
// while the first is never closed, so one subscriber bills as two and one of
// them stays open forever. Keyed by target ID the move is invisible to
// billing, which is the point — the grant did not change, only where its bytes
// go. The ledger counters survive the move because a reconcile carries them by
// pointer, so the delta stays honest across it.
func TestTargetSurvivesAddressChangeOnOneSession(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 100, Packets: 10},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	// The grant is re-pointed at a new endpoint. Same target, same session.
	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.9:9000", Bytes: 180, Packets: 18},
	}); err != nil {
		t.Fatalf("Tick after address change: %v", err)
	}

	records := sink.forTarget("grant-a")
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	if records[0].SessionID != records[1].SessionID {
		t.Errorf("address change split the target across sessions %s and %s; "+
			"a re-granted subscriber must stay on one session",
			records[0].SessionID, records[1].SessionID)
	}
	if open := reporter.tracker.OpenSessions(); open != 1 {
		t.Errorf("open sessions = %d, want 1; the pre-move session was orphaned", open)
	}

	var billed uint64
	for _, record := range records {
		billed += record.BytesOut
	}
	if billed != 180 {
		t.Errorf("summed bytes_out = %d, want 180", billed)
	}
	// The address is still reported — as metadata, tracking where the bytes of
	// each interval actually went.
	if records[0].Destination != "10.0.0.1:8000" || records[1].Destination != "10.0.0.9:9000" {
		t.Errorf("record destinations = %q then %q, want the pre- then post-move address",
			records[0].Destination, records[1].Destination)
	}
}

// TestTwoTargetsSharingOneAddressBillSeparately is the regression test for the
// second mis-bill: two grants resolving to one address.
//
// Fanout.ReconcileDestinations dedupes on target ID alone, so this state is
// valid by construction rather than a misconfiguration. Keyed by address the
// two collapse into a single session and a single watermark, and two customers
// bill as one — with the second target's traffic silently folded into the
// first's invoice.
func TestTwoTargetsSharingOneAddressBillSeparately(t *testing.T) {
	reporter, sink := newTestReporter(t)

	// One host behind NAT, two distinct grants.
	const shared = "10.0.0.1:8000"
	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: shared, Bytes: 100, Packets: 10},
		{TargetID: "grant-b", Destination: shared, Bytes: 250, Packets: 25},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	first := sink.forTarget("grant-a")
	second := sink.forTarget("grant-b")
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("records per target = %d/%d, want 1/1; two grants on one address "+
			"were merged into a single session", len(first), len(second))
	}
	if first[0].SessionID == second[0].SessionID {
		t.Error("both targets share a session ID; sessions are per target, not per address")
	}
	if first[0].BytesOut != 100 {
		t.Errorf("first target bytes_out = %d, want 100", first[0].BytesOut)
	}
	if second[0].BytesOut != 250 {
		t.Errorf("second target bytes_out = %d, want 250", second[0].BytesOut)
	}

	// Watermarks are per target too: a shared watermark would make the second
	// tick's delta come out against the other target's total.
	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: shared, Bytes: 130, Packets: 13},
		{TargetID: "grant-b", Destination: shared, Bytes: 300, Packets: 30},
	}); err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if got := sink.forTarget("grant-a")[1].BytesOut; got != 30 {
		t.Errorf("first target second bytes_out = %d, want its own 30-byte delta", got)
	}
	if got := sink.forTarget("grant-b")[1].BytesOut; got != 50 {
		t.Errorf("second target second bytes_out = %d, want its own 50-byte delta", got)
	}
}

// TestCloseAllClosesEachTargetSharingAnAddress pins that the shutdown path is
// keyed by target too. CloseAll builds its close set from a map; keyed by
// address, two targets sharing one address collapse to a single entry and one
// of the two sessions never gets a terminating record at all.
func TestCloseAllClosesEachTargetSharingAnAddress(t *testing.T) {
	reporter, sink := newTestReporter(t)

	const shared = "10.0.0.1:8000"
	samples := []LedgerSample{
		{TargetID: "grant-a", Destination: shared, Bytes: 100, Packets: 10},
		{TargetID: "grant-b", Destination: shared, Bytes: 250, Packets: 25},
	}
	if err := reporter.Tick(samples); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := reporter.CloseAll(samples, CloseShutdown); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}

	for _, targetID := range []string{"grant-a", "grant-b"} {
		records := sink.forTarget(targetID)
		last := records[len(records)-1]
		if !last.Final || last.CloseReason != CloseShutdown {
			t.Errorf("%s last record = {final:%v reason:%q}, want {true %q}: every "+
				"target needs its own terminating record",
				targetID, last.Final, last.CloseReason, CloseShutdown)
		}
	}
	if open := reporter.tracker.OpenSessions(); open != 0 {
		t.Errorf("open sessions after CloseAll = %d, want 0", open)
	}
}

// TestRemovedTargetGetsFinalRecordWithTailDelta is the regression test for a
// revoked grant billed as a shutdown.
//
// Before CloseRemoved existed, a target dropped by a reconcile kept an open
// session until the process exited, and then closed as SHUTDOWN. Two things
// were wrong with that: the reason misreports a lapsed grant as a deliberate
// sender shutdown, and — the part no later reading can repair — the traffic
// between the target's last periodic record and its removal was never billed,
// because the counters carrying it vanished at the table swap.
func TestRemovedTargetGetsFinalRecordWithTailDelta(t *testing.T) {
	reporter, sink := newTestReporter(t)

	// One periodic interval bills the first 1000 bytes.
	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1000, Packets: 10},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	// More traffic lands, then the grant is revoked. The reconcile hands back
	// the cumulative counters as of the swap; the un-billed tail is the 500
	// bytes / 5 packets delivered since the periodic record above.
	if err := reporter.CloseRemoved([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1500, Packets: 15},
	}); err != nil {
		t.Fatalf("CloseRemoved: %v", err)
	}

	records := sink.forTarget("grant-a")
	var finals []Record
	for _, record := range records {
		if record.Final {
			finals = append(finals, record)
		}
	}
	if len(finals) != 1 {
		t.Fatalf("got %d final records, want exactly 1: %+v", len(finals), records)
	}
	final := finals[0]
	if final.CloseReason != CloseTicketExpired {
		t.Errorf("final record close_reason = %q, want %q", final.CloseReason, CloseTicketExpired)
	}
	if final.CloseReason == CloseShutdown {
		t.Error("a revoked grant closed as SHUTDOWN, which defers the record to process exit")
	}
	// The tail, not the cumulative total: billing 1500 here would re-bill the
	// 1000 the periodic record already carried.
	if final.BytesOut != 500 || final.PacketsOut != 5 {
		t.Errorf("final record billed %d bytes / %d packets, want the 500/5 tail", final.BytesOut, final.PacketsOut)
	}

	// Nothing goes unbilled across the removal: the records must account for
	// the whole ledger reading exactly once.
	var billedBytes, billedPackets uint64
	for _, record := range records {
		billedBytes += record.BytesOut
		billedPackets += record.PacketsOut
	}
	if billedBytes != 1500 || billedPackets != 15 {
		t.Errorf("records bill %d bytes / %d packets in total, want the full 1500/15 ledger", billedBytes, billedPackets)
	}
}

// TestReGrantedTargetOpensDistinctSession covers the other side of a removal:
// the same subscriber coming back.
//
// A re-grant must be a NEW session, because the closed one has already been
// invoiced and its final record cannot be reopened. It must also not re-bill:
// the re-granted target gets fresh fan-out counters starting at zero while the
// Reporter still holds the pre-removal watermark, and a naive delta against
// that watermark would underflow uint64 into an astronomical over-bill.
func TestReGrantedTargetOpensDistinctSession(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1000, Packets: 10},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if err := reporter.CloseRemoved([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1500, Packets: 15},
	}); err != nil {
		t.Fatalf("CloseRemoved: %v", err)
	}

	// Re-granted. The target is a new entry in the fan-out table, so its
	// counters start from zero -- below the watermark the Reporter still holds.
	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.2:8000", Bytes: 400, Packets: 4},
	}); err != nil {
		t.Fatalf("Tick after re-grant: %v", err)
	}

	records := sink.forTarget("grant-a")
	sessions := make(map[string]struct{}, len(records))
	for _, record := range records {
		sessions[record.SessionID] = struct{}{}
	}
	if len(sessions) != 2 {
		t.Fatalf("records span %d sessions, want 2 (the closed one and the re-granted one): %+v", len(sessions), records)
	}

	// The re-granted traffic must not resume the closed session.
	for _, record := range records {
		if record.Final && record.Destination == "10.0.0.2:8000" {
			t.Error("the re-granted interval landed on the closed session's final record")
		}
	}

	// Exactly the two ledgers' totals: 1500 before removal, 400 after. Anything
	// higher is a re-bill; the underflow bug reports ~1.8e19 here.
	var billedBytes, billedPackets uint64
	for _, record := range records {
		billedBytes += record.BytesOut
		billedPackets += record.PacketsOut
	}
	if billedBytes != 1900 || billedPackets != 19 {
		t.Errorf("records bill %d bytes / %d packets, want exactly 1900/19 (1500 pre-removal + 400 post-re-grant)", billedBytes, billedPackets)
	}
}

// TestReGrantedTargetCanBillBeforeTheOldGenerationCloses covers the reconcile
// handoff where the new table starts delivering before its caller has consumed
// the old generation's final sample. The two generations must remain separate:
// closing the old sample later must not close or bill the new session.
func TestReGrantedTargetCanBillBeforeTheOldGenerationCloses(t *testing.T) {
	reporter, sink := newTestReporter(t)

	oldPeriodic := LedgerSample{TargetID: "grant-a", Generation: 1, Destination: "10.0.0.1:8000", Bytes: 1000, Packets: 10}
	if err := reporter.Tick([]LedgerSample{oldPeriodic}); err != nil {
		t.Fatalf("Tick old generation: %v", err)
	}

	// Reconcile has returned old's final sample but the caller has not closed it
	// yet. A re-granted target can already deliver through the new table.
	old := LedgerSample{TargetID: "grant-a", Generation: 1, Destination: "10.0.0.1:8000", Bytes: 1500, Packets: 15}
	new := LedgerSample{TargetID: "grant-a", Generation: 2, Destination: "10.0.0.2:8000", Bytes: 400, Packets: 4}
	if err := reporter.Tick([]LedgerSample{new}); err != nil {
		t.Fatalf("Tick new generation before old close: %v", err)
	}
	if err := reporter.CloseRemoved([]LedgerSample{old}); err != nil {
		t.Fatalf("CloseRemoved old generation: %v", err)
	}

	records := sink.forTarget("grant-a")
	var oldFinal Record
	var haveOldFinal bool
	sessions := make(map[string]struct{})
	var billed uint64
	for _, record := range records {
		sessions[record.SessionID] = struct{}{}
		billed += record.BytesOut
		if record.Final {
			oldFinal, haveOldFinal = record, true
		}
	}
	if !haveOldFinal {
		t.Fatal("old generation emitted no final record")
	}
	if oldFinal.Destination != old.Destination || oldFinal.BytesOut != old.Bytes-oldPeriodic.Bytes {
		t.Errorf("old final = destination %q, bytes %d; want old generation %q / %d tail", oldFinal.Destination, oldFinal.BytesOut, old.Destination, old.Bytes-oldPeriodic.Bytes)
	}
	if _, open := reporter.tracker.SessionIDForGeneration("grant-a", 2); !open {
		t.Error("closing the old generation also closed the new generation")
	}
	if len(sessions) != 2 {
		t.Errorf("records use %d sessions, want distinct old and new sessions", len(sessions))
	}
	if billed != old.Bytes+new.Bytes {
		t.Errorf("records billed %d bytes, want exactly %d", billed, old.Bytes+new.Bytes)
	}
}

// A close that the sink refuses must not be silently dropped: the final record
// is the interval nothing will ever restate, so it is retained for verbatim
// retransmission and reported as owed.
func TestCloseRemovedRetainsAFinalRecordTheSinkRefused(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1000, Packets: 10},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	sink.failing = true
	if err := reporter.CloseRemoved([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1500, Packets: 15},
	}); err == nil {
		t.Fatal("CloseRemoved reported success while the sink was refusing records")
	}
	if reporter.Pending() != 1 {
		t.Fatalf("Pending() = %d, want 1 record owed", reporter.Pending())
	}

	// The retained record ships verbatim once the sink recovers.
	sink.failing = false
	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 1500, Packets: 15},
	}); err != nil {
		t.Fatalf("Tick after sink recovery: %v", err)
	}
	if reporter.Pending() != 0 {
		t.Errorf("Pending() = %d after recovery, want 0", reporter.Pending())
	}
	var finals int
	for _, record := range sink.forTarget("grant-a") {
		if record.Final {
			finals++
			if record.BytesOut != 500 {
				t.Errorf("retransmitted final record billed %d bytes, want the original 500 tail", record.BytesOut)
			}
		}
	}
	if finals != 1 {
		t.Errorf("got %d final records, want exactly 1 (retransmitted, not regenerated)", finals)
	}
}

// CloseRemoved must close every target even when one fails, for the same reason
// Tick does: a final record is the one interval nothing will ever restate.
func TestCloseRemovedClosesEveryTargetDespiteAFailure(t *testing.T) {
	reporter, sink := newTestReporter(t)

	if err := reporter.Tick([]LedgerSample{
		{TargetID: "grant-a", Destination: "10.0.0.1:8000", Bytes: 100, Packets: 1},
		{TargetID: "grant-b", Destination: "10.0.0.2:8000", Bytes: 200, Packets: 2},
	}); err != nil {
		t.Fatalf("Tick: %v", err)
	}

	err := reporter.CloseRemoved([]LedgerSample{
		// An empty target ID cannot be closed; grant-b after it still must be.
		{TargetID: "", Destination: "10.0.0.9:8000", Bytes: 1, Packets: 1},
		{TargetID: "grant-b", Destination: "10.0.0.2:8000", Bytes: 350, Packets: 3},
	})
	if err == nil {
		t.Fatal("CloseRemoved reported success despite an unusable sample")
	}

	var closed bool
	for _, record := range sink.forTarget("grant-b") {
		if record.Final && record.CloseReason == CloseTicketExpired {
			closed = true
			if record.BytesOut != 150 {
				t.Errorf("grant-b final record billed %d bytes, want the 150 tail", record.BytesOut)
			}
		}
	}
	if !closed {
		t.Error("grant-b was never closed because an earlier sample failed")
	}
}
