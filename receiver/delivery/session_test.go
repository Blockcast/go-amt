package delivery

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeClock lets a test advance time deterministically.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time      { return c.now }
func (c *fakeClock) Add(d time.Duration) { c.now = c.now.Add(d) }

func newTestTracker(t *testing.T, clock *fakeClock, seqs SeqStore) *Tracker {
	t.Helper()
	if seqs == nil {
		seqs = NewMemorySeqStore()
	}
	tracker, err := NewTracker(seqs, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}
	return tracker
}

// TestReopenAfterTeardownMintsDistinctSession pins the acceptance criterion
// that every open and every reopen-after-teardown mints a distinct session
// UUID, so consecutive sessions for one subscriber can never be merged into a
// single billing row.
func TestReopenAfterTeardownMintsDistinctSession(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	first, err := tracker.Open("subscriber-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := tracker.Close("subscriber-a", CloseStaleTimeout); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := tracker.Open("subscriber-a")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if first == second {
		t.Fatalf("reopen reused session ID %s; consecutive sessions must be distinct", first)
	}
	if len(first) != 36 || len(second) != 36 {
		t.Fatalf("session IDs are not UUIDs: %q, %q", first, second)
	}
}

func TestOpenRejectsDoubleOpen(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := tracker.Open("subscriber-a"); !errors.Is(err, ErrSessionOpen) {
		t.Fatalf("second Open error = %v, want ErrSessionOpen", err)
	}
}

// TestDurationCumulativeBytesDelta pins the asymmetry that the Traffic Ops
// rollup depends on: duration_ms restates the session total on every record,
// while bytes_out covers only the interval since the previous record.
func TestDurationCumulativeBytesDelta(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := tracker.Observe("subscriber-a", 1_000, 10); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clock.Add(30 * time.Second)
	first, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if first.DurationMS != 30_000 {
		t.Fatalf("first DurationMS = %d, want 30000", first.DurationMS)
	}
	if first.BytesOut != 1_000 || first.PacketsOut != 10 {
		t.Fatalf("first delta = %d bytes/%d packets, want 1000/10", first.BytesOut, first.PacketsOut)
	}

	if err := tracker.Observe("subscriber-a", 250, 3); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clock.Add(30 * time.Second)
	second, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if second.DurationMS != 60_000 {
		t.Fatalf("second DurationMS = %d, want 60000 (cumulative, not per-interval)", second.DurationMS)
	}
	if second.BytesOut != 250 || second.PacketsOut != 3 {
		t.Fatalf("second delta = %d bytes/%d packets, want 250/3 (delta, not cumulative)", second.BytesOut, second.PacketsOut)
	}
	if second.Seq <= first.Seq {
		t.Fatalf("Seq did not advance: %d then %d", first.Seq, second.Seq)
	}
	if second.SessionID != first.SessionID {
		t.Fatalf("session ID changed mid-session: %s then %s", first.SessionID, second.SessionID)
	}
}

// TestRollupReconstructsTruthFromDuplicates is the reason for the asymmetry.
// It replays a duplicated and an out-of-order record through the documented
// rollup — MAX(duration_ms), SUM(bytes_out) deduplicated by (session, seq) —
// and asserts the result equals what was actually delivered.
func TestRollupReconstructsTruthFromDuplicates(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	var emitted []Record
	const rounds = 4
	for round := 0; round < rounds; round++ {
		if err := tracker.Observe("subscriber-a", 100, 1); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		clock.Add(15 * time.Second)
		record, err := tracker.Emit("subscriber-a")
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
		emitted = append(emitted, record)
	}
	final, err := tracker.Close("subscriber-a", CloseHeartbeatAbsent)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	emitted = append(emitted, final)

	// A Traffic Ops outage replays records: duplicate one and reverse order.
	replayed := append([]Record(nil), emitted...)
	replayed = append(replayed, emitted[1], emitted[1], final)
	for i, j := 0, len(replayed)-1; i < j; i, j = i+1, j-1 {
		replayed[i], replayed[j] = replayed[j], replayed[i]
	}

	seen := make(map[string]struct{})
	var totalBytes uint64
	var maxDuration int64
	var closeReason CloseReason
	for _, record := range replayed {
		key := record.SessionID + ":" + strconv.FormatUint(record.Seq, 10)
		if _, duplicate := seen[key]; duplicate {
			continue // idempotent by (session_id, seq)
		}
		seen[key] = struct{}{}
		totalBytes += record.BytesOut
		if record.DurationMS > maxDuration {
			maxDuration = record.DurationMS
		}
		if record.CloseReason != "" {
			closeReason = record.CloseReason
		}
	}

	if totalBytes != uint64(rounds)*100 {
		t.Fatalf("SUM(bytes_out) = %d, want %d", totalBytes, rounds*100)
	}
	if maxDuration != int64(rounds)*15_000 {
		t.Fatalf("MAX(duration_ms) = %d, want %d", maxDuration, rounds*15_000)
	}
	if closeReason != CloseHeartbeatAbsent {
		t.Fatalf("close_reason = %q, want %q", closeReason, CloseHeartbeatAbsent)
	}
}

// TestForgedTeardownDoesNotShortenDuration pins D8: an AMT Teardown is
// unauthenticated, so it must be a liveness hint only. It must not close the
// session, must not change its identity, and must not shorten duration_ms.
func TestForgedTeardownDoesNotShortenDuration(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	sessionID, err := tracker.Open("subscriber-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	clock.Add(20 * time.Second)
	if hinted := tracker.Teardown("subscriber-a"); !hinted {
		t.Fatal("Teardown on an open session should report a hint")
	}
	clock.Add(40 * time.Second)

	if tracker.OpenSessions() != 1 {
		t.Fatal("a forged Teardown closed the session; it must only be a hint")
	}
	if got, ok := tracker.SessionID("subscriber-a"); !ok || got != sessionID {
		t.Fatalf("session identity changed after Teardown: %q vs %q", got, sessionID)
	}

	record, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if record.DurationMS != 60_000 {
		t.Fatalf("DurationMS = %d, want 60000; a forged Teardown must not shorten duration", record.DurationMS)
	}
	if record.CloseReason != "" {
		t.Fatalf("CloseReason = %q, want empty; a hint is not a close", record.CloseReason)
	}
}

// TestTeardownHintsEveryGenerationForSubscriber drives the subscriber-ID API
// with the same nonzero generations produced by Fanout. A re-grant can
// temporarily leave two live lifecycles under one subscriber ID; a forgeable
// teardown cannot safely choose one, so it must hint both rather than silently
// doing nothing for every broker-target session.
func TestTeardownHintsEveryGenerationForSubscriber(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	const (
		oldGeneration = 7
		newGeneration = 8
	)
	if _, err := tracker.OpenForGeneration("subscriber-a", oldGeneration); err != nil {
		t.Fatalf("OpenForGeneration old: %v", err)
	}
	if _, err := tracker.OpenForGeneration("subscriber-a", newGeneration); err != nil {
		t.Fatalf("OpenForGeneration new: %v", err)
	}
	clock.Add(time.Second)
	if !tracker.TeardownForGeneration("subscriber-a", oldGeneration) {
		t.Fatal("TeardownForGeneration did not find the requested generation")
	}
	if got := tracker.sessions[sessionKey("subscriber-a", oldGeneration)].lastTeardown; !got.Equal(clock.Now()) {
		t.Errorf("old generation lastTeardown = %s, want %s", got, clock.Now())
	}
	if got := tracker.sessions[sessionKey("subscriber-a", newGeneration)].lastTeardown; !got.IsZero() {
		t.Errorf("new generation lastTeardown = %s after old-generation hint, want zero", got)
	}

	clock.Add(time.Second)
	if !tracker.Teardown("subscriber-a") {
		t.Fatal("Teardown did not find the generation-aware sessions")
	}
	for _, generation := range []uint64{oldGeneration, newGeneration} {
		current := tracker.sessions[sessionKey("subscriber-a", generation)]
		if current == nil {
			t.Fatalf("generation %d session disappeared", generation)
		}
		if !current.lastTeardown.Equal(clock.Now()) {
			t.Errorf("generation %d lastTeardown = %s, want %s", generation, current.lastTeardown, clock.Now())
		}
	}
	if tracker.TeardownForGeneration("subscriber-a", 9) {
		t.Fatal("TeardownForGeneration found an unknown generation")
	}
}

// TestCloseReasonIsOnTheWire pins that every close carries a reason, and that
// TEARDOWN is not an accepted one.
func TestCloseReasonIsOnTheWire(t *testing.T) {
	valid := []CloseReason{
		CloseHeartbeatAbsent, CloseTicketExpired, CloseStaleTimeout,
		CloseBlockOldSources, CloseShutdown,
	}
	for _, reason := range valid {
		if !reason.Valid() {
			t.Fatalf("%q should be a valid close reason", reason)
		}
	}
	for _, reason := range []CloseReason{"", "TEARDOWN", "teardown", "nonsense"} {
		if reason.Valid() {
			t.Fatalf("%q should not be a valid close reason", reason)
		}
	}

	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)
	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := tracker.Close("subscriber-a", "TEARDOWN"); err == nil {
		t.Fatal("Close accepted TEARDOWN; a forgeable wire event must not be a close reason")
	}

	record, err := tracker.Close("subscriber-a", CloseTicketExpired)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !record.Final || record.CloseReason != CloseTicketExpired {
		t.Fatalf("final record = %+v, want Final with TICKET_EXPIRED", record)
	}
	if tracker.OpenSessions() != 0 {
		t.Fatal("Close did not retire the session")
	}
}

func TestObserveAndEmitRequireOpenSession(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	if err := tracker.Observe("ghost", 1, 1); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Observe error = %v, want ErrNoSession", err)
	}
	if _, err := tracker.Emit("ghost"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Emit error = %v, want ErrNoSession", err)
	}
	if hinted := tracker.Teardown("ghost"); hinted {
		t.Fatal("Teardown on an unknown subscriber should not report a hint")
	}
}

// TestEmitFailureDoesNotDiscardBytes proves the delta watermark only advances
// once a record is successfully built. A dropped watermark would silently
// under-bill the interval that failed.
func TestEmitFailureDoesNotDiscardBytes(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	failing := &failingSeqStore{failUntil: 1, inner: NewMemorySeqStore()}
	tracker := newTestTracker(t, clock, failing)

	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := tracker.Observe("subscriber-a", 900, 9); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clock.Add(10 * time.Second)

	if _, err := tracker.Emit("subscriber-a"); err == nil {
		t.Fatal("Emit should fail while the sequence store fails")
	}

	record, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit after recovery: %v", err)
	}
	if record.BytesOut != 900 || record.PacketsOut != 9 {
		t.Fatalf("delta after a failed emit = %d/%d, want 900/9", record.BytesOut, record.PacketsOut)
	}
}

type failingSeqStore struct {
	calls     int
	failUntil int
	inner     SeqStore
	retired   []string
}

func (f *failingSeqStore) NextSeq(sessionID string) (uint64, error) {
	f.calls++
	if f.calls <= f.failUntil {
		return 0, errors.New("sequence store unavailable")
	}
	return f.inner.NextSeq(sessionID)
}

func (f *failingSeqStore) Retire(sessionID string) {
	f.retired = append(f.retired, sessionID)
	f.inner.Retire(sessionID)
}

// TestCloseRetiresSequenceState pins the retirement hook. Without it the
// sequence store keeps one entry per session for the lifetime of the process,
// and a durable store keeps one record per session in its file forever.
func TestCloseRetiresSequenceState(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	store := &failingSeqStore{inner: NewMemorySeqStore()}
	tracker := newTestTracker(t, clock, store)

	sessionID, err := tracker.Open("subscriber-a")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := tracker.Emit("subscriber-a"); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(store.retired) != 0 {
		t.Fatalf("a periodic emit retired the session: %v", store.retired)
	}

	final, err := tracker.Close("subscriber-a", CloseShutdown)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(store.retired) != 1 || store.retired[0] != sessionID {
		t.Fatalf("Close retired %v, want exactly [%s]", store.retired, sessionID)
	}
	// Retirement happens after the final record is built, so the final record
	// still carries a sequence number from the same run of the session.
	if final.Seq != 2 {
		t.Fatalf("final Seq = %d, want 2; retirement must not precede the record", final.Seq)
	}
}

// TestFailedCloseDoesNotRetire pins that a session whose final record could not
// be built keeps its sequence state, so a retry can still produce one.
func TestFailedCloseDoesNotRetire(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	store := &failingSeqStore{failUntil: 1, inner: NewMemorySeqStore()}
	tracker := newTestTracker(t, clock, store)

	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := tracker.Close("subscriber-a", CloseShutdown); err == nil {
		t.Fatal("Close should fail while the sequence store fails")
	}
	if len(store.retired) != 0 {
		t.Fatalf("a failed Close retired the session anyway: %v", store.retired)
	}
	if _, err := tracker.Close("subscriber-a", CloseShutdown); err != nil {
		t.Fatalf("Close after recovery: %v", err)
	}
	if len(store.retired) != 1 {
		t.Fatalf("the retry did not retire the session: %v", store.retired)
	}
}

// TestEmitWatermarkAdvancesOnConstruction pins the retry contract documented on
// Tracker.Emit, because the wrong reflex is the natural one: calling Emit again
// after a shipment failure does NOT reproduce the lost interval, it silently
// drops it. The contract is to retransmit the returned Record verbatim.
func TestEmitWatermarkAdvancesOnConstruction(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	if _, err := tracker.Open("subscriber-a"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := tracker.Observe("subscriber-a", 1_000, 10); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	clock.Add(10 * time.Second)

	shipped, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if shipped.BytesOut != 1_000 {
		t.Fatalf("first delta = %d, want 1000", shipped.BytesOut)
	}

	// Shipping failed. The wrong reflex: emit again instead of retransmitting.
	clock.Add(10 * time.Second)
	regenerated, err := tracker.Emit("subscriber-a")
	if err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if regenerated.BytesOut != 0 {
		t.Fatalf("second Emit restated %d bytes; the documented contract is that "+
			"it does not, and callers must retransmit the first Record verbatim",
			regenerated.BytesOut)
	}
	if regenerated.Seq == shipped.Seq {
		t.Fatalf("a second Emit reused Seq %d; the sink would drop it as a duplicate", shipped.Seq)
	}

	// Retransmitting the first record verbatim is the safe path, and the
	// documented rollup reconstructs the truth from it.
	seen := make(map[uint64]struct{})
	var total uint64
	for _, record := range []Record{shipped, shipped, regenerated} {
		if _, duplicate := seen[record.Seq]; duplicate {
			continue
		}
		seen[record.Seq] = struct{}{}
		total += record.BytesOut
	}
	if total != 1_000 {
		t.Fatalf("SUM(bytes_out) after a verbatim retransmit = %d, want 1000", total)
	}
}

func TestNewSessionIDIsUUIDv4(t *testing.T) {
	seen := make(map[string]struct{}, 512)
	for i := 0; i < 512; i++ {
		id, err := NewSessionID()
		if err != nil {
			t.Fatalf("NewSessionID: %v", err)
		}
		if len(id) != 36 {
			t.Fatalf("session ID %q is %d chars, want 36", id, len(id))
		}
		if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
			t.Fatalf("session ID %q is not UUID-shaped", id)
		}
		if id[14] != '4' {
			t.Fatalf("session ID %q is not version 4", id)
		}
		if variant := id[19]; !strings.ContainsRune("89ab", rune(variant)) {
			t.Fatalf("session ID %q has variant nibble %q, want RFC 4122", id, variant)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("NewSessionID returned a duplicate: %s", id)
		}
		seen[id] = struct{}{}
	}
}
