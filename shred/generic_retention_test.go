package shred

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// feedGenericWindow drives one whole window of length records, spaced 1ms apart,
// starting at at. It returns the arrival of the last record so a caller can place
// the next window relative to it.
func feedGenericWindow(t *testing.T, scorer *GenericScorer, window uint64, length uint16, at time.Time) time.Time {
	t.Helper()
	last := at
	for index := uint16(0); index < length; index++ {
		last = at.Add(time.Duration(index) * time.Millisecond)
		record := genericRecord(window, index, length, window*uint64(length)+uint64(index))
		if _, err := scorer.Observe(record, last); err != nil {
			t.Fatalf("observe window %d index %d: %v", window, index, err)
		}
	}
	return last
}

// TestGenericRetentionPlateaus is the core of BLO-28909: --mode generic held
// per-window state with no eviction path at all, so a long-running receiver grew
// monotonically. Feeding many windows well past the bound must leave held state
// flat, not proportional to the window count.
func TestGenericRetentionPlateaus(t *testing.T) {
	const windowLength, rounds = 8, 30
	scorer := NewGenericScorerWithRetention("test", "test", testWindow)
	started := time.Unix(3, 0)

	var afterFirst GenericRetention
	for round := uint64(0); round < rounds; round++ {
		// Rounds are two windows apart, so each round's state is expired well
		// before the next round's sweep.
		feedGenericWindow(t, scorer, round, windowLength, started.Add(time.Duration(round)*2*testWindow))
		if round == 2 {
			afterFirst = scorer.Retention()
		}
	}
	afterAll := scorer.Retention()

	if afterFirst.TrackedWindows == 0 {
		t.Fatalf("nothing retained after the first rounds: %+v", afterFirst)
	}
	if afterAll.TrackedWindows > afterFirst.TrackedWindows {
		t.Fatalf("tracked windows grew from %d to %d across %dx more rounds; retention is not bounded",
			afterFirst.TrackedWindows, afterAll.TrackedWindows, rounds/3)
	}
	// TrackedRecords is the figure that actually scales with window length, so a
	// bound on the window count alone would not prove the state is bounded.
	if afterAll.TrackedRecords > afterFirst.TrackedRecords {
		t.Fatalf("tracked records grew from %d to %d", afterFirst.TrackedRecords, afterAll.TrackedRecords)
	}
	// Reclamation is lazy — it runs once per window — so at most two rounds'
	// worth can be held at any instant.
	if want := 2 * windowLength; afterAll.TrackedRecords > want {
		t.Fatalf("tracked records = %d, want at most two rounds' %d", afterAll.TrackedRecords, want)
	}
}

// TestGenericEvictionPreservesReceiptFigures is the AC bullet that bounding must
// not change what the receipt reports: an evicted window has to survive as a
// counter. It compares a bounded scorer against an effectively unbounded one over
// identical input, which is the only comparison that can catch a fold that drops
// or double-counts a window.
func TestGenericEvictionPreservesReceiptFigures(t *testing.T) {
	const windowLength, rounds = 8, 20
	feed := func(scorer *GenericScorer) {
		started := time.Unix(3, 0)
		for round := uint64(0); round < rounds; round++ {
			feedGenericWindow(t, scorer, round, windowLength, started.Add(time.Duration(round)*2*testWindow))
		}
	}

	bounded := NewGenericScorerWithRetention("test", "test", testWindow)
	feed(bounded)
	unbounded := NewGenericScorerWithRetention("test", "test", 24*time.Hour)
	feed(unbounded)

	got, want := bounded.Receipt(), unbounded.Receipt()
	if got != want {
		t.Fatalf("bounded receipt differs from unbounded:\n got %+v\nwant %+v", got, want)
	}
	// Pin the absolute figures too, so a bug that corrupts both scorers
	// identically still fails.
	if got.Windows != rounds {
		t.Errorf("Windows = %d, want %d; evicted windows must survive as counters", got.Windows, rounds)
	}
	if got.WindowsComplete != rounds {
		t.Errorf("WindowsComplete = %d, want %d", got.WindowsComplete, rounds)
	}
	if got.RecordsExpected != rounds*windowLength {
		t.Errorf("RecordsExpected = %d, want %d", got.RecordsExpected, rounds*windowLength)
	}
	if got.InteriorMissing != 0 || got.TrailingMissing != 0 {
		t.Errorf("loss interior=%d trailing=%d, want 0/0; every window was delivered whole",
			got.InteriorMissing, got.TrailingMissing)
	}
	if got.Completeness != 1 {
		t.Errorf("Completeness = %v, want 1", got.Completeness)
	}
}

// TestGenericEvictionPreservesPartialWindowLoss is the loss-carrying counterpart:
// a window with an interior hole and a missing tail must report the same split
// after it has been evicted as it did while live. Folding loss at eviction is easy
// to get wrong in the direction that silently reports a clean feed.
func TestGenericEvictionPreservesPartialWindowLoss(t *testing.T) {
	const windowLength = 8
	// Indices 0,1,3,4 arrive: index 2 is an interior hole, 5..7 a trailing run.
	present := []uint16{0, 1, 3, 4}
	feed := func(scorer *GenericScorer) {
		at := time.Unix(3, 0)
		for offset, index := range present {
			record := genericRecord(0, index, windowLength, uint64(index))
			if _, err := scorer.Observe(record, at.Add(time.Duration(offset)*time.Millisecond)); err != nil {
				t.Fatalf("observe index %d: %v", index, err)
			}
		}
		// A second window, far enough past the first to push it out of the bound.
		feedGenericWindow(t, scorer, 1, windowLength, at.Add(4*testWindow))
	}

	bounded := NewGenericScorerWithRetention("test", "test", testWindow)
	feed(bounded)
	if held := bounded.Retention(); held.TrackedWindows != 1 {
		t.Fatalf("TrackedWindows = %d, want 1; the lossy window should have been evicted", held.TrackedWindows)
	}
	unbounded := NewGenericScorerWithRetention("test", "test", 24*time.Hour)
	feed(unbounded)

	got, want := bounded.Receipt(), unbounded.Receipt()
	if got != want {
		t.Fatalf("bounded receipt differs from unbounded:\n got %+v\nwant %+v", got, want)
	}
	if got.InteriorMissing != 1 {
		t.Errorf("InteriorMissing = %d, want 1", got.InteriorMissing)
	}
	if got.TrailingMissing != 3 {
		t.Errorf("TrailingMissing = %d, want 3", got.TrailingMissing)
	}
	if got.WindowsComplete != 1 {
		t.Errorf("WindowsComplete = %d, want 1; only the second window filled", got.WindowsComplete)
	}
}

// TestGenericLiveWindowIsNeverEvicted pins the axis choice. A window is aged on
// its NEWEST record, so one that keeps receiving stays live however long ago it
// opened. Ageing on the first record instead would evict a slow window out from
// under its own tail and report the tail as a fresh window.
func TestGenericLiveWindowIsNeverEvicted(t *testing.T) {
	const windowLength = 6
	scorer := NewGenericScorerWithRetention("test", "test", testWindow)
	at := time.Unix(3, 0)

	// One record every third of a window: the window's first record ends up far
	// older than the bound, but it never goes quiet for a whole window.
	for index := uint16(0); index < windowLength; index++ {
		record := genericRecord(0, index, windowLength, uint64(index))
		if _, err := scorer.Observe(record, at.Add(time.Duration(index)*testWindow/3)); err != nil {
			t.Fatalf("observe index %d: %v", index, err)
		}
	}
	span := time.Duration(windowLength-1) * testWindow / 3
	if span <= testWindow {
		t.Fatalf("test is vacuous: window spans %s, which is inside the %s bound", span, testWindow)
	}

	receipt := scorer.Receipt()
	if receipt.Windows != 1 {
		t.Fatalf("Windows = %d, want 1; a window still receiving records was split or dropped", receipt.Windows)
	}
	if receipt.WindowsComplete != 1 {
		t.Fatalf("WindowsComplete = %d, want 1; the window did fill", receipt.WindowsComplete)
	}
	if receipt.InteriorMissing != 0 || receipt.TrailingMissing != 0 {
		t.Fatalf("loss interior=%d trailing=%d, want 0/0", receipt.InteriorMissing, receipt.TrailingMissing)
	}
}

// TestGenericStragglerBeyondWindowRevivesItsWindow pins the price of bounding,
// so it is a decision on the record rather than a surprise in the field. A record
// arriving after its window has been evicted cannot be recognised as belonging to
// the old window — that identity is exactly what was released — so it opens a
// second lifetime and the window id is counted twice.
//
// Scorer has the identical property for FEC sets; see
// TestLateDuplicateBeyondWindowCountsAsNew. Neither can be closed without
// retaining evicted identities forever, which is the growth this eviction exists
// to stop.
func TestGenericStragglerBeyondWindowRevivesItsWindow(t *testing.T) {
	const windowLength = 4
	scorer := NewGenericScorerWithRetention("test", "test", testWindow)
	at := time.Unix(8, 0)

	// A whole window, delivered complete.
	feedGenericWindow(t, scorer, 0, windowLength, at)
	// A second window far enough ahead to push the first out of the bound.
	feedGenericWindow(t, scorer, 1, windowLength, at.Add(4*testWindow))
	// Now a straggler for window 0, well beyond its eviction.
	straggler := genericRecord(0, 0, windowLength, 0)
	if _, err := scorer.Observe(straggler, at.Add(8*testWindow)); err != nil {
		t.Fatalf("observe straggler: %v", err)
	}

	receipt := scorer.Receipt()
	// Three lifetimes: window 0, window 1, and window 0 again.
	if receipt.Windows != 3 {
		t.Fatalf("Windows = %d, want 3; a straggler past the bound opens a second lifetime", receipt.Windows)
	}
	// The straggler is counted as newly received, not as a duplicate: the dedup
	// state that would have recognised it is gone.
	if receipt.RecordsDuplicate != 0 {
		t.Errorf("RecordsDuplicate = %d, want 0; the evicted window's dedup state cannot recognise it", receipt.RecordsDuplicate)
	}
	if want := 2*windowLength + 1; receipt.RecordsReceived != want {
		t.Errorf("RecordsReceived = %d, want %d", receipt.RecordsReceived, want)
	}
	// The revived lifetime declares the full window length and has only one of
	// its records, so it contributes a trailing run. That is the visible cost.
	if want := 3 * windowLength; receipt.RecordsExpected != want {
		t.Errorf("RecordsExpected = %d, want %d", receipt.RecordsExpected, want)
	}
	if receipt.TrailingMissing != windowLength-1 {
		t.Errorf("TrailingMissing = %d, want %d", receipt.TrailingMissing, windowLength-1)
	}
}

// TestGenericHeldMemoryPlateaus is the heap consequence of the bound, mirroring
// TestScorerHeldMemoryPlateaus. The AC is about a receiver process whose RSS must
// reach a steady state, so the data-structure assertion above is not on its own
// sufficient.
//
// Both the load and the comparison are chosen from measurements, because the
// obvious versions of this test do not fail on the unfixed code:
//
//   - At the handful-of-rounds scale the other tests use, the retained maps are
//     too small to see. With eviction disabled entirely, 30 rounds of 8 records
//     passed a 2x ratio check comfortably.
//   - HeapAlloc carries a ~1.35 MB fixed floor from the rest of the test binary,
//     which dilutes a ratio badly: 10x the retained state showed up as only 2.0x
//     the heap, landing just inside a 2x threshold. A ratio against an absolute
//     heap reading is therefore the wrong shape.
//
// So this compares two same-shaped readings and allows absolute slack. Measured
// on this branch at 64 records per round: unfixed, 1.49 MB at 200 rounds against
// 3.05 MB at 2000, a 1.56 MB difference; fixed, 1.326 MB against 1.331 MB, a
// 5.5 KB difference with TrackedRecords flat at 64. The 512 KiB slack sits an
// order of magnitude above the observed noise and a third of the way below the
// unfixed signal.
func TestGenericHeldMemoryPlateaus(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement is noisy under -short")
	}
	const windowLength = 64
	const slack = 512 * 1024

	held := func(rounds uint64) (uint64, int) {
		scorer := NewGenericScorerWithRetention("test", "test", testWindow)
		started := time.Unix(4, 0)
		for round := uint64(0); round < rounds; round++ {
			feedGenericWindow(t, scorer, round, windowLength, started.Add(time.Duration(round)*2*testWindow))
		}
		var stats runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&stats)
		// Keep the scorer live across the measurement, or the GC is entitled to
		// collect the very state being measured.
		runtime.KeepAlive(scorer)
		return stats.HeapAlloc, scorer.Retention().TrackedRecords
	}

	baseline, baselineTracked := held(200)
	scaled, scaledTracked := held(2000)
	if scaled > baseline+slack {
		t.Fatalf("held heap grew from %d B at 200 rounds to %d B at 2000 (+%d B, slack %d B); expected a plateau, not linear growth",
			baseline, scaled, scaled-baseline, slack)
	}
	// The heap check above is the loose one; this is the tight statement of the
	// same fact, and it is what actually pins the bound.
	if scaledTracked != baselineTracked {
		t.Fatalf("tracked records moved from %d at 200 rounds to %d at 2000; the bound is not a steady state",
			baselineTracked, scaledTracked)
	}
	if want := 2 * windowLength; scaledTracked > want {
		t.Fatalf("tracked records = %d at 2000 rounds, want at most two rounds' %d", scaledTracked, want)
	}
}

// TestGenericRetentionWindowIsConfigurable is the --retain half of the AC: the
// flag was accepted in generic mode and silently ignored, because
// NewGenericFeedScorer took no retention parameter. A wider window must hold
// strictly more state than a narrower one over identical input, which is the only
// assertion that fails if the parameter is threaded but dropped.
func TestGenericRetentionWindowIsConfigurable(t *testing.T) {
	const windowLength, rounds = 4, 12
	held := func(window time.Duration) int {
		scorer := NewGenericScorerWithRetention("test", "test", window)
		started := time.Unix(5, 0)
		for round := uint64(0); round < rounds; round++ {
			feedGenericWindow(t, scorer, round, windowLength, started.Add(time.Duration(round)*testWindow))
		}
		return scorer.Retention().TrackedWindows
	}

	narrow := held(testWindow)
	wide := held(6 * testWindow)
	if wide <= narrow {
		t.Fatalf("a %s window held %d windows and a %s window held %d; --retain is not reaching the generic scorer",
			6*testWindow, wide, testWindow, narrow)
	}
}

// TestGenericFeedScorerRetentionIsPerFeed pins the plumbing the demo command
// actually runs: the flag has to reach every feed's scorer, not just the first.
func TestGenericFeedScorerRetentionIsPerFeed(t *testing.T) {
	const windowLength, rounds = 4, 12
	names := []string{"a", "b"}
	scorer := NewGenericFeedScorerWithRetention(names, "synthetic", "test", testWindow)
	started := time.Unix(6, 0)
	for round := uint64(0); round < rounds; round++ {
		at := started.Add(time.Duration(round) * 2 * testWindow)
		for _, name := range names {
			for index := uint16(0); index < windowLength; index++ {
				record := genericRecord(round, index, windowLength, round*windowLength+uint64(index))
				if _, err := scorer.Observe(name, record, at.Add(time.Duration(index)*time.Millisecond)); err != nil {
					t.Fatalf("observe feed %s round %d: %v", name, round, err)
				}
			}
		}
	}

	held := scorer.Retention()
	// Two feeds, lazy reclamation, so at most two rounds each.
	if want := len(names) * 2 * windowLength; held.TrackedRecords > want {
		t.Fatalf("TrackedRecords = %d across %d feeds, want at most %d; a feed's scorer is unbounded",
			held.TrackedRecords, len(names), want)
	}
	if held.Window != testWindow {
		t.Errorf("Window = %s, want %s", held.Window, testWindow)
	}
	// Every feed still reports every round, evicted or not.
	for _, feed := range scorer.Receipt().Feeds {
		if feed.Receipt.Windows != rounds {
			t.Errorf("feed %s Windows = %d, want %d", feed.Name, feed.Receipt.Windows, rounds)
		}
		if feed.Receipt.Completeness != 1 {
			t.Errorf("feed %s Completeness = %v, want 1", feed.Name, feed.Receipt.Completeness)
		}
	}
}

// TestGenericWindowFillPercentilesAreBucketedUpperBounds documents the one figure
// bounding does change. Exact per-window latencies cannot be retained under a
// memory bound, so fills go into the same histogram shred mode uses and the
// reported percentile is the upper edge of the bucket the truth fell in: never
// below the truth, and over by at most CompletionRelativeError.
func TestGenericWindowFillPercentilesAreBucketedUpperBounds(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	start := time.Unix(1, 0)
	const truth = 2 * time.Millisecond
	for window := uint64(0); window < 4; window++ {
		at := start.Add(time.Duration(window) * time.Millisecond * 10)
		if _, err := scorer.Observe(genericRecord(window, 0, 2, window*2), at); err != nil {
			t.Fatalf("observe window %d: %v", window, err)
		}
		if _, err := scorer.Observe(genericRecord(window, 1, 2, window*2+1), at.Add(truth)); err != nil {
			t.Fatalf("observe window %d: %v", window, err)
		}
	}

	got := scorer.Receipt().WindowP50
	if got < truth {
		t.Fatalf("p50 = %s, which is BELOW the true fill %s; the histogram must never understate a bucketed value", got, truth)
	}
	if slack := float64(got-truth) / float64(truth); slack > CompletionRelativeError {
		t.Fatalf("p50 = %s overstates the true fill %s by %.4f, above the documented %.4f",
			got, truth, slack, CompletionRelativeError)
	}
}

// TestGenericWindowFillOverflowIsReported is the paired negative of the bucketing
// promise: a fill at or above CompletionCeiling is recorded as that floor and so
// UNDERSTATES, and the receipt has to say so rather than presenting the number
// with an error bar that does not apply.
func TestGenericWindowFillOverflowIsReported(t *testing.T) {
	// The window must stay live long enough to fill, so the retention bound has
	// to exceed the fill span being measured.
	span := CompletionCeiling * 2
	scorer := NewGenericScorerWithRetention("test", "test", 24*time.Hour)
	at := time.Unix(7, 0)
	if _, err := scorer.Observe(genericRecord(0, 0, 2, 0), at); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if _, err := scorer.Observe(genericRecord(0, 1, 2, 1), at.Add(span)); err != nil {
		t.Fatalf("observe: %v", err)
	}

	receipt := scorer.Receipt()
	if receipt.WindowFillsAboveCeiling != 1 {
		t.Fatalf("WindowFillsAboveCeiling = %d, want 1", receipt.WindowFillsAboveCeiling)
	}
	if receipt.WindowFillsTotal != 1 {
		t.Fatalf("WindowFillsTotal = %d, want 1", receipt.WindowFillsTotal)
	}
	if receipt.WindowP50 != CompletionCeiling {
		t.Fatalf("WindowP50 = %s, want the ceiling %s reported as a floor", receipt.WindowP50, CompletionCeiling)
	}
	// The human table is what an operator reads in a dispute, so the caveat has
	// to be in the rendered receipt and not only in the JSON field.
	rendered := receipt.String()
	for _, needed := range []string{"window_fill WARNING", "UNDERSTATES", CompletionCeiling.String()} {
		if !strings.Contains(rendered, needed) {
			t.Errorf("rendered receipt is missing %q:\n%s", needed, rendered)
		}
	}
}
