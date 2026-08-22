package erasure_test

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/shred"
)

func TestTrackerScoresDistinctShredsAtGraceDeadline(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(100, 0)
	for index := uint8(0); index < 31; index++ {
		if !tracker.Observe(header(10, 64, index), started) {
			t.Fatalf("first observation of index %d was rejected", index)
		}
	}
	if tracker.Observe(header(10, 64, 0), started) {
		t.Fatal("duplicate shred counted twice")
	}

	boundary := started.Add(time.Second)
	tracker.Observe(header(11, 0, 0), boundary)
	tracker.Advance(boundary.Add(grace - time.Nanosecond))
	if got := drain(t, tracker, boundary.Add(grace-time.Nanosecond)); got.SetsTotal != 0 || got.SetsErased != 0 {
		t.Fatalf("scored before grace deadline: %+v", got)
	}

	if tracker.Observe(header(10, 64, 31), boundary.Add(grace)) {
		t.Fatal("deadline shred changed a set before the timer advanced")
	}
	if got := drain(t, tracker, boundary.Add(grace+time.Nanosecond)); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("31-shred set score = %+v, want one erased set", got)
	} else if got.ErasureFraction != 1 {
		t.Fatalf("erasure fraction = %v, want 1", got.ErasureFraction)
	}
	if tracker.Observe(header(10, 64, 31), boundary.Add(grace+time.Millisecond)) {
		t.Fatal("late shred changed an already-scored slot")
	}
	if got := drain(t, tracker, boundary.Add(grace+time.Millisecond)); got.ErasureFraction != 0 {
		t.Fatalf("erasure fraction did not reset: %v", got.ErasureFraction)
	}
}

func TestTrackerCompletesSetAtThirtyTwoDistinctShreds(t *testing.T) {
	tracker, err := erasure.NewTracker(400*time.Millisecond, time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(200, 0)
	for index := uint8(0); index < 32; index++ {
		tracker.Observe(header(20, 96, index), started)
	}
	boundary := started.Add(time.Second)
	tracker.Observe(header(21, 0, 0), boundary)
	tracker.Advance(boundary.Add(400 * time.Millisecond))

	if got := drain(t, tracker, boundary.Add(400*time.Millisecond+time.Nanosecond)); got.SetsTotal != 1 || got.SetsErased != 0 {
		t.Fatalf("32-shred set score = %+v, want one complete set", got)
	}
	if got := drain(t, tracker, boundary.Add(401*time.Millisecond)); got.SetsTotal != 0 || got.SetsErased != 0 {
		t.Fatalf("window did not reset: %+v", got)
	}
}

func TestTrackerReportsRateGapAndSchemaWindow(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace, time.Unix(700, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(700, 0)
	arrivalOffsets := []time.Duration{
		0,
		500 * time.Microsecond,
		1500 * time.Microsecond,
		4500 * time.Microsecond,
		12500 * time.Microsecond,
		44500 * time.Microsecond,
	}
	for index, offset := range arrivalOffsets {
		if !tracker.Observe(header(40, 0, uint8(index)), started.Add(offset)) {
			t.Fatalf("observation %d was rejected", index)
		}
	}
	if tracker.Observe(header(40, 0, 0), started.Add(50*time.Millisecond)) {
		t.Fatal("duplicate observation was accepted")
	}

	window := drain(t, tracker, started.Add(30*time.Second))
	if math.Abs(window.RMean-0.2) > 1e-12 {
		t.Fatalf("mean rate = %v, want 0.2 shreds/s", window.RMean)
	}
	if window.RPeak100MS != 60 {
		t.Fatalf("peak rate = %v, want 60 shreds/s", window.RPeak100MS)
	}
	wantGaps := erasure.GapHistogram{LT1: 1, From1To2_4: 1, From2_4To7: 1, From7To32: 1, GTE32: 1}
	if window.GapMSHist != wantGaps {
		t.Fatalf("gap histogram = %+v, want %+v", window.GapMSHist, wantGaps)
	}
	if window.GraceMS != 400 || window.Schema != 2 {
		t.Fatalf("contract metadata = grace %d schema %d", window.GraceMS, window.Schema)
	}
	// The tracker was constructed at time.Unix(700, 0) and drained 30s later,
	// so the window identity and duration are both fully determined.
	if window.WindowStart != "1970-01-01T00:11:40Z" || window.WindowMS != 30_000 {
		t.Fatalf("window identity = start %q ms %d, want %q and 30000",
			window.WindowStart, window.WindowMS, "1970-01-01T00:11:40Z")
	}

	payload, err := json.Marshal(window)
	if err != nil {
		t.Fatal(err)
	}
	var contract map[string]any
	if err := json.Unmarshal(payload, &contract); err != nil {
		t.Fatal(err)
	}
	wantContract := map[string]any{
		"sets_total":       float64(0),
		"sets_erased":      float64(0),
		"erasure_fraction": float64(0),
		"r_mean":           0.2,
		"r_peak_100ms":     float64(60),
		"gap_ms_hist": map[string]any{
			"<1":    float64(1),
			"1-2.4": float64(1),
			"2.4-7": float64(1),
			"7-32":  float64(1),
			">=32":  float64(1),
		},
		"grace_ms":     float64(400),
		"schema":       float64(2),
		"window_start": "1970-01-01T00:11:40Z",
		"window_ms":    float64(30_000),
	}
	if !reflect.DeepEqual(contract, wantContract) {
		t.Fatalf("serialized window = %#v, want %#v", contract, wantContract)
	}
}

func TestTrackerGapBucketBoundaries(t *testing.T) {
	tests := []struct {
		name string
		gap  time.Duration
		want erasure.GapHistogram
	}{
		{name: "one millisecond", gap: time.Millisecond, want: erasure.GapHistogram{From1To2_4: 1}},
		{name: "two point four milliseconds", gap: 2400 * time.Microsecond, want: erasure.GapHistogram{From2_4To7: 1}},
		{name: "seven milliseconds", gap: 7 * time.Millisecond, want: erasure.GapHistogram{From7To32: 1}},
		{name: "thirty two milliseconds", gap: 32 * time.Millisecond, want: erasure.GapHistogram{GTE32: 1}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tracker, err := erasure.NewTracker(0, time.Unix(750, 0))
			if err != nil {
				t.Fatal(err)
			}
			started := time.Unix(750, 0)
			tracker.Observe(header(45, 0, 0), started)
			tracker.Observe(header(45, 0, 1), started.Add(test.gap))
			if got := drain(t, tracker, started.Add(30*time.Second)).GapMSHist; got != test.want {
				t.Fatalf("histogram at %s = %+v, want %+v", test.gap, got, test.want)
			}
		})
	}
}

func TestTrackerDrainResetsRateAndGapWindow(t *testing.T) {
	tracker, err := erasure.NewTracker(0, time.Unix(800, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(800, 0)
	tracker.Observe(header(50, 0, 0), started)
	tracker.Observe(header(50, 0, 1), started.Add(time.Millisecond))
	drain(t, tracker, started.Add(10*time.Second))

	tracker.Observe(header(50, 0, 2), started.Add(10*time.Second))
	window := drain(t, tracker, started.Add(40*time.Second))
	if math.Abs(window.RMean-(1.0/30.0)) > 1e-12 || window.RPeak100MS != 10 {
		t.Fatalf("reset rate window = mean %v peak %v", window.RMean, window.RPeak100MS)
	}
	if window.GapMSHist != (erasure.GapHistogram{}) {
		t.Fatalf("cross-window gap was counted: %+v", window.GapMSHist)
	}
}

func TestTrackerPeakRateUsesAlignedHundredMillisecondBuckets(t *testing.T) {
	tracker, err := erasure.NewTracker(0, time.Unix(900, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(900, 0)
	tracker.Observe(header(60, 0, 0), started.Add(100*time.Millisecond-time.Nanosecond))
	tracker.Observe(header(60, 0, 1), started.Add(100*time.Millisecond))

	if got := drain(t, tracker, started.Add(30*time.Second)); got.RPeak100MS != 10 {
		t.Fatalf("peak rate across aligned bucket boundary = %v, want 10", got.RPeak100MS)
	}
}

func TestTrackerReclaimsStateOlderThanTwoSlots(t *testing.T) {
	tracker, err := erasure.NewTracker(0, time.Unix(300, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(300, 0)
	for slot := uint64(1); slot <= 4; slot++ {
		tracker.Observe(header(slot, 0, 0), started.Add(time.Duration(slot)*time.Millisecond))
	}

	stats := tracker.Stats()
	if stats.NewestSlot != 4 {
		t.Fatalf("newest slot = %d, want 4", stats.NewestSlot)
	}
	if stats.TrackedSlots != 3 || stats.TrackedSets != 3 {
		t.Fatalf("retained state = %+v, want slots 2-4 only", stats)
	}
}

func TestTrackerScoresSetFirstObservedAfterItsBoundary(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace, time.Unix(400, 0))
	if err != nil {
		t.Fatal(err)
	}

	boundary := time.Unix(400, 0)
	tracker.Observe(header(11, 0, 0), boundary)
	tracker.Observe(header(10, 64, 0), boundary.Add(100*time.Millisecond))
	tracker.Advance(boundary.Add(grace))

	if got := drain(t, tracker, boundary.Add(grace+time.Nanosecond)); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("late first observation score = %+v, want one erased set", got)
	}
}

func TestTrackerRetainsOriginalBoundaryForSecondPriorSlot(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace, time.Unix(500, 0))
	if err != nil {
		t.Fatal(err)
	}

	boundary := time.Unix(500, 0)
	tracker.Observe(header(11, 0, 0), boundary)
	tracker.Observe(header(12, 0, 0), boundary.Add(100*time.Millisecond))
	if !tracker.Observe(header(10, 64, 0), boundary.Add(grace-time.Nanosecond)) {
		t.Fatal("second-prior slot rejected before its original grace deadline")
	}
	tracker.Advance(boundary.Add(grace))

	if got := drain(t, tracker, boundary.Add(grace+time.Nanosecond)); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("score = %+v, want slot 10 scored at its original deadline", got)
	}
}

func TestTrackerSupportsConcurrentDistinctCodingPositions(t *testing.T) {
	tracker, err := erasure.NewTracker(0, time.Unix(600, 0))
	if err != nil {
		t.Fatal(err)
	}

	started := time.Unix(600, 0)
	var wg sync.WaitGroup
	for index := uint8(32); index < 64; index++ {
		wg.Add(1)
		go func(index uint8) {
			defer wg.Done()
			tracker.Observe(header(30, 64, index), started)
		}(index)
	}
	wg.Wait()
	tracker.Observe(header(31, 0, 0), started.Add(time.Second))

	if got := drain(t, tracker, started.Add(time.Second+time.Nanosecond)); got.SetsTotal != 1 || got.SetsErased != 0 {
		t.Fatalf("concurrent coding-half score = %+v, want one complete set", got)
	}
}

func TestNewTrackerRejectsNegativeGrace(t *testing.T) {
	if _, err := erasure.NewTracker(-time.Millisecond, time.Unix(1, 0)); err == nil {
		t.Fatal("negative grace accepted")
	}
}

func TestNewTrackerRequiresWindowStart(t *testing.T) {
	if _, err := erasure.NewTracker(0, time.Time{}); err == nil {
		t.Fatal("zero report window start accepted")
	}
}

func TestTrackerDrainScoresIdleExpiredSet(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1000, 0)
	for index := uint8(0); index < 31; index++ {
		tracker.Observe(header(70, 0, index), started)
	}
	boundary := started.Add(time.Second)
	tracker.Observe(header(71, 0, 0), boundary)

	window := drain(t, tracker, boundary.Add(grace+time.Nanosecond))
	if window.SetsTotal != 1 || window.SetsErased != 1 {
		t.Fatalf("idle expired set score = %+v, want one erased set", window)
	}
}

func TestTrackerDelayedDrainUsesActualElapsedWindow(t *testing.T) {
	tracker, err := erasure.NewTracker(0, time.Unix(1100, 0))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1100, 0)
	tracker.Observe(header(80, 0, 0), started)

	window := drain(t, tracker, started.Add(60*time.Second))
	if math.Abs(window.RMean-(1.0/60.0)) > 1e-12 {
		t.Fatalf("delayed mean rate = %v, want %v", window.RMean, 1.0/60.0)
	}
}

func TestTrackerRejectsBackwardDrainWithoutReset(t *testing.T) {
	tracker, err := erasure.NewTracker(0, time.Unix(1200, 0))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(1200, 0)
	tracker.Observe(header(90, 0, 0), started)
	if _, err := tracker.DrainWindow(started.Add(-time.Nanosecond)); !errors.Is(err, erasure.ErrInvalidWindowCutoff) {
		t.Fatalf("backward drain error = %v, want %v", err, erasure.ErrInvalidWindowCutoff)
	}
	if got := drain(t, tracker, started.Add(30*time.Second)); got.RMean != 1.0/30.0 {
		t.Fatalf("failed drain reset state: mean rate = %v", got.RMean)
	}
}

// The shipped receiver drains from a ticker goroutine that does not hold the
// read-path mutex and passes the ticker's fire time as the cutoff, so arrivals
// stamped at or after that cutoff are routine rather than exceptional. This
// pins what happens to them: they belong to the window being drained, they are
// not double counted, and no arrival is lost.
func TestTrackerDrainAttributesArrivalsObservedBeforeTheCall(t *testing.T) {
	started := time.Unix(1300, 0)
	tracker, err := erasure.NewTracker(0, started)
	if err != nil {
		t.Fatal(err)
	}
	tracker.Observe(header(100, 0, 0), started.Add(30*time.Second))
	tracker.Observe(header(100, 0, 1), started.Add(31*time.Second))

	if got := drain(t, tracker, started.Add(30*time.Second)); got.RMean != 2.0/30.0 {
		t.Fatalf("arrivals at and after cutoff were withheld: mean = %v, want %v", got.RMean, 2.0/30.0)
	}
	if got := drain(t, tracker, started.Add(60*time.Second)); got.RMean != 0 {
		t.Fatalf("arrivals were counted twice: mean = %v, want 0", got.RMean)
	}
}

// A drain that lands mid-burst must not lose the gap or peak contribution of
// the arrivals it sweeps in, and must not carry either across the boundary.
func TestTrackerDrainAttributesGapAndPeakForArrivalsAfterCutoff(t *testing.T) {
	started := time.Unix(1350, 0)
	tracker, err := erasure.NewTracker(0, started)
	if err != nil {
		t.Fatal(err)
	}
	// Offset from a whole second so the cutoff does not itself land on a 100 ms
	// bucket edge, which would split the burst for reasons unrelated to the
	// drain.
	cutoff := started.Add(10*time.Second + 50*time.Millisecond)
	// Two arrivals before the cutoff and two at or after it, all inside one
	// 100 ms bucket, 3 ms apart.
	for index := uint8(0); index < 4; index++ {
		at := cutoff.Add(time.Duration(index)*3*time.Millisecond - 6*time.Millisecond)
		if !tracker.Observe(header(101, 0, index), at) {
			t.Fatalf("observation %d was rejected", index)
		}
	}

	got := drain(t, tracker, cutoff)
	if want := 4.0 / cutoff.Sub(started).Seconds(); math.Abs(got.RMean-want) > 1e-12 {
		t.Fatalf("mean = %v, want %v", got.RMean, want)
	}
	// One whole bucket of four, not a bucket split across two windows.
	if got.RPeak100MS != 40 {
		t.Fatalf("peak = %v, want 40", got.RPeak100MS)
	}
	if want := (erasure.GapHistogram{From2_4To7: 3}); got.GapMSHist != want {
		t.Fatalf("gaps = %+v, want %+v", got.GapMSHist, want)
	}
	if next := drain(t, tracker, cutoff.Add(30*time.Second)); next.RMean != 0 || next.RPeak100MS != 0 || next.GapMSHist != (erasure.GapHistogram{}) {
		t.Fatalf("delivery state leaked past the drain: %+v", next)
	}
}

func TestTrackerDrainPreservesFutureScore(t *testing.T) {
	const grace = 400 * time.Millisecond
	started := time.Unix(1400, 0)
	tracker, err := erasure.NewTracker(grace, started)
	if err != nil {
		t.Fatal(err)
	}
	tracker.Observe(header(110, 0, 0), started)
	boundary := started.Add(30 * time.Second)
	tracker.Observe(header(111, 0, 0), boundary)
	tracker.Advance(boundary.Add(grace))

	if got := drain(t, tracker, boundary); got.SetsTotal != 0 {
		t.Fatalf("first window included future score: %+v", got)
	}
	if got := drain(t, tracker, boundary.Add(30*time.Second)); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("future score was lost: %+v", got)
	}
}

func TestTrackerRejectsRepeatedCutoffWithoutReset(t *testing.T) {
	started := time.Unix(1500, 0)
	tracker, err := erasure.NewTracker(0, started)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := started.Add(30 * time.Second)
	drain(t, tracker, cutoff)
	tracker.Observe(header(120, 0, 0), cutoff.Add(time.Second))
	if _, err := tracker.DrainWindow(cutoff); !errors.Is(err, erasure.ErrInvalidWindowCutoff) {
		t.Fatalf("repeated cutoff error = %v, want %v", err, erasure.ErrInvalidWindowCutoff)
	}
	if got := drain(t, tracker, cutoff.Add(30*time.Second)); got.RMean != 1.0/30.0 {
		t.Fatalf("repeated cutoff reset state: mean = %v", got.RMean)
	}
}

func TestTrackerRejectsArrivalBeforeCurrentWindow(t *testing.T) {
	started := time.Unix(1600, 0)
	tracker, err := erasure.NewTracker(0, started)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := started.Add(30 * time.Second)
	drain(t, tracker, cutoff)
	if tracker.Observe(header(130, 0, 0), cutoff.Add(-time.Nanosecond)) {
		t.Fatal("arrival before current report window was accepted")
	}
}

func drain(t *testing.T, tracker *erasure.Tracker, cutoff time.Time) erasure.Window {
	t.Helper()
	window, err := tracker.DrainWindow(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	return window
}

func header(slot uint64, fecSetIndex uint32, index uint8) shred.Header {
	return shred.Header{
		Slot:           slot,
		FECSetIndex:    fecSetIndex,
		Index:          fecSetIndex + uint32(index),
		IndexWithinSet: index,
	}
}

// One wire-valid datagram carrying an out-of-range slot used to advance the
// frontier arbitrarily and, because every real shred then sat more than two
// slots behind it, permanently zero the erasure SLA -- while delivery and
// ingress accounting stayed green, so the operator saw a live feed with a
// perfect score. Slot is the one header field ParseWireHeader does not bound,
// and the receiver listens on 0.0.0.0 with no source filtering.
func TestTrackerRejectsImplausibleSlotJump(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Unix(100, 0)

	for index := uint8(0); index < 32; index++ {
		if !tracker.Observe(header(10, 64, index), started) {
			t.Fatalf("real shred %d rejected", index)
		}
	}

	poison := header(1<<40, 64, 0)
	if tracker.Observe(poison, started) {
		t.Fatal("implausible slot advanced the frontier")
	}
	if got := tracker.Stats(); got.NewestSlot != 10 {
		t.Fatalf("newestSlot = %d after poison, want 10 (frontier moved)", got.NewestSlot)
	} else if got.RejectedSlotJumps != 1 {
		t.Fatalf("RejectedSlotJumps = %d, want 1", got.RejectedSlotJumps)
	}

	// The feed must keep scoring: this is the whole point of the guard.
	for index := uint8(0); index < 32; index++ {
		if !tracker.Observe(header(11, 64, index), started.Add(time.Millisecond)) {
			t.Fatalf("real shred %d rejected after poison -- SLA is blacked out", index)
		}
	}
}

// The naive guard trades one blackout for another: a receiver that misses a
// genuine multi-minute gap sees every subsequent packet beyond the bound of a
// frontier that can no longer advance. A lone poisoned datagram does not
// repeat, so a plausible observation clears the counter; a real jump arrives as
// a continuous stream and must resync.
func TestTrackerResyncsOnSustainedSlotJump(t *testing.T) {
	tracker, err := erasure.NewTracker(400*time.Millisecond, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0)
	if !tracker.Observe(header(10, 64, 0), at) {
		t.Fatal("first shred rejected")
	}

	// A single outlier followed by real traffic must NOT accumulate to a resync.
	tracker.Observe(header(1<<40, 64, 0), at)
	if !tracker.Observe(header(10, 64, 1), at) {
		t.Fatal("real shred rejected after a lone outlier")
	}
	if got := tracker.Stats(); got.FrontierResyncs != 0 {
		t.Fatalf("FrontierResyncs = %d after an isolated outlier, want 0", got.FrontierResyncs)
	}

	// A genuine jump arrives as a stream and must be adopted.
	newSlot := uint64(10 + 100_000)
	var accepted bool
	for i := 0; i < 32; i++ {
		accepted = tracker.Observe(header(newSlot, 64, uint8(i)), at.Add(time.Duration(i)*time.Millisecond))
	}
	got := tracker.Stats()
	if !accepted || got.NewestSlot != newSlot {
		t.Fatalf("sustained jump not adopted: accepted=%v newestSlot=%d want %d", accepted, got.NewestSlot, newSlot)
	}
	if got.FrontierResyncs != 1 {
		t.Fatalf("FrontierResyncs = %d, want 1", got.FrontierResyncs)
	}
}

// TestTrackerRejectsIncoherentSlotJumps pins the difference between "16 in a
// row" and "16 that agree".
//
// TestTrackerResyncsOnSustainedSlotJump drives one constant slot value, so it
// exercises only the coherent case. Sixteen MUTUALLY UNRELATED out-of-range
// slots are noise, not a feed that moved somewhere; adopting the last of them
// would let whichever datagram arrived 16th choose the frontier and black out
// the erasure SLA for the life of the process.
func TestTrackerRejectsIncoherentSlotJumps(t *testing.T) {
	tracker, err := erasure.NewTracker(400*time.Millisecond, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0)
	if !tracker.Observe(header(10, 64, 0), at) {
		t.Fatal("first shred rejected")
	}

	// Well past slotResyncThreshold, each far out of range and far from every
	// other, so no run of coherent evidence ever forms.
	for i := 0; i < 64; i++ {
		slot := uint64(1<<40) + uint64(i)*(erasure.MaxSlotJumpForTest*97)
		if tracker.Observe(header(slot, 64, uint8(i%64)), at.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("incoherent jump %d (slot %d) was accepted", i, slot)
		}
	}

	got := tracker.Stats()
	if got.FrontierResyncs != 0 {
		t.Fatalf("FrontierResyncs = %d after 64 incoherent jumps, want 0", got.FrontierResyncs)
	}
	if got.NewestSlot != 10 {
		t.Fatalf("NewestSlot = %d after 64 incoherent jumps, want 10 (frontier must not move)", got.NewestSlot)
	}
	// The frontier is intact, so real traffic still scores.
	if !tracker.Observe(header(10, 64, 1), at.Add(time.Second)) {
		t.Fatal("real shred rejected after incoherent jumps: frontier was poisoned")
	}
}

// realisticSlotStep is the top of the step range observed in the bundled capture
// fixture (gaps of 159, 270, 69, 364, 207 — see the maxSlotJump docstring).
//
// The recovery path below drives this rather than a comfortable mid-range value
// so that this test is a second, independent guard on the anchor rule, at the
// integration layer instead of on extendRun directly. Under opener anchoring the
// per-observation step is capped at maxSlotJump/(threshold-1) = 273, so 15 steps
// of 364 never assemble a run, the frontier never resyncs, and `accepted` stays
// false. At the previous step of 137 both anchorings passed, so the end-to-end
// path proved nothing about which one was implemented.
const realisticSlotStep = 364

// TestTrackerRecoversFromPoisonedFrontier proves the guard is two-way.
//
// Before the self-heal, a frontier that reached a far-future slot was terminal:
// every real shred sat more than two slots behind it, took the stale branch, and
// returned without accumulating toward anything. Ingress and delivery stayed
// green while the erasure SLA read a permanent zero -- the failure this package
// exists to remove, reached through the guard rather than around it.
func TestTrackerRecoversFromPoisonedFrontier(t *testing.T) {
	tracker, err := erasure.NewTracker(400*time.Millisecond, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0)
	if !tracker.Observe(header(1_000, 64, 0), at) {
		t.Fatal("first shred rejected")
	}

	// Drive a coherent run to a far-future slot: the frontier is now wrong.
	poison := uint64(1) << 40
	for i := 0; i < erasure.SlotResyncThresholdForTest; i++ {
		tracker.Observe(header(poison, 64, uint8(i)), at.Add(time.Duration(i)*time.Millisecond))
	}
	if got := tracker.Stats(); got.NewestSlot != poison {
		t.Fatalf("setup failed: NewestSlot = %d, want the poisoned %d", got.NewestSlot, poison)
	}

	// Real traffic resumes at real slots. It must claw the frontier back.
	base := at.Add(time.Second)
	real := uint64(1_100)
	var accepted bool
	for i := 0; i < erasure.FrontierDistrustThresholdForTest; i++ {
		// Slots advance the way a real feed's do -- non-contiguous but coherent,
		// and at the top of the observed range so the anchor rule is exercised.
		accepted = tracker.Observe(header(real+uint64(i)*realisticSlotStep, 64, uint8(i)), base.Add(time.Duration(i)*time.Millisecond))
	}
	if !accepted {
		t.Fatal("real traffic never re-accepted: frontier poisoning is still terminal")
	}
	got := tracker.Stats()
	if got.NewestSlot >= poison {
		t.Fatalf("NewestSlot = %d, want the frontier clawed back near %d", got.NewestSlot, real)
	}
	if got.FrontierResyncs != 2 {
		t.Fatalf("FrontierResyncs = %d, want 2 (one to poison, one to recover)", got.FrontierResyncs)
	}

	// And scoring genuinely works again, rather than merely not rejecting.
	// Advance plausibly from the recovered frontier: re-observing the frontier
	// slot itself would be refused as already-scored once grace has elapsed,
	// which would prove nothing about recovery.
	next := got.NewestSlot + realisticSlotStep
	if !tracker.Observe(header(next, 65, 0), base.Add(20*time.Millisecond)) {
		t.Fatal("plausible advance from the recovered frontier rejected")
	}
	if tracker.Stats().TrackedSets == 0 {
		t.Fatal("recovered frontier accepts shreds but tracks no sets")
	}
}

// TestTrackerStaleRunDoesNotTripOnInterleavedTraffic guards the self-heal from
// becoming its own resync vector: ordinary reordering behind a HEALTHY frontier
// must never reach frontierDistrustThreshold, because accepted traffic keeps
// clearing the run.
func TestTrackerStaleRunDoesNotTripOnInterleavedTraffic(t *testing.T) {
	tracker, err := erasure.NewTracker(400*time.Millisecond, time.Unix(100, 0))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(100, 0)
	if !tracker.Observe(header(10_000, 63, 0), at) {
		t.Fatal("first shred rejected")
	}
	for i := 0; i < 64; i++ {
		// One late straggler far behind, then real in-window traffic. Distinct
		// indices throughout, so a refusal means the run tripped rather than
		// that the observation was a duplicate.
		tracker.Observe(header(9_000, 64, uint8(i)), at.Add(time.Duration(2*i)*time.Millisecond))
		if !tracker.Observe(header(10_000, 64, uint8(i)), at.Add(time.Duration(2*i+1)*time.Millisecond)) {
			t.Fatalf("in-window shred %d rejected", i)
		}
	}
	if got := tracker.Stats(); got.FrontierResyncs != 0 {
		t.Fatalf("FrontierResyncs = %d on interleaved stragglers, want 0", got.FrontierResyncs)
	}
}
