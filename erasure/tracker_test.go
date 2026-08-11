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
	if window.GraceMS != 400 || window.Schema != 1 {
		t.Fatalf("contract metadata = grace %d schema %d", window.GraceMS, window.Schema)
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
		"grace_ms": float64(400),
		"schema":   float64(1),
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

func TestTrackerDrainPreservesArrivalsAtAndAfterCutoff(t *testing.T) {
	started := time.Unix(1300, 0)
	tracker, err := erasure.NewTracker(0, started)
	if err != nil {
		t.Fatal(err)
	}
	tracker.Observe(header(100, 0, 0), started.Add(30*time.Second))
	tracker.Observe(header(100, 0, 1), started.Add(31*time.Second))

	if got := drain(t, tracker, started.Add(30*time.Second)); got.RMean != 0 {
		t.Fatalf("first window included cutoff arrival: mean = %v", got.RMean)
	}
	if got := drain(t, tracker, started.Add(60*time.Second)); got.RMean != 2.0/30.0 {
		t.Fatalf("future arrivals were lost: mean = %v, want %v", got.RMean, 2.0/30.0)
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
