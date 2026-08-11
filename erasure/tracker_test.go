package erasure_test

import (
	"sync"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/shred"
)

func TestTrackerScoresDistinctShredsAtGraceDeadline(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace)
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
	if got := tracker.DrainWindow(); got != (erasure.Window{}) {
		t.Fatalf("scored before grace deadline: %+v", got)
	}

	if tracker.Observe(header(10, 64, 31), boundary.Add(grace)) {
		t.Fatal("deadline shred changed a set before the timer advanced")
	}
	if got := tracker.DrainWindow(); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("31-shred set score = %+v, want one erased set", got)
	}
	if tracker.Observe(header(10, 64, 31), boundary.Add(grace+time.Millisecond)) {
		t.Fatal("late shred changed an already-scored slot")
	}
}

func TestTrackerCompletesSetAtThirtyTwoDistinctShreds(t *testing.T) {
	tracker, err := erasure.NewTracker(400 * time.Millisecond)
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

	if got := tracker.DrainWindow(); got.SetsTotal != 1 || got.SetsErased != 0 {
		t.Fatalf("32-shred set score = %+v, want one complete set", got)
	}
	if got := tracker.DrainWindow(); got != (erasure.Window{}) {
		t.Fatalf("window did not reset: %+v", got)
	}
}

func TestTrackerReclaimsStateOlderThanTwoSlots(t *testing.T) {
	tracker, err := erasure.NewTracker(0)
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
	tracker, err := erasure.NewTracker(grace)
	if err != nil {
		t.Fatal(err)
	}

	boundary := time.Unix(400, 0)
	tracker.Observe(header(11, 0, 0), boundary)
	tracker.Observe(header(10, 64, 0), boundary.Add(100*time.Millisecond))
	tracker.Advance(boundary.Add(grace))

	if got := tracker.DrainWindow(); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("late first observation score = %+v, want one erased set", got)
	}
}

func TestTrackerRetainsOriginalBoundaryForSecondPriorSlot(t *testing.T) {
	const grace = 400 * time.Millisecond
	tracker, err := erasure.NewTracker(grace)
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

	if got := tracker.DrainWindow(); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("score = %+v, want slot 10 scored at its original deadline", got)
	}
}

func TestTrackerSupportsConcurrentDistinctCodingPositions(t *testing.T) {
	tracker, err := erasure.NewTracker(0)
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

	if got := tracker.DrainWindow(); got.SetsTotal != 1 || got.SetsErased != 0 {
		t.Fatalf("concurrent coding-half score = %+v, want one complete set", got)
	}
}

func TestNewTrackerRejectsNegativeGrace(t *testing.T) {
	if _, err := erasure.NewTracker(-time.Millisecond); err == nil {
		t.Fatal("negative grace accepted")
	}
}

func header(slot uint64, fecSetIndex uint32, index uint8) shred.Header {
	return shred.Header{
		Slot:           slot,
		FECSetIndex:    fecSetIndex,
		Index:          fecSetIndex + uint32(index),
		IndexWithinSet: index,
	}
}
