package erasure_test

import (
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/shred"
)

// driveSlots feeds slotCount slots of shredsPerSlot distinct shreds each into a
// fresh tracker. Slot numbers step by slotStep and each slot's shreds are
// separated from the next slot's by slotGap of wall time. It returns the window
// drained well after every scoring deadline has passed.
func driveSlots(t *testing.T, grace time.Duration, slotStep uint64, shredsPerSlot, slotCount int, slotGap time.Duration) erasure.Window {
	t.Helper()
	base := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	tracker, err := erasure.NewTracker(grace, base.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	at := base
	for slotIndex := range slotCount {
		slot := uint64(1000) + uint64(slotIndex)*slotStep
		for shredIndex := range shredsPerSlot {
			tracker.Observe(shred.Header{
				Slot:           slot,
				FECSetIndex:    0,
				IndexWithinSet: uint8(shredIndex),
			}, at)
			at = at.Add(time.Millisecond)
		}
		at = at.Add(slotGap)
	}
	// Advance far past the last deadline so nothing is pending for timing
	// reasons; anything still unscored was destroyed, not merely delayed.
	tracker.Advance(at.Add(time.Hour))
	window, err := tracker.DrainWindow(at.Add(2 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return window
}

// TestSetsAreScoredWhenSlotNumbersAreNotContiguous pins the retention rule that
// makes the erasure SLA reportable at all.
//
// Slot state used to be reclaimed on slot-number distance alone: any slot more
// than two behind the newest was deleted in the same Observe call that first
// gave it a boundary. Because a set cannot be scored until boundary+grace has
// elapsed, that deletion always won the race and every set died unscored --
// erasure_fraction then read 0 through arbitrary real loss, which is the
// failure this guards.
//
// Contiguous slot numbers are the special case, not the norm: this receiver
// sees only its own feed's shreds, so consecutive OBSERVED slots in the bundled
// capture differ by 69 to 364. A test that only ever steps by one would pass
// against the broken reclaim.
func TestSetsAreScoredWhenSlotNumbersAreNotContiguous(t *testing.T) {
	const grace = 400 * time.Millisecond
	// One set per slot, and the newest slot is never scored because no later
	// slot has proved it ended -- so slotCount-1 sets are expected.
	const slotCount = 6
	const wantTotal = slotCount - 1

	for _, testCase := range []struct {
		name     string
		slotStep uint64
		slotGap  time.Duration
	}{
		{name: "contiguous slots", slotStep: 1, slotGap: 500 * time.Millisecond},
		{name: "one past the two-slot window", slotStep: 3, slotGap: 500 * time.Millisecond},
		{name: "capture-sized slot gap", slotStep: 159, slotGap: 500 * time.Millisecond},
		// Three slots inside one grace period reclaims the oldest before its
		// own deadline, so this fails on the broken rule even at step 1.
		{name: "slots arriving faster than grace", slotStep: 1, slotGap: 50 * time.Millisecond},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			erased := driveSlots(t, grace, testCase.slotStep, 5, slotCount, testCase.slotGap)
			if erased.SetsTotal != wantTotal {
				t.Fatalf("SetsTotal = %d, want %d: sets were reclaimed before their scoring deadline", erased.SetsTotal, wantTotal)
			}
			if erased.SetsErased != wantTotal {
				t.Fatalf("SetsErased = %d, want %d: 5 of 64 shreds is an erased set", erased.SetsErased, wantTotal)
			}
			if erased.ErasureFraction != 1 {
				t.Fatalf("ErasureFraction = %v, want 1", erased.ErasureFraction)
			}

			// The same geometry with enough shreds must score complete, so the
			// assertion above cannot be satisfied by a tracker that simply
			// calls everything erased.
			complete := driveSlots(t, grace, testCase.slotStep, 40, slotCount, testCase.slotGap)
			if complete.SetsTotal != wantTotal {
				t.Fatalf("complete-set SetsTotal = %d, want %d", complete.SetsTotal, wantTotal)
			}
			if complete.SetsErased != 0 {
				t.Fatalf("complete-set SetsErased = %d, want 0: 40 of 64 shreds is above the 32 threshold", complete.SetsErased)
			}
		})
	}
}

// TestRetentionStaysBoundedWhileSlotsAreUnscored covers the cost of retaining
// unscored slots. Holding state until it is scored must not become "hold every
// slot forever": once a slot's deadline passes it is scored and reclaimed, so a
// long run over many non-contiguous slots settles at a small resident set
// rather than growing with the number of slots observed.
func TestRetentionStaysBoundedWhileSlotsAreUnscored(t *testing.T) {
	base := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	tracker, err := erasure.NewTracker(400*time.Millisecond, base.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	at := base
	for slotIndex := range 500 {
		slot := uint64(1000) + uint64(slotIndex)*159
		for shredIndex := range 5 {
			tracker.Observe(shred.Header{Slot: slot, IndexWithinSet: uint8(shredIndex)}, at)
			at = at.Add(time.Millisecond)
		}
		at = at.Add(500 * time.Millisecond)
	}
	// Only the newest slot can still be unscored: every earlier one is past its
	// deadline and reclaimed.
	if stats := tracker.Stats(); stats.TrackedSlots > 2 {
		t.Fatalf("TrackedSlots = %d after 500 slots, want <= 2; unscored state is accumulating", stats.TrackedSlots)
	}
}
