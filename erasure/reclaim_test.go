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

// TestRetentionScalesWithArrivalRateNotSlotCount covers the geometry the
// bounded-retention test above cannot reach.
//
// That test steps 500ms per slot against a 400ms grace, so every slot is past
// its deadline before the next arrives and retention collapses to the newest
// one. Its `TrackedSlots > 2` assertion therefore proves only that the
// gap-exceeds-grace case is bounded -- it would hold just as well if the real
// bound were ten times higher, and it is what let the docstring claim "only the
// newest slot is held indefinitely" go unchallenged.
//
// When the slot gap is well UNDER grace -- a burst, a post-hiccup replay, a
// backfill -- every slot observed within the last grace period is still
// unscorable, so retention sits at arrival-rate x grace. That is bounded, but it
// is not small, and nothing in the suite would have noticed it growing.
func TestRetentionScalesWithArrivalRateNotSlotCount(t *testing.T) {
	const grace = 400 * time.Millisecond
	const slotPeriod = 20 * time.Millisecond // deliberately << grace
	const slotCount = 500

	base := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	tracker, err := erasure.NewTracker(grace, base.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	at := base
	var peak int
	for slotIndex := range slotCount {
		slot := uint64(1000) + uint64(slotIndex)*159
		tracker.Observe(shred.Header{Slot: slot, IndexWithinSet: 0}, at)
		at = at.Add(slotPeriod)
		if tracked := tracker.Stats().TrackedSlots; tracked > peak {
			peak = tracked
		}
	}

	// Slots in flight: those whose boundary+grace has not yet passed. The
	// boundary of a slot is set by the arrival of the NEXT one, so a slot stays
	// unscorable for grace after its successor, hence the +1 for the newest
	// slot that no successor has closed yet.
	inFlight := int(grace/slotPeriod) + 1
	upperBound := inFlight + 2 // reclaim keeps the 2 slots behind the frontier

	if peak > upperBound {
		t.Fatalf("peak TrackedSlots = %d over %d slots, want <= %d (rate x grace); retention is not rate-bounded",
			peak, slotCount, upperBound)
	}
	// The point of the case: this geometry genuinely retains more than the
	// gap-exceeds-grace one, so a bound stated as a small constant is wrong.
	if peak <= 2 {
		t.Fatalf("peak TrackedSlots = %d, want > 2: this test is not exercising the sub-grace-gap geometry it exists for", peak)
	}
	// Retention must track the RATE, not the number of slots ever observed.
	if peak >= slotCount/2 {
		t.Fatalf("peak TrackedSlots = %d over %d slots: retention is scaling with slot count, not arrival rate", peak, slotCount)
	}
}

// TestDrainReleasesBurstArrivalBuffer pins resident memory to the CURRENT feed
// rather than to the worst burst the process ever saw.
//
// DrainWindow filters arrivals in place via s[:0], which reuses -- and therefore
// retains -- the backing array. On a long-running validator that means one
// catch-up replay sets the high-water mark and the memory is never returned,
// even across hours of idle feed. A test asserting only len() would pass
// against exactly that bug, so this asserts capacity.
func TestDrainReleasesBurstArrivalBuffer(t *testing.T) {
	base := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	tracker, err := erasure.NewTracker(0, base.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}

	// A burst well past the shrink floor, so the backing array is forced to grow.
	const burst = 40 * erasure.MinRetainedCapacityForTest
	at := base
	for i := range burst {
		tracker.Observe(shred.Header{Slot: uint64(1000 + i/16), IndexWithinSet: uint8(i % 16)}, at)
		at = at.Add(time.Microsecond)
	}
	peakCap := tracker.ArrivalsCapForTest()
	if peakCap < burst/2 {
		t.Fatalf("arrivals cap = %d after a %d-shred burst; the burst did not grow the buffer, so this test proves nothing", peakCap, burst)
	}

	// Drain past every arrival: the window keeps nothing.
	if _, err := tracker.DrainWindow(at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	drainedCap := tracker.ArrivalsCapForTest()
	if drainedCap > erasure.MinRetainedCapacityForTest {
		t.Fatalf("arrivals cap = %d after draining a %d-shred burst, want <= %d; the burst high-water mark is still pinned",
			drainedCap, burst, erasure.MinRetainedCapacityForTest)
	}
}
