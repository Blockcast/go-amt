// Package erasure tracks receiver-observed Solana FEC-set completion.
package erasure

import (
	"errors"
	"sync"
	"time"

	"github.com/blockcast/go-amt/shred"
)

const (
	shredsPerSet   = 64
	peakRateBucket = 100 * time.Millisecond
	reportSchema   = 1
)

var ErrInvalidWindowCutoff = errors.New("report cutoff must follow window start")

// GapHistogram contains the fixed v1 consecutive-arrival gap buckets.
type GapHistogram struct {
	LT1        uint64 `json:"<1"`
	From1To2_4 uint64 `json:"1-2.4"`
	From2_4To7 uint64 `json:"2.4-7"`
	From7To32  uint64 `json:"7-32"`
	GTE32      uint64 `json:">=32"`
}

// Window is one schema-1 receiver delivery report.
type Window struct {
	SetsTotal       uint64       `json:"sets_total"`
	SetsErased      uint64       `json:"sets_erased"`
	ErasureFraction float64      `json:"erasure_fraction"`
	RMean           float64      `json:"r_mean"`
	RPeak100MS      float64      `json:"r_peak_100ms"`
	GapMSHist       GapHistogram `json:"gap_ms_hist"`
	GraceMS         int64        `json:"grace_ms"`
	Schema          uint8        `json:"schema"`
}

// Stats describes the currently retained scoring state.
type Stats struct {
	NewestSlot   uint64
	TrackedSlots int
	TrackedSets  int
}

type setKey struct {
	fecSetIndex uint32
}

type slotState struct {
	sets     map[setKey]uint64
	boundary time.Time
	scored   bool
}

type scoreEvent struct {
	at     time.Time
	erased bool
}

// deliveryWindow accumulates the three delivery outputs of one report window --
// mean rate, peak 100 ms rate, and the consecutive-gap histogram -- in space
// that does not depend on how many shreds the window observed.
//
// The tracker previously kept every arrival timestamp in a slice until the
// window drained, which pinned 24 bytes per shred per feed and, because
// DrainWindow reused the backing array, never released the high-water capacity:
// one 50k/s burst held ~38 MB of timestamps for the process lifetime. Each
// output is an O(1) fold, so none of that retention bought anything.
//
// Every field is a running fold over arrivals in Observe order. Observe
// requires receivedAt to be monotonic, and that requirement -- not merely the
// absolute bucket keying -- is what makes the peak fold exact: under it, an
// arrival landing in a different bucket proves the previous bucket closed for
// good, so only the current bucket's count has to stay live. The slice form
// this replaces accumulated into a map keyed by bucket and so was
// order-independent; observe degrades that loss conservatively rather than
// silently (see the out-of-order note there).
type deliveryWindow struct {
	arrivals    uint64
	peakRate    float64
	bucketIndex int64
	bucketOpen  bool
	bucketCount uint64
	lastArrival time.Time
	gaps        GapHistogram
}

func (w *deliveryWindow) observe(receivedAt time.Time) {
	w.arrivals++

	// Monotonic receivedAt is Observe's contract, and under it a differing
	// bucket index always means the previous bucket closed for good. Were that
	// contract ever broken, rotating on the stale index would reset the open
	// bucket's count and *under-report* the peak -- the one direction an SLA
	// metric must not fail in, and one no equivalence test over monotonic input
	// can catch. Folding an out-of-order arrival into the open bucket instead
	// keeps the failure conservative: the peak may be overstated, never hidden.
	// This is a safety net, not a second supported ordering; the fold is exact
	// only for monotonic input.
	bucket := receivedAt.UnixNano() / peakRateBucket.Nanoseconds()
	outOfOrder := !w.lastArrival.IsZero() && receivedAt.Before(w.lastArrival)
	if !w.bucketOpen || (bucket != w.bucketIndex && !outOfOrder) {
		w.bucketIndex = bucket
		w.bucketCount = 0
		w.bucketOpen = true
	}
	w.bucketCount++
	if rate := float64(w.bucketCount) / peakRateBucket.Seconds(); rate > w.peakRate {
		w.peakRate = rate
	}

	// A window's first arrival has no predecessor to measure against, so it
	// contributes no gap. lastArrival is cleared on drain, which is what keeps
	// a gap from being reported across a window boundary.
	if !w.lastArrival.IsZero() {
		w.gaps.observe(receivedAt.Sub(w.lastArrival))
	}
	w.lastArrival = receivedAt
}

// report folds the window into rep and resets the accumulator for the next one.
// elapsed is the wall interval the report covers.
func (w *deliveryWindow) report(rep *Window, elapsed time.Duration) {
	rep.RMean = float64(w.arrivals) / elapsed.Seconds()
	rep.RPeak100MS = w.peakRate
	rep.GapMSHist = w.gaps
	*w = deliveryWindow{}
}

// Tracker deduplicates shred positions and scores observed FEC sets once their
// slot boundary plus the configured grace has elapsed.
type Tracker struct {
	mu sync.Mutex

	grace       time.Duration
	initialized bool
	newestSlot  uint64
	boundaries  map[uint64]time.Time
	slots       map[uint64]*slotState
	windowStart time.Time
	delivery    deliveryWindow
	scores      []scoreEvent
}

// NewTracker constructs a tracker whose first report begins at windowStart. A
// zero grace scores at the slot boundary.
func NewTracker(grace time.Duration, windowStart time.Time) (*Tracker, error) {
	if grace < 0 {
		return nil, errors.New("erasure grace must not be negative")
	}
	if windowStart.IsZero() {
		return nil, errors.New("report window start must be set")
	}
	return &Tracker{
		grace:       grace,
		boundaries:  make(map[uint64]time.Time),
		slots:       make(map[uint64]*slotState),
		windowStart: windowStart,
	}, nil
}

// Observe records one parsed shred. receivedAt must be monotonic for both peak
// and consecutive-gap reporting, as it is on the receiver's serial UDP read
// path -- the timestamp is taken and folded in under the same lock, so the two
// cannot reorder. Out-of-order input does not corrupt totals or erasure
// scoring; it degrades RPeak100MS conservatively (see deliveryWindow.observe).
// It returns false for duplicate, stale, invalid, or already-scored
// observations.
func (t *Tracker) Observe(header shred.Header, receivedAt time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if header.IndexWithinSet >= shredsPerSet {
		return false
	}
	if receivedAt.Before(t.windowStart) {
		return false
	}
	if !t.initialized {
		t.initialized = true
		t.newestSlot = header.Slot
		t.recordPriorBoundaries(header.Slot, receivedAt)
	} else if header.Slot > t.newestSlot {
		for slot, state := range t.slots {
			if slot < header.Slot && state.boundary.IsZero() {
				state.boundary = receivedAt
				t.boundaries[slot] = receivedAt
			}
		}
		t.newestSlot = header.Slot
		t.recordPriorBoundaries(header.Slot, receivedAt)
	} else if t.newestSlot-header.Slot > 2 {
		return false
	}
	t.scoreDue(receivedAt)
	t.reclaimOldSlots()

	state := t.slots[header.Slot]
	if state == nil {
		state = &slotState{sets: make(map[setKey]uint64)}
		if header.Slot < t.newestSlot {
			boundary, ok := t.boundaries[header.Slot]
			if !ok || !receivedAt.Before(boundary.Add(t.grace)) {
				return false
			}
			state.boundary = boundary
		}
		t.slots[header.Slot] = state
	}
	if state.scored {
		return false
	}

	key := setKey{fecSetIndex: header.FECSetIndex}
	bit := uint64(1) << header.IndexWithinSet
	if state.sets[key]&bit != 0 {
		return false
	}
	state.sets[key] |= bit
	t.delivery.observe(receivedAt)
	return true
}

// Advance scores every set whose grace deadline is at or before now.
func (t *Tracker) Advance(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scoreDue(now)
	t.reclaimOldSlots()
}

// DrainWindow scores through cutoff, returns one report, and resets its
// counters. The broker normally calls it every 30 seconds; delayed calls use
// their actual elapsed interval so the mean rate is not silently distorted.
//
// Arrival attribution: every shred Observe accepted before this call belongs to
// the window being drained, whatever its timestamp is relative to cutoff.
// cutoff fixes the window's elapsed time and the next window's start; it does
// not re-partition arrivals that have already been folded into the counters.
// Scores are still partitioned by cutoff, because a score carries its own
// deadline and can legitimately fall in a later window than the drain.
//
// This rule replaces the old one, under which arrivals at or after cutoff were
// held back and re-counted in the next window. That is unrepresentable in O(1)
// space -- un-counting an arrival needs its timestamp, which is the retention
// this type exists to remove -- so the alternatives were to reject such a
// cutoff, to carry a single pending arrival, or to attribute as above. The
// first two are unsafe for the receiver this tracker is being built for. Note
// that at this commit DrainWindow has no production caller: the reporter that
// drives it arrives with #47, which adds a reportInterval ticker goroutine that
// does NOT hold the read-path mutex and passes the ticker's own fire time as
// cutoff, while the mu-guarded ReadFromUDP loop keeps stamping later arrivals
// (cmd/blockcast-shreds/main.go, once #47 lands). Under that wiring, arrivals
// at or after cutoff are routine and arbitrarily many, not an
// empty-barring-clock-skew set. Rejecting the cutoff would make the reporter
// skip the drain on every tick and freeze the erasure SLA at its last value --
// the confidently-clean-feed failure this reporting path exists to prevent --
// and one pending arrival cannot hold a suffix that is thousands of shreds long
// at 50k/s. Only the final drain, which runs under mu after the sockets close,
// sees the quiescent case.
//
// The cost is bounded and self-correcting: an arrival is still counted exactly
// once, so totals are conserved across windows, and only reporter scheduling
// lag can shift one between them. RPeak100MS gets more accurate, since a burst
// straddling the cutoff is now scored in one whole bucket instead of being
// split across two windows and understated.
func (t *Tracker) DrainWindow(cutoff time.Time) (Window, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !cutoff.After(t.windowStart) {
		return Window{}, ErrInvalidWindowCutoff
	}
	t.scoreDue(cutoff)
	window := Window{GraceMS: t.grace.Milliseconds(), Schema: reportSchema}

	retainedScores := t.scores[:0]
	for _, event := range t.scores {
		if event.at.Before(cutoff) {
			window.SetsTotal++
			if event.erased {
				window.SetsErased++
			}
			continue
		}
		retainedScores = append(retainedScores, event)
	}
	t.scores = retainedScores
	window.ErasureFraction = fraction(window.SetsErased, window.SetsTotal)

	t.delivery.report(&window, cutoff.Sub(t.windowStart))
	t.windowStart = cutoff
	return window, nil
}

// Stats returns the size of retained state for observability and tests.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats := Stats{NewestSlot: t.newestSlot, TrackedSlots: len(t.slots)}
	for _, state := range t.slots {
		stats.TrackedSets += len(state.sets)
	}
	return stats
}

func (t *Tracker) scoreDue(now time.Time) {
	for _, state := range t.slots {
		if state.scored || state.boundary.IsZero() || now.Before(state.boundary.Add(t.grace)) {
			continue
		}
		for _, bitmap := range state.sets {
			t.scores = append(t.scores, scoreEvent{
				at:     state.boundary.Add(t.grace),
				erased: bitsSet(bitmap) < 32,
			})
		}
		state.scored = true
	}
}

func (h *GapHistogram) observe(gap time.Duration) {
	switch {
	case gap < time.Millisecond:
		h.LT1++
	case gap < 2400*time.Microsecond:
		h.From1To2_4++
	case gap < 7*time.Millisecond:
		h.From2_4To7++
	case gap < 32*time.Millisecond:
		h.From7To32++
	default:
		h.GTE32++
	}
}

func fraction(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func (t *Tracker) reclaimOldSlots() {
	for slot := range t.slots {
		if slot < t.newestSlot && t.newestSlot-slot > 2 {
			delete(t.slots, slot)
		}
	}
	for slot := range t.boundaries {
		if slot < t.newestSlot && t.newestSlot-slot > 2 {
			delete(t.boundaries, slot)
		}
	}
}

func (t *Tracker) recordPriorBoundaries(slot uint64, observedAt time.Time) {
	for distance := uint64(1); distance <= 2 && slot >= distance; distance++ {
		prior := slot - distance
		if _, exists := t.boundaries[prior]; !exists {
			t.boundaries[prior] = observedAt
		}
	}
}

func bitsSet(bitmap uint64) int {
	count := 0
	for bitmap != 0 {
		bitmap &= bitmap - 1
		count++
	}
	return count
}
