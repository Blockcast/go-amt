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

// maxSlotJump bounds how far a single observation may advance the frontier.
//
// Slot arrives from the wire as a raw little-endian uint64 and, unlike version,
// geometry and local index, is not validated by ParseWireHeader. The receiver
// listens on 0.0.0.0 with no source filtering, so one wire-valid datagram
// carrying an out-of-range slot used to advance newestSlot arbitrarily; every
// real shred then sat more than 2 slots behind the frontier and was rejected
// for the life of the process. Delivery and ingress accounting are untouched by
// that, so /healthz and ingress_packets_total stay green and the operator sees a
// live feed with a perfect erasure score -- the exact "confidently clean feed
// under arbitrary real loss" failure this package exists to remove.
//
// Sized from capture data: consecutive slots differ by 69 to 364, so a few
// thousand is generous for real reordering while still making one bad datagram
// non-permanent.
const maxSlotJump = 4096

// slotResyncThreshold is how many consecutive implausible observations are
// treated as evidence that the FEED moved rather than that one datagram lied.
//
// Rejecting a large jump outright would trade one permanent blackout for
// another: a receiver that misses a genuine multi-minute gap would reject every
// subsequent packet, since they are all beyond the bound of a frontier that can
// no longer advance. A single poisoned datagram does not repeat -- the next real
// shred is within the bound and clears the counter -- whereas a genuine jump
// arrives as a continuous stream, so sustained evidence resyncs the frontier.
const slotResyncThreshold = 16

// Stats describes the currently retained scoring state.
type Stats struct {
	NewestSlot   uint64
	TrackedSlots int
	TrackedSets  int
	// RejectedSlotJumps counts observations refused for an implausible slot
	// advance. A silent guard replaces one invisible failure with another, so
	// this is exported for the same reason the erasure gauge is.
	RejectedSlotJumps uint64
	// FrontierResyncs counts how often sustained implausible slots were accepted
	// as a genuine feed jump.
	FrontierResyncs uint64
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

// Tracker deduplicates shred positions and scores observed FEC sets once their
// slot boundary plus the configured grace has elapsed.
type Tracker struct {
	mu sync.Mutex

	grace       time.Duration
	initialized bool
	newestSlot  uint64
	// pendingJumps counts CONSECUTIVE implausible advances; any plausible
	// observation clears it, which is what separates one bad datagram from a
	// feed that genuinely moved.
	pendingJumps      int
	pendingJumpSlot   uint64
	rejectedSlotJumps uint64
	frontierResyncs   uint64
	boundaries        map[uint64]time.Time
	slots             map[uint64]*slotState
	windowStart       time.Time
	arrivals          []time.Time
	scores            []scoreEvent
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

// Observe records one parsed shred. receivedAt must be monotonic for consecutive
// gap reporting, as it is on the receiver's serial UDP read path. It returns
// false for duplicate, stale, invalid, or already-scored observations.
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
		if header.Slot-t.newestSlot > maxSlotJump {
			t.rejectedSlotJumps++
			t.pendingJumps++
			t.pendingJumpSlot = header.Slot
			if t.pendingJumps < slotResyncThreshold {
				return false
			}
			// Sustained: the feed moved. Resync rather than stay blacked out.
			t.frontierResyncs++
			t.pendingJumps = 0
			t.slots = make(map[uint64]*slotState)
			t.boundaries = make(map[uint64]time.Time)
			t.newestSlot = header.Slot
			t.recordPriorBoundaries(header.Slot, receivedAt)
			t.scoreDue(receivedAt)
			t.reclaimOldSlots()
			state := &slotState{sets: make(map[setKey]uint64), boundary: receivedAt}
			t.slots[header.Slot] = state
			state.sets[setKey{fecSetIndex: header.FECSetIndex}] |= 1 << header.IndexWithinSet
			t.observeDelivery(receivedAt)
			return true
		}
		t.pendingJumps = 0
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
	} else {
		// A plausible in-window observation is evidence the frontier is still
		// real, so a lone poisoned datagram cannot accumulate toward a resync.
		t.pendingJumps = 0
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
	t.observeDelivery(receivedAt)
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

	retainedArrivals := t.arrivals[:0]
	rateBuckets := make(map[int64]uint64)
	var lastArrival time.Time
	for _, arrival := range t.arrivals {
		if !arrival.Before(cutoff) {
			retainedArrivals = append(retainedArrivals, arrival)
			continue
		}
		window.RMean++
		bucket := arrival.UnixNano() / peakRateBucket.Nanoseconds()
		rateBuckets[bucket]++
		if rate := float64(rateBuckets[bucket]) / peakRateBucket.Seconds(); rate > window.RPeak100MS {
			window.RPeak100MS = rate
		}
		if !lastArrival.IsZero() {
			window.GapMSHist.observe(arrival.Sub(lastArrival))
		}
		lastArrival = arrival
	}
	t.arrivals = retainedArrivals
	window.RMean /= cutoff.Sub(t.windowStart).Seconds()
	t.windowStart = cutoff
	return window, nil
}

// Stats returns the size of retained state for observability and tests.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats := Stats{
		NewestSlot:        t.newestSlot,
		TrackedSlots:      len(t.slots),
		RejectedSlotJumps: t.rejectedSlotJumps,
		FrontierResyncs:   t.frontierResyncs,
	}
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

func (t *Tracker) observeDelivery(receivedAt time.Time) {
	t.arrivals = append(t.arrivals, receivedAt)
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

// reclaimOldSlots drops scoring state that can no longer change.
//
// Slot state is retained until it has been SCORED, not merely until it is two
// slots behind the newest. Slot numbers are not contiguous on a real feed --
// this receiver sees only the shreds for its own feed, so consecutive observed
// slots routinely differ by tens or hundreds -- and reclaiming on slot-number
// distance alone deletes a set in the same Observe call that first gave it a
// boundary, which is always before boundary+grace has elapsed. Every set is
// then destroyed unscored and the erasure SLA reads a permanent zero under
// arbitrary real loss. The same race fires on contiguous slots whenever three
// slots arrive within one grace period.
//
// Retention stays bounded: scoreDue runs on every Observe and Advance, so a
// slot is scored once its deadline passes and reclaimed on the next pass. Only
// the newest slot is held indefinitely, and only because a slot cannot be
// scored until a later slot proves it ended.
func (t *Tracker) reclaimOldSlots() {
	for slot, state := range t.slots {
		if slot < t.newestSlot && t.newestSlot-slot > 2 && state.scored {
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
