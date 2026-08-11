// Package erasure tracks receiver-observed Solana FEC-set completion.
package erasure

import (
	"errors"
	"sync"
	"time"

	"github.com/blockcast/go-amt/shred"
)

const (
	shredsPerSet    = 64
	reportingWindow = 30 * time.Second
	peakRateBucket  = 100 * time.Millisecond
	reportSchema    = 1
)

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

// Tracker deduplicates shred positions and scores observed FEC sets once their
// slot boundary plus the configured grace has elapsed.
type Tracker struct {
	mu sync.Mutex

	grace       time.Duration
	initialized bool
	newestSlot  uint64
	boundaries  map[uint64]time.Time
	slots       map[uint64]*slotState
	window      Window
	shreds      uint64
	peakCount   uint64
	rateBuckets map[int64]uint64
	lastArrival time.Time
}

// NewTracker constructs a tracker. A zero grace scores at the slot boundary.
func NewTracker(grace time.Duration) (*Tracker, error) {
	if grace < 0 {
		return nil, errors.New("erasure grace must not be negative")
	}
	return &Tracker{
		grace:       grace,
		boundaries:  make(map[uint64]time.Time),
		slots:       make(map[uint64]*slotState),
		rateBuckets: make(map[int64]uint64),
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

// DrainWindow returns and resets one fixed 30-second report. The broker
// heartbeat scheduler must call it once per reporting interval.
func (t *Tracker) DrainWindow() Window {
	t.mu.Lock()
	defer t.mu.Unlock()
	window := t.window
	window.ErasureFraction = fraction(window.SetsErased, window.SetsTotal)
	window.RMean = float64(t.shreds) / reportingWindow.Seconds()
	window.RPeak100MS = float64(t.peakCount) / peakRateBucket.Seconds()
	window.GraceMS = t.grace.Milliseconds()
	window.Schema = reportSchema
	t.window = Window{}
	t.shreds = 0
	t.peakCount = 0
	clear(t.rateBuckets)
	t.lastArrival = time.Time{}
	return window
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
			t.window.SetsTotal++
			if bitsSet(bitmap) < 32 {
				t.window.SetsErased++
			}
		}
		state.scored = true
	}
}

func (t *Tracker) observeDelivery(receivedAt time.Time) {
	t.shreds++
	bucket := receivedAt.UnixNano() / peakRateBucket.Nanoseconds()
	t.rateBuckets[bucket]++
	if t.rateBuckets[bucket] > t.peakCount {
		t.peakCount = t.rateBuckets[bucket]
	}

	if !t.lastArrival.IsZero() && !receivedAt.Before(t.lastArrival) {
		t.window.GapMSHist.observe(receivedAt.Sub(t.lastArrival))
	}
	if t.lastArrival.IsZero() || receivedAt.After(t.lastArrival) {
		t.lastArrival = receivedAt
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
