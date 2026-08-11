// Package erasure tracks receiver-observed Solana FEC-set completion.
package erasure

import (
	"errors"
	"sync"
	"time"

	"github.com/blockcast/go-amt/shred"
)

const shredsPerSet = 64

// Window is the scored FEC-set portion of one reporting window.
type Window struct {
	SetsTotal  uint64
	SetsErased uint64
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
}

// NewTracker constructs a tracker. A zero grace scores at the slot boundary.
func NewTracker(grace time.Duration) (*Tracker, error) {
	if grace < 0 {
		return nil, errors.New("erasure grace must not be negative")
	}
	return &Tracker{
		grace:      grace,
		boundaries: make(map[uint64]time.Time),
		slots:      make(map[uint64]*slotState),
	}, nil
}

// Observe records one parsed shred. It returns false for duplicate, stale,
// invalid, or already-scored observations.
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
	return true
}

// Advance scores every set whose grace deadline is at or before now.
func (t *Tracker) Advance(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scoreDue(now)
	t.reclaimOldSlots()
}

// DrainWindow returns and resets the scored window counters.
func (t *Tracker) DrainWindow() Window {
	t.mu.Lock()
	defer t.mu.Unlock()
	window := t.window
	t.window = Window{}
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
