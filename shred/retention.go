package shred

import (
	"math/bits"
	"time"
)

// DefaultRetention is how far behind the newest arrival a scorer keeps
// per-shred identity.
//
// # Why arrival time and not slot distance
//
// erasure.Tracker bounds the same kind of state by slot distance: it reclaims
// slots more than two behind its frontier (erasure/tracker.go, reclaimOldSlots).
// That works there because the tracker scores a dense live feed, where slot
// numbers advance one at a time and "two slots back" really is ~800ms back.
//
// It does not survive contact with a capture. In the bundled fixture the
// observed slots are 438757867, 438758026, 438758296, 438758365, 438758729 and
// 438758936 — gaps of 69 to 364 — and two of them arrive with slot numbers
// several hundred *below* their neighbours while their timestamps are the
// newest yet seen. A slot-distance window reads those as ancient and drops
// them; both belong to sets the receipt reports as erased, so scoring the
// bundled capture that way moves erasure_fraction from 0.286 to 0.000. The
// proxy fails because a slot number is a property of the shred and the question
// being asked — how long ago did this arrive — is a property of the arrival.
//
// So the bound here is the arrival clock directly. Two seconds is about five
// Solana slots: far wider than any inter-feed skew a duplicate can survive (the
// duplicates this recognises come from a second feed milliseconds behind the
// first), and still only a few thousand shreds at mainnet rates.
const DefaultRetention = 2 * time.Second

// Retention describes the per-shred state a scorer is currently holding. It
// exists so the retention bound can be asserted directly rather than inferred
// from process memory, mirroring erasure.Tracker.Stats.
type Retention struct {
	// Newest is the arrival the window is measured back from.
	Newest time.Time
	// Window is how far behind Newest state is kept.
	Window time.Duration
	// TrackedShreds is the number of per-shred dedup entries held.
	TrackedShreds int
	// TrackedSets is the number of per-FEC-set entries held.
	TrackedSets int
	// TrackedAttributions is the number of per-shred first-arrival credit
	// entries held. Always zero for a single-feed scorer, which needs none.
	TrackedAttributions int
}

// sweepAt is when the next eviction pass runs, expressed as a fraction of the
// window past the last one. Sweeping every arrival would make each one O(state);
// sweeping once per window amortizes it to O(1) at the cost of holding at most
// two windows rather than one. Rejecting is exact regardless — only reclamation
// is lazy.
func (s *Scorer) scheduleSweep(now time.Time) bool {
	if s.nextSweep.IsZero() {
		s.nextSweep = now.Add(s.window)
		return false
	}
	if now.Before(s.nextSweep) {
		return false
	}
	s.nextSweep = now.Add(s.window)
	return true
}

// retention reports this scorer's held state. FeedScorer.Retention aggregates it
// across the union and every feed.
func (s *Scorer) retention() Retention {
	return Retention{
		Newest:        s.lastArrival,
		Window:        s.window,
		TrackedShreds: len(s.dedup),
		TrackedSets:   len(s.sets),
	}
}

// Retention reports the per-shred state this scorer is currently holding.
func (s *Scorer) Retention() Retention {
	return s.retention()
}

// Completion-histogram geometry. Durations are recorded in microseconds into a
// log-linear (HDR-style) histogram: the first completionSubBuckets values get a
// bucket each, and every octave above that is divided into the same number of
// linear sub-buckets. That bounds the table at a fixed size while holding
// relative error to at most one part in completionSubBuckets.
const (
	completionSubBucketBits = 7
	completionSubBuckets    = 1 << completionSubBucketBits
	// completionOctaves covers 2^7µs through 2^20µs, so any completion under
	// ~1.05s is bucketed and anything at or above it lands in the overflow
	// bucket. A set is finalized once its newest arrival falls out of the
	// retention window, so its arrival extent cannot much exceed that window.
	completionOctaves     = 13
	completionBucketCount = (completionOctaves + 1) * completionSubBuckets
	// completionOverflow is the index of the single unbounded tail bucket.
	completionOverflow = completionBucketCount
	// CompletionRelativeError is the worst-case fractional overstatement of a
	// reported completion percentile, exposed so the receipt's accuracy is a
	// documented number rather than folklore.
	CompletionRelativeError = 1.0 / float64(completionSubBuckets)
)

// completionHistogram is a bounded distribution of FEC-set completion
// durations.
//
// Percentiles cannot be both exact and bounded in one pass over an unbounded
// stream, and the scorer must be bounded — see Scorer's retention contract. So
// completion times are bucketed rather than retained individually, and reported
// percentiles are the upper edge of the bucket the true value fell in: never
// less than the truth, and over by at most CompletionRelativeError.
type completionHistogram struct {
	buckets [completionBucketCount + 1]uint64
	count   uint64
}

func (h *completionHistogram) observe(completed time.Duration) {
	h.buckets[completionBucket(completed)]++
	h.count++
}

// completionBucket maps a duration to its bucket index. Durations at or below
// zero — a set whose 32nd distinct shred lands in the same clock tick as its
// first is a legitimate zero — map to bucket zero, whose upper edge is exactly
// zero, so that case stays exact rather than being rounded up into a bucket.
func completionBucket(completed time.Duration) int {
	micros := int64(0)
	if completed > 0 {
		micros = int64(completed / time.Microsecond)
	}
	value := uint64(micros)
	if value < completionSubBuckets {
		return int(value)
	}
	magnitude := bits.Len64(value) - 1
	octave := magnitude - completionSubBucketBits + 1
	if octave > completionOctaves {
		return completionOverflow
	}
	shift := uint(magnitude - completionSubBucketBits)
	return octave*completionSubBuckets + int((value>>shift)-completionSubBuckets)
}

// completionBucketUpperEdge is the largest duration that lands in bucket index.
func completionBucketUpperEdge(index int) time.Duration {
	if index >= completionOverflow {
		// The overflow bucket has no upper edge; report its floor, which is the
		// strongest statement that remains true.
		return time.Duration(uint64(1)<<(completionOctaves+completionSubBucketBits)) * time.Microsecond
	}
	if index < completionSubBuckets {
		return time.Duration(index) * time.Microsecond
	}
	octave := index / completionSubBuckets
	shift := uint(octave - 1)
	upper := (uint64(completionSubBuckets+index%completionSubBuckets) + 1) << shift
	return time.Duration(upper-1) * time.Microsecond
}

// percentile returns the nearest-rank pth percentile, matching the ranking the
// scorer used when it sorted completions individually.
func (h *completionHistogram) percentile(p int) time.Duration {
	if h.count == 0 {
		return 0
	}
	rank := (uint64(p)*h.count + 99) / 100
	if rank == 0 {
		rank = 1
	}
	var cumulative uint64
	for index, count := range h.buckets {
		cumulative += count
		if cumulative >= rank {
			return completionBucketUpperEdge(index)
		}
	}
	return completionBucketUpperEdge(completionOverflow)
}
