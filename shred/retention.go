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
	// completionOctaves covers 2^7µs through 2^22µs, so any completion under
	// ~4.19s is bucketed and anything at or above it lands in the overflow
	// bucket. A set is finalized once its newest arrival falls out of the
	// retention window, so its arrival extent cannot much exceed that window —
	// but "cannot much exceed" is not "cannot exceed", and the ceiling has to
	// clear the window itself. At 13 octaves it did not: the ladder stopped at
	// ~1.05s while DefaultRetention is 2s, so every completion between them
	// reported the overflow floor, i.e. UNDER the truth, while three separate
	// docs promised the opposite. A set collecting shreds every ~100ms stays
	// live indefinitely and can legitimately span 1.8s. Two more octaves cost
	// 256 uint64 (2 KiB) and buy 4.19s of headroom over a user-settable window.
	completionOctaves     = 15
	completionBucketCount = (completionOctaves + 1) * completionSubBuckets
	// CompletionCeiling is the largest duration the ladder resolves. At or above
	// it a completion lands in the overflow bucket, whose reported value is this
	// same number — a LOWER bound, unlike every other bucket's upper edge.
	//
	// Exported for the same reason as CompletionRelativeError: the accuracy
	// claim has a boundary, and a caller that lets an operator widen the
	// retention window past it needs to be able to say so. See the --retain
	// check in cmd/blockcast-shreds.
	CompletionCeiling = time.Duration(uint64(1)<<(completionOctaves+completionSubBucketBits)) * time.Microsecond
	// completionOverflow is the index of the single unbounded tail bucket.
	completionOverflow = completionBucketCount
	// CompletionRelativeError is the worst-case fractional overstatement of a
	// reported completion percentile, exposed so the receipt's accuracy is a
	// documented number rather than folklore. It bounds the bucketed range
	// only: a percentile falling in the overflow bucket (at or above
	// CompletionCeiling) is reported as that floor and understates instead,
	// with no bound. See completionHistogram.
	CompletionRelativeError = 1.0 / float64(completionSubBuckets)
)

// Compile-time floor on the ladder's reach relative to the default window.
//
// This is a weaker statement than it looks, and the comment it replaced
// overclaimed: keeping the ceiling above DefaultRetention does NOT prevent
// understatement, because the window does not bound a set's completion span
// (see completionHistogram). It only stops the ladder being narrower than the
// window itself, which was the specific regression that widening the octaves
// fixed. The general condition is reported by Receipt.CompletionsAboveCeiling,
// not prevented here.
//
// Named rather than blank so that the thing it protects is legible at the point
// anyone would delete it: a bare `const _` reads as leftover scaffolding.
const _completionCeilingCoversDefaultRetention = uint(CompletionCeiling - DefaultRetention)

// completionHistogram is a bounded distribution of FEC-set completion
// durations.
//
// Percentiles cannot be both exact and bounded in one pass over an unbounded
// stream, and the scorer must be bounded — see Scorer's retention contract. So
// completion times are bucketed rather than retained individually, and reported
// percentiles are the upper edge of the bucket the true value fell in: never
// less than the truth, and over by at most CompletionRelativeError.
//
// One exception, and it is the only one: a completion at or above
// CompletionCeiling lands in the overflow bucket, which has no upper edge and
// reports its floor. That value is a LOWER bound, so a percentile that lands
// there understates.
//
// --retain does NOT bound this. The window ages a set on its NEWEST arrival
// (see Scorer.expiredKeys), so a set that keeps receiving shreds is never
// evicted and its first-to-32nd span is bounded only by the inter-arrival gap
// staying inside the window, not by the window itself. 32 shreds arriving 200ms
// apart span 6.2s at the 2s default — above the ceiling, with every gap well
// inside the window. Measured, not hypothetical.
//
// So no startup-time comparison against the window can predict this, and
// overflowed() exists to report it after the fact instead: it is the exact
// condition, observed rather than guessed.
type completionHistogram struct {
	buckets [completionBucketCount + 1]uint64
	count   uint64
}

// overflowed reports how many completions landed at or above CompletionCeiling
// and were therefore reported as that floor. Any nonzero value means this
// receipt's completion percentiles UNDERSTATE, by an unbounded amount.
func (h *completionHistogram) overflowed() uint64 {
	return h.buckets[completionOverflow]
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
		// Round up. Truncating reported 45.6µs as 45µs — below the truth, the
		// one direction this histogram promises never to go. Bounded at <1µs so
		// it does not move the ms-scale receipt numbers, but it makes the
		// guarantee unqualified. The completed > 0 guard keeps a genuine zero
		// exactly zero rather than rounding it up to one microsecond.
		micros = int64((completed + time.Microsecond - 1) / time.Microsecond)
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
		// strongest statement that remains true. This is the one bucket whose
		// reported value can be BELOW the observation — see completionHistogram.
		return CompletionCeiling
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
