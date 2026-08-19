package shred

import (
	"testing"
	"time"
)

// TestNoFeedCountsMoreSetsThanTheUnion pins the containment invariant that the
// nil-universe sentinel used to break.
//
// A feed's set universe is a subset of the union's by construction, so a feed
// can never legitimately know more sets than the union does. It could when
// Scorer.evict took keys == nil to mean "derive your own universe", because
// Scorer.expiredKeys also returns a nil slice when nothing expired: a FeedScorer
// sweep that expired nothing at the union level handed every feed that same nil
// and each one silently finalized against itself, counting a set once then again
// when the union finally expired it.
//
// "The union expired nothing while a feed did" is the routine case, not an
// exotic one. The union's set.last is the max across feeds, so one feed's late
// shred keeps the union's copy live while another feed's copy sits below the
// floor. That is exactly the shape below.
func TestNoFeedCountsMoreSetsThanTheUnion(t *testing.T) {
	scorer := NewFeedScorerWithRetention(FormatAgave, []string{"a", "b"}, testWindow)
	start := time.Unix(100, 0)

	// Feed a carries most of one FEC set, early.
	for index := uint32(0); index < 20; index++ {
		at := start.Add(time.Duration(index) * time.Millisecond)
		if _, err := scorer.Observe("a", dataPacket(1, 0, index), at); err != nil {
			t.Fatal(err)
		}
	}
	// Feed b contributes one shred of the SAME set, late enough that the union's
	// copy stays live while feed a's copy has fallen below the floor.
	if _, err := scorer.Observe("b", dataPacket(1, 0, 20), start.Add(600*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// An arrival on an unrelated set drives the frontier forward so the union
	// finally expires the first set too.
	if _, err := scorer.Observe("a", dataPacket(2, 0, 0), start.Add(1200*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	receipt := scorer.Receipt()
	for _, feed := range receipt.Feeds {
		if feed.Receipt.SetsTotal > receipt.Union.SetsTotal {
			t.Errorf("feed %q SetsTotal = %d but the union knows only %d: a feed's set "+
				"universe is a subset of the union's, so this means a set was counted twice",
				feed.Name, feed.Receipt.SetsTotal, receipt.Union.SetsTotal)
		}
		// The other half of the same invariant. Containment on SetsTotal catches a
		// feed knowing more sets than the union, but not its erasure count drifting
		// within that bound — and erasure is the number the SLA is argued over. A
		// feed sees a subset of the union's shreds for every set, so its distinct
		// count per set can only be lower, so a set the union calls erased cannot
		// be complete on a feed: erasures are monotone the other way from totals.
		// A feed reporting FEWER erasures than the union would mean a feed saw a
		// shred the union did not.
		if feed.Receipt.SetsErased < receipt.Union.SetsErased {
			t.Errorf("feed %q SetsErased = %d but the union erased %d: a feed sees a "+
				"subset of each set's shreds, so it cannot complete a set the union "+
				"could not", feed.Name, feed.Receipt.SetsErased, receipt.Union.SetsErased)
		}
		if feed.Receipt.ErasureFraction < receipt.Union.ErasureFraction {
			t.Errorf("feed %q ErasureFraction = %.6f, below the union's %.6f: "+
				"GapClosed is defined as feed-minus-union, so this would report a "+
				"negative gap and read as multicast having lost ground",
				feed.Name, feed.Receipt.ErasureFraction, receipt.Union.ErasureFraction)
		}
		if feed.Receipt.MeanShredsPerSet > receipt.Union.MeanShredsPerSet {
			t.Errorf("feed %q MeanShredsPerSet = %.4f above the union's %.4f over the "+
				"same set universe, so the feed is credited with shreds the union "+
				"never counted", feed.Name, feed.Receipt.MeanShredsPerSet,
				receipt.Union.MeanShredsPerSet)
		}
	}
}

// TestUniqueFirstPartitionsUniqueShredsAcrossEviction pins the partition
// invariant README states as holding "exactly, always":
//
//	sum(unique_first) == unique_shreds_total
//
// Reclamation is what can break it, because eviction ages dedup entries by
// first < floor but sets by set.last < floor. A set whose arrival extent
// straddles the floor therefore keeps its bitmap after its early shreds have
// lost their dedup entries, and a later copy of one of those shreds misses
// dedup (so it looks new) but hits the set bitmap (so it is refused). Counting
// that shred into UniqueShreds while no feed is credited for it breaks the
// partition by one, cumulatively, with nothing to reconcile it.
func TestUniqueFirstPartitionsUniqueShredsAcrossEviction(t *testing.T) {
	scorer := NewFeedScorerWithRetention(FormatAgave, []string{"a", "b"}, testWindow)
	start := time.Unix(200, 0)

	for index := uint32(0); index < 20; index++ {
		at := start.Add(time.Duration(index) * time.Millisecond)
		if _, err := scorer.Observe("a", dataPacket(1, 0, index), at); err != nil {
			t.Fatal(err)
		}
	}
	// A straggler for the same set: the set survives the sweep because its
	// newest arrival is recent, while shreds 0..19 fall out of dedup because
	// their first arrivals do not. This is the decoupling.
	if _, err := scorer.Observe("a", dataPacket(1, 0, 25), start.Add(600*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// The second feed now re-sends one of the shreds whose dedup entry is gone.
	if _, err := scorer.Observe("b", dataPacket(1, 0, 5), start.Add(650*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	receipt := scorer.Receipt()
	var summed uint64
	for _, feed := range receipt.Feeds {
		summed += feed.UniqueFirst
	}
	if summed != receipt.UniqueShreds {
		t.Errorf("sum(UniqueFirst) = %d, UniqueShreds = %d: the partition invariant "+
			"README promises holds exactly is off by %d",
			summed, receipt.UniqueShreds, int64(receipt.UniqueShreds)-int64(summed))
	}
}

// TestCompletionWithinTheRetentionWindowIsNeverUnderstated pins the histogram's
// stated direction of error across the whole range the window permits.
//
// Every bucket but one reports its upper edge, so a percentile is at or above
// the truth. The overflow bucket is the exception: it has no upper edge and
// reports its floor, a LOWER bound. That was reachable at the default window,
// because the ladder stopped at ~1.05s while DefaultRetention is 2s, so a
// completion of 1.8s reported 1.048576s — understated by 42%, against three
// separate docs promising "never below the truth".
func TestCompletionWithinTheRetentionWindowIsNeverUnderstated(t *testing.T) {
	if CompletionCeiling <= DefaultRetention {
		t.Fatalf("CompletionCeiling %s must exceed DefaultRetention %s, or completions "+
			"inside the permitted window land in the overflow bucket and understate",
			CompletionCeiling, DefaultRetention)
	}
	for _, completed := range []time.Duration{
		1500 * time.Millisecond,
		1800 * time.Millisecond,
		1990 * time.Millisecond,
		DefaultRetention,
	} {
		var histogram completionHistogram
		histogram.observe(completed)
		if got := histogram.percentile(100); got < completed {
			t.Errorf("completion %s reported as %s, which is BELOW the truth", completed, got)
		}
	}
}

// TestCompletionAboveTheCeilingUnderstatesAndIsDocumented is the other side of
// the guarantee above, and exists because the guarantee is conditional while the
// docs once stated it flat.
//
// --retain is validated for positivity only, so an operator can widen the window
// past CompletionCeiling — and the README explicitly advises widening it when
// feeds can be seconds apart. Above the ceiling every completion collapses into
// the overflow bucket, which reports its floor, so the error flips direction and
// loses its bound: a 6s completion reports 4.194304s, a ~30% understatement
// against a documented 0.78% overstatement. That is intended behaviour for a
// bounded histogram; what is not acceptable is claiming otherwise, so this test
// pins the direction of the error rather than pretending it cannot happen.
func TestCompletionAboveTheCeilingUnderstatesAndIsDocumented(t *testing.T) {
	for _, completed := range []time.Duration{
		CompletionCeiling,
		CompletionCeiling + time.Microsecond,
		6 * time.Second,
		30 * time.Second,
	} {
		var histogram completionHistogram
		histogram.observe(completed)
		got := histogram.percentile(100)
		if got != CompletionCeiling {
			t.Errorf("completion %s reported as %s, want the overflow floor %s: the "+
				"overflow bucket is the documented exception and must report the "+
				"ceiling, not an invented upper edge", completed, got, CompletionCeiling)
		}
		if completed > CompletionCeiling && got >= completed {
			t.Errorf("completion %s reported as %s, which is not below the truth: this "+
				"test exists to pin that the overflow bucket understates, so if it now "+
				"holds the never-understate guarantee the docs and the --retain warning "+
				"in cmd/blockcast-shreds are both stale", completed, got)
		}
	}
}

// TestSubMicrosecondCompletionIsNotReportedBelowTheTruth covers the same
// guarantee at the other end of the ladder, where truncating to whole
// microseconds used to round 45.6µs down to 45µs. The error is bounded at <1µs
// and does not move the ms-scale receipt numbers, but it is the same direction
// the histogram promises never to go.
func TestSubMicrosecondCompletionIsNotReportedBelowTheTruth(t *testing.T) {
	const completed = 45600 * time.Nanosecond
	var histogram completionHistogram
	histogram.observe(completed)
	if got := histogram.percentile(100); got < completed {
		t.Errorf("completion %s reported as %s, which is below the truth", completed, got)
	}

	// A genuine zero must stay exactly zero rather than rounding up: a set whose
	// 32nd distinct shred lands in the same clock tick as its first is real.
	var zero completionHistogram
	zero.observe(0)
	if got := zero.percentile(100); got != 0 {
		t.Errorf("zero completion reported as %s, want exactly 0", got)
	}
}
