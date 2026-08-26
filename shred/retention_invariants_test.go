package shred

import (
	"math/rand"
	"strings"
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

// TestCompletionBelowTheLadderCeilingIsNeverUnderstated pins the histogram's
// stated direction of error BELOW the ladder's ceiling.
//
// The name is deliberate. This used to be called ...WithinTheRetentionWindow...
// and its doc claimed to cover "the whole range the window permits", which is
// false and hid a real defect: --retain does not bound a set's completion span,
// so completions above the ceiling occur at the default window (see
// TestDefaultWindowStillProducesCompletionsAboveTheCeiling). What this test
// actually pins is the bucketed range, which is the guarantee that holds.
//
// Every bucket but one reports its upper edge, so a percentile is at or above
// the truth. The overflow bucket is the exception: it has no upper edge and
// reports its floor, a LOWER bound. That was reachable at the default window,
// because the ladder stopped at ~1.05s while DefaultRetention is 2s, so a
// completion of 1.8s reported 1.048576s — understated by 42%, against three
// separate docs promising "never below the truth".
func TestCompletionBelowTheLadderCeilingIsNeverUnderstated(t *testing.T) {
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

// TestDefaultWindowStillProducesCompletionsAboveTheCeiling is the test whose
// absence let a false claim ship.
//
// The PR that widened the ladder asserted, in the README and in a startup
// warning, that the default window could not reach the overflow bucket because
// CompletionCeiling exceeds DefaultRetention. That reasoning bounds the wrong
// quantity. --retain ages a set on its NEWEST arrival (Scorer.expiredKeys), so a
// set that keeps receiving is never evicted and its first-to-32nd span is
// bounded only by the inter-arrival gap staying inside the window — not by the
// window. 32 shreds 200ms apart is 6.2s of span with every gap 200ms, well
// inside a 2s window.
//
// Nothing in the suite caught it because every completion test drove the
// histogram directly with hand-picked durations instead of driving a Scorer with
// arrivals. This one uses a real Scorer so the span is produced rather than
// asserted.
func TestDefaultWindowStillProducesCompletionsAboveTheCeiling(t *testing.T) {
	const gap = 200 * time.Millisecond
	scorer := NewScorerWithRetention(FormatAgave, DefaultRetention)
	start := time.Unix(1000, 0)
	for index := uint32(0); index < completionThreshold; index++ {
		if _, err := scorer.Observe(dataPacket(7, 0, index), start.Add(time.Duration(index)*gap)); err != nil {
			t.Fatal(err)
		}
	}
	span := time.Duration(completionThreshold-1) * gap
	if gap >= DefaultRetention {
		t.Fatalf("fixture is wrong: gap %s must stay inside the %s window or the set "+
			"is evicted and the scenario is not the one under test", gap, DefaultRetention)
	}
	if span <= CompletionCeiling {
		t.Fatalf("fixture is wrong: span %s must exceed the ceiling %s", span, CompletionCeiling)
	}

	receipt := scorer.Receipt()
	if receipt.CompletionsAboveCeiling == 0 {
		t.Errorf("a %s completion at the %s default window did not register above the "+
			"%s ceiling: the receipt cannot flag an understatement it does not count",
			span, DefaultRetention, CompletionCeiling)
	}
	if receipt.CompletionP50 >= span {
		t.Errorf("p50 = %s for a true span of %s: this test exists because the default "+
			"window DOES understate, so if it no longer does, the README caveat and "+
			"Receipt.CompletionsAboveCeiling are both describing a condition that can "+
			"no longer arise", receipt.CompletionP50, span)
	}
	// The caveat must reach the human table, not just the JSON field.
	rendered := receipt.String()
	if !strings.Contains(rendered, "UNDERSTATE") {
		t.Errorf("receipt understates but its rendering does not say so:\n%s", rendered)
	}
	// Guards the exact bug this caveat introduced on first attempt: the rendered
	// caveat contains a literal "0.78%", and splicing it into a format string
	// turns that into a verb, shifting every later argument.
	if strings.Contains(rendered, "%!") {
		t.Errorf("receipt rendering contains a format-verb error, so pre-rendered text "+
			"reached a format string:\n%s", rendered)
	}
}

// TestCleanReceiptCarriesNoCompletionCaveat is the paired negative: a run whose
// completions all fit the ladder must not carry the warning, or the caveat
// becomes noise that is ignored on the run where it matters.
func TestCleanReceiptCarriesNoCompletionCaveat(t *testing.T) {
	scorer := NewScorerWithRetention(FormatAgave, DefaultRetention)
	start := time.Unix(2000, 0)
	for index := uint32(0); index < completionThreshold; index++ {
		if _, err := scorer.Observe(dataPacket(11, 0, index), start.Add(time.Duration(index)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	receipt := scorer.Receipt()
	if receipt.CompletionsAboveCeiling != 0 {
		t.Fatalf("a 31ms span counted %d completions above the %s ceiling",
			receipt.CompletionsAboveCeiling, CompletionCeiling)
	}
	if rendered := receipt.String(); strings.Contains(rendered, "UNDERSTATE") {
		t.Errorf("a receipt with no above-ceiling completion still carries the caveat:\n%s", rendered)
	}
}

// TestCompletionsTotalIsTheCompletedSetCount pins the relationship Receipt
// documents between three of its fields, so the caveat's denominator cannot
// quietly stop being the thing it claims to count.
//
// A set is either completed into the histogram or counted erased, never both,
// so CompletionsTotal == SetsTotal-SetsErased. The fixture spans an eviction
// boundary because that is where the two paths diverge: finalize folds evicted
// sets into cumulative counters while receiptFor scores still-live sets into a
// copy of the histogram, and a completion counted in one but not the other
// would break the identity without either number looking wrong alone.
func TestCompletionsTotalIsTheCompletedSetCount(t *testing.T) {
	scorer := NewScorerWithRetention(FormatAgave, 500*time.Millisecond)
	start := time.Unix(1, 0)
	// One set completes and is then evicted by the far-future arrivals below.
	for index := uint32(0); index < completionThreshold; index++ {
		if _, err := scorer.Observe(dataPacket(1, 0, index), start.Add(time.Duration(index)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	// One set never completes, so it must land in SetsErased and not the histogram.
	for index := uint32(0); index < 5; index++ {
		if _, err := scorer.Observe(dataPacket(2, 0, index), start.Add(time.Duration(100+index)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	// One set completes and is still live when the receipt is taken.
	for index := uint32(0); index < completionThreshold; index++ {
		at := start.Add(5*time.Second + time.Duration(index)*time.Millisecond)
		if _, err := scorer.Observe(dataPacket(3, 0, index), at); err != nil {
			t.Fatal(err)
		}
	}

	receipt := scorer.Receipt()
	completed := receipt.SetsTotal - receipt.SetsErased
	if completed <= 0 {
		t.Fatalf("fixture is wrong: expected completed sets, got SetsTotal=%d SetsErased=%d",
			receipt.SetsTotal, receipt.SetsErased)
	}
	if receipt.CompletionsTotal != uint64(completed) {
		t.Errorf("CompletionsTotal = %d but SetsTotal-SetsErased = %d: the caveat's "+
			"denominator is no longer the number of completed sets, so \"N of M\" "+
			"misstates how much of the run is affected",
			receipt.CompletionsTotal, completed)
	}
}

// TestPartialOverflowDoesNotClaimEveryPercentileUnderstates is the honesty test
// for the caveat itself.
//
// Overflow is per-completion. A run where one completion in a hundred overflows
// leaves every reported percentile accurate, so a caveat asserting "the
// percentiles UNDERSTATE" would be false exactly where the rest of this change
// is about not making false statements.
func TestPartialOverflowDoesNotClaimEveryPercentileUnderstates(t *testing.T) {
	var histogram completionHistogram
	for i := 0; i < 99; i++ {
		histogram.observe(10 * time.Millisecond)
	}
	histogram.observe(30 * time.Second)

	if got := histogram.overflowed(); got != 1 {
		t.Fatalf("fixture is wrong: overflowed = %d, want 1", got)
	}
	// Every percentile here is accurate; only the one 30s completion is affected.
	for _, p := range []int{50, 95, 99} {
		if got := histogram.percentile(p); got > time.Second {
			t.Fatalf("fixture is wrong: p%d = %s, expected an unaffected percentile", p, got)
		}
	}

	caveat := completionCaveat(histogram.overflowed(), histogram.count)
	if !strings.Contains(caveat, "1 of 100") {
		t.Errorf("caveat does not state the affected fraction, so a reader cannot tell "+
			"a one-in-a-hundred run from a wholly-overflowed one: %s", caveat)
	}
	if !strings.Contains(caveat, CompletionCeiling.String()) {
		t.Errorf("caveat does not name the value that identifies an affected "+
			"percentile, so the reader must derive it: %s", caveat)
	}
	if strings.Contains(caveat, "the percentiles above UNDERSTATE") {
		t.Errorf("caveat asserts every percentile understates, which is false here — "+
			"p50/p95/p99 are all accurate and only one completion overflowed: %s", caveat)
	}
}

// TestCeilingValueUniquelyIdentifiesAnOverflowedPercentile is the precondition
// for the caveat naming a value instead of describing a rule.
//
// The caveat tells the reader "a percentile printed as exactly 4.194304s is one
// of them". That is only sound if no bucket other than the overflow one can
// report that duration — otherwise an unaffected percentile could wear the
// marker. Checking all 2048 non-overflow buckets rather than the top one alone,
// because the edge arithmetic is per-octave and a future widening changes every
// edge, not just the last.
func TestCeilingValueUniquelyIdentifiesAnOverflowedPercentile(t *testing.T) {
	var highest time.Duration
	for index := 0; index < completionOverflow; index++ {
		edge := completionBucketUpperEdge(index)
		if edge >= CompletionCeiling {
			t.Errorf("non-overflow bucket %d reports %s, at or above the ceiling %s: the "+
				"caveat's claim that this value identifies an overflowed percentile is "+
				"no longer true, so an accurate percentile can wear the marker",
				index, edge, CompletionCeiling)
		}
		if edge > highest {
			highest = edge
		}
	}
	if highest >= CompletionCeiling {
		t.Fatalf("highest non-overflow edge %s does not clear the ceiling %s", highest, CompletionCeiling)
	}
	// The overflow bucket must actually report the value the caveat names.
	if got := completionBucketUpperEdge(completionOverflow); got != CompletionCeiling {
		t.Errorf("overflow bucket reports %s, but the caveat tells operators to look "+
			"for %s", got, CompletionCeiling)
	}
}

// TestCompletionsTotalIdentityHoldsAcrossRandomArrivals is the randomized form
// of TestCompletionsTotalIsTheCompletedSetCount.
//
// That test pins the identity in one arrangement while Receipt documents it "by
// construction". The construction is that finalize and receiptFor each count a
// set once and then take exactly one of two exclusive branches — erased, or into
// the histogram. A third disposition in either loop (a set that is neither) would
// leave both counters individually plausible while the caveat's denominator
// quietly stopped being the completed-set count. Randomizing the window, set
// sizes and gaps holds that shut, and asserts on every feed receipt as well as
// the union, since receiptFor runs per-feed over the union's key universe.
func TestCompletionsTotalIdentityHoldsAcrossRandomArrivals(t *testing.T) {
	random := rand.New(rand.NewSource(20260819))
	var completions, erased uint64
	for trial := 0; trial < 300; trial++ {
		window := time.Duration(100+random.Intn(2000)) * time.Millisecond
		scorer := NewFeedScorerWithRetention(FormatAgave, []string{"a", "b", "c"}, window)
		at := time.Unix(int64(1000+trial), 0)
		type arrival struct {
			set   uint64
			index uint32
		}
		var arrivals []arrival
		for set := uint64(0); set < uint64(1+random.Intn(4)); set++ {
			// A shred index must stay inside its FEC set, so the population is
			// 0..completionThreshold. Half the sets are forced to the full count so
			// completions actually occur — a purely uniform draw would complete a
			// set only ~3% of the time and the identity would go mostly untested on
			// the histogram side.
			shreds := uint32(random.Intn(completionThreshold + 1))
			if random.Intn(2) == 0 {
				shreds = completionThreshold
			}
			for index := uint32(0); index < shreds; index++ {
				arrivals = append(arrivals, arrival{set: set, index: index})
			}
		}
		// Present shreds in a mixed order rather than walking one complete set
		// before the next. Production feeds interleave concurrent FEC sets, and
		// that is the arrangement in which one set can remain live while another
		// crosses the eviction boundary.
		random.Shuffle(len(arrivals), func(i, j int) {
			arrivals[i], arrivals[j] = arrivals[j], arrivals[i]
		})
		for _, arrival := range arrivals {
			// Gaps up to 3s so sets land on both sides of the eviction boundary.
			at = at.Add(time.Duration(random.Intn(3000)) * time.Millisecond)
			feed := []string{"a", "b", "c"}[random.Intn(3)]
			if _, err := scorer.Observe(feed, dataPacket(arrival.set, 0, arrival.index), at); err != nil {
				t.Fatalf("trial %d: %v", trial, err)
			}
		}

		receipt := scorer.Receipt()
		completions += receipt.Union.CompletionsTotal
		if receipt.Union.SetsErased > receipt.Union.SetsTotal {
			t.Fatalf("trial %d: SetsErased = %d exceeds SetsTotal = %d", trial,
				receipt.Union.SetsErased, receipt.Union.SetsTotal)
		}
		erased += uint64(receipt.Union.SetsErased)
		check := func(label string, r Receipt) {
			t.Helper()
			if want := r.SetsTotal - r.SetsErased; r.CompletionsTotal != uint64(want) {
				t.Fatalf("trial %d window=%s %s: CompletionsTotal = %d but "+
					"SetsTotal-SetsErased = %d", trial, window, label,
					r.CompletionsTotal, want)
			}
			if r.CompletionsAboveCeiling > r.CompletionsTotal {
				t.Fatalf("trial %d window=%s %s: CompletionsAboveCeiling = %d exceeds "+
					"CompletionsTotal = %d, so the caveat would read \"N of M\" with "+
					"N > M", trial, window, label, r.CompletionsAboveCeiling,
					r.CompletionsTotal)
			}
		}
		check("union", receipt.Union)
		for _, feed := range receipt.Feeds {
			check("feed "+feed.Name, feed.Receipt)
		}
	}
	if completions == 0 || erased == 0 {
		t.Fatalf("randomized fixture was vacuous: observed %d completions and %d erasures across 300 trials; want both paths exercised", completions, erased)
	}
}
