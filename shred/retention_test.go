package shred

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// testWindow is short enough that a test can step past it cheaply, and long
// enough to hold one round of arrivals.
const testWindow = 500 * time.Millisecond

// assertCompletionNear asserts that got is the bounded histogram's rendering of
// exactly want: never below the truth, and over by at most the documented
// relative error. Completion percentiles come from a fixed-size histogram
// because exact quantiles cannot be held in bounded memory, so an exact-equality
// assertion here would be asserting the absence of the bound.
func assertCompletionNear(t *testing.T, label string, got, want time.Duration) {
	t.Helper()
	ceiling := want + time.Duration(float64(want)*CompletionRelativeError) + time.Microsecond
	if got < want || got > ceiling {
		t.Fatalf("%s = %s, want within [%s, %s] — the bucketed rendering of %s", label, got, want, ceiling, want)
	}
}

func TestCompletionHistogramGeometry(t *testing.T) {
	t.Run("zero stays exact", func(t *testing.T) {
		// A set whose 32nd distinct shred lands in the same tick as its first is
		// a legitimate zero, and rounding it up would invent latency.
		var histogram completionHistogram
		histogram.observe(0)
		if got := histogram.percentile(50); got != 0 {
			t.Fatalf("percentile(50) = %s, want 0", got)
		}
	})

	t.Run("sub-bucket range stays exact", func(t *testing.T) {
		for micros := 0; micros < completionSubBuckets; micros++ {
			want := time.Duration(micros) * time.Microsecond
			var histogram completionHistogram
			histogram.observe(want)
			if got := histogram.percentile(50); got != want {
				t.Fatalf("percentile(50) = %s, want exactly %s below the sub-bucket ceiling", got, want)
			}
		}
	})

	t.Run("never understates and stays inside the error bound", func(t *testing.T) {
		for _, want := range []time.Duration{
			129 * time.Microsecond, 999 * time.Microsecond,
			time.Millisecond, 7 * time.Millisecond, 31 * time.Millisecond,
			62 * time.Millisecond, 400 * time.Millisecond, time.Second,
		} {
			var histogram completionHistogram
			histogram.observe(want)
			got := histogram.percentile(50)
			if got < want {
				t.Fatalf("percentile(50) = %s understates %s; a reported latency must never be below the truth", got, want)
			}
			if ceiling := want + time.Duration(float64(want)*CompletionRelativeError) + time.Microsecond; got > ceiling {
				t.Fatalf("percentile(50) = %s exceeds %s, the documented %.2f%% bound on %s", got, ceiling, CompletionRelativeError*100, want)
			}
		}
	})

	t.Run("bucket indices are monotonic and in range", func(t *testing.T) {
		previous := -1
		for micros := int64(0); micros < 4_000_000; micros = micros*3/2 + 1 {
			index := completionBucket(time.Duration(micros) * time.Microsecond)
			if index < previous {
				t.Fatalf("bucket(%dµs) = %d went backwards from %d", micros, index, previous)
			}
			if index > completionOverflow {
				t.Fatalf("bucket(%dµs) = %d exceeds the overflow index %d", micros, index, completionOverflow)
			}
			previous = index
		}
	})

	t.Run("above the top octave lands in overflow", func(t *testing.T) {
		var histogram completionHistogram
		histogram.observe(time.Hour)
		floor := time.Duration(uint64(1)<<(completionOctaves+completionSubBucketBits)) * time.Microsecond
		if got := histogram.percentile(50); got != floor {
			t.Fatalf("percentile(50) = %s, want the overflow floor %s", got, floor)
		}
	})

	t.Run("nearest-rank matches the exact ranking it replaces", func(t *testing.T) {
		// The histogram must rank the same way the sorted-slice helper does, so
		// the only difference between them is bucket rounding.
		values := []time.Duration{10 * time.Microsecond, 20 * time.Microsecond, 30 * time.Microsecond, 40 * time.Microsecond}
		var histogram completionHistogram
		for _, value := range values {
			histogram.observe(value)
		}
		for _, p := range []int{50, 95, 99} {
			if got, want := histogram.percentile(p), percentile(values, p); got != want {
				t.Fatalf("percentile(%d) = %s, want %s from the exact ranking", p, got, want)
			}
		}
	})
}

// feedRound delivers one round of shreds: sets FEC sets of 32 data shreds each,
// all complete, arriving 1ms apart from base. A data shred's position in its set
// is Index-FECSetIndex, so consecutive sets are laid out 32 apart.
func feedRound(t *testing.T, observe func([]byte, time.Time), slot uint64, sets int, base time.Time) {
	t.Helper()
	for set := 0; set < sets; set++ {
		fec := uint32(set * completionThreshold)
		for index := 0; index < completionThreshold; index++ {
			at := base.Add(time.Duration(set*completionThreshold+index) * time.Millisecond)
			observe(dataPacket(slot, fec, fec+uint32(index)), at)
		}
	}
}

// TestScorerRetentionPlateaus is the bound itself: held per-shred state must stop
// growing once the stream is longer than the window, not merely grow slower.
//
// It asserts on Retention rather than on process memory because the structure's
// bound is the property under test; TestScorerHeldMemoryPlateaus covers the heap
// consequence separately.
func TestScorerRetentionPlateaus(t *testing.T) {
	const setsPerRound, rounds = 4, 30
	scorer := NewScorerWithRetention(FormatAgave, testWindow)
	started := time.Unix(3, 0)
	observe := func(packet []byte, at time.Time) {
		if _, err := scorer.Observe(packet, at); err != nil {
			t.Fatalf("Observe() = %v", err)
		}
	}

	var afterFirst Retention
	for round := uint64(0); round < rounds; round++ {
		// Rounds are two windows apart, so each round's state is expired well
		// before the next round's sweep.
		feedRound(t, observe, round, setsPerRound, started.Add(time.Duration(round)*2*testWindow))
		if round == 2 {
			afterFirst = scorer.Retention()
		}
	}
	afterAll := scorer.Retention()

	if afterFirst.TrackedShreds == 0 {
		t.Fatalf("nothing retained after the first rounds: %+v", afterFirst)
	}
	if afterAll.TrackedShreds > afterFirst.TrackedShreds {
		t.Fatalf("tracked shreds grew from %d to %d across %dx more rounds; retention is not bounded",
			afterFirst.TrackedShreds, afterAll.TrackedShreds, rounds/3)
	}
	if afterAll.TrackedSets > afterFirst.TrackedSets {
		t.Fatalf("tracked sets grew from %d to %d", afterFirst.TrackedSets, afterAll.TrackedSets)
	}
	// Reclamation is lazy — it runs once per window — so at most two rounds'
	// worth can be held at any instant.
	if want := 2 * setsPerRound * completionThreshold; afterAll.TrackedShreds > want {
		t.Fatalf("tracked shreds = %d, want at most two rounds' %d", afterAll.TrackedShreds, want)
	}
	// Eviction must not cost the run-scoped receipt: every set is complete and
	// every round is counted, including the ones whose state is long gone.
	receipt := scorer.Receipt()
	if want := rounds * setsPerRound; receipt.SetsTotal != want {
		t.Fatalf("SetsTotal = %d, want %d; evicted sets must survive as counters", receipt.SetsTotal, want)
	}
	if receipt.SetsErased != 0 {
		t.Fatalf("SetsErased = %d, want 0; every set was delivered complete", receipt.SetsErased)
	}
	if receipt.MeanShredsPerSet != completionThreshold {
		t.Fatalf("MeanShredsPerSet = %v, want %d", receipt.MeanShredsPerSet, completionThreshold)
	}
}

// TestScorerHeldMemoryPlateaus is the heap consequence of the bound: the AC is
// about a receiver process whose RSS must reach a steady state, so the
// data-structure assertion above is not on its own sufficient.
func TestScorerHeldMemoryPlateaus(t *testing.T) {
	if testing.Short() {
		t.Skip("allocation measurement is noisy under -short")
	}
	const setsPerRound = 4

	held := func(rounds uint64) uint64 {
		scorer := NewScorerWithRetention(FormatAgave, testWindow)
		started := time.Unix(4, 0)
		for round := uint64(0); round < rounds; round++ {
			feedRound(t, func(packet []byte, at time.Time) {
				if _, err := scorer.Observe(packet, at); err != nil {
					t.Fatalf("Observe() = %v", err)
				}
			}, round, setsPerRound, started.Add(time.Duration(round)*2*testWindow))
		}
		var stats runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&stats)
		// Keep the scorer live across the measurement, or the GC is entitled to
		// collect the very state being measured.
		runtime.KeepAlive(scorer)
		return stats.HeapAlloc
	}

	baseline := held(10)
	tripled := held(30)
	// Linear growth would put tripled at ~3x baseline. The bound makes the
	// difference a fixed histogram plus one window of state, so allow generous
	// headroom for heap noise and still catch a 3x.
	if tripled > baseline*2 {
		t.Fatalf("held heap grew from %d B at 10 rounds to %d B at 30; expected a plateau, not linear growth", baseline, tripled)
	}
}

// TestRetentionDoesNotChangeTheFixtureReceipt is the regression this whole
// change has to survive: the bundled capture is the demo artifact, and bounding
// memory must not move a single number a customer reads off it.
//
// It is also the test that catches an age proxy that looks reasonable and is
// not. Bounding by slot distance (which is what erasure.Tracker does, and which
// is dense-feed-correct) drops two of this capture's shreds — their slot numbers
// sit hundreds below their neighbours' while their timestamps are the newest yet
// seen — and takes erasure_fraction from 0.286 to 0.000.
func TestRetentionDoesNotChangeTheFixtureReceipt(t *testing.T) {
	unbounded := NewScorerWithRetention(FormatForwarder, 24*time.Hour)
	if err := ReplayFixture(unbounded); err != nil {
		t.Fatal(err)
	}
	bounded := NewScorer()
	if err := ReplayFixture(bounded); err != nil {
		t.Fatal(err)
	}

	want, got := unbounded.Receipt(), bounded.Receipt()
	if got.SetsTotal != want.SetsTotal || got.SetsErased != want.SetsErased {
		t.Fatalf("retention changed the fixture's set accounting: got %d/%d erased, want %d/%d",
			got.SetsTotal, got.SetsErased, want.SetsTotal, want.SetsErased)
	}
	if got.ErasureFraction != want.ErasureFraction {
		t.Fatalf("retention changed erasure_fraction: got %v, want %v", got.ErasureFraction, want.ErasureFraction)
	}
	if got.MeanShredsPerSet != want.MeanShredsPerSet {
		t.Fatalf("retention changed mean_shreds_per_set: got %v, want %v", got.MeanShredsPerSet, want.MeanShredsPerSet)
	}
	if got.Gaps != want.Gaps {
		t.Fatalf("retention changed the gap histogram: got %+v, want %+v", got.Gaps, want.Gaps)
	}
	// Percentiles come from the same bounded histogram on both sides, so these
	// must match exactly; the histogram's rounding is covered separately.
	if got.CompletionP50 != want.CompletionP50 || got.CompletionP95 != want.CompletionP95 || got.CompletionP99 != want.CompletionP99 {
		t.Fatalf("retention changed completion percentiles: got %s/%s/%s, want %s/%s/%s",
			got.CompletionP50, got.CompletionP95, got.CompletionP99, want.CompletionP50, want.CompletionP95, want.CompletionP99)
	}
	if bounded.Retention().TrackedShreds >= unbounded.Retention().TrackedShreds {
		t.Fatalf("the bounded scorer retained %d shreds and the unbounded one %d; the window did nothing",
			bounded.Retention().TrackedShreds, unbounded.Retention().TrackedShreds)
	}
}

// TestEvictionPreservesConservation pins the invariant that makes
// first_arrival_fraction meaningful: the per-feed first-arrival counters
// partition the union's unique-shred count. Eviction drops the identity that
// lets credit move, so it must not drop the credit itself.
func TestEvictionPreservesConservation(t *testing.T) {
	scorer := NewFeedScorerWithRetention(FormatAgave, []string{"blockcast", "external"}, testWindow)
	started := time.Unix(5, 0)
	const rounds, setsPerRound = 20, 2

	for round := uint64(0); round < rounds; round++ {
		base := started.Add(time.Duration(round) * 2 * testWindow)
		for set := 0; set < setsPerRound; set++ {
			fec := uint32(set * completionThreshold)
			for index := 0; index < completionThreshold; index++ {
				packet := dataPacket(round, fec, fec+uint32(index))
				at := base.Add(time.Duration(index) * time.Millisecond)
				// Alternate which feed carries the earlier copy so credit is
				// split and re-attribution actually fires.
				early, late := "blockcast", "external"
				if index%2 == 1 {
					early, late = late, early
				}
				if _, err := scorer.Observe(late, packet, at.Add(time.Millisecond)); err != nil {
					t.Fatalf("Observe(%s) = %v", late, err)
				}
				if _, err := scorer.Observe(early, packet, at); err != nil {
					t.Fatalf("Observe(%s) = %v", early, err)
				}
			}
		}
	}

	receipt := scorer.Receipt()
	var total uint64
	for _, feed := range receipt.Feeds {
		total += feed.UniqueFirst
	}
	if total != receipt.UniqueShreds {
		t.Fatalf("sum(UniqueFirst) = %d, want UniqueShreds = %d; eviction unbalanced the partition", total, receipt.UniqueShreds)
	}
	if want := uint64(rounds * setsPerRound * completionThreshold); receipt.UniqueShreds != want {
		t.Fatalf("UniqueShreds = %d, want %d across the whole run", receipt.UniqueShreds, want)
	}
	var fraction float64
	for _, feed := range receipt.Feeds {
		fraction += feed.FirstArrivalFraction
	}
	if fraction < 0.999 || fraction > 1.001 {
		t.Fatalf("first-arrival fractions sum to %v, want 1", fraction)
	}
	// Every feed carried every shred, so neither rescued anything from the other.
	if receipt.SecondFeed == nil || receipt.SecondFeed.RescuedSets != 0 {
		t.Fatalf("second-feed worth = %+v, want no rescues", receipt.SecondFeed)
	}
	if got, want := receipt.Union.SetsTotal, rounds*setsPerRound; got != want {
		t.Fatalf("union SetsTotal = %d, want %d across the whole run", got, want)
	}
	if retention := scorer.Retention(); retention.TrackedAttributions > 2*setsPerRound*completionThreshold {
		t.Fatalf("first-arrival attributions unbounded: %+v", retention)
	}
}

// TestQuietFeedDoesNotPinState covers the feed that stops sending. Its own
// arrival frontier stops advancing, so ageing each feed against its own clock
// would keep that feed's last shreds forever — a slow leak that only shows up
// when an input fails, which is exactly when the receiver must stay up.
func TestQuietFeedDoesNotPinState(t *testing.T) {
	scorer := NewFeedScorerWithRetention(FormatAgave, []string{"blockcast", "external"}, testWindow)
	started := time.Unix(10, 0)

	// Both feeds carry the first round.
	for index := 0; index < completionThreshold; index++ {
		packet := dataPacket(0, 0, uint32(index))
		at := started.Add(time.Duration(index) * time.Millisecond)
		for _, name := range []string{"blockcast", "external"} {
			if _, err := scorer.Observe(name, packet, at); err != nil {
				t.Fatalf("Observe(%s) = %v", name, err)
			}
		}
	}
	// "external" then goes silent while "blockcast" keeps running.
	for round := uint64(1); round < 20; round++ {
		base := started.Add(time.Duration(round) * 2 * testWindow)
		for index := 0; index < completionThreshold; index++ {
			packet := dataPacket(round, 0, uint32(index))
			if _, err := scorer.Observe("blockcast", packet, base.Add(time.Duration(index)*time.Millisecond)); err != nil {
				t.Fatalf("Observe() = %v", err)
			}
		}
	}

	// The quiet feed's state must have aged out against the union's frontier.
	if got := scorer.Retention().TrackedShreds; got > 3*completionThreshold {
		t.Fatalf("tracked shreds = %d; a silent feed pinned its state instead of ageing out", got)
	}
	// It must still be reported, with the one round it did carry.
	receipt := scorer.Receipt()
	if len(receipt.Feeds) != 2 {
		t.Fatalf("receipt lost a feed: %+v", receipt.Feeds)
	}
	if got := receipt.Feeds[1].UniqueFirst; got != 0 {
		t.Fatalf("external UniqueFirst = %d; blockcast was processed first every time", got)
	}
	// The quiet feed's own gap histogram must be untouched by the union's
	// frontier. Ageing a feed by overwriting its lastArrival would work for
	// reclamation and silently corrupt this: lastArrival is also the gap
	// frontier, so the feed's 31 one-millisecond gaps would be replaced by one
	// enormous gap against the union's clock.
	if got := receipt.Feeds[1].Receipt.Gaps; got.From1To2_4 != completionThreshold-1 || got.GTE32 != 0 {
		t.Fatalf("quiet feed gap histogram = %+v, want %d gaps in 1-2.4ms and none >=32ms", got, completionThreshold-1)
	}
	if got, want := receipt.Union.SetsTotal, 20; got != want {
		t.Fatalf("union SetsTotal = %d, want %d", got, want)
	}
}

// TestLateDuplicateBeyondWindowCountsAsNew documents the one thing the bound
// gives up, so that it is a decision on the record rather than a surprise: a
// second copy arriving after the window has no surviving identity to match, and
// is counted as a new unique shred. The window exists to make this not happen
// for real duplicates, which arrive milliseconds apart.
func TestLateDuplicateBeyondWindowCountsAsNew(t *testing.T) {
	scorer := NewScorerWithRetention(FormatAgave, testWindow)
	started := time.Unix(12, 0)
	packet := dataPacket(7, 0, 0)
	if _, err := scorer.Observe(packet, started); err != nil {
		t.Fatalf("Observe() = %v", err)
	}

	// Inside the window the copy is recognised.
	accepted, err := scorer.Observe(packet, started.Add(testWindow/2))
	if err != nil {
		t.Fatalf("Observe() = %v", err)
	}
	if accepted {
		t.Fatal("a duplicate inside the window was counted as a new unique shred")
	}

	// Push the frontier past the window so the identity is reclaimed, then
	// re-deliver.
	for round := uint64(100); round < 110; round++ {
		if _, err := scorer.Observe(dataPacket(round, 0, 0), started.Add(time.Duration(round)*testWindow)); err != nil {
			t.Fatalf("Observe() = %v", err)
		}
	}
	accepted, err = scorer.Observe(packet, started.Add(200*testWindow))
	if err != nil {
		t.Fatalf("Observe() = %v", err)
	}
	if !accepted {
		t.Fatal("expected a copy arriving beyond the window to read as new; if this now fails the window semantics changed and the README must too")
	}
}

// TestConcurrentEvictionAndObservation exercises eviction under the same lock as
// attribution, which is what the -race job has to stay green against.
func TestConcurrentEvictionAndObservation(t *testing.T) {
	names := []string{"blockcast", "external"}
	scorer := NewFeedScorerWithRetention(FormatAgave, names, testWindow)
	started := time.Unix(7, 0)

	var wait sync.WaitGroup
	for _, name := range names {
		wait.Add(1)
		go func(feed string) {
			defer wait.Done()
			for round := uint64(0); round < 40; round++ {
				for index := 0; index < completionThreshold; index++ {
					packet := dataPacket(round, 0, uint32(index))
					at := started.Add(time.Duration(round)*2*testWindow + time.Duration(index)*time.Millisecond)
					if _, err := scorer.Observe(feed, packet, at); err != nil {
						t.Errorf("Observe(%s) = %v", feed, err)
						return
					}
				}
			}
		}(name)
	}
	// Observers race the writers: Receipt and Retention both read state that
	// eviction is concurrently deleting.
	wait.Add(1)
	go func() {
		defer wait.Done()
		for i := 0; i < 200; i++ {
			receipt := scorer.Receipt()
			var total uint64
			for _, feed := range receipt.Feeds {
				total += feed.UniqueFirst
			}
			if total != receipt.UniqueShreds {
				t.Errorf("observed torn receipt: sum(UniqueFirst) = %d, UniqueShreds = %d", total, receipt.UniqueShreds)
				return
			}
			_ = scorer.Retention()
		}
	}()
	wait.Wait()

	receipt := scorer.Receipt()
	var total uint64
	for _, feed := range receipt.Feeds {
		total += feed.UniqueFirst
	}
	if total != receipt.UniqueShreds {
		t.Fatalf("sum(UniqueFirst) = %d, want UniqueShreds = %d after concurrent eviction", total, receipt.UniqueShreds)
	}
}

// TestRetentionWindowIsConfigurable covers the knob the receiver exposes: a
// wider window must hold proportionally more, so the flag is doing something.
func TestRetentionWindowIsConfigurable(t *testing.T) {
	measure := func(window time.Duration) int {
		scorer := NewScorerWithRetention(FormatAgave, window)
		started := time.Unix(8, 0)
		for round := uint64(0); round < 20; round++ {
			feedRound(t, func(packet []byte, at time.Time) {
				if _, err := scorer.Observe(packet, at); err != nil {
					t.Fatalf("Observe() = %v", err)
				}
			}, round, 1, started.Add(time.Duration(round)*testWindow))
		}
		return scorer.Retention().TrackedShreds
	}
	narrow, wide := measure(testWindow/4), measure(8*testWindow)
	if narrow >= wide {
		t.Fatalf("a %s window held %d shreds and a %s window held %d; the bound is not configurable",
			testWindow/4, narrow, 8*testWindow, wide)
	}
}

func ExampleScorer_Retention() {
	scorer := NewScorerWithRetention(FormatAgave, 500*time.Millisecond)
	started := time.Unix(9, 0)
	for round := uint64(0); round < 10; round++ {
		for index := 0; index < completionThreshold; index++ {
			packet := dataPacket(round, 0, uint32(index))
			at := started.Add(time.Duration(round)*time.Second + time.Duration(index)*time.Millisecond)
			if _, err := scorer.Observe(packet, at); err != nil {
				panic(err)
			}
		}
	}
	retention := scorer.Retention()
	fmt.Println(retention.Window, retention.TrackedShreds, retention.TrackedSets)
	fmt.Println(scorer.Receipt().SetsTotal, scorer.Receipt().SetsErased)
	// Output:
	// 500ms 32 1
	// 10 0
}
