package shred

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

func genericRecord(window uint64, index, length uint16, sequence uint64) []byte {
	return AppendGenericHeader(nil, GenericHeader{
		Sequence:      sequence,
		Window:        window,
		IndexInWindow: index,
		WindowLength:  length,
	})
}

// observeGeneric feeds indices at a fixed 1ms spacing so every assertion about
// latency and gap bucketing is a function of the indices alone.
func observeGeneric(t *testing.T, scorer *GenericScorer, window uint64, length uint16, indices []uint16) {
	t.Helper()
	start := time.Unix(1, 0)
	for step, index := range indices {
		record := genericRecord(window, index, length, uint64(index))
		if _, err := scorer.Observe(record, start.Add(time.Duration(step)*time.Millisecond)); err != nil {
			t.Fatalf("observe window %d index %d: %v", window, index, err)
		}
	}
}

func TestGenericScorerSeparatesInteriorFromTrailingLoss(t *testing.T) {
	// The two losses are reported separately because they are different claims:
	// an interior hole is attested by the records that bracket it, while a
	// trailing run is only knowable from the declared WindowLength.
	tests := []struct {
		name             string
		length           uint16
		indices          []uint16
		wantInterior     int
		wantTrailing     int
		wantComplete     int
		wantCompleteness float64
	}{
		{
			name:         "clean window is complete",
			length:       8,
			indices:      []uint16{0, 1, 2, 3, 4, 5, 6, 7},
			wantInterior: 0, wantTrailing: 0, wantComplete: 1, wantCompleteness: 1,
		},
		{
			name:         "interior hole below the highest index seen",
			length:       8,
			indices:      []uint16{0, 1, 3, 4, 5, 6, 7},
			wantInterior: 1, wantTrailing: 0, wantComplete: 0, wantCompleteness: 7.0 / 8.0,
		},
		{
			name:         "trailing run above the highest index seen",
			length:       8,
			indices:      []uint16{0, 1, 2, 3, 4},
			wantInterior: 0, wantTrailing: 3, wantComplete: 0, wantCompleteness: 5.0 / 8.0,
		},
		{
			name:         "interior and trailing loss in one window",
			length:       8,
			indices:      []uint16{0, 2, 3, 4},
			wantInterior: 1, wantTrailing: 3, wantComplete: 0, wantCompleteness: 4.0 / 8.0,
		},
		{
			name:         "only the first record survives",
			length:       4,
			indices:      []uint16{0},
			wantInterior: 0, wantTrailing: 3, wantComplete: 0, wantCompleteness: 1.0 / 4.0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scorer := NewGenericScorer("test", "test")
			observeGeneric(t, scorer, 0, test.length, test.indices)
			receipt := scorer.Receipt()
			if receipt.InteriorMissing != test.wantInterior {
				t.Errorf("interior missing = %d, want %d", receipt.InteriorMissing, test.wantInterior)
			}
			if receipt.TrailingMissing != test.wantTrailing {
				t.Errorf("trailing missing = %d, want %d", receipt.TrailingMissing, test.wantTrailing)
			}
			if receipt.WindowsComplete != test.wantComplete {
				t.Errorf("windows complete = %d, want %d", receipt.WindowsComplete, test.wantComplete)
			}
			if receipt.Completeness != test.wantCompleteness {
				t.Errorf("completeness = %v, want %v", receipt.Completeness, test.wantCompleteness)
			}
		})
	}
}

// A window whose every record is lost is invisible, and the receipt must not
// pretend otherwise. This is the honest limit of the contract: completeness is
// scoped to windows at least one of whose records arrived.
func TestGenericScorerCannotSeeAWindowThatNeverArrived(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	observeGeneric(t, scorer, 0, 4, []uint16{0, 1, 2, 3})
	observeGeneric(t, scorer, 2, 4, []uint16{0, 1, 2, 3})
	receipt := scorer.Receipt()
	if receipt.Windows != 2 {
		t.Fatalf("windows = %d, want 2 — window 1 is unobservable, not partially counted", receipt.Windows)
	}
	if receipt.Completeness != 1 {
		t.Errorf("completeness = %v, want 1: every record of every observed window arrived", receipt.Completeness)
	}
}

func TestGenericScorerDuplicatesDoNotInflateCompleteness(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	// Index 2 is delivered three times; index 3 never arrives.
	observeGeneric(t, scorer, 0, 4, []uint16{0, 1, 2, 2, 2})
	receipt := scorer.Receipt()
	if receipt.RecordsDuplicate != 2 {
		t.Errorf("duplicates = %d, want 2", receipt.RecordsDuplicate)
	}
	if receipt.RecordsReceived != 3 {
		t.Errorf("received = %d, want 3 distinct records", receipt.RecordsReceived)
	}
	if receipt.Completeness != 0.75 {
		t.Errorf("completeness = %v, want 0.75 — five deliveries must not exceed four expected", receipt.Completeness)
	}
	if receipt.WindowsComplete != 0 {
		t.Errorf("windows complete = %d, want 0: a redelivered record cannot close a window", receipt.WindowsComplete)
	}
}

func TestGenericScorerOutOfOrderIsCountedButNotPenalised(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	start := time.Unix(1, 0)
	// Sequence numbers are carried by the record, so delivering 2 before 1
	// leaves 1 detectably late without making it a loss.
	for step, index := range []uint16{0, 2, 1, 3} {
		record := genericRecord(0, index, 4, uint64(index))
		if _, err := scorer.Observe(record, start.Add(time.Duration(step)*time.Millisecond)); err != nil {
			t.Fatalf("observe index %d: %v", index, err)
		}
	}
	receipt := scorer.Receipt()
	if receipt.RecordsOutOfOrder != 1 {
		t.Errorf("out of order = %d, want 1", receipt.RecordsOutOfOrder)
	}
	if receipt.Completeness != 1 {
		t.Errorf("completeness = %v, want 1: reordering is not loss", receipt.Completeness)
	}
	if receipt.WindowsComplete != 1 {
		t.Errorf("windows complete = %d, want 1", receipt.WindowsComplete)
	}
	if receipt.InteriorMissing != 0 || receipt.TrailingMissing != 0 {
		t.Errorf("loss = interior %d trailing %d, want 0/0", receipt.InteriorMissing, receipt.TrailingMissing)
	}
}

// Window closure is by the declared terminal count, never by a timer or by the
// arrival of a flag, so a window closes on its last distinct record whenever
// that arrives.
func TestGenericScorerClosesWindowOnDeclaredLength(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	observeGeneric(t, scorer, 0, 3, []uint16{2, 0})
	if got := scorer.Receipt().WindowsComplete; got != 0 {
		t.Fatalf("windows complete = %d before the final record, want 0", got)
	}
	observeGeneric(t, scorer, 0, 3, []uint16{1})
	receipt := scorer.Receipt()
	if receipt.WindowsComplete != 1 {
		t.Errorf("windows complete = %d after the final record, want 1", receipt.WindowsComplete)
	}
	if receipt.TrailingMissing != 0 {
		t.Errorf("trailing missing = %d, want 0", receipt.TrailingMissing)
	}
}

func TestGenericScorerRejectsMalformedFraming(t *testing.T) {
	tests := []struct {
		name   string
		record []byte
	}{
		{"short record", []byte("BCG1")},
		{"bad magic", append([]byte("XXXX"), genericRecord(0, 0, 4, 0)[4:]...)},
		{"zero window length", genericRecord(0, 0, 0, 0)},
		{"index outside declared length", genericRecord(0, 9, 4, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scorer := NewGenericScorer("test", "test")
			counted, err := scorer.Observe(test.record, time.Unix(1, 0))
			if !errors.Is(err, ErrNotGenericFrame) {
				t.Fatalf("error = %v, want ErrNotGenericFrame", err)
			}
			if counted {
				t.Error("a malformed record must not be counted as delivered")
			}
			if scorer.Receipt().RecordsReceived != 0 {
				t.Error("a malformed record must not enter completeness")
			}
		})
	}
}

// Re-declaring a window's length is a framing violation rather than a resize:
// accepting it would retroactively change what completeness meant for records
// already counted.
func TestGenericScorerRejectsWindowLengthChange(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	observeGeneric(t, scorer, 0, 4, []uint16{0})
	_, err := scorer.Observe(genericRecord(0, 1, 8, 1), time.Unix(2, 0))
	if !errors.Is(err, ErrNotGenericFrame) {
		t.Fatalf("error = %v, want ErrNotGenericFrame", err)
	}
	if got := scorer.Receipt().RecordsExpected; got != 4 {
		t.Errorf("expected records = %d, want 4 — the first declaration stands", got)
	}
}

func TestGenericScorerGapBucketsAndPercentilesAreDeterministic(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	start := time.Unix(1, 0)
	// Spacings chosen to land one gap in each histogram bucket.
	offsets := []time.Duration{
		0,
		500 * time.Microsecond, // <1ms
		2 * time.Millisecond,   // 1-2.4ms
		7 * time.Millisecond,   // 2.4-7ms
		27 * time.Millisecond,  // 7-32ms
		127 * time.Millisecond, // >=32ms
	}
	for index, offset := range offsets {
		record := genericRecord(0, uint16(index), uint16(len(offsets)), uint64(index))
		if _, err := scorer.Observe(record, start.Add(offset)); err != nil {
			t.Fatalf("observe index %d: %v", index, err)
		}
	}
	gaps := scorer.Receipt().Gaps
	want := GapHistogram{LT1: 1, From1To2_4: 1, From2_4To7: 1, From7To32: 1, GTE32: 1}
	if gaps != want {
		t.Errorf("gaps = %+v, want %+v", gaps, want)
	}
	// The first record contributes no gap: an inter-arrival gap is only defined
	// between two records this scorer actually saw. Reordered is summed in even
	// though this ladder is strictly increasing and cannot produce one: omitting
	// it is what let BLO-29880 hide, because folding a reordered arrival into
	// LT1 leaves a bucket-only total correct and this assertion green.
	total := gaps.LT1 + gaps.From1To2_4 + gaps.From2_4To7 + gaps.From7To32 + gaps.GTE32 + gaps.Reordered
	if total != uint64(len(offsets)-1) {
		t.Errorf("gap count = %d, want %d", total, len(offsets)-1)
	}
}

// TestGenericScorerToleratesOutOfOrderArrivalTimestamps is the generic-mode
// mirror of TestScorerToleratesOutOfOrderArrivalTimestamps. receivedAt is
// captured at the read before any per-packet work, so concurrent feed goroutines
// can reach Observe as t2, t1 — the premise GenericScorer's own doc comment
// acknowledges. Before BLO-29880 this path had neither of the shred path's two
// guards: the negative delta fell through the bucket ladder into LT1, and the
// frontier was assigned unconditionally.
func TestGenericScorerToleratesOutOfOrderArrivalTimestamps(t *testing.T) {
	started := time.Unix(40, 0)
	at := func(ms int) time.Time { return started.Add(time.Duration(ms) * time.Millisecond) }

	scorer := NewGenericScorer("test", "test")
	// One 32-record window with every pair of adjacent arrivals transposed, so
	// the call order regresses 16 times. Timestamps are 2ms apart, so no honest
	// gap can land in LT1 and any LT1 count is a charged regression.
	const length = 32
	for i := 0; i < length; i += 2 {
		for _, index := range [2]int{i + 1, i} {
			record := genericRecord(0, uint16(index), length, uint64(index))
			if _, err := scorer.Observe(record, at(2*index)); err != nil {
				t.Fatalf("observe index %d: %v", index, err)
			}
		}
	}

	gaps := scorer.Receipt().Gaps
	if gaps.LT1 != 0 {
		t.Fatalf("Gaps.LT1 = %d, want 0; reordered arrivals must not be charged to the sub-millisecond bucket", gaps.LT1)
	}
	// 31 non-first arrivals: 15 advance the frontier by 4ms (the leading element
	// of each transposed pair after the opening one), and 16 regress — the 15
	// trailing elements plus the opening pair's second element.
	if gaps.Reordered != 16 {
		t.Fatalf("Gaps.Reordered = %d, want 16", gaps.Reordered)
	}
	// Every non-first arrival is attributable to exactly one counter.
	bucketed := gaps.LT1 + gaps.From1To2_4 + gaps.From2_4To7 + gaps.From7To32 + gaps.GTE32
	if bucketed+gaps.Reordered != length-1 {
		t.Fatalf("bucketed(%d) + reordered(%d) = %d, want %d non-first arrivals accounted for",
			bucketed, gaps.Reordered, bucketed+gaps.Reordered, length-1)
	}
}

// TestGenericScorerGapFrontierDoesNotRegress isolates the stale-frontier half of
// BLO-29880: after a late arrival, the next honest gap must be measured from the
// newest timestamp seen, not from the late one. In generic mode the frontier is
// also the retention clock (retentionFloor is lastArrival minus the window), so a
// regressing assignment would drag the eviction floor backwards as well.
func TestGenericScorerGapFrontierDoesNotRegress(t *testing.T) {
	started := time.Unix(50, 0)
	at := func(ms int) time.Time { return started.Add(time.Duration(ms) * time.Millisecond) }

	scorer := NewGenericScorer("test", "test")
	const length = 4
	// 0ms, then +30ms, then a regression to 10ms, then 31ms. The last gap must
	// read +1ms from the 30ms frontier, not +21ms from the regressed 10ms.
	for index, ms := range [length]int{0, 30, 10, 31} {
		record := genericRecord(0, uint16(index), length, uint64(index))
		if _, err := scorer.Observe(record, at(ms)); err != nil {
			t.Fatalf("observe index %d: %v", index, err)
		}
	}

	gaps := scorer.Receipt().Gaps
	want := GapHistogram{From1To2_4: 1, From7To32: 1, Reordered: 1}
	if gaps != want {
		t.Errorf("gaps = %+v, want %+v; a 1-2.4ms gap means the frontier held at 30ms", gaps, want)
	}
	// Stated as its own assertion because it is the specific misreading the bug
	// produced: measuring from the regressed 10ms yields +21ms, in From7To32.
	if gaps.From7To32 != 1 {
		t.Errorf("From7To32 = %d, want 1; a second entry here means the gap was measured from the regressed arrival", gaps.From7To32)
	}
	if gaps.Reordered+gaps.From1To2_4+gaps.From7To32 != length-1 {
		t.Errorf("accounted %d of %d non-first arrivals", gaps.Reordered+gaps.From1To2_4+gaps.From7To32, length-1)
	}
}

// TestGenericScorerReorderedAndOutOfOrderObserveDifferentAxes pins the reason
// RecordsOutOfOrder was never a substitute for Gaps.Reordered, which is what the
// pre-BLO-29880 doc comment claimed. Reordered observes the arrival clock;
// RecordsOutOfOrder observes header.Sequence. Either can move without the other.
func TestGenericScorerReorderedAndOutOfOrderObserveDifferentAxes(t *testing.T) {
	started := time.Unix(60, 0)
	at := func(ms int) time.Time { return started.Add(time.Duration(ms) * time.Millisecond) }

	t.Run("arrival regresses, sequence monotonic", func(t *testing.T) {
		scorer := NewGenericScorer("test", "test")
		// Sequence 0,1,2 ascending; arrival 0ms, 30ms, 10ms regresses once.
		for index, ms := range [3]int{0, 30, 10} {
			record := genericRecord(0, uint16(index), 3, uint64(index))
			if _, err := scorer.Observe(record, at(ms)); err != nil {
				t.Fatalf("observe index %d: %v", index, err)
			}
		}
		receipt := scorer.Receipt()
		if receipt.Gaps.Reordered != 1 {
			t.Errorf("Gaps.Reordered = %d, want 1; the arrival clock regressed", receipt.Gaps.Reordered)
		}
		if receipt.RecordsOutOfOrder != 0 {
			t.Errorf("RecordsOutOfOrder = %d, want 0; sequence never regressed, so it cannot report this hazard", receipt.RecordsOutOfOrder)
		}
	})

	t.Run("sequence regresses, arrival monotonic", func(t *testing.T) {
		scorer := NewGenericScorer("test", "test")
		// Arrival strictly increasing at 2ms spacing; sequence 0,2,1 regresses once.
		for step, index := range [3]uint16{0, 2, 1} {
			record := genericRecord(0, index, 3, uint64(index))
			if _, err := scorer.Observe(record, at(2*step)); err != nil {
				t.Fatalf("observe index %d: %v", index, err)
			}
		}
		receipt := scorer.Receipt()
		if receipt.RecordsOutOfOrder != 1 {
			t.Errorf("RecordsOutOfOrder = %d, want 1; sequence regressed", receipt.RecordsOutOfOrder)
		}
		if receipt.Gaps.Reordered != 0 {
			t.Errorf("Gaps.Reordered = %d, want 0; the arrival clock never regressed", receipt.Gaps.Reordered)
		}
	})
}

// Percentiles are the upper edge of the bucket the true fill landed in, not the
// fill itself: BLO-28909 bounded the scorer's per-window state, and exact
// per-window latencies cannot be retained under a bound. The expected values
// below are therefore 2ms and 3ms rounded up to their bucket edges. See
// completionHistogram, and
// TestGenericWindowFillPercentilesAreBucketedUpperBounds for the error bound
// asserted as a property rather than pinned as a constant.
func TestGenericScorerPercentilesTrackWindowFillLatency(t *testing.T) {
	scorer := NewGenericScorer("test", "test")
	start := time.Unix(1, 0)
	// Three windows filling in 1ms, 2ms and 3ms respectively.
	for window, span := range []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond} {
		for index := uint16(0); index < 2; index++ {
			at := start.Add(time.Duration(window) * time.Second)
			if index == 1 {
				at = at.Add(span)
			}
			if _, err := scorer.Observe(genericRecord(uint64(window), index, 2, uint64(index)), at); err != nil {
				t.Fatalf("observe window %d: %v", window, err)
			}
		}
	}
	receipt := scorer.Receipt()
	if want := completionBucketUpperEdge(completionBucket(2 * time.Millisecond)); receipt.WindowP50 != want {
		t.Errorf("p50 = %s, want %s (2ms at its bucket edge)", receipt.WindowP50, want)
	}
	if want := completionBucketUpperEdge(completionBucket(3 * time.Millisecond)); receipt.WindowP99 != want {
		t.Errorf("p99 = %s, want %s (3ms at its bucket edge)", receipt.WindowP99, want)
	}
}

// The fixture is a regression artifact: the demo receipt must be byte-identical
// on every run and every machine, or it cannot be quoted in an asset.
func TestGenericFixtureReceiptIsDeterministic(t *testing.T) {
	const want = `generic source=synthetic rights=synthetic-generated-no-third-party-content
window_fill p50=27.903ms p95=29.823ms p99=29.823ms
completeness windows=6 complete=4 expected=192 received=186 fraction=0.968750
loss interior=3 trailing=3 duplicates=2 out_of_order=2
gap_ms <1=187 1-2.4=0 2.4-7=0 7-32=0 >=32=0`

	for attempt := 0; attempt < 3; attempt++ {
		scorer := NewGenericScorer(GenericSyntheticSource, GenericSyntheticRightsBasis)
		if err := ReplayGenericFixture(scorer); err != nil {
			t.Fatalf("replay: %v", err)
		}
		if got := scorer.Receipt().String(); got != want {
			t.Fatalf("attempt %d receipt =\n%s\nwant\n%s", attempt, got, want)
		}
	}
}

// The fixture must actually contain every anomaly the receipt claims to
// distinguish, or the deterministic test above is asserting on a feed that
// never exercises the interesting paths.
func TestGenericFixtureExercisesEveryAnomaly(t *testing.T) {
	scorer := NewGenericScorer(GenericSyntheticSource, GenericSyntheticRightsBasis)
	if err := ReplayGenericFixture(scorer); err != nil {
		t.Fatalf("replay: %v", err)
	}
	receipt := scorer.Receipt()
	for _, check := range []struct {
		name string
		got  int
	}{
		{"interior loss", receipt.InteriorMissing},
		{"trailing loss", receipt.TrailingMissing},
		{"duplicates", receipt.RecordsDuplicate},
		{"out of order", receipt.RecordsOutOfOrder},
	} {
		if check.got == 0 {
			t.Errorf("fixture exercises no %s", check.name)
		}
	}
	if receipt.WindowsComplete == 0 || receipt.WindowsComplete == receipt.Windows {
		t.Errorf("windows complete = %d of %d: the fixture must show both clean and lossy windows",
			receipt.WindowsComplete, receipt.Windows)
	}
}

// The fixture is the reference feed shipped to demonstrate the framing
// contract, so it is the one artifact that must not violate it. A reordered
// pair is *delivered* out of order but must still carry distinct sequence
// numbers that increase with index — an earlier revision rewound the counter
// after emitting the pair, handing two records the same sequence. The receipt
// survived that only because Observe compares with a strict `<`, i.e. it was
// right by luck rather than by construction, which is exactly the kind of thing
// a demo artifact must not rely on.
func TestGenericFixtureSequencesAreDistinctAndIndexMonotonic(t *testing.T) {
	type slot struct {
		window uint64
		index  uint16
	}
	seqOf := make(map[slot]uint64)
	owner := make(map[uint64]slot)

	for i, record := range DefaultGenericFixtureSpec().Build() {
		header, err := ParseGeneric(record.Payload)
		if err != nil {
			t.Fatalf("record %d: parse: %v", i, err)
		}
		key := slot{header.Window, header.IndexInWindow}
		if first, seen := seqOf[key]; seen {
			// A redelivery is the same record arriving twice, so it must reuse
			// its original sequence rather than consume a fresh one.
			if first != header.Sequence {
				t.Errorf("w%d/i%d redelivered as seq=%d, first copy carried seq=%d",
					key.window, key.index, header.Sequence, first)
			}
			continue
		}
		if other, taken := owner[header.Sequence]; taken {
			t.Errorf("seq=%d carried by both w%d/i%d and w%d/i%d",
				header.Sequence, other.window, other.index, key.window, key.index)
		}
		seqOf[key] = header.Sequence
		owner[header.Sequence] = key
	}

	// Sequence must increase with (window, index) even where arrival order does
	// not: that ordering is what lets a late record be detected as out-of-order
	// rather than counted as a fresh one.
	slots := make([]slot, 0, len(seqOf))
	for key := range seqOf {
		slots = append(slots, key)
	}
	sort.Slice(slots, func(i, j int) bool {
		if slots[i].window != slots[j].window {
			return slots[i].window < slots[j].window
		}
		return slots[i].index < slots[j].index
	})
	for i := 1; i < len(slots); i++ {
		if seqOf[slots[i]] <= seqOf[slots[i-1]] {
			t.Fatalf("sequence not monotonic in index: w%d/i%d seq=%d follows w%d/i%d seq=%d",
				slots[i].window, slots[i].index, seqOf[slots[i]],
				slots[i-1].window, slots[i-1].index, seqOf[slots[i-1]])
		}
	}
}

// Generic mode must never reach shred parsing or FEC reconstruction. A shred
// packet carries no BCG1 magic, so it is rejected as foreign framing rather
// than scored — and conversely a generic record is not a shred in any format.
func TestGenericAndShredFramingAreMutuallyUnreadable(t *testing.T) {
	generic := genericRecord(0, 0, 4, 0)
	if _, err := Parse(generic, FormatForwarder); err == nil {
		t.Error("a generic record must not parse as a forwarder shred")
	}
	if _, err := Parse(generic, FormatAgave); err == nil {
		t.Error("a generic record must not parse as an Agave shred")
	}

	scorer := NewGenericScorer("test", "test")
	shredPacket := dataPacket(10, 0, 0)
	if _, err := scorer.Observe(shredPacket, time.Unix(1, 0)); !errors.Is(err, ErrNotGenericFrame) {
		t.Errorf("a shred scored in generic mode: error = %v, want ErrNotGenericFrame", err)
	}
}

// ReplayPCAP is the seam that keeps this one client: it must drive the generic
// scorer through the same replay path the shred scorer uses.
func TestGenericScorerSatisfiesTheReplayObserverSeam(t *testing.T) {
	var observer Observer = NewGenericScorer("test", "test")
	if _, err := observer.Observe(genericRecord(0, 0, 1, 0), time.Unix(1, 0)); err != nil {
		t.Fatalf("observe through the seam: %v", err)
	}
	var shredObserver Observer = NewScorer()
	if shredObserver == nil {
		t.Fatal("the shred scorer must satisfy the same seam")
	}
}

func TestGenericReceiptStatesProvenanceVerbatim(t *testing.T) {
	scorer := NewGenericScorer("synthetic", "synthetic-generated-no-third-party-content")
	observeGeneric(t, scorer, 0, 1, []uint16{0})
	rendered := scorer.Receipt().String()
	if !strings.HasPrefix(rendered, "generic source=synthetic rights=synthetic-generated-no-third-party-content") {
		t.Errorf("receipt must lead with its input provenance, got:\n%s", rendered)
	}
}

func TestGenericFeedScorerKeepsFeedsSeparate(t *testing.T) {
	scorer := NewGenericFeedScorer([]string{"a", "b"}, "synthetic", "test")
	if _, err := scorer.Observe("a", genericRecord(0, 0, 2, 0), time.Unix(1, 0)); err != nil {
		t.Fatalf("observe feed a: %v", err)
	}
	if _, err := scorer.Observe("b", genericRecord(0, 1, 2, 1), time.Unix(1, 0)); err != nil {
		t.Fatalf("observe feed b: %v", err)
	}
	if _, err := scorer.Observe("missing", genericRecord(0, 0, 2, 0), time.Unix(1, 0)); err == nil {
		t.Error("an unknown feed must be rejected, not silently scored")
	}
	rendered := scorer.Receipt().String()
	// Each feed saw one of the two records, so neither window is complete. A
	// union across feeds would report completeness 1 — that is D4's claim, and
	// this mode must not make it.
	if strings.Count(rendered, "complete=0") != 2 {
		t.Errorf("expected both feeds incomplete with no cross-feed union, got:\n%s", rendered)
	}
}

func TestAppendGenericHeaderRoundTrips(t *testing.T) {
	want := GenericHeader{Sequence: 1 << 40, Window: 1 << 33, IndexInWindow: 300, WindowLength: 1024}
	encoded := AppendGenericHeader([]byte("prefix"), want)
	if !bytes.HasPrefix(encoded, []byte("prefix")) {
		t.Fatal("AppendGenericHeader must append to dst rather than replace it")
	}
	got, err := ParseGeneric(encoded[len("prefix"):])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

// TestGenericScorerReceiptIsRaceFreeAgainstLateObserve pins the lock that lets
// the demo command drop its caller-held mutex.
//
// The command closes its sockets and then prints the receipt while a reader
// goroutine may still be mid-packet, so Receipt can run concurrently with
// Observe. FeedScorer has always been safe there because it takes its own lock;
// GenericScorer originally was not, and relied on a mutex held by the caller.
// That asymmetry is invisible behind the session-scorer seam and becomes a race
// the moment the two modes are used interchangeably, so the lock lives here.
//
// Run under -race: without GenericScorer.mu this fails on the windows map.
func TestGenericScorerReceiptIsRaceFreeAgainstLateObserve(t *testing.T) {
	scorer := NewGenericFeedScorer([]string{"a"}, "synthetic", "test")
	const records = 200

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < records; i++ {
			// One window of `records` entries, so the scorer is still
			// accumulating while the reader below snapshots it.
			if _, err := scorer.Observe("a", genericRecord(0, uint16(i), records, uint64(i)), time.Unix(1, int64(i)*1e6)); err != nil {
				t.Errorf("observe %d: %v", i, err)
				return
			}
		}
	}()

	// Snapshot repeatedly while the writer runs. Any value is legal — this
	// asserts only that concurrent access is defined, which is what the demo
	// command depends on at shutdown.
	for i := 0; i < records; i++ {
		_ = scorer.Receipt()
	}
	<-done

	if got := scorer.Receipt().Feeds[0].Receipt.RecordsReceived; got != records {
		t.Errorf("every record should be counted once the writer is done, got %d want %d", got, records)
	}
}
