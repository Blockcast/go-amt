package shred

import (
	"encoding/binary"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScorerCountsCompleteErasedAndPaddedSets(t *testing.T) {
	tests := []struct {
		name        string
		observe     func(*testing.T, *Scorer, time.Time)
		total       int
		erased      int
		erasureRate float64
	}{
		{
			name: "erased below 32 of 64",
			observe: func(t *testing.T, scorer *Scorer, started time.Time) {
				for i := uint32(0); i < 31; i++ {
					observeTestPacket(t, scorer, dataPacket(10, 0, i), started.Add(time.Duration(i)*time.Millisecond))
				}
			},
			total: 1, erased: 1, erasureRate: 1,
		},
		{
			name: "padded final set remains consensus 32 plus 32",
			observe: func(t *testing.T, scorer *Scorer, started time.Time) {
				for i := uint32(0); i < 32; i++ {
					observeTestPacket(t, scorer, codingPacket(11, 0, i), started.Add(time.Duration(i)*time.Millisecond))
				}
			},
			total: 1, erased: 0, erasureRate: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scorer := NewScorerWithFormat(FormatAgave)
			test.observe(t, scorer, time.Unix(1, 0))
			receipt := scorer.Receipt()
			if receipt.SetsTotal != test.total || receipt.SetsErased != test.erased || receipt.ErasureFraction != test.erasureRate {
				t.Fatalf("receipt = %+v", receipt)
			}
		})
	}
}

func TestCompletionPercentilesKnownFixture(t *testing.T) {
	tests := []struct {
		name      string
		latencies []time.Duration
		p50, p95  time.Duration
		p99       time.Duration
	}{
		{name: "single set", latencies: []time.Duration{31 * time.Millisecond}, p50: 31 * time.Millisecond, p95: 31 * time.Millisecond, p99: 31 * time.Millisecond},
		{name: "nearest rank", latencies: []time.Duration{40 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}, p50: 20 * time.Millisecond, p95: 40 * time.Millisecond, p99: 40 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := append([]time.Duration(nil), test.latencies...)
			sortDurations(values)
			if got := percentile(values, 50); got != test.p50 {
				t.Fatalf("p50 = %s, want %s", got, test.p50)
			}
			if got := percentile(values, 95); got != test.p95 {
				t.Fatalf("p95 = %s, want %s", got, test.p95)
			}
			if got := percentile(values, 99); got != test.p99 {
				t.Fatalf("p99 = %s, want %s", got, test.p99)
			}
		})
	}
}

func TestScorerDeduplicatesFirstArrivalAcrossTwoFeeds(t *testing.T) {
	scorer := NewScorerWithFormat(FormatAgave)
	started := time.Unix(2, 0)
	for i := uint32(0); i < 32; i++ {
		packet := dataPacket(20, 0, i)
		// Feed A reaches the shared scorer first.
		if accepted, err := scorer.Observe(packet, started.Add(time.Duration(i)*time.Millisecond)); err != nil || !accepted {
			t.Fatalf("feed A shred %d = %v, %v", i, accepted, err)
		}
		// Feed B carries the same UDP payload later and must not change metrics.
		if accepted, err := scorer.Observe(packet, started.Add(time.Second+time.Duration(i)*time.Millisecond)); err != nil || accepted {
			t.Fatalf("feed B duplicate %d = %v, %v", i, accepted, err)
		}
	}
	got := scorer.Receipt()
	if got.SetsTotal != 1 || got.CompletionP50 != 31*time.Millisecond || got.Gaps.From1To2_4 != 31 {
		t.Fatalf("duplicates changed first-arrival receipt: %+v", got)
	}
	if !strings.HasPrefix(got.String(), "time_to_32nd_shred") {
		t.Fatalf("receipt does not lead with latency: %q", got.String())
	}
}

func TestFeedScorerReportsPerFeedAndUnionBenefit(t *testing.T) {
	scorer := NewFeedScorerWithFormat(FormatAgave, []string{"blockcast", "external"})
	started := time.Unix(3, 0)
	for i := uint32(0); i < 31; i++ {
		if _, err := scorer.Observe("blockcast", dataPacket(30, 0, i), started.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scorer.Observe("external", dataPacket(30, 0, 31), started.Add(31*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < 31; i++ {
		if _, err := scorer.Observe("external", codingPacket(30, 0, i), started.Add(time.Duration(32+i)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}

	got := scorer.Receipt()
	if len(got.Feeds) != 2 || got.Feeds[0].Receipt.ErasureFraction != 1 || got.Feeds[1].Receipt.ErasureFraction != 0 || got.Union.ErasureFraction != 0 {
		t.Fatalf("dual-feed receipt = %+v", got)
	}
	if got.SecondFeed == nil || got.SecondFeed.RescuedSets != 1 || got.SecondFeed.GapClosed != 1 || got.SecondFeed.Baseline != "blockcast" {
		t.Fatalf("second-feed worth = %+v", got.SecondFeed)
	}
	if got.GapClosed != 1 {
		t.Fatalf("deprecated GapClosed = %v, want baseline minus union erasure = 1", got.GapClosed)
	}
	if got.SecondFeed.Label != "measured worth of a second feed" {
		t.Fatalf("second-feed label = %q", got.SecondFeed.Label)
	}
	want := "time_to_32nd_shred union p50=31ms p95=31ms p99=31ms\n" +
		"union erasure sets=1 erased=0 fraction=0.000000 mean_shreds_per_set=63.00\n" +
		"gap_ms union <1=0 1-2.4=62 2.4-7=0 7-32=0 >=32=0 reordered=0\n" +
		"feed name=blockcast erasure sets=1 erased=1 fraction=1.000000 mean_shreds_per_set=31.00 unique_first=31 first_arrival_fraction=0.492063\n" +
		"feed name=external erasure sets=1 erased=0 fraction=0.000000 mean_shreds_per_set=32.00 unique_first=32 first_arrival_fraction=0.507937\n" +
		"second_feed_measured_worth baseline=blockcast rescued_sets=1 gap_closed_fraction=1.000000"
	if got.String() != want {
		t.Fatalf("receipt = %q, want %q", got.String(), want)
	}
}

func TestFeedScorerDeduplicatesUnionFirstArrival(t *testing.T) {
	scorer := NewFeedScorerWithFormat(FormatAgave, []string{"first", "second"})
	packet := dataPacket(31, 0, 0)
	if accepted, err := scorer.Observe("second", packet, time.Unix(4, 0)); err != nil || !accepted {
		t.Fatalf("first union arrival = %v, %v", accepted, err)
	}
	if accepted, err := scorer.Observe("first", packet, time.Unix(5, 0)); err != nil || accepted {
		t.Fatalf("later union duplicate = %v, %v", accepted, err)
	}
	if got := scorer.Receipt(); got.Feeds[0].Receipt.SetsTotal != 1 || got.Feeds[1].Receipt.SetsTotal != 1 || got.Union.SetsTotal != 1 {
		t.Fatalf("feed universe mismatch: %+v", got)
	}
}

// First-arrival credit must follow the arrival timestamp, not the order the
// feeds happened to reach the scorer. The two feed goroutines capture receivedAt
// at their own socket read and then race through health, metrics and fan-out
// before scoring, so the later-timestamped copy can easily be observed first.
// Deciding unique_shreds_first on processing order makes the "is the second feed
// earning its keep" numbers a report on the Go scheduler.
//
// Both interleavings of the same two arrivals must therefore produce byte-equal
// receipts, with the credit on the earlier one either way.
func TestFeedScorerCreditsFirstArrivalByTimestampNotProcessingOrder(t *testing.T) {
	packet := dataPacket(31, 0, 0)
	early, late := time.Unix(4, 0), time.Unix(5, 0)

	receiptFor := func(t *testing.T, firstObserved string) UnionReceipt {
		t.Helper()
		scorer := NewFeedScorerWithFormat(FormatAgave, []string{"early", "late"})
		at := map[string]time.Time{"early": early, "late": late}
		order := []string{"early", "late"}
		if firstObserved == "late" {
			order = []string{"late", "early"}
		}
		for _, feed := range order {
			if _, err := scorer.Observe(feed, packet, at[feed]); err != nil {
				t.Fatal(err)
			}
		}
		return scorer.Receipt()
	}

	inOrder := receiptFor(t, "early")
	reversed := receiptFor(t, "late")

	for _, test := range []struct {
		name    string
		receipt UnionReceipt
	}{{"early observed first", inOrder}, {"late observed first", reversed}} {
		feeds := map[string]FeedReceipt{}
		for _, feed := range test.receipt.Feeds {
			feeds[feed.Name] = feed
		}
		if feeds["early"].UniqueFirst != 1 || feeds["late"].UniqueFirst != 0 {
			t.Errorf("%s: credit = early %d, late %d, want 1 and 0",
				test.name, feeds["early"].UniqueFirst, feeds["late"].UniqueFirst)
		}
		if feeds["early"].FirstArrivalFraction != 1 || feeds["late"].FirstArrivalFraction != 0 {
			t.Errorf("%s: fraction = early %.6f, late %.6f, want 1 and 0",
				test.name, feeds["early"].FirstArrivalFraction, feeds["late"].FirstArrivalFraction)
		}
	}
	if inOrder.String() != reversed.String() {
		t.Fatalf("receipt depends on processing order:\n in-order: %s\nreversed: %s", inOrder.String(), reversed.String())
	}
}

// The test above stops before its FEC set completes, so it never exercises the
// completion fields. Driving the same two raced copies to a completed set is
// what shows whether time_to_32nd_shred is decided by arrival timestamps or by
// which copy the scheduler presented first: the set's latency is measured from
// its arrival floor, and the floor is exactly what a duplicate older than the
// counted copy has to lower.
//
// Before the duplicate path widened the extent, the two orders read p50=1.031s
// and p50=31ms on identical arrivals — the later understating by the whole
// inter-feed skew, which is the harm the extent tracking is supposed to prevent.
//
// The gap histogram is deliberately NOT asserted equal here. Gaps are derived
// from the first-*processed* copy of each shred against a running frontier, so a
// duplicate that turns out to be older cannot re-derive a gap already recorded.
// That residual is documented in README.md and on setScore; the assertion below
// pins it, so closing it forces this test and that prose to be updated together.
func TestFeedScorerCompletionLatencyIgnoresDuplicateProcessingOrder(t *testing.T) {
	const slot, fecSet = 31, 0
	early, late := time.Unix(4, 0), time.Unix(5, 0)

	receiptFor := func(t *testing.T, firstObserved string) UnionReceipt {
		t.Helper()
		scorer := NewFeedScorerWithFormat(FormatAgave, []string{"early", "late"})
		raced := dataPacket(slot, fecSet, 0)
		at := map[string]time.Time{"early": early, "late": late}
		order := []string{"early", "late"}
		if firstObserved == "late" {
			order = []string{"late", "early"}
		}
		for _, feed := range order {
			if _, err := scorer.Observe(feed, raced, at[feed]); err != nil {
				t.Fatal(err)
			}
		}
		// Complete the set on "late" alone, 1ms apart, so the only variable
		// between the two receipts is the order of the two copies of shred 0.
		for index := uint32(1); index < completionThreshold; index++ {
			at := late.Add(time.Duration(index) * time.Millisecond)
			if _, err := scorer.Observe("late", dataPacket(slot, fecSet, index), at); err != nil {
				t.Fatal(err)
			}
		}
		return scorer.Receipt()
	}

	inOrder := receiptFor(t, "early")
	reversed := receiptFor(t, "late")

	// The floor is the early copy at t=4s and the 32nd shred lands at t=5.031s,
	// so the set's extent is 1.031s whichever copy was processed first.
	const want = 1031 * time.Millisecond
	for _, test := range []struct {
		name    string
		receipt UnionReceipt
	}{{"early observed first", inOrder}, {"late observed first", reversed}} {
		union := test.receipt.Union
		if union.SetsTotal != 1 || union.SetsErased != 0 {
			t.Errorf("%s: sets = %d total, %d erased, want 1 and 0",
				test.name, union.SetsTotal, union.SetsErased)
		}
		for _, percentile := range []struct {
			label string
			got   time.Duration
		}{{"p50", union.CompletionP50}, {"p95", union.CompletionP95}, {"p99", union.CompletionP99}} {
			if percentile.got != want {
				t.Errorf("%s: completion %s = %v, want %v",
					test.name, percentile.label, percentile.got, want)
			}
		}
	}

	// Known residual, pinned: the raced shred contributes its processed timestamp
	// to the frontier, so the >=32ms gap into the rest of the set is recorded only
	// when the early copy was processed first.
	if inOrder.Union.Gaps.GTE32 != 1 || reversed.Union.Gaps.GTE32 != 0 {
		t.Errorf("gap residual moved: >=32 = %d in-order, %d reversed, want 1 and 0 "+
			"(if the frontier now re-derives gaps, update README.md and setScore)",
			inOrder.Union.Gaps.GTE32, reversed.Union.Gaps.GTE32)
	}
}

// The same shred delivered down two feeds at once is the contended case that
// decides attribution, and nothing covered it: the receiver's concurrency test
// gives every feed a disjoint FEC set by design, so its feeds never compete for
// credit on one shred.
//
// Every shred here arrives on "early" strictly before "late", so a
// timestamp-decided attribution has exactly one answer no matter how the
// goroutines interleave. Run under -race in CI (the race job), this pins both
// halves: no data race, and no scheduling-dependent result.
func TestFeedScorerAttributionIsStableUnderConcurrentDuplicateDelivery(t *testing.T) {
	const shreds = 64
	scorer := NewFeedScorer([]string{"early", "late"})
	base := time.Unix(200, 0)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, feed := range []string{"early", "late"} {
		wg.Add(1)
		go func(feed string) {
			defer wg.Done()
			offset := time.Duration(0)
			if feed == "late" {
				offset = time.Millisecond
			}
			<-start
			for i := 0; i < shreds; i++ {
				at := base.Add(time.Duration(i)*10*time.Millisecond + offset)
				// Two full FEC sets: a data shred's local index only spans the
				// 32 data shreds of its own set.
				fecSet, index := uint32(i/32)*64, uint32(i%32)
				if _, err := scorer.Observe(feed, forwarderPacket(3, 300, fecSet, index, false, 0), at); err != nil {
					t.Errorf("observe on %s: %v", feed, err)
					return
				}
			}
		}(feed)
	}
	close(start)
	wg.Wait()

	got := scorer.Receipt()
	if got.UniqueShreds != shreds {
		t.Fatalf("unique shreds = %d, want %d", got.UniqueShreds, shreds)
	}
	if got.Feeds[0].UniqueFirst != shreds || got.Feeds[1].UniqueFirst != 0 {
		t.Fatalf("credit = early %d, late %d, want %d and 0 — attribution followed processing order, not arrival time",
			got.Feeds[0].UniqueFirst, got.Feeds[1].UniqueFirst, shreds)
	}
	// Re-attribution moves credit between feeds; it must never mint or lose it.
	if total := got.Feeds[0].UniqueFirst + got.Feeds[1].UniqueFirst; total != got.UniqueShreds {
		t.Fatalf("first arrivals sum to %d, want %d unique shreds", total, got.UniqueShreds)
	}
}

// The dedup key must be (slot, fec_set_index, local_index). The issue text for
// BLO-26447 said (slot, shred_index); that key collapses distinct shreds
// because the in-set index repeats across FEC sets of one slot — the exact
// mistake that produced the 31x distinct-shred undercount in BLO-26535. The
// local index already unifies data (0..num_data-1) and coding
// (num_data+position) shreds, so no is_coding term is needed.
func TestDedupKeyKeepsDistinctShredsDistinct(t *testing.T) {
	tests := []struct {
		name    string
		packets [][]byte
		want    []bool // accepted, in observation order
	}{
		{
			// Collapses to one shred under the wrong (slot, index) key.
			name: "same slot and local index in different FEC sets stay distinct",
			packets: [][]byte{
				forwarderPacket(3, 1, 0, 5, false, 0),
				forwarderPacket(3, 1, 64, 5, false, 0),
			},
			want: []bool{true, true},
		},
		{
			name: "data and coding shreds are distinct without an is_coding term",
			packets: [][]byte{
				forwarderPacket(3, 1, 0, 5, false, 0),
				forwarderPacket(3, 1, 0, 37, true, 0), // coding local 37 = num_data 32 + position 5
			},
			want: []bool{true, true},
		},
		{
			name: "identical shred is deduplicated",
			packets: [][]byte{
				forwarderPacket(3, 1, 0, 5, false, 0),
				forwarderPacket(3, 1, 0, 5, false, 0),
			},
			want: []bool{true, false},
		},
		{
			name: "same FEC set and local index in different slots stay distinct",
			packets: [][]byte{
				forwarderPacket(3, 1, 0, 5, false, 0),
				forwarderPacket(3, 2, 0, 5, false, 0),
			},
			want: []bool{true, true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scorer := NewScorer()
			for i, packet := range test.packets {
				accepted, err := scorer.Observe(packet, time.Unix(20, 0).Add(time.Duration(i)*time.Millisecond))
				if err != nil {
					t.Fatalf("packet %d: %v", i, err)
				}
				if accepted != test.want[i] {
					t.Fatalf("packet %d accepted = %v, want %v", i, accepted, test.want[i])
				}
			}
		})
	}
}

func TestFeedScorerAttributesFirstArrivals(t *testing.T) {
	scorer := NewFeedScorer([]string{"blockcast", "external"})
	started := time.Unix(6, 0)
	at := func(step int) time.Time { return started.Add(time.Duration(step) * time.Millisecond) }
	// Feed A wins the first half of the set, feed B wins the second half and
	// then repeats A's half, which must not shift attribution.
	for i := uint32(0); i < 16; i++ {
		if _, err := scorer.Observe("blockcast", forwarderPacket(3, 200, 0, i, false, 0), at(int(i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint32(16); i < 32; i++ {
		if _, err := scorer.Observe("external", forwarderPacket(3, 200, 0, i, false, 0), at(int(i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := uint32(0); i < 16; i++ {
		if _, err := scorer.Observe("external", forwarderPacket(3, 200, 0, i, false, 0), at(int(32+i))); err != nil {
			t.Fatal(err)
		}
	}

	got := scorer.Receipt()
	if got.UniqueShreds != 32 {
		t.Fatalf("unique shreds = %d, want 32", got.UniqueShreds)
	}
	for i, want := range []uint64{16, 16} {
		feed := got.Feeds[i]
		if feed.UniqueFirst != want || feed.FirstArrivalFraction != 0.5 {
			t.Fatalf("feed %s attribution = %d (%.6f), want %d (0.5)", feed.Name, feed.UniqueFirst, feed.FirstArrivalFraction, want)
		}
	}
	if got.Union.SetsErased != 0 {
		t.Fatalf("union erased = %d, want 0", got.Union.SetsErased)
	}
}

func TestFeedScorerSecondFeedRescueAccounting(t *testing.T) {
	scorer := NewFeedScorer([]string{"blockcast", "backup"})
	started := time.Unix(7, 0)
	step := 0
	observe := func(feed string, packet []byte) {
		t.Helper()
		if _, err := scorer.Observe(feed, packet, started.Add(time.Duration(step)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		step++
	}
	// Set 0: complete on the baseline feed alone — nothing to rescue.
	for i := uint32(0); i < 32; i++ {
		observe("blockcast", forwarderPacket(3, 100, 0, i, false, 0))
	}
	// Set 1: baseline misses one shred; the second feed supplies it. Rescued.
	for i := uint32(0); i < 31; i++ {
		observe("blockcast", forwarderPacket(3, 100, 64, i, false, 0))
	}
	observe("backup", forwarderPacket(3, 100, 64, 31, false, 0))
	// Set 2: the second feed only duplicates the baseline's shreds. Not rescued.
	for i := uint32(0); i < 10; i++ {
		observe("blockcast", forwarderPacket(3, 100, 128, i, false, 0))
		observe("backup", forwarderPacket(3, 100, 128, i, false, 0))
	}

	got := scorer.Receipt()
	if got.Union.SetsTotal != 3 || got.Union.SetsErased != 1 {
		t.Fatalf("union = %+v", got.Union)
	}
	if got.SecondFeed == nil || got.SecondFeed.RescuedSets != 1 || got.SecondFeed.GapClosed != 1.0/3.0 {
		t.Fatalf("second-feed worth = %+v", got.SecondFeed)
	}
	baseline := got.Feeds[0]
	if baseline.Receipt.SetsErased != 2 || baseline.Receipt.MeanShredsPerSet != 73.0/3.0 {
		t.Fatalf("baseline receipt = %+v", baseline.Receipt)
	}
	// The backup feed never saw set 0; it still counts against the shared
	// universe of 3 sets, with zero shreds contributed there.
	backup := got.Feeds[1]
	if backup.Receipt.SetsTotal != 3 || backup.Receipt.SetsErased != 3 || backup.Receipt.MeanShredsPerSet != 11.0/3.0 {
		t.Fatalf("backup receipt = %+v", backup.Receipt)
	}
	if got.UniqueShreds != 74 || baseline.UniqueFirst != 73 || backup.UniqueFirst != 1 {
		t.Fatalf("attribution = total %d, baseline %d, backup %d", got.UniqueShreds, baseline.UniqueFirst, backup.UniqueFirst)
	}
}

// Splitting the bundled production capture across two feeds must leave the
// first-arrival union identical to a single scorer consuming the whole capture,
// with the unique shreds partitioned between the feeds.
func TestFeedScorerFixtureUnionMatchesSingleScorer(t *testing.T) {
	single := NewScorer()
	if err := ReplayFixture(single); err != nil {
		t.Fatal(err)
	}
	want := single.Receipt()

	dual := NewFeedScorer([]string{"a", "b"})
	packets := 0
	err := ReplayFixtureFunc(func(payload []byte, at time.Time) error {
		name := "a"
		if packets%2 == 1 {
			name = "b"
		}
		packets++
		_, err := dual.Observe(name, payload, at)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	got := dual.Receipt()
	if got.Union != want {
		t.Fatalf("dual-feed union = %+v, want single-scorer %+v", got.Union, want)
	}
	if got.UniqueShreds == 0 || got.Feeds[0].UniqueFirst+got.Feeds[1].UniqueFirst != got.UniqueShreds {
		t.Fatalf("first arrivals do not partition %d unique shreds: %+v", got.UniqueShreds, got.Feeds)
	}
	if got.SecondFeed == nil || got.SecondFeed.Baseline != "a" {
		t.Fatalf("second-feed worth = %+v", got.SecondFeed)
	}
}

func TestParseHeaderRejectsNonConsensusCodingShape(t *testing.T) {
	packet := codingPacket(1, 0, 0)
	binary.LittleEndian.PutUint16(packet[83:85], 31)
	if _, err := ParseHeader(packet); err == nil {
		t.Fatal("31+32 coding header accepted")
	}
}

func sortDurations(values []time.Duration) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func observeTestPacket(t *testing.T, scorer *Scorer, packet []byte, at time.Time) {
	t.Helper()
	if accepted, err := scorer.Observe(packet, at); err != nil || !accepted {
		t.Fatalf("Observe() = %v, %v", accepted, err)
	}
}

func dataPacket(slot uint64, fec, index uint32) []byte {
	packet := make([]byte, commonHeaderSize)
	packet[64] = 0x96
	binary.LittleEndian.PutUint64(packet[65:73], slot)
	binary.LittleEndian.PutUint32(packet[73:77], index)
	binary.LittleEndian.PutUint32(packet[79:83], fec)
	return packet
}

func codingPacket(slot uint64, fec, position uint32) []byte {
	packet := make([]byte, commonHeaderSize+codingHeaderSize)
	packet[64] = 0x66
	binary.LittleEndian.PutUint64(packet[65:73], slot)
	binary.LittleEndian.PutUint32(packet[73:77], fec+32+position)
	binary.LittleEndian.PutUint32(packet[79:83], fec)
	binary.LittleEndian.PutUint16(packet[83:85], 32)
	binary.LittleEndian.PutUint16(packet[85:87], 32)
	binary.LittleEndian.PutUint16(packet[87:89], uint16(position))
	return packet
}

// TestScorerToleratesOutOfOrderArrivalTimestamps pins the ordering contract that
// the receiver's ingress path relies on. receivedAt is captured at the socket
// read, before any per-packet work, so two feed goroutines can capture t1 < t2
// and reach Observe as t2, t1. Nothing in the scorer may assume otherwise.
//
// The regression this guards is silent and single-directional: a negative gap
// falls through the bucket ladder into LT1, inflating the sub-millisecond count
// that a customer reads as "this feed is dense"; lastArrival regresses so the
// next gap is measured from a stale frontier; and a set can report a negative
// completion latency, which sorts to the front of the latency slice and drags
// every completion percentile down.
func TestScorerToleratesOutOfOrderArrivalTimestamps(t *testing.T) {
	started := time.Unix(40, 0)
	at := func(ms int) time.Time { return started.Add(time.Duration(ms) * time.Millisecond) }

	scorer := NewScorerWithFormat(FormatAgave)
	// Deliver a full set with every pair of adjacent arrivals transposed, so the
	// true extent is still 0..31ms but the call order regresses 16 times.
	// Timestamps are 2ms apart, so no honest gap can land in LT1.
	for i := 0; i < 32; i += 2 {
		observeTestPacket(t, scorer, dataPacket(90, 0, uint32(i+1)), at(2*(i+1)))
		observeTestPacket(t, scorer, dataPacket(90, 0, uint32(i)), at(2*i))
	}

	got := scorer.Receipt()
	if got.SetsTotal != 1 || got.SetsErased != 0 {
		t.Fatalf("Receipt() = %+v, want 1 complete set", got)
	}
	// Extent is min..max over the 32 arrivals: 0ms .. 62ms.
	if want := 62 * time.Millisecond; got.CompletionP50 != want {
		t.Fatalf("CompletionP50 = %s, want %s; completion must measure the set's arrival extent, not the timestamp of whichever shred was processed 32nd", got.CompletionP50, want)
	}
	if got.CompletionP50 < 0 {
		t.Fatalf("CompletionP50 = %s is negative; a negative latency understates time_to_32nd_shred", got.CompletionP50)
	}
	// 31 non-first arrivals: 15 advance the frontier by 4ms (the first element of
	// each transposed pair after the opening one), and 16 regress — the 15
	// trailing elements plus the opening pair's second element.
	if got.Gaps.LT1 != 0 {
		t.Fatalf("Gaps.LT1 = %d, want 0; reordered arrivals must not be charged to the sub-millisecond bucket", got.Gaps.LT1)
	}
	if got.Gaps.Reordered != 16 {
		t.Fatalf("Gaps.Reordered = %d, want 16", got.Gaps.Reordered)
	}
	// Every non-first arrival is either bucketed or counted as reordered.
	bucketed := got.Gaps.LT1 + got.Gaps.From1To2_4 + got.Gaps.From2_4To7 + got.Gaps.From7To32 + got.Gaps.GTE32
	if bucketed+got.Gaps.Reordered != 31 {
		t.Fatalf("bucketed(%d) + reordered(%d) = %d, want 31 non-first arrivals accounted for", bucketed, got.Gaps.Reordered, bucketed+got.Gaps.Reordered)
	}
}

// TestScorerGapFrontierDoesNotRegress isolates the stale-frontier half of the
// bug: after a late arrival, the next honest gap must be measured from the
// newest timestamp seen, not from the late one.
func TestScorerGapFrontierDoesNotRegress(t *testing.T) {
	started := time.Unix(50, 0)
	at := func(ms int) time.Time { return started.Add(time.Duration(ms) * time.Millisecond) }

	scorer := NewScorerWithFormat(FormatAgave)
	observeTestPacket(t, scorer, dataPacket(91, 0, 0), at(0))
	observeTestPacket(t, scorer, dataPacket(91, 0, 1), at(30)) // +30ms -> 7-32 bucket
	observeTestPacket(t, scorer, dataPacket(91, 0, 2), at(10)) // regression -> reordered
	observeTestPacket(t, scorer, dataPacket(91, 0, 3), at(31)) // +1ms from 30, NOT +21ms from 10

	got := scorer.Receipt()
	if got.Gaps.Reordered != 1 {
		t.Fatalf("Gaps.Reordered = %d, want 1", got.Gaps.Reordered)
	}
	// at(31) is 1ms after the frontier at(30): the 1-2.4ms bucket.
	if got.Gaps.From1To2_4 != 1 {
		t.Fatalf("Gaps.From1To2_4 = %d, want 1; the gap after a late arrival must be measured from the frontier", got.Gaps.From1To2_4)
	}
	// Only the at(30) step belongs in 7-32ms. If the frontier had regressed to
	// at(10), at(31) would have produced a second 7-32ms sample (+21ms).
	if got.Gaps.From7To32 != 1 {
		t.Fatalf("Gaps.From7To32 = %d, want 1; a regressed frontier inflates the next gap", got.Gaps.From7To32)
	}
}
