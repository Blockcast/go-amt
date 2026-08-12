package shred

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const completionThreshold = 32

type SetKey struct {
	Slot        uint64
	FECSetIndex uint32
}

type GapHistogram struct {
	LT1, From1To2_4, From2_4To7, From7To32, GTE32 uint64
}

type Receipt struct {
	SetsTotal       int
	SetsErased      int
	ErasureFraction float64
	CompletionP50   time.Duration
	CompletionP95   time.Duration
	CompletionP99   time.Duration
	Gaps            GapHistogram
}

type setScore struct {
	seen      uint64
	first     time.Time
	completed time.Duration
}

// Scorer applies first-arrival-wins deduplication across feeds and scores each
// consensus 32+32 FEC set when its 32nd distinct shred arrives.
type Scorer struct {
	dedup       map[[2]uint64]struct{}
	sets        map[SetKey]*setScore
	lastArrival time.Time
	gaps        GapHistogram
}

type FeedReceipt struct {
	Name    string
	Receipt Receipt
}

type UnionReceipt struct {
	Feeds     []FeedReceipt
	Union     Receipt
	GapClosed float64
}

// FeedScorer keeps each feed's loss accounting separate while applying
// first-arrival-wins deduplication to the union.
type FeedScorer struct {
	names []string
	feeds map[string]*Scorer
	union *Scorer
}

func NewFeedScorer(names []string) *FeedScorer {
	feeds := make(map[string]*Scorer, len(names))
	for _, name := range names {
		feeds[name] = NewScorer()
	}
	return &FeedScorer{names: append([]string(nil), names...), feeds: feeds, union: NewScorer()}
}

func (s *FeedScorer) Observe(feed string, packet []byte, receivedAt time.Time) (bool, error) {
	scorer := s.feeds[feed]
	if scorer == nil {
		return false, fmt.Errorf("unknown feed %q", feed)
	}
	if _, err := scorer.Observe(packet, receivedAt); err != nil {
		return false, err
	}
	return s.union.Observe(packet, receivedAt)
}

func (s *FeedScorer) Receipt() UnionReceipt {
	keys := make([]SetKey, 0, len(s.union.sets))
	for key := range s.union.sets {
		keys = append(keys, key)
	}
	receipt := UnionReceipt{Feeds: make([]FeedReceipt, 0, len(s.names)), Union: s.union.receiptFor(keys)}
	for _, name := range s.names {
		receipt.Feeds = append(receipt.Feeds, FeedReceipt{Name: name, Receipt: s.feeds[name].receiptFor(keys)})
	}
	if len(receipt.Feeds) > 1 {
		receipt.GapClosed = receipt.Feeds[0].Receipt.ErasureFraction - receipt.Union.ErasureFraction
	}
	return receipt
}

func NewScorer() *Scorer {
	return &Scorer{dedup: make(map[[2]uint64]struct{}), sets: make(map[SetKey]*setScore)}
}

func (s *Scorer) Observe(packet []byte, receivedAt time.Time) (bool, error) {
	header, err := ParseHeader(packet)
	if err != nil {
		return false, err
	}
	dedupKey := [2]uint64{header.Slot, uint64(header.Index)}
	if _, exists := s.dedup[dedupKey]; exists {
		return false, nil
	}
	s.dedup[dedupKey] = struct{}{}

	if !s.lastArrival.IsZero() {
		s.gaps.observe(receivedAt.Sub(s.lastArrival))
	}
	s.lastArrival = receivedAt

	key := SetKey{Slot: header.Slot, FECSetIndex: header.FECSetIndex}
	set := s.sets[key]
	if set == nil {
		set = &setScore{first: receivedAt}
		s.sets[key] = set
	}
	bit := uint64(1) << header.IndexWithinSet
	if set.seen&bit != 0 {
		return false, nil
	}
	set.seen |= bit
	if set.completed == 0 && bitsSet64(set.seen) == completionThreshold {
		set.completed = receivedAt.Sub(set.first)
	}
	return true, nil
}

func (s *Scorer) Receipt() Receipt {
	keys := make([]SetKey, 0, len(s.sets))
	for key := range s.sets {
		keys = append(keys, key)
	}
	return s.receiptFor(keys)
}

func (s *Scorer) receiptFor(keys []SetKey) Receipt {
	receipt := Receipt{SetsTotal: len(keys), Gaps: s.gaps}
	latencies := make([]time.Duration, 0, len(keys))
	for _, key := range keys {
		set := s.sets[key]
		if set == nil || set.completed == 0 {
			receipt.SetsErased++
			continue
		}
		latencies = append(latencies, set.completed)
	}
	if receipt.SetsTotal != 0 {
		receipt.ErasureFraction = float64(receipt.SetsErased) / float64(receipt.SetsTotal)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	receipt.CompletionP50 = percentile(latencies, 50)
	receipt.CompletionP95 = percentile(latencies, 95)
	receipt.CompletionP99 = percentile(latencies, 99)
	return receipt
}

func (r UnionReceipt) String() string {
	var output strings.Builder
	fmt.Fprintf(&output, "time_to_32nd_shred union p50=%s p95=%s p99=%s\n", r.Union.CompletionP50, r.Union.CompletionP95, r.Union.CompletionP99)
	fmt.Fprintf(&output, "union erasure sets=%d erased=%d fraction=%.6f\n", r.Union.SetsTotal, r.Union.SetsErased, r.Union.ErasureFraction)
	fmt.Fprintf(&output, "gap_ms union <1=%d 1-2.4=%d 2.4-7=%d 7-32=%d >=32=%d\n",
		r.Union.Gaps.LT1, r.Union.Gaps.From1To2_4, r.Union.Gaps.From2_4To7, r.Union.Gaps.From7To32, r.Union.Gaps.GTE32)
	for _, feed := range r.Feeds {
		fmt.Fprintf(&output, "feed name=%s erasure sets=%d erased=%d fraction=%.6f\n", feed.Name, feed.Receipt.SetsTotal, feed.Receipt.SetsErased, feed.Receipt.ErasureFraction)
	}
	if len(r.Feeds) > 1 {
		fmt.Fprintf(&output, "second_feed_gap_closed baseline=%s fraction=%.6f", r.Feeds[0].Name, r.GapClosed)
	}
	return strings.TrimSuffix(output.String(), "\n")
}

func (r Receipt) String() string {
	return fmt.Sprintf("time_to_32nd_shred p50=%s p95=%s p99=%s\nerasure sets=%d erased=%d fraction=%.6f\ngap_ms <1=%d 1-2.4=%d 2.4-7=%d 7-32=%d >=32=%d",
		r.CompletionP50, r.CompletionP95, r.CompletionP99, r.SetsTotal, r.SetsErased, r.ErasureFraction,
		r.Gaps.LT1, r.Gaps.From1To2_4, r.Gaps.From2_4To7, r.Gaps.From7To32, r.Gaps.GTE32)
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

func percentile(values []time.Duration, p int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := (p*len(values) + 99) / 100
	return values[index-1]
}

func bitsSet64(bitmap uint64) int {
	count := 0
	for bitmap != 0 {
		bitmap &= bitmap - 1
		count++
	}
	return count
}
