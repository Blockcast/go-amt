package shred

import (
	"fmt"
	"sort"
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
	receipt := Receipt{SetsTotal: len(s.sets), Gaps: s.gaps}
	latencies := make([]time.Duration, 0, len(s.sets))
	for _, set := range s.sets {
		if set.completed == 0 {
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
