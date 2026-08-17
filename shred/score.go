package shred

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const completionThreshold = 32

type SetKey struct {
	Slot        uint64
	FECSetIndex uint32
}

type GapHistogram struct {
	LT1        uint64 `json:"lt_1ms"`
	From1To2_4 uint64 `json:"from_1ms_to_2_4ms"`
	From2_4To7 uint64 `json:"from_2_4ms_to_7ms"`
	From7To32  uint64 `json:"from_7ms_to_32ms"`
	GTE32      uint64 `json:"gte_32ms"`
	// Reordered counts arrivals whose timestamp did not advance the frontier, so
	// no inter-arrival gap could be derived from them. These are excluded from
	// the buckets above rather than folded into LT1. It is reported so the
	// buckets stay auditable: bucket total + Reordered is the number of
	// non-first accepted shreds, and a nonzero value here means the histogram
	// is a sample of arrivals rather than all of them.
	Reordered uint64 `json:"reordered"`
}

type Receipt struct {
	SetsTotal       int     `json:"sets_total"`
	SetsErased      int     `json:"sets_erased"`
	ErasureFraction float64 `json:"erasure_fraction"`
	// MeanShredsPerSet is the mean number of distinct shreds this scorer saw per
	// FEC set, over the same set universe as SetsTotal. Sets the scorer never
	// saw at all contribute zero.
	MeanShredsPerSet float64       `json:"mean_shreds_per_set"`
	CompletionP50    time.Duration `json:"completion_p50_ns"`
	CompletionP95    time.Duration `json:"completion_p95_ns"`
	CompletionP99    time.Duration `json:"completion_p99_ns"`
	Gaps             GapHistogram  `json:"gap_histogram"`
}

type setScore struct {
	seen  uint64
	first time.Time
	// last is the newest arrival timestamp among the distinct shreds counted
	// into seen. Together with first it gives the set's true arrival extent,
	// which is what completed measures. Tracking it explicitly (rather than
	// using the timestamp of whichever shred happened to be processed 32nd)
	// keeps the extent correct when arrivals are presented out of order.
	last time.Time
	// completed is only meaningful when complete is true. A duration of zero is
	// a legitimate value — a set whose 32nd distinct shred lands in the same
	// clock tick as its first — so completion must not be inferred from
	// completed != 0, which would misreport such a set as erased.
	complete  bool
	completed time.Duration
}

// Scorer applies first-arrival-wins deduplication across feeds and scores each
// consensus 32+32 FEC set when its 32nd distinct shred arrives.
type Scorer struct {
	format Format
	// dedup maps each distinct shred to the earliest arrival timestamp seen for
	// it, not merely to its presence. Keeping the running minimum is what lets a
	// duplicate that is older than the incumbent be recognised as the true first
	// arrival, which is how FeedScorer attributes first-arrival credit by
	// timestamp instead of by whichever goroutine reached the lock first.
	dedup       map[dedupKey]time.Time
	sets        map[SetKey]*setScore
	lastArrival time.Time
	gaps        GapHistogram
}

type FeedReceipt struct {
	Name string `json:"name"`
	// UniqueFirst counts the union-unique shreds whose first arrival was on this
	// feed. Summed across feeds it equals UnionReceipt.UniqueShreds.
	//
	// "First" is decided by arrival timestamp, not by which feed's goroutine
	// reached the scorer first, so the value is a function of the arrivals alone
	// and is reproducible from a capture. Shreds arriving on two feeds within the
	// same clock tick are credited to whichever was processed first; on a coarse
	// clock that tie-break, not the concurrency, is the residual ambiguity.
	UniqueFirst          uint64  `json:"unique_shreds_first"`
	FirstArrivalFraction float64 `json:"first_arrival_fraction"`
	Receipt              Receipt `json:"receipt"`
}

// SecondFeedWorth reports what the non-baseline inputs added during this run:
// how many FEC sets were unrecoverable on the baseline feed alone but complete
// in the first-arrival union. It measures the observed run only — it cannot
// tell whether the inputs are independently operated or share one tap, so it
// must never be presented as evidence of decorrelated infrastructure.
type SecondFeedWorth struct {
	Label       string  `json:"label"`
	Baseline    string  `json:"baseline"`
	RescuedSets int     `json:"rescued_sets"`
	GapClosed   float64 `json:"gap_closed_fraction"`
}

const secondFeedLabel = "measured worth of a second feed"

type UnionReceipt struct {
	Feeds []FeedReceipt `json:"feeds"`
	Union Receipt       `json:"union"`
	// UniqueShreds is the number of distinct shreds seen across all feeds.
	UniqueShreds uint64           `json:"unique_shreds_total"`
	SecondFeed   *SecondFeedWorth `json:"second_feed,omitempty"`
	// GapClosed is the baseline feed's erasure fraction minus the union's.
	//
	// Deprecated: kept for source compatibility with pre-SecondFeed consumers.
	// Use SecondFeed for per-set rescue accounting.
	GapClosed float64 `json:"gap_closed,omitempty"`
}

// FeedScorer keeps each feed's loss accounting separate while applying
// first-arrival-wins deduplication to the union.
//
// FeedScorer is safe for concurrent use. It is the type shared across a
// receiver's per-feed ingress goroutines, so it synchronizes itself rather than
// requiring every caller to bring a lock — the same contract receiver.Health and
// receiver.ReceiverMetrics already offer. The embedded Scorers are NOT
// individually safe for concurrent use and must only be reached through here;
// a bare Scorer (as used by fixture replay) stays lock-free.
type FeedScorer struct {
	mu            sync.Mutex
	names         []string
	feeds         map[string]*Scorer
	union         *Scorer
	firstArrivals map[string]uint64
	// firstBy records which feed currently holds first-arrival credit for each
	// union-unique shred, so that credit can be moved when a later-processed but
	// earlier-timestamped copy of the same shred arrives on another feed.
	//
	// Nil when fewer than two feeds are configured: with one feed every
	// union-unique shred is trivially its own first arrival, so there is nothing
	// to re-attribute and no reason to carry a per-shred map to prove it.
	firstBy map[dedupKey]string
}

// NewFeedScorer scores the shred-forwarder wire format on every feed.
func NewFeedScorer(names []string) *FeedScorer {
	return NewFeedScorerWithFormat(FormatForwarder, names)
}

func NewFeedScorerWithFormat(format Format, names []string) *FeedScorer {
	feeds := make(map[string]*Scorer, len(names))
	for _, name := range names {
		feeds[name] = NewScorerWithFormat(format)
	}
	scorer := &FeedScorer{
		names:         append([]string(nil), names...),
		feeds:         feeds,
		union:         NewScorerWithFormat(format),
		firstArrivals: make(map[string]uint64, len(names)),
	}
	if len(names) > 1 {
		scorer.firstBy = make(map[dedupKey]string)
	}
	return scorer
}

// Observe scores packet against feed's own scorer and against the first-arrival
// union, reporting whether this call was the union's first sighting of the shred.
//
// The reported bool is a processing-order fact and is deliberately left as one:
// callers use it to decide whether they are the goroutine that must do
// once-per-shred work, and exactly one caller must win that regardless of
// timestamps. First-arrival *credit* is a different question and is not decided
// by it — see the re-attribution below.
func (s *FeedScorer) Observe(feed string, packet []byte, receivedAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scorer := s.feeds[feed]
	if scorer == nil {
		return false, fmt.Errorf("unknown feed %q", feed)
	}
	if _, err := scorer.Observe(packet, receivedAt); err != nil {
		return false, err
	}
	key, accepted, incumbent, err := s.union.observe(packet, receivedAt)
	if err != nil {
		return false, err
	}
	if accepted {
		s.firstArrivals[feed]++
		if s.firstBy != nil {
			s.firstBy[key] = feed
		}
		return true, nil
	}
	// A duplicate whose arrival timestamp precedes the incumbent's was in truth
	// the first arrival; it only looks second because its feed's goroutine
	// reached the lock later. receivedAt is captured at the socket read, ahead of
	// health, metrics and fan-out work, so the interval between capture and this
	// call is real and differs per feed. Without this, unique_shreds_first and
	// first_arrival_fraction — the numbers a customer reads as "is the second
	// feed earning its keep" — would be decided by scheduling.
	//
	// Moving the credit to the earlier arrival makes attribution a function of
	// the timestamps alone: the incumbent is always the running minimum, so the
	// outcome is the same for every interleaving of the same arrivals. Equal
	// timestamps keep the incumbent, so a coarse clock degrades to first-processed
	// rather than to flapping. The total is conserved — one feed's counter falls
	// as another's rises — so UniqueFirst continues to partition UniqueShreds.
	if s.firstBy != nil && receivedAt.Before(incumbent) {
		if holder, held := s.firstBy[key]; held && holder != feed {
			s.firstArrivals[holder]--
			s.firstArrivals[feed]++
			s.firstBy[key] = feed
		}
	}
	return false, nil
}

func (s *FeedScorer) Receipt() UnionReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]SetKey, 0, len(s.union.sets))
	for key := range s.union.sets {
		keys = append(keys, key)
	}
	receipt := UnionReceipt{
		Feeds:        make([]FeedReceipt, 0, len(s.names)),
		Union:        s.union.receiptFor(keys),
		UniqueShreds: uint64(len(s.union.dedup)),
	}
	for _, name := range s.names {
		feed := FeedReceipt{Name: name, UniqueFirst: s.firstArrivals[name], Receipt: s.feeds[name].receiptFor(keys)}
		if receipt.UniqueShreds != 0 {
			feed.FirstArrivalFraction = float64(feed.UniqueFirst) / float64(receipt.UniqueShreds)
		}
		receipt.Feeds = append(receipt.Feeds, feed)
	}
	if len(receipt.Feeds) > 1 {
		receipt.SecondFeed = s.secondFeedWorth(keys)
		receipt.GapClosed = receipt.Feeds[0].Receipt.ErasureFraction - receipt.Union.ErasureFraction
	}
	return receipt
}

// secondFeedWorth counts the FEC sets the baseline feed (the first configured
// feed) could not complete on its own but the first-arrival union could. The
// union sees a superset of every feed's shreds, so a set complete on the
// baseline is always complete in the union; the rescued count is therefore
// exactly the erasure gap the other feeds closed.
func (s *FeedScorer) secondFeedWorth(keys []SetKey) *SecondFeedWorth {
	baseline := s.feeds[s.names[0]]
	worth := &SecondFeedWorth{Label: secondFeedLabel, Baseline: s.names[0]}
	for _, key := range keys {
		if set := baseline.sets[key]; set != nil && set.complete {
			continue
		}
		if set := s.union.sets[key]; set != nil && set.complete {
			worth.RescuedSets++
		}
	}
	if len(keys) != 0 {
		worth.GapClosed = float64(worth.RescuedSets) / float64(len(keys))
	}
	return worth
}

// dedupKey identifies one shred for first-arrival-wins deduplication.
//
// It must include FECSetIndex and the kind-bearing in-set index: Header.Index is
// an absolute index whose space differs between data and coding shreds, so
// keying on (Slot, Index) alone collides a data shred with a coding shred of the
// same index in the same slot and silently discards the second one — which
// reads downstream as packet loss.
type dedupKey struct {
	slot           uint64
	fecSetIndex    uint32
	indexWithinSet uint8
}

// NewScorer scores the shred-forwarder wire format, which is what the SSM group
// and the demo tap carry. Use NewScorerWithFormat for canonical Agave shreds.
func NewScorer() *Scorer {
	return NewScorerWithFormat(FormatForwarder)
}

func NewScorerWithFormat(format Format) *Scorer {
	return &Scorer{
		format: format,
		dedup:  make(map[dedupKey]time.Time),
		sets:   make(map[SetKey]*setScore),
	}
}

func (s *Scorer) Observe(packet []byte, receivedAt time.Time) (bool, error) {
	_, accepted, _, err := s.observe(packet, receivedAt)
	return accepted, err
}

// observe is Observe plus the deduplication detail a FeedScorer needs in order
// to attribute first arrival: the shred's dedup key, and — when the shred is a
// duplicate — the earliest arrival timestamp recorded for it so far.
//
// incumbent is only meaningful when accepted is false.
func (s *Scorer) observe(packet []byte, receivedAt time.Time) (key dedupKey, accepted bool, incumbent time.Time, err error) {
	header, err := Parse(packet, s.format)
	if err != nil {
		return dedupKey{}, false, time.Time{}, err
	}
	key = dedupKey{
		slot:           header.Slot,
		fecSetIndex:    header.FECSetIndex,
		indexWithinSet: header.IndexWithinSet,
	}
	if first, exists := s.dedup[key]; exists {
		// Hold the running minimum so the recorded first arrival is the earliest
		// one seen, not the earliest one that happened to be processed first.
		if receivedAt.Before(first) {
			s.dedup[key] = receivedAt
		}
		return key, false, first, nil
	}
	s.dedup[key] = receivedAt

	// receivedAt is a true arrival timestamp, captured at the read before any
	// per-packet work, so it is NOT guaranteed to be nondecreasing across calls:
	// concurrent feed goroutines can capture t1 < t2 and reach Observe as t2, t1.
	// Nothing here may assume call order matches timestamp order. A regressing
	// timestamp would otherwise yield a negative gap, which falls through the
	// bucket ladder into LT1 and silently inflates the sub-millisecond count,
	// and would drag lastArrival backwards so the *next* gap is measured from a
	// stale frontier and reads too large.
	if !s.lastArrival.IsZero() {
		if gap := receivedAt.Sub(s.lastArrival); gap > 0 {
			s.gaps.observe(gap)
		} else {
			s.gaps.Reordered++
		}
	}
	if receivedAt.After(s.lastArrival) {
		s.lastArrival = receivedAt
	}

	setKey := SetKey{Slot: header.Slot, FECSetIndex: header.FECSetIndex}
	set := s.sets[setKey]
	if set == nil {
		set = &setScore{first: receivedAt, last: receivedAt}
		s.sets[setKey] = set
	}
	bit := uint64(1) << header.IndexWithinSet
	if set.seen&bit != 0 {
		// Unreachable while the dedup key and the set bitmap carry the same
		// (slot, fec_set_index, index_within_set) identity — the dedup miss above
		// implies a clear bit. Kept as a belt-and-braces guard so the bitmap can
		// never double-count. There is no incumbent timestamp to report here: the
		// zero value cannot precede any real arrival, so it withholds credit
		// rather than mis-assigning it.
		return key, false, time.Time{}, nil
	}
	set.seen |= bit
	// Widen the extent to this arrival before testing completion, so first is a
	// true minimum and last a true maximum over the shreds counted into seen.
	// This is what keeps completed from going negative — a negative duration
	// sorts to the front of the latency slice and drags every completion
	// percentile down, understating time_to_32nd_shred on a customer-facing
	// receipt.
	if receivedAt.Before(set.first) {
		set.first = receivedAt
	}
	if receivedAt.After(set.last) {
		set.last = receivedAt
	}
	if !set.complete && bitsSet64(set.seen) == completionThreshold {
		set.complete = true
		set.completed = set.last.Sub(set.first)
	}
	return key, true, time.Time{}, nil
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
	shreds := 0
	for _, key := range keys {
		set := s.sets[key]
		if set != nil {
			shreds += bitsSet64(set.seen)
		}
		if set == nil || !set.complete {
			receipt.SetsErased++
			continue
		}
		latencies = append(latencies, set.completed)
	}
	if receipt.SetsTotal != 0 {
		receipt.ErasureFraction = float64(receipt.SetsErased) / float64(receipt.SetsTotal)
		receipt.MeanShredsPerSet = float64(shreds) / float64(receipt.SetsTotal)
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
	fmt.Fprintf(&output, "union erasure sets=%d erased=%d fraction=%.6f mean_shreds_per_set=%.2f\n", r.Union.SetsTotal, r.Union.SetsErased, r.Union.ErasureFraction, r.Union.MeanShredsPerSet)
	fmt.Fprintf(&output, "gap_ms union <1=%d 1-2.4=%d 2.4-7=%d 7-32=%d >=32=%d reordered=%d\n",
		r.Union.Gaps.LT1, r.Union.Gaps.From1To2_4, r.Union.Gaps.From2_4To7, r.Union.Gaps.From7To32, r.Union.Gaps.GTE32, r.Union.Gaps.Reordered)
	for _, feed := range r.Feeds {
		fmt.Fprintf(&output, "feed name=%s erasure sets=%d erased=%d fraction=%.6f mean_shreds_per_set=%.2f unique_first=%d first_arrival_fraction=%.6f\n",
			feed.Name, feed.Receipt.SetsTotal, feed.Receipt.SetsErased, feed.Receipt.ErasureFraction, feed.Receipt.MeanShredsPerSet, feed.UniqueFirst, feed.FirstArrivalFraction)
	}
	if r.SecondFeed != nil {
		fmt.Fprintf(&output, "second_feed_measured_worth baseline=%s rescued_sets=%d gap_closed_fraction=%.6f",
			r.SecondFeed.Baseline, r.SecondFeed.RescuedSets, r.SecondFeed.GapClosed)
	}
	return strings.TrimSuffix(output.String(), "\n")
}

func (r Receipt) String() string {
	return fmt.Sprintf("time_to_32nd_shred p50=%s p95=%s p99=%s\nerasure sets=%d erased=%d fraction=%.6f mean_shreds_per_set=%.2f\ngap_ms <1=%d 1-2.4=%d 2.4-7=%d 7-32=%d >=32=%d reordered=%d",
		r.CompletionP50, r.CompletionP95, r.CompletionP99, r.SetsTotal, r.SetsErased, r.ErasureFraction, r.MeanShredsPerSet,
		r.Gaps.LT1, r.Gaps.From1To2_4, r.Gaps.From2_4To7, r.Gaps.From7To32, r.Gaps.GTE32, r.Gaps.Reordered)
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
