package shred

import (
	"fmt"
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
	// CompletionsAboveCeiling counts completions at or above CompletionCeiling.
	// Those land in the histogram's single unbounded bucket and are reported as
	// its floor, so ANY nonzero value here means the three percentiles above
	// UNDERSTATE, by an unbounded amount, and the documented
	// CompletionRelativeError does not apply to this receipt.
	//
	// This is reported rather than predicted because it cannot be predicted:
	// --retain does not bound a set's completion span (a set is aged on its
	// newest arrival, so one that keeps receiving is never evicted), and 32
	// shreds arriving 200ms apart span 6.2s at the 2s default. A startup-time
	// comparison against the window is blind to exactly those cases, so the
	// condition is counted where it actually occurs.
	CompletionsAboveCeiling uint64 `json:"completions_above_ceiling"`
	// CompletionsTotal is how many completions the percentiles above summarise,
	// i.e. the sets that reached 32 distinct shreds. It is the denominator for
	// CompletionsAboveCeiling: one-in-a-million overflowing and half-of-two are
	// very different runs, and without this a reader cannot tell them apart.
	//
	// It equals SetsTotal-SetsErased by construction — a set is either completed
	// into the histogram or counted erased, never both — which
	// TestCompletionsTotalIsTheCompletedSetCount pins. Reported rather than left
	// to the reader to derive, because that relationship is not evident from the
	// two field names.
	CompletionsTotal uint64       `json:"completions_total"`
	Gaps             GapHistogram `json:"gap_histogram"`
}

type setScore struct {
	seen uint64
	// first and last are the oldest and newest arrival timestamps among the
	// distinct shreds counted into seen, as presented to observe. Together they
	// give the set's arrival extent, which is what completed measures. Tracking
	// them explicitly (rather than using the timestamp of whichever shred
	// happened to be processed 32nd) keeps the extent correct when arrivals are
	// presented out of order, and a duplicate carrying an earlier timestamp
	// lowers first so the floor does not depend on which copy arrived first.
	//
	// Both stop moving at completion, and neither is repaired retroactively: a
	// duplicate older than the copy already counted can only lower first while
	// the set is still incomplete, and it can never lower last. So a set whose
	// newest-counted shred was itself raced keeps a slightly wide extent. Making
	// both true extremes over true arrivals needs per-shred earliest-arrival
	// tracking, which this type deliberately does not carry.
	first time.Time
	last  time.Time
	// completed is only meaningful when complete is true. A duration of zero is
	// a legitimate value — a set whose 32nd distinct shred lands in the same
	// clock tick as its first — so completion must not be inferred from
	// completed != 0, which would misreport such a set as erased.
	complete  bool
	completed time.Duration
}

// Scorer applies first-arrival-wins deduplication across feeds and scores each
// consensus 32+32 FEC set when its 32nd distinct shred arrives.
//
// # Retention
//
// The maps below are per-shred and per-set, so on a live feed they are unbounded
// in exactly the way the shred stream is. Scorer therefore keeps them only for
// arrivals within window of the newest arrival it has seen; older entries are
// finalized into the counters beside them and dropped. Every number the receipt
// reports is one of those counters, so the receipt covers the whole run even
// though the state behind it does not.
//
// What the window bounds is not what is counted but what can still be recognised
// as a *repeat*: a second copy of a shred arriving more than window after the
// first has no surviving identity to match against and is counted as a new
// unique shred. The duplicates this exists to recognise arrive milliseconds
// apart on a second feed, so the default window clears them by three orders of
// magnitude — see DefaultRetention.
type Scorer struct {
	format Format
	window time.Duration
	// dedup maps each distinct shred to the earliest arrival timestamp seen for
	// it, not merely to its presence. Keeping the running minimum is what lets a
	// duplicate that is older than the incumbent be recognised as the true first
	// arrival, which is how FeedScorer attributes first-arrival credit by
	// timestamp instead of by whichever goroutine reached the lock first. It is
	// also what eviction ages entries by.
	dedup       map[dedupKey]time.Time
	sets        map[SetKey]*setScore
	lastArrival time.Time
	gaps        GapHistogram

	// nextSweep is when reclamation next runs. See scheduleSweep.
	nextSweep time.Time

	// Counters below outlive the maps. They are the receipt: each is advanced
	// when an entry leaves the window, and receiptFor adds whatever is still
	// live.
	uniqueShreds uint64
	setsTotal    uint64
	setsErased   uint64
	setsShreds   uint64
	completions  completionHistogram
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
	// rescuedSets accumulates the sets counted by secondFeedWorth as they leave
	// the retention window, for the same reason the Scorers carry counters: the
	// per-set state the correlation reads is gone after eviction.
	rescuedSets int
}

// NewFeedScorer scores the shred-forwarder wire format on every feed.
func NewFeedScorer(names []string) *FeedScorer {
	return NewFeedScorerWithFormat(FormatForwarder, names)
}

func NewFeedScorerWithFormat(format Format, names []string) *FeedScorer {
	return NewFeedScorerWithRetention(format, names, DefaultRetention)
}

// NewFeedScorerWithRetention builds a feed scorer whose scorers all keep
// per-shred identity for window past each arrival. See DefaultRetention.
func NewFeedScorerWithRetention(format Format, names []string, window time.Duration) *FeedScorer {
	feeds := make(map[string]*Scorer, len(names))
	for _, name := range names {
		feeds[name] = NewScorerWithRetention(format, window)
	}
	scorer := &FeedScorer{
		names:         append([]string(nil), names...),
		feeds:         feeds,
		union:         NewScorerWithRetention(format, window),
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
	// The UNEXPORTED observe: the exported Scorer.Observe carries a per-scorer
	// eviction sweep, and reaching it here made each feed self-finalize on its
	// own frontier and its own set universe. The feed's sweep runs before the
	// union's evict below, so the feed deleted sets the union still held live;
	// the union pass then finalized the same keys a second time as phantom
	// erased. A feed that carried every shred of every set reported 42.9%
	// erasure, and the false-nil baseline inflated "measured worth of a second
	// feed" to 75% gap closed when the second feed rescued nothing.
	// Reclamation inside a FeedScorer must run at one frontier across every feed
	// and the union -- that is FeedScorer.evict's job, and only its job.
	if _, _, _, err := scorer.observe(packet, receivedAt); err != nil {
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
	} else if s.firstBy != nil && receivedAt.Before(incumbent) {
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
		//
		// The window bounds how long this remains possible: once the shred's entry
		// is evicted its firstBy record is gone, and a straggler that would have
		// won credit can no longer take it. That interval, not the run, is what
		// "exact" means for first_arrival_fraction.
		if holder, held := s.firstBy[key]; held && holder != feed {
			s.firstArrivals[holder]--
			s.firstArrivals[feed]++
			s.firstBy[key] = feed
		}
	}
	if s.union.scheduleSweep(s.union.lastArrival) {
		s.evict()
	}
	return accepted, nil
}

// evict finalizes and releases every scorer against one common set universe and
// one common floor, the union's.
//
// Order matters twice over: the rescued-set correlation has to read the baseline
// and union set state before either is dropped, and each feed has to be
// finalized against the union's set universe rather than its own so that a set a
// feed never saw still counts against that feed as erased.
func (s *FeedScorer) evict() {
	floor := s.union.retentionFloor()
	keys := s.union.expiredKeys(floor)
	if len(keys) != 0 && len(s.names) > 1 {
		s.rescuedSets += s.rescuedAmong(keys)
	}
	dropped := s.union.evictAgainst(floor, keys)
	for _, scorer := range s.feeds {
		scorer.evictAgainst(floor, keys)
	}
	for _, key := range dropped {
		delete(s.firstBy, key)
	}
}

// rescuedAmong counts, over keys, the sets the baseline feed could not complete
// alone but the union could.
func (s *FeedScorer) rescuedAmong(keys []SetKey) int {
	baseline := s.feeds[s.names[0]]
	rescued := 0
	for _, key := range keys {
		if set := baseline.sets[key]; set != nil && set.complete {
			continue
		}
		if set := s.union.sets[key]; set != nil && set.complete {
			rescued++
		}
	}
	return rescued
}

// Retention reports the per-shred state the scorer is currently holding, across
// the union and every feed. It is what binds the retention bound in tests
// without going through process memory.
//
// Newest and Window are the union's, since the union's frontier is the one every
// feed is aged against.
func (s *FeedScorer) Retention() Retention {
	s.mu.Lock()
	defer s.mu.Unlock()
	retention := s.union.retention()
	retention.TrackedAttributions = len(s.firstBy)
	for _, scorer := range s.feeds {
		retention.TrackedShreds += len(scorer.dedup)
		retention.TrackedSets += len(scorer.sets)
	}
	return retention
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
		UniqueShreds: s.union.uniqueShreds,
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
//
// keys covers only the sets still inside the retention window; everything older
// was correlated by evict as it was dropped and is carried in rescuedSets.
func (s *FeedScorer) secondFeedWorth(keys []SetKey) *SecondFeedWorth {
	worth := &SecondFeedWorth{
		Label:       secondFeedLabel,
		Baseline:    s.names[0],
		RescuedSets: s.rescuedSets + s.rescuedAmong(keys),
	}
	if total := s.union.setsTotal + uint64(len(keys)); total != 0 {
		worth.GapClosed = float64(worth.RescuedSets) / float64(total)
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
	return NewScorerWithRetention(format, DefaultRetention)
}

// NewScorerWithRetention builds a scorer that keeps per-shred identity for
// window past each shred's arrival. See DefaultRetention for what the bound
// costs and Scorer's retention contract for what it buys.
func NewScorerWithRetention(format Format, window time.Duration) *Scorer {
	return &Scorer{
		format: format,
		window: window,
		dedup:  make(map[dedupKey]time.Time),
		sets:   make(map[SetKey]*setScore),
	}
}

func (s *Scorer) Observe(packet []byte, receivedAt time.Time) (bool, error) {
	_, accepted, _, err := s.observe(packet, receivedAt)
	// A bare Scorer reclaims on its own frontier. Inside a FeedScorer BOTH the
	// union and the per-feed scorers bypass this method and call the unexported
	// observe, because reclamation there must run at one frontier across every
	// feed and the union. The earlier wording said only the union bypassed it,
	// which was true of the code and untrue of the requirement.
	if s.scheduleSweep(s.lastArrival) {
		s.evictSelf(s.retentionFloor())
	}
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
			// This copy does not change *which* shreds the set has seen — the bit
			// is already set — but it does lower the set's true arrival floor, and
			// completion latency is measured from that floor. Without this, the
			// floor is whichever copy of a raced shred was processed first, so
			// time_to_32nd_shred would keep the processing-order dependence that
			// first-arrival attribution no longer has.
			//
			// Only a set that has not completed yet can be repaired: completed is
			// frozen when the 32nd distinct shred lands, so an earlier duplicate
			// observed after that point has nothing left to move. Repairing it
			// would need per-shred earliest-arrival tracking so the extent could
			// be recomputed over true arrivals rather than presented ones.
			setKey := SetKey{Slot: header.Slot, FECSetIndex: header.FECSetIndex}
			if set := s.sets[setKey]; set != nil && !set.complete && receivedAt.Before(set.first) {
				set.first = receivedAt
			}
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
		// Reached only when reclamation has decoupled the dedup key from the set
		// bitmap, which is precisely what eviction does: dedup entries age by
		// first < floor while sets age by set.last < floor, so a set whose arrival
		// extent straddles the floor keeps its bitmap after its early shreds have
		// lost their dedup entries. Absent reclamation the two carry the same
		// (slot, fec_set_index, index_within_set) identity and the dedup miss above
		// implies a clear bit. The shift is in range regardless: Parse
		// rejects a data index outside 0..31 and a coding index outside 32..63
		// before the header is built, so IndexWithinSet is always < 64 and the
		// shift can never widen to zero and quietly disable this guard.
		//
		// Kept as a belt-and-braces guard so the bitmap can never double-count.
		// There is no incumbent timestamp to report here: the zero value cannot
		// precede any real arrival, so it withholds credit rather than
		// mis-assigning it. s.dedup[key] is already written above and no later
		// copy can repair that, so this shred is credited to nobody — but it is
		// also not counted into UniqueShreds, because that increment now sits
		// below this guard. Both sides of sum(UniqueFirst) == UniqueShreds omit
		// it, so the partition invariant holds exactly instead of drifting by one
		// per occurrence.
		return key, false, time.Time{}, nil
	}
	set.seen |= bit
	// Counted here, not at the dedup write above, so it increments on exactly the
	// paths that return accepted=true. Above the bitmap guard it could count a
	// shred that the guard then refused, which credits no feed and breaks
	// sum(UniqueFirst) == UniqueShreds by one, cumulatively, with nothing to
	// reconcile it.
	s.uniqueShreds++
	// Widen the extent to this arrival before testing completion, so first is a
	// true minimum and last a true maximum over the shreds counted into seen.
	// This is what keeps completed from going negative — a negative duration
	// sorts to the front of the latency slice and drags every completion
	// percentile down, understating time_to_32nd_shred on a customer-facing
	// receipt.
	//
	// Widening stops at completion. completed is frozen there, so shreds 33..63
	// could only drift first and last away from the extent that produced it;
	// keeping the whole block behind the same guard makes completed == last minus
	// first an invariant rather than something that holds only at one instant.
	if !set.complete {
		if receivedAt.Before(set.first) {
			set.first = receivedAt
		}
		if receivedAt.After(set.last) {
			set.last = receivedAt
		}
		if bitsSet64(set.seen) == completionThreshold {
			set.complete = true
			set.completed = set.last.Sub(set.first)
		}
	}
	return key, true, time.Time{}, nil
}

// retentionFloor is the oldest arrival still inside the window. Entries older
// than it hold nothing a later arrival could revise.
func (s *Scorer) retentionFloor() time.Time {
	return s.lastArrival.Add(-s.window)
}

// expiredKeys lists the sets whose newest arrival has fallen out of the window
// and which are therefore ready to be folded into counters. A set's newest
// arrival is used, not its oldest: a set still collecting shreds is still live.
func (s *Scorer) expiredKeys(floor time.Time) []SetKey {
	var keys []SetKey
	for key, set := range s.sets {
		if set.last.Before(floor) {
			keys = append(keys, key)
		}
	}
	return keys
}

// finalize folds keys into this scorer's cumulative counters. The caller passes
// the set universe — for a FeedScorer that is the union's, so every feed is
// scored over the same denominator and a set a feed never saw counts against it
// as erased, exactly as receiptFor did while the sets were still live.
func (s *Scorer) finalize(keys []SetKey) {
	for _, key := range keys {
		s.setsTotal++
		set := s.sets[key]
		if set == nil {
			s.setsErased++
			continue
		}
		s.setsShreds += uint64(bitsSet64(set.seen))
		if !set.complete {
			s.setsErased++
			continue
		}
		s.completions.observe(set.completed)
	}
}

// evict finalizes the sets that have left the window and releases their state,
// along with every dedup entry that first arrived before floor.
//
// floor is passed in rather than derived from this scorer's own frontier: inside
// a FeedScorer every scorer ages against the union's frontier, and a feed that
// has gone quiet would otherwise hold its last shreds forever because its own
// frontier stops advancing. It must not be conflated with lastArrival, which is
// the gap histogram's frontier and has to stay this feed's own.
//
// keys is the set universe to finalize against — a FeedScorer passes the
// union's so that a set a feed never saw still counts against that feed as
// erased. dropped collects the dedup keys released, which is how FeedScorer
// keeps firstBy in lockstep with the union's identities rather than ageing it
// separately.
//
// There is deliberately no "derive the universe yourself" sentinel here. It
// used to be keys == nil, which collided with expiredKeys returning a nil
// slice whenever nothing had expired: a feed then silently finalized against
// its OWN universe at the union's floor, counting a set once for itself and
// again when the union later expired it. "The union expired nothing while a
// feed did" is routine rather than exotic, because the union's set.last is the
// max across feeds — one feed's late shred keeps the union's copy live while
// another feed's copy sits below the floor. A caller that genuinely wants its
// own universe now says so by name through evictSelf, which makes the
// wrong-universe fallback unrepresentable rather than merely absent.
func (s *Scorer) evictAgainst(floor time.Time, keys []SetKey) (dropped []dedupKey) {
	s.finalize(keys)
	for _, key := range keys {
		delete(s.sets, key)
	}
	for key, first := range s.dedup {
		if first.Before(floor) {
			delete(s.dedup, key)
			dropped = append(dropped, key)
		}
	}
	return dropped
}

// evictSelf ages a standalone Scorer against its own set universe. Inside a
// FeedScorer this is never the right call — every scorer there must age against
// the union's universe at one common frontier; see evictAgainst.
func (s *Scorer) evictSelf(floor time.Time) (dropped []dedupKey) {
	return s.evictAgainst(floor, s.expiredKeys(floor))
}

func (s *Scorer) Receipt() Receipt {
	keys := make([]SetKey, 0, len(s.sets))
	for key := range s.sets {
		keys = append(keys, key)
	}
	return s.receiptFor(keys)
}

// receiptFor reports the scorer's cumulative counters plus whatever keys are
// still live. keys is the set universe the caller wants scored — for a
// FeedScorer that is the union's live keys, so every feed shares one
// denominator — and it must contain only sets still inside the window; sets
// below the floor were already folded in by finalize and would double-count.
func (s *Scorer) receiptFor(keys []SetKey) Receipt {
	total := s.setsTotal
	erased := s.setsErased
	shreds := s.setsShreds
	// The histogram is a fixed-size array, so this is a copy, not an alias: the
	// live sets below are scored into the receipt without being committed to the
	// scorer, which would double-count them once they are finalized for real.
	completions := s.completions
	for _, key := range keys {
		total++
		set := s.sets[key]
		if set == nil {
			erased++
			continue
		}
		shreds += uint64(bitsSet64(set.seen))
		if !set.complete {
			erased++
			continue
		}
		completions.observe(set.completed)
	}
	receipt := Receipt{SetsTotal: int(total), SetsErased: int(erased), Gaps: s.gaps}
	if total != 0 {
		receipt.ErasureFraction = float64(erased) / float64(total)
		receipt.MeanShredsPerSet = float64(shreds) / float64(total)
	}
	receipt.CompletionP50 = completions.percentile(50)
	receipt.CompletionP95 = completions.percentile(95)
	receipt.CompletionP99 = completions.percentile(99)
	receipt.CompletionsAboveCeiling = completions.overflowed()
	receipt.CompletionsTotal = completions.count
	return receipt
}

// completionCaveat renders the line that has to appear beside completion
// percentiles when any completion overflowed the ladder, or "" otherwise.
//
// It says "a percentile that fell among them" rather than "the percentiles",
// because overflow is per-completion, not per-run: 99 completions at 10ms plus
// one at 30s leaves p50, p95 and p99 all accurate at 10.047ms while one
// completion overflowed. Asserting that all three understate there would be the
// same species of overclaim this change set out to remove, so the count and its
// denominator are stated and the reader is left to weigh them.
//
// It is printed rather than left to the JSON field because the human table is
// what an operator reads in a dispute, and a percentile whose stated error bar
// may not apply is worse than no percentile at all.
func completionCaveat(aboveCeiling, total uint64) string {
	if aboveCeiling == 0 {
		return ""
	}
	return fmt.Sprintf("time_to_32nd_shred WARNING: %d of %d completion(s) were at or "+
		"above %s and recorded as that value, so a percentile that fell among them "+
		"UNDERSTATES by an unbounded amount and the documented %.2f%% error does not "+
		"apply to it. Percentiles below that point are unaffected.",
		aboveCeiling, total, CompletionCeiling, CompletionRelativeError*100)
}

func (r UnionReceipt) String() string {
	var output strings.Builder
	fmt.Fprintf(&output, "time_to_32nd_shred union p50=%s p95=%s p99=%s\n", r.Union.CompletionP50, r.Union.CompletionP95, r.Union.CompletionP99)
	if line := completionCaveat(r.Union.CompletionsAboveCeiling, r.Union.CompletionsTotal); line != "" {
		fmt.Fprintf(&output, "%s\n", line)
	}
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
	// The caveat is APPENDED, never concatenated into the format string below.
	// It contains a rendered "0.78%", and splicing that into a format string
	// turns the percent into a verb: every argument after it shifts by one and
	// the receipt renders as `erased=%!d(float64=0) fraction=32.000000`. That is
	// the same failure that produced the `%%` bug this PR already fixed once, so
	// pre-rendered text stays out of format strings here.
	out := fmt.Sprintf("time_to_32nd_shred p50=%s p95=%s p99=%s\nerasure sets=%d erased=%d fraction=%.6f mean_shreds_per_set=%.2f\ngap_ms <1=%d 1-2.4=%d 2.4-7=%d 7-32=%d >=32=%d reordered=%d",
		r.CompletionP50, r.CompletionP95, r.CompletionP99, r.SetsTotal, r.SetsErased, r.ErasureFraction, r.MeanShredsPerSet,
		r.Gaps.LT1, r.Gaps.From1To2_4, r.Gaps.From2_4To7, r.Gaps.From7To32, r.Gaps.GTE32, r.Gaps.Reordered)
	if caveat := completionCaveat(r.CompletionsAboveCeiling, r.CompletionsTotal); caveat != "" {
		out += "\n" + caveat
	}
	return out
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

// percentile is nearest-rank over an already-sorted slice. The Scorer's own
// completion percentiles come from a bounded histogram instead (see
// completionHistogram.percentile, which reproduces this ranking), but the helper
// stays: it is the shared primitive the generic-mode scorer ranks its window
// latencies with, where the value count is bounded by the window rather than by
// the run.
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
