// Package erasure tracks receiver-observed Solana FEC-set completion.
package erasure

import (
	"errors"
	"sync"
	"time"

	"github.com/blockcast/go-amt/shred"
)

const (
	shredsPerSet   = 64
	peakRateBucket = 100 * time.Millisecond

	// reportSchema is the report shape this producer emits. It moved 1 -> 2
	// when WindowStart and WindowMS were added (BLO-29493).
	//
	// A broker validates against its own copy of this number, so bumping one
	// without the other invalidates every heartbeat while both files still read
	// correctly. Nothing in the type system ties them: the guard is
	// broker.TestDrainedWindowSatisfiesIngest, which drains a real tracker and
	// requires the validator to accept what comes out.
	reportSchema = 2
)

var ErrInvalidWindowCutoff = errors.New("report cutoff must follow window start")

// GapHistogram contains the fixed v1 consecutive-arrival gap buckets.
type GapHistogram struct {
	LT1        uint64 `json:"<1"`
	From1To2_4 uint64 `json:"1-2.4"`
	From2_4To7 uint64 `json:"2.4-7"`
	From7To32  uint64 `json:"7-32"`
	GTE32      uint64 `json:">=32"`
}

// Window is one receiver delivery report.
//
// SetsTotal and SetsErased are a COUNTER DELTA over the half-open interval
// [WindowStart, WindowStart+WindowMS), not a gauge. They are summable across
// consecutive reports, and a consumer deduplicates on the feed's ID plus
// WindowStart before summing. Both halves of that sentence are load-bearing:
// the receiver's metrics surface republishes the last drained window on every
// scrape (see receiver.ReceiverMetrics.PublishWindow), so the same window
// object is observed repeatedly, and a consumer that summed without
// deduplicating would multiply delivery by however many times it saw one
// window — ten-fold at the longest legal drain interval.
//
// WindowMS is the MEASURED elapsed time DrainWindow computed, not the
// producer's configured drain interval. The two differ precisely when it
// matters: one serial ticker drains every feed, Go's ticker drops ticks under
// a slow receiver, and a delayed drain deliberately reports its actual elapsed
// interval so the derived rate is not distorted. A consumer must therefore
// treat WindowMS as data, not as a restatement of a setting it already knows.
//
// WindowStart is the identity rather than a monotonic counter because a
// counter resets on gateway restart and can then collide across genuinely
// distinct windows — reintroducing the ambiguity it was added to remove. It is
// sound modulo wall-clock steps, which is not a new exposure: an NTP step
// already corrupts the surrounding packet timestamps.
//
// Schema 1 carried neither field, so its counts were comparable only within
// one producer. See broker.FeedReport for what a broker owes each schema.
type Window struct {
	SetsTotal       uint64       `json:"sets_total"`
	SetsErased      uint64       `json:"sets_erased"`
	ErasureFraction float64      `json:"erasure_fraction"`
	RMean           float64      `json:"r_mean"`
	RPeak100MS      float64      `json:"r_peak_100ms"`
	GapMSHist       GapHistogram `json:"gap_ms_hist"`
	GraceMS         int64        `json:"grace_ms"`
	Schema          uint8        `json:"schema"`

	// WindowStart and WindowMS are omitempty so that a schema-1 report's
	// canonical bytes are byte-identical to what they were before these
	// fields existed. A broker's ledger diffs on those bytes, so without
	// omitempty every retained schema-1 feed would diff as changed the moment
	// this struct grew, producing a one-time wave of spurious drift across
	// feeds whose delivery did not change. With it, the wave coincides with
	// the actual move to schema 2.
	WindowStart string `json:"window_start,omitempty"`
	WindowMS    int64  `json:"window_ms,omitempty"`
}

// canonicalUTCTimestamp renders a window boundary in the one spelling the
// heartbeat contract accepts: UTC, "Z" rather than "+00:00", and fractional
// seconds present only when non-zero with trailing zeros trimmed.
//
// This duplicates broker.FormatTimestamp, which is the canonical statement of
// the rule and what every other producer of these timestamps should call. The
// duplication is forced rather than chosen: broker imports erasure, so erasure
// cannot import broker without a cycle, and WindowStart has to be rendered
// where the window is drained. Since a shared symbol is unavailable, the drift
// guard is behavioural — broker.TestDrainedWindowSatisfiesIngest drains a real
// tracker and requires broker's validator to accept the timestamp this
// produces, so the two spellings cannot diverge silently.
func canonicalUTCTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// maxSlotJump bounds how far a single observation may advance the frontier.
//
// Slot arrives from the wire as a raw little-endian uint64 and, unlike version,
// geometry and local index, is not validated by ParseWireHeader. The receiver
// listens on 0.0.0.0 with no source filtering, so one wire-valid datagram
// carrying an out-of-range slot used to advance newestSlot arbitrarily; every
// real shred then sat more than 2 slots behind the frontier and was rejected
// for the life of the process. Delivery and ingress accounting are untouched by
// that, so /healthz and ingress_packets_total stay green and the operator sees a
// live feed with a perfect erasure score -- the exact "confidently clean feed
// under arbitrary real loss" failure this package exists to remove.
//
// Sized from capture data: consecutive slots differ by 69 to 364, so a few
// thousand is generous for real reordering while still making one bad datagram
// non-permanent.
const maxSlotJump = 4096

// slotResyncThreshold is how many consecutive implausible observations are
// treated as evidence that the FEED moved rather than that one datagram lied.
//
// Rejecting a large jump outright would trade one permanent blackout for
// another: a receiver that misses a genuine multi-minute gap would reject every
// subsequent packet, since they are all beyond the bound of a frontier that can
// no longer advance. A single poisoned datagram does not repeat -- the next real
// shred is within the bound and clears the counter -- whereas a genuine jump
// arrives as a continuous stream, so sustained evidence resyncs the frontier.
//
// Counting alone is not enough: 16 MUTUALLY UNRELATED out-of-range slots are
// evidence of noise, not of a feed that moved, and adopting the last of them
// would hand the frontier to whichever datagram happened to arrive 16th. A run
// therefore only extends while each observation stays within maxSlotJump of its
// PREDECESSOR -- a coherent chain, not 16 in a row. Scattered noise still
// perpetually restarts its own run, which is the property that matters; what a
// chain does not give is a tight bound on where the run ends up, so 16 steps can
// carry the frontier up to (16-1)*maxSlotJump = 61,440 slots from the opener.
// See extendRun for why the tighter opener-anchored rule cannot be used: it
// would cap the per-observation step at 273 slots, below the 69-364 range real
// traffic occupies, and a feed at the top of its own normal range would never
// recover.
const slotResyncThreshold = 16

// frontierDistrustThreshold is how many consecutive too-far-BEHIND rejections
// are treated as evidence that the FRONTIER is wrong rather than the traffic.
//
// Without it the forward guard is one-way and its failure is terminal: once
// newestSlot holds a far-future value, every real shred is more than two slots
// behind it, takes the stale branch, and returns without accumulating toward
// anything. Delivery and ingress accounting are untouched, so the operator sees
// a live feed with a permanently perfect erasure score -- the same failure this
// package exists to remove, reached through the guard instead of around it.
//
// The same coherence rule applies as for forward jumps, and any accepted
// observation clears the run, so ordinary reordering behind a healthy frontier
// cannot reach the threshold while real in-window traffic is interleaved.
const frontierDistrustThreshold = 16

// Stats describes the currently retained scoring state, plus the cumulative
// slot-guard totals.
//
// The guard counters reach /metrics via ReceiverMetrics.PublishGuard, which
// publishWindows calls with this value on every report tick. They are deliberately
// not carried on Window: Window is drained and reset per reporting window, and a
// frontier resync is a discontinuity an operator must still be able to see after
// the window that contained it has rolled.
type Stats struct {
	NewestSlot   uint64
	TrackedSlots int
	TrackedSets  int
	// RejectedSlotJumps counts observations refused for an implausible slot
	// advance. A silent guard replaces one invisible failure with another, so
	// this is exported for the same reason the erasure gauge is.
	RejectedSlotJumps uint64
	// StaleRejections counts observations refused for sitting too far BEHIND
	// the frontier. Sustained growth here means the frontier is suspect: real
	// traffic is being refused because a prior advance moved it too far.
	StaleRejections uint64
	// FrontierResyncs counts how often sustained implausible slots were accepted
	// as a genuine feed jump.
	FrontierResyncs uint64
}

type setKey struct {
	fecSetIndex uint32
}

type slotState struct {
	sets     map[setKey]uint64
	boundary time.Time
	scored   bool
}

type scoreEvent struct {
	at     time.Time
	erased bool
}

// deliveryWindow accumulates the three delivery outputs of one report window --
// mean rate, peak 100 ms rate, and the consecutive-gap histogram -- in space
// that does not depend on how many shreds the window observed.
//
// The tracker previously kept every arrival timestamp in a slice until the
// window drained, which pinned 24 bytes per shred per feed and, because
// DrainWindow reused the backing array, never released the high-water capacity:
// one 50k/s burst held ~38 MB of timestamps for the process lifetime. Each
// output is an O(1) fold, so none of that retention bought anything.
//
// Every field is a running fold over arrivals in Observe order. Observe
// requires receivedAt to be monotonic, and that requirement -- not merely the
// absolute bucket keying -- is what makes the peak fold exact: under it, an
// arrival landing in a different bucket proves the previous bucket closed for
// good, so only the current bucket's count has to stay live. The slice form
// this replaces accumulated into a map keyed by bucket and so was
// order-independent; observe reduces the resulting error but does not bound
// its direction (see the out-of-order note there).
type deliveryWindow struct {
	arrivals    uint64
	peakRate    float64
	bucketIndex int64
	bucketOpen  bool
	bucketCount uint64
	lastArrival time.Time
	gaps        GapHistogram
}

func (w *deliveryWindow) observe(receivedAt time.Time) {
	w.arrivals++

	// Monotonic receivedAt is Observe's contract, and under it a differing
	// bucket index always means the previous bucket closed for good. Were that
	// contract ever broken, rotating on the stale index would reset the open
	// bucket's count and *under-report* the peak -- the one direction an SLA
	// metric must not fail in, and one no equivalence test over monotonic input
	// can catch. Folding an out-of-order arrival into the open bucket instead
	// makes under-reporting much rarer, but does NOT eliminate it: the peak can
	// still be understated, and can also be overstated.
	//
	// Measured against the order-independent map this fold replaced, over 200k
	// random orderings of 2-8 arrivals spread across 0-500 ms, five seeds:
	// under-reporting falls from ~47% of orderings to 7.6%, and the worst
	// under-report from 4x to 3x.
	//
	// That is not a free win, and the shape of the cost matters more than the
	// percentages. Without this guard, bucketCount only ever counts a
	// contiguous run of same-bucket arrivals, which is necessarily a subset of
	// that bucket's true total -- so the unguarded fold can *never* overstate.
	// It is a strict lower bound on the peak (0 overstatements in 1M trials,
	// and provably so). The guard trades that predictable one-directional error
	// for a smaller but unsigned one: ~55% of orderings now overstate. For a
	// peak-rate SLA metric that is the better trade -- a false investigation
	// beats a missed bad feed -- and it costs two comparisons per shred on a
	// path already holding the mutex. But it is a trade, not a strict
	// improvement, and the aggregate win does not hold per-input: over the 24
	// permutations of {0, 0, 500ms, 0} the guard under-reports 18 times versus
	// 12 without it.
	//
	// This is a safety net, not a second supported ordering; the fold is exact
	// only for monotonic input.
	bucket := receivedAt.UnixNano() / peakRateBucket.Nanoseconds()
	outOfOrder := !w.lastArrival.IsZero() && receivedAt.Before(w.lastArrival)
	if !w.bucketOpen || (bucket != w.bucketIndex && !outOfOrder) {
		w.bucketIndex = bucket
		w.bucketCount = 0
		w.bucketOpen = true
	}
	w.bucketCount++
	if rate := float64(w.bucketCount) / peakRateBucket.Seconds(); rate > w.peakRate {
		w.peakRate = rate
	}

	// A window's first arrival has no predecessor to measure against, so it
	// contributes no gap. lastArrival is cleared on drain, which is what keeps
	// a gap from being reported across a window boundary.
	if !w.lastArrival.IsZero() {
		w.gaps.observe(receivedAt.Sub(w.lastArrival))
	}
	w.lastArrival = receivedAt
}

// report folds the window into rep and resets the accumulator for the next one.
// elapsed is the wall interval the report covers.
func (w *deliveryWindow) report(rep *Window, elapsed time.Duration) {
	rep.RMean = float64(w.arrivals) / elapsed.Seconds()
	rep.RPeak100MS = w.peakRate
	rep.GapMSHist = w.gaps
	*w = deliveryWindow{}
}

// Tracker deduplicates shred positions and scores observed FEC sets once their
// slot boundary plus the configured grace has elapsed.
type Tracker struct {
	mu sync.Mutex

	grace       time.Duration
	initialized bool
	newestSlot  uint64
	// pendingJumps counts CONSECUTIVE implausible advances; any plausible
	// observation clears it, which is what separates one bad datagram from a
	// feed that genuinely moved. pendingJumpSlot anchors the run so that only
	// mutually coherent jumps accumulate toward slotResyncThreshold.
	pendingJumps    int
	pendingJumpSlot uint64
	// staleRun is the mirror of pendingJumps for observations too far BEHIND
	// the frontier, anchored by staleRunSlot on the same coherence rule. It is
	// the only way out of a frontier that was resynced to a wrong slot.
	staleRun          int
	staleRunSlot      uint64
	rejectedSlotJumps uint64
	staleRejections   uint64
	frontierResyncs   uint64
	boundaries        map[uint64]time.Time
	slots             map[uint64]*slotState
	windowStart       time.Time
	delivery          deliveryWindow
	scores            []scoreEvent
}

// NewTracker constructs a tracker whose first report begins at windowStart. A
// zero grace scores at the slot boundary.
func NewTracker(grace time.Duration, windowStart time.Time) (*Tracker, error) {
	if grace < 0 {
		return nil, errors.New("erasure grace must not be negative")
	}
	if windowStart.IsZero() {
		return nil, errors.New("report window start must be set")
	}
	return &Tracker{
		grace:       grace,
		boundaries:  make(map[uint64]time.Time),
		slots:       make(map[uint64]*slotState),
		windowStart: windowStart,
	}, nil
}

// Observe records one parsed shred. receivedAt must be monotonic for both peak
// and consecutive-gap reporting, as it is on the receiver's serial UDP read
// path -- the timestamp is taken and folded in under the same lock, so the two
// cannot reorder. Out-of-order input does not corrupt totals or erasure
// scoring; it makes RPeak100MS inexact in either direction, most often high
// (see deliveryWindow.observe for the measured distribution).
// It returns false for duplicate, stale, invalid, or already-scored
// observations.
func (t *Tracker) Observe(header shred.Header, receivedAt time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if header.IndexWithinSet >= shredsPerSet {
		return false
	}
	if receivedAt.Before(t.windowStart) {
		return false
	}
	if !t.initialized {
		t.initialized = true
		t.newestSlot = header.Slot
		t.recordPriorBoundaries(header.Slot, receivedAt)
	} else if header.Slot > t.newestSlot {
		if header.Slot-t.newestSlot > maxSlotJump {
			t.rejectedSlotJumps++
			if extendRun(&t.pendingJumps, &t.pendingJumpSlot, header.Slot) < slotResyncThreshold {
				return false
			}
			// Sustained AND self-consistent: the feed moved. Resync rather
			// than stay blacked out.
			return t.resyncFrontier(header, receivedAt)
		}
		t.clearRuns()
		for slot, state := range t.slots {
			if slot < header.Slot && state.boundary.IsZero() {
				state.boundary = receivedAt
				t.boundaries[slot] = receivedAt
			}
		}
		t.newestSlot = header.Slot
		t.recordPriorBoundaries(header.Slot, receivedAt)
	} else if t.newestSlot-header.Slot > 2 {
		t.staleRejections++
		if extendRun(&t.staleRun, &t.staleRunSlot, header.Slot) < frontierDistrustThreshold {
			return false
		}
		// A sustained, self-consistent run of traffic behind the frontier is
		// evidence the FRONTIER is wrong, not the traffic. Adopt it; this is
		// the only exit from a frontier poisoned by a forged advance.
		return t.resyncFrontier(header, receivedAt)
	} else {
		// A plausible in-window observation is evidence the frontier is still
		// real, so a lone poisoned datagram cannot accumulate toward a resync.
		t.clearRuns()
	}
	t.scoreDue(receivedAt)
	t.reclaimOldSlots()

	state := t.slots[header.Slot]
	if state == nil {
		state = &slotState{sets: make(map[setKey]uint64)}
		if header.Slot < t.newestSlot {
			boundary, ok := t.boundaries[header.Slot]
			if !ok || !receivedAt.Before(boundary.Add(t.grace)) {
				return false
			}
			state.boundary = boundary
		}
		t.slots[header.Slot] = state
	}
	if state.scored {
		return false
	}

	key := setKey{fecSetIndex: header.FECSetIndex}
	bit := uint64(1) << header.IndexWithinSet
	if state.sets[key]&bit != 0 {
		return false
	}
	state.sets[key] |= bit
	t.delivery.observe(receivedAt)
	return true
}

// Advance scores every set whose grace deadline is at or before now.
func (t *Tracker) Advance(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scoreDue(now)
	t.reclaimOldSlots()
}

// DrainWindow scores through cutoff, returns one report, and resets its
// counters. The broker normally calls it every 30 seconds; delayed calls use
// their actual elapsed interval so the mean rate is not silently distorted.
//
// Arrival attribution: every shred Observe accepted before this call belongs to
// the window being drained, whatever its timestamp is relative to cutoff.
// cutoff fixes the window's elapsed time and the next window's start; it does
// not re-partition arrivals that have already been folded into the counters.
// Scores are still partitioned by cutoff, because a score carries its own
// deadline and can legitimately fall in a later window than the drain.
//
// This rule replaces the old one, under which arrivals at or after cutoff were
// held back and re-counted in the next window. That is unrepresentable in O(1)
// space -- un-counting an arrival needs its timestamp, which is the retention
// this type exists to remove -- so the alternatives were to reject such a
// cutoff, to carry a single pending arrival, or to attribute as above. The
// first two are unsafe for the receiver this tracker is being built for. Note
// that at this commit DrainWindow has no production caller: the reporter that
// drives it arrives with #47, which adds a reportInterval ticker goroutine that
// does NOT hold the read-path mutex and passes the ticker's own fire time as
// cutoff, while the mu-guarded ReadFromUDP loop keeps stamping later arrivals
// (cmd/blockcast-shreds/main.go, once #47 lands). Under that wiring, arrivals
// at or after cutoff are routine and arbitrarily many, not an
// empty-barring-clock-skew set. Rejecting the cutoff would make the reporter
// skip the drain on every tick and freeze the erasure SLA at its last value --
// the confidently-clean-feed failure this reporting path exists to prevent --
// and one pending arrival cannot hold a suffix that is thousands of shreds long
// at 50k/s. Only the final drain, which runs under mu after the sockets close,
// sees the quiescent case.
//
// The cost is bounded and self-correcting: an arrival is still counted exactly
// once, so totals are conserved across windows, and only reporter scheduling
// lag can shift one between them. RPeak100MS gets more accurate, since a burst
// straddling the cutoff is now scored in one whole bucket instead of being
// split across two windows and understated.
func (t *Tracker) DrainWindow(cutoff time.Time) (Window, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !cutoff.After(t.windowStart) {
		return Window{}, ErrInvalidWindowCutoff
	}
	t.scoreDue(cutoff)
	// DrainWindow guarantees only that cutoff is strictly after windowStart,
	// so elapsed can be sub-millisecond and truncate to 0 — reachable in
	// production via the final drain that runs immediately after a ticker
	// drain when the sockets close. Zero is not a usable wire value: it is
	// what an ABSENT window_ms decodes to, so emitting it would make a
	// legitimate sub-millisecond window indistinguishable from a producer
	// that failed to populate the field, and ingest could no longer require
	// the field at all. Report the 1ms floor instead. The cost is an
	// overstatement bounded by one millisecond, on a window too short for
	// rate normalization to mean anything (sets_total is 0 or 1 there); the
	// alternative is an ambiguity in the contract itself.
	elapsed := cutoff.Sub(t.windowStart)
	windowMS := elapsed.Milliseconds()
	if windowMS < 1 {
		windowMS = 1
	}
	window := Window{
		GraceMS:     t.grace.Milliseconds(),
		Schema:      reportSchema,
		WindowStart: canonicalUTCTimestamp(t.windowStart),
		WindowMS:    windowMS,
	}

	retainedScores := t.scores[:0]
	for _, event := range t.scores {
		if event.at.Before(cutoff) {
			window.SetsTotal++
			if event.erased {
				window.SetsErased++
			}
			continue
		}
		retainedScores = append(retainedScores, event)
	}
	t.scores = releaseUnused(retainedScores)
	window.ErasureFraction = Fraction(window.SetsErased, window.SetsTotal)

	// Delivery is a fixed-size streaming fold (BLO-28451), so unlike the score
	// slice above there is no arrival backing array to walk, filter, or
	// right-size here. This branch's releaseUnused guard therefore applies to
	// t.scores only; the arrival high-water mark it also used to cover cannot
	// exist any more. See releaseUnused and maxReportInterval in
	// cmd/blockcast-shreds for what that does and does not still bound.
	// report takes the untruncated elapsed rather than the 1ms-floored
	// WindowMS above: the derived rate divides by it, so flooring here would
	// understate the rate of a sub-millisecond window instead of merely
	// rounding its reported duration.
	t.delivery.report(&window, elapsed)
	t.windowStart = cutoff
	return window, nil
}

// Stats returns the size of retained state for observability and tests.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats := Stats{
		NewestSlot:        t.newestSlot,
		TrackedSlots:      len(t.slots),
		RejectedSlotJumps: t.rejectedSlotJumps,
		StaleRejections:   t.staleRejections,
		FrontierResyncs:   t.frontierResyncs,
	}
	for _, state := range t.slots {
		stats.TrackedSets += len(state.sets)
	}
	return stats
}

func (t *Tracker) scoreDue(now time.Time) {
	for _, state := range t.slots {
		if state.scored || state.boundary.IsZero() || now.Before(state.boundary.Add(t.grace)) {
			continue
		}
		for _, bitmap := range state.sets {
			t.scores = append(t.scores, scoreEvent{
				at:     state.boundary.Add(t.grace),
				erased: bitsSet(bitmap) < 32,
			})
		}
		state.scored = true
	}
}

// minRetainedCapacity is the slice capacity below which shrinking is not worth
// the copy: a steady feed refills a small backing array immediately.
const minRetainedCapacity = 1024

// releaseUnused right-sizes a drained slice so a burst does not pin resident
// memory for the process lifetime.
//
// The drain filters in place via s[:0], which reuses -- and therefore retains --
// the backing array at its high-water mark. On a long-running validator that
// mark is set by the worst burst the process ever saw, so a single catch-up
// leaves the peak pinned across an otherwise idle feed forever. Copying only
// when the array is mostly empty keeps the steady-state path allocation-free.
//
// Scope note: this guarded BOTH the score slice and an arrival slice when it
// was written. BLO-28451 replaced the arrival slice with the fixed-size
// deliveryWindow fold, which removes that retention outright rather than
// right-sizing it, so t.scores is now the only in-place-filtered slice left and
// the only caller. It is still load-bearing there: one scoreEvent accumulates
// per completed FEC set for the whole report interval, so a catch-up burst
// still grows this array and nothing else returns it.
func releaseUnused[T any](s []T) []T {
	if cap(s) <= minRetainedCapacity || cap(s) <= 4*len(s) {
		return s
	}
	return append(make([]T, 0, max(len(s), minRetainedCapacity)), s...)
}

// extendRun advances a coherence-gated run of rejected observations.
//
// The run extends while each new slot stays within maxSlotJump of its
// PREDECESSOR, and restarts at length 1 otherwise. It is a chain of small steps,
// not a cluster around the slot that opened it, so a run of n can drift up to
// (n-1)*maxSlotJump from where it started — 61,440 slots at the thresholds used
// here.
//
// That is deliberate and the tighter opener-anchored rule is NOT available.
// Anchoring on the opener would cap the per-observation step at
// maxSlotJump/(threshold-1) = 273 slots, and the observed step range is 69–364,
// so a feed in the upper half of its own normal range could never assemble a run
// and would never recover — which is the permanent blackout this guard exists to
// prevent, reintroduced. Measured, not assumed:
// TestRampingFeedAtRealisticSlotSpacingStillResyncs fails if the anchor is
// hoisted into the else branch.
//
// Where 69–364 comes from, since that number decides the rule: it is the five
// gaps between the six slots of the bundled capture fixture, quoted verbatim in
// README.md and shred/retention.go — 159, 270, 69, 364, 207. Two consequences
// are easy to get backwards. 364 is a floor on the top of the range, not a
// candidate ceiling: it was observed, so the true maximum is >= 364 and cannot
// turn out to be lower. And the cliff sits INSIDE that five-sample set rather
// than out in its tail — the second-largest gap, 270, is three slots under the
// 273 cap — so under opener anchoring the feed that never recovers is an
// ordinary one, not a pathological one.
//
// One caveat, recorded so it is not later mistaken for an argument to switch:
// those same two files describe the slot-distance window as correct "for the
// dense live feed it scores", where slots advance one at a time. So 69–364
// characterises the capture regime, not the live feed. It is still the regime
// that decides this, because blockcast-shreds scores captures too — and the
// asymmetry settles it either way. Predecessor anchoring costs a looser reach:
// 61,440 slots, bounded, and self-healing once real traffic resumes. Opener
// anchoring costs a frontier that never recovers for the life of the process.
// Under uncertainty about the real step distribution, the loose rule is the
// right trade even where the tight one would probably have worked.
//
// What the chain still buys is the property the counting alone lacks: scattered
// noise perpetually restarts its own run and never reaches a threshold, because
// unrelated datagrams are further apart than maxSlotJump. Verified to hold under
// both anchorings — only the reach differs, not the noise rejection.
func extendRun(count *int, anchor *uint64, slot uint64) int {
	if *count > 0 && slotDistance(slot, *anchor) <= maxSlotJump {
		*count++
	} else {
		*count = 1
	}
	// Deliberately outside the if/else: the anchor is the predecessor, which is
	// what makes a ramping feed able to recover. See the docstring before
	// "simplifying" this into the else branch.
	*anchor = slot
	return *count
}

func slotDistance(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// clearRuns discards both rejection runs. Any observation the tracker accepts
// is evidence the current frontier is real, which is what keeps a lone forged
// datagram -- in either direction -- from accumulating toward a resync.
func (t *Tracker) clearRuns() {
	t.pendingJumps = 0
	t.staleRun = 0
}

// resyncFrontier abandons scoring state and adopts header.Slot as the frontier.
//
// Reached from both directions: a sustained coherent run of advances beyond
// maxSlotJump (the feed moved forward), or a sustained coherent run of traffic
// behind the frontier (the frontier itself is wrong). Retained state describes
// a slot range that no longer exists either way, so it is dropped rather than
// scored -- scoring it would charge sets to an erasure figure they never had a
// chance to complete under.
func (t *Tracker) resyncFrontier(header shred.Header, receivedAt time.Time) bool {
	t.frontierResyncs++
	t.clearRuns()
	t.slots = make(map[uint64]*slotState)
	t.boundaries = make(map[uint64]time.Time)
	t.newestSlot = header.Slot
	t.recordPriorBoundaries(header.Slot, receivedAt)
	t.scoreDue(receivedAt)
	t.reclaimOldSlots()
	state := &slotState{sets: make(map[setKey]uint64), boundary: receivedAt}
	t.slots[header.Slot] = state
	state.sets[setKey{fecSetIndex: header.FECSetIndex}] |= 1 << header.IndexWithinSet
	// A resync accepts this observation, so it must be folded into delivery
	// exactly like the ordinary accept path in Observe. Dropping scoring state
	// must not drop the arrival: delivery and erasure are independent surfaces,
	// and a resync that silently stopped counting shreds would make r_mean and
	// the gap histogram under-report for the window containing it.
	t.delivery.observe(receivedAt)
	return true
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

// Fraction is the erased-set ratio carried in Window.ErasureFraction.
//
// It is exported so that a consumer validating an untrusted Window recomputes
// the ratio with the same implementation that produced it, rather than a second
// spelling that could disagree at the edges. A zero denominator yields 0: a
// window that scored no sets has no erasure, which is distinct from a window
// that scored sets and erased none only in SetsTotal.
//
// The parameters are named for their meaning rather than their arithmetic role
// because both are uint64 and transposing them compiles: Fraction(total,
// erased) is a silent bug that returns a value above 1 for any window with a
// non-total erasure.
func Fraction(erased, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(erased) / float64(total)
}

// reclaimOldSlots drops scoring state that can no longer change.
//
// Slot state is retained until it has been SCORED, not merely until it is two
// slots behind the newest. Slot numbers are not contiguous on a real feed --
// this receiver sees only the shreds for its own feed, so consecutive observed
// slots routinely differ by tens or hundreds -- and reclaiming on slot-number
// distance alone deletes a set in the same Observe call that first gave it a
// boundary, which is always before boundary+grace has elapsed. Every set is
// then destroyed unscored and the erasure SLA reads a permanent zero under
// arbitrary real loss. The same race fires on contiguous slots whenever three
// slots arrive within one grace period.
//
// Retention stays bounded, but the bound is a RATE, not a constant: scoreDue
// runs on every Observe and Advance, so a slot is scored once boundary+grace has
// passed and reclaimed on the next pass. Slots observed within the last grace
// period cannot be scored yet, so retained slot state is
// (observed-slot arrival rate x grace) + 1, the trailing term being the newest
// slot -- which is held indefinitely, and only because a slot cannot be scored
// until a later slot proves it ended.
//
// At steady capture rates that product is small, but it is NOT "only the newest
// slot": a burst or catch-up -- post-hiccup replay, backfill -- raises the
// arrival rate and the retained set grows with it for the duration.
func (t *Tracker) reclaimOldSlots() {
	for slot, state := range t.slots {
		if slot < t.newestSlot && t.newestSlot-slot > 2 && state.scored {
			delete(t.slots, slot)
		}
	}
	for slot := range t.boundaries {
		if slot < t.newestSlot && t.newestSlot-slot > 2 {
			delete(t.boundaries, slot)
		}
	}
}

func (t *Tracker) recordPriorBoundaries(slot uint64, observedAt time.Time) {
	for distance := uint64(1); distance <= 2 && slot >= distance; distance++ {
		prior := slot - distance
		if _, exists := t.boundaries[prior]; !exists {
			t.boundaries[prior] = observedAt
		}
	}
}

func bitsSet(bitmap uint64) int {
	count := 0
	for bitmap != 0 {
		bitmap &= bitmap - 1
		count++
	}
	return count
}
