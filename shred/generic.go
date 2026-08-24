package shred

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Generic framing is the payload-agnostic contract the demo rail scores when the
// payload is not shreds. It is deliberately a separate contract from Format:
// wire.go carries a no-auto-detect doctrine for shred formats, and a generic
// record is not a shred in any format, so it must never be reachable from Parse.
//
// Nothing in this file parses shreds or reconstructs FEC. The demo claim it
// supports is exactly "the same delivery receipt, on a payload that isn't
// shreds" — same completeness, arrival-percentile and gap primitives, different
// framing.
//
// Wire layout, 24 bytes big-endian, followed by an opaque body this scorer never
// interprets:
//
//	[0:4)   magic "BCG1"
//	[4:12)  Sequence      uint64 — monotonic across the whole feed
//	[12:20) Window        uint64 — window identifier
//	[20:22) IndexInWindow uint16 — position within the window
//	[22:24) WindowLength  uint16 — records this window will contain
//
// WindowLength is repeated in *every* record rather than being announced by a
// terminal "final" flag on the last one. That is the whole reason trailing loss
// is detectable: a closure flag is itself droppable, so a window whose tail is
// lost would simply look unfinished and could never be distinguished from one
// still in flight. Carrying the expected terminal count on every record means
// any single surviving record of a window establishes what completeness for that
// window requires — which is what "received packets alone cannot prove trailing
// completeness" demands.
//
// Clock basis: every latency here is measured from receivedAt, the arrival
// instant observed by this process. No sender timestamp is read from the wire,
// so these are receive-side observations and carry no clock-sync claim between
// sender and receiver.
const (
	GenericHeaderSize = 24
	genericMagic      = "BCG1"
)

// ErrNotGenericFrame reports a record that does not carry the generic framing
// contract. It is returned rather than swallowed so the caller can count
// unparsed records instead of silently scoring a foreign payload as delivered.
var ErrNotGenericFrame = errors.New("not a generic frame")

// GenericHeader is the parsed framing contract of one generic record.
type GenericHeader struct {
	Sequence      uint64
	Window        uint64
	IndexInWindow uint16
	WindowLength  uint16
}

// ParseGeneric decodes the generic framing contract. It never inspects the body.
func ParseGeneric(record []byte) (GenericHeader, error) {
	if len(record) < GenericHeaderSize {
		return GenericHeader{}, fmt.Errorf("%w: record is %d bytes, need at least %d", ErrNotGenericFrame, len(record), GenericHeaderSize)
	}
	if string(record[0:4]) != genericMagic {
		return GenericHeader{}, fmt.Errorf("%w: bad magic %q", ErrNotGenericFrame, record[0:4])
	}
	header := GenericHeader{
		Sequence:      binary.BigEndian.Uint64(record[4:12]),
		Window:        binary.BigEndian.Uint64(record[12:20]),
		IndexInWindow: binary.BigEndian.Uint16(record[20:22]),
		WindowLength:  binary.BigEndian.Uint16(record[22:24]),
	}
	if header.WindowLength == 0 {
		return GenericHeader{}, fmt.Errorf("%w: window %d declares zero length", ErrNotGenericFrame, header.Window)
	}
	if header.IndexInWindow >= header.WindowLength {
		return GenericHeader{}, fmt.Errorf("%w: window %d index %d outside declared length %d", ErrNotGenericFrame, header.Window, header.IndexInWindow, header.WindowLength)
	}
	return header, nil
}

// AppendGenericHeader encodes the framing contract onto dst.
func AppendGenericHeader(dst []byte, header GenericHeader) []byte {
	var encoded [GenericHeaderSize]byte
	copy(encoded[0:4], genericMagic)
	binary.BigEndian.PutUint64(encoded[4:12], header.Sequence)
	binary.BigEndian.PutUint64(encoded[12:20], header.Window)
	binary.BigEndian.PutUint16(encoded[20:22], header.IndexInWindow)
	binary.BigEndian.PutUint16(encoded[22:24], header.WindowLength)
	return append(dst, encoded[:]...)
}

// GenericReceipt is the payload-agnostic delivery receipt. It reports the same
// three things D1 reports for shreds — arrival percentiles, gap distribution,
// completeness — with FEC erasure deliberately absent, because no erasure coding
// exists in this mode and reporting one would be a fabricated number.
type GenericReceipt struct {
	Source            string  `json:"source"`
	RightsBasis       string  `json:"rights_basis"`
	Windows           int     `json:"windows"`
	WindowsComplete   int     `json:"windows_complete"`
	RecordsExpected   int     `json:"records_expected"`
	RecordsReceived   int     `json:"records_received"`
	RecordsDuplicate  int     `json:"records_duplicate"`
	RecordsOutOfOrder int     `json:"records_out_of_order"`
	InteriorMissing   int     `json:"interior_missing"`
	TrailingMissing   int     `json:"trailing_missing"`
	Completeness      float64 `json:"completeness"`
	// WindowP50, WindowP95 and WindowP99 are window-fill percentiles drawn from a
	// bounded histogram, not from retained per-window latencies: the scorer's
	// retention contract forbids keeping one sample per window forever. They are
	// therefore the upper edge of the bucket the true value fell in — never less
	// than the truth, and over by at most CompletionRelativeError. See
	// completionHistogram for the full argument.
	WindowP50 time.Duration `json:"window_p50_ns"`
	WindowP95 time.Duration `json:"window_p95_ns"`
	WindowP99 time.Duration `json:"window_p99_ns"`
	// WindowFillsAboveCeiling is how many window fills were at or above
	// CompletionCeiling and so recorded as that floor. Any nonzero value means a
	// percentile that fell among them UNDERSTATES by an unbounded amount, which is
	// the one direction the bucketing otherwise promises never to go.
	WindowFillsAboveCeiling uint64 `json:"window_fills_above_ceiling"`
	// WindowFillsTotal is the denominator for WindowFillsAboveCeiling.
	WindowFillsTotal uint64 `json:"window_fills_total"`
	// Gaps is the same GapHistogram the shred receipt carries, and every field of
	// it — Reordered included — is populated on the same terms, so the two modes
	// classify an identical arrival-timestamp sequence identically. That parity is
	// asserted, not assumed: see TestGenericScorerToleratesOutOfOrderArrivalTimestamps
	// and TestGenericScorerGapFrontierDoesNotRegress, which mirror the shred-path
	// tests of the same names.
	//
	// Gaps.Reordered is NOT the same signal as RecordsOutOfOrder above, and the
	// two are not substitutes for one another: Reordered counts arrival-CLOCK
	// regressions (receivedAt behind the frontier), RecordsOutOfOrder counts
	// SEQUENCE regressions (header.Sequence behind the high-water mark). A record
	// can regress on either axis while monotonic on the other, so neither count
	// bounds the other. TestGenericScorerReorderedAndOutOfOrderObserveDifferentAxes
	// pins both directions.
	//
	// Read Reordered as "arrivals that did not advance the frontier", not strictly
	// as "arrivals that were reordered". Two records the clock could not separate
	// produce a gap of exactly zero and are counted here rather than in LT1, so on
	// a coarse-clock host a nonzero Reordered may carry same-tick pairs and imply
	// no reordering at all. The alternative was worse: a zero gap is not evidence
	// of sub-millisecond delivery, and LT1 feeds the published latency tail.
	// TestGenericScorerRepeatedArrivalTimestampIsNotSubMillisecond pins this.
	Gaps GapHistogram `json:"gap_histogram"`
}

type genericWindow struct {
	length    uint16
	seen      map[uint16]struct{}
	maxIndex  uint16
	first     time.Time
	last      time.Time
	completed bool
}

// GenericScorer scores generic framed records. It reuses the same GapHistogram
// and percentile primitives as the shred scorer rather than copying them, so the
// two modes cannot drift into reporting differently-computed numbers.
//
// Like Scorer, it serializes its own state: the demo command runs one reader
// goroutine per feed and prints the receipt while a late Observe may still be in
// flight, so the lock lives here rather than being a caller obligation. Making
// it internal keeps both halves of the session-scorer seam honest about the same
// contract — a caller-held lock on one mode and not the other is the shape that
// produces a race the moment the two are used interchangeably.
//
// # Retention contract
//
// Per-window state is bounded, on the same arrival-clock axis as Scorer. A
// window whose NEWEST arrival has fallen more than window behind the newest
// arrival seen anywhere is folded into the cumulative counters below and its
// state released; a window still receiving records is still live and is never
// evicted, however old its first record is.
//
// The axis is the arrival clock and not window-number distance, for exactly the
// reason DefaultRetention gives for not using slot distance: a window number is
// a property of the record and "how long ago did this arrive" is a property of
// the arrival. Generic window numbers are attacker- and generator-controlled
// (nothing in ParseGeneric constrains them to advance by one, or to advance at
// all), so a window-number window is strictly weaker here than it is for slots —
// a sender emitting sparse or non-monotonic window ids would have live state
// evicted while genuinely stale state was retained.
//
// Bounding the state is what makes the fill percentiles bucketed rather than
// exact: see completionHistogram for why percentiles cannot be both exact and
// bounded in one pass, and WindowFillsAboveCeiling for the one case where a
// reported percentile understates.
type GenericScorer struct {
	mu          sync.Mutex
	source      string
	rightsBasis string
	// window is how far behind the newest arrival per-window state is kept.
	window time.Duration
	// nextSweep is when reclamation next runs. See sweepDue.
	nextSweep   time.Time
	windows     map[uint64]*genericWindow
	order       []uint64
	lastArrival time.Time
	highestSeq  uint64
	haveSeq     bool
	gaps        GapHistogram
	duplicates  int
	outOfOrder  int
	received    int

	// Cumulative counters, folded in by finalize as windows leave the retention
	// window. Every receipt figure derived from live window state has a
	// counterpart here, so evicting a window changes what is retained and not
	// what is reported.
	windowsTotal    int
	windowsComplete int
	recordsExpected int
	interiorMissing int
	trailingMissing int
	fills           completionHistogram
}

// NewGenericScorer builds a scorer labelled with the provenance of its input.
// Both labels are mandatory and surface verbatim in the receipt: a receipt whose
// input provenance is unstated is exactly the artifact the rights guardrail
// exists to prevent, so there is no unlabelled constructor.
func NewGenericScorer(source, rightsBasis string) *GenericScorer {
	return NewGenericScorerWithRetention(source, rightsBasis, DefaultRetention)
}

// NewGenericScorerWithRetention builds a scorer that keeps per-window state for
// window past each record's arrival. See DefaultRetention for what the bound
// costs and GenericScorer's retention contract for what it buys.
func NewGenericScorerWithRetention(source, rightsBasis string, window time.Duration) *GenericScorer {
	return &GenericScorer{
		source:      source,
		rightsBasis: rightsBasis,
		window:      window,
		windows:     make(map[uint64]*genericWindow),
	}
}

// Observe scores one record. It reports whether the record was newly counted, so
// duplicates return false without inflating completeness. It satisfies Observer,
// which is what lets ReplayPCAP drive this mode with no separate replay path.
func (s *GenericScorer) Observe(record []byte, receivedAt time.Time) (bool, error) {
	header, err := ParseGeneric(record)
	if err != nil {
		return false, err
	}

	// Parsing is pure, so it stays outside the lock; everything below mutates
	// scorer state shared with the other feeds' goroutines.
	s.mu.Lock()
	defer s.mu.Unlock()

	accepted, err := s.observeLocked(header, receivedAt)

	// Reclaim on the frontier, after the window bookkeeping rather than before it:
	// a window created earlier in this call has not had its `last` set yet, and a
	// sweep at that point would read the zero time as infinitely stale and evict
	// the window this very record created.
	//
	// The sweep is attempted on every path, including the ones that advanced
	// nothing. A duplicate does advance the frontier — it arrived on the wire, and
	// a feed degraded to nothing but duplicates still needs its older windows
	// released. A framing violation returns before the frontier update, and so
	// does an arrival that regressed behind it; for those the attempt is a no-op
	// against an unmoved clock, which is why it is safe to run unconditionally
	// rather than duplicating the path analysis here.
	if sweepDue(&s.nextSweep, s.lastArrival, s.window) {
		s.evict(s.retentionFloor())
	}
	return accepted, err
}

// observeLocked is Observe's scoring half. The caller holds s.mu and is
// responsible for reclamation.
func (s *GenericScorer) observeLocked(header GenericHeader, receivedAt time.Time) (bool, error) {
	window := s.windows[header.Window]
	if window == nil {
		window = &genericWindow{length: header.WindowLength, seen: make(map[uint16]struct{}), first: receivedAt}
		s.windows[header.Window] = window
		s.order = append(s.order, header.Window)
	}
	// A window's declared length is fixed by its first observed record. A later
	// record disagreeing is a framing violation, not a resize: silently adopting
	// the new value would retroactively change what completeness meant for the
	// records already counted.
	if header.WindowLength != window.length {
		return false, fmt.Errorf("%w: window %d declared length %d then %d", ErrNotGenericFrame, header.Window, window.length, header.WindowLength)
	}

	// Inter-arrival gaps are a delivery observation, not a completeness one, so
	// they are recorded before the duplicate check below: a redelivered record
	// did arrive on the wire, and it both closes the preceding gap and opens the
	// next one. Excluding it would make the following record's gap span two
	// intervals and systematically inflate the upper buckets under multi-path
	// delivery, where duplication is routine rather than exceptional. Only the
	// first record of a run contributes no gap, having nothing to measure from.
	//
	// receivedAt is a true arrival timestamp, captured at the read before any
	// per-packet work, so it is NOT nondecreasing across calls: the concurrent
	// feed goroutines this scorer documents can capture t1 < t2 and reach Observe
	// as t2, t1. Both halves of that hazard are guarded, exactly as Scorer.observe
	// guards them. A negative gap would otherwise fall through the bucket ladder
	// into LT1 and inflate the sub-millisecond count, and an unconditional
	// assignment would drag the frontier backwards so the *next* gap is measured
	// from a stale origin and reads too large. The frontier is also this scorer's
	// retention clock — retentionFloor is lastArrival minus the window — so a
	// regressing assignment would move the eviction floor backwards too.
	//
	// The test is `gap > 0`, so a gap of exactly ZERO is charged to Reordered
	// alongside the negative ones, and does not advance the frontier. That case
	// is not exotic: it needs no concurrency at all, only a clock too coarse to
	// separate two arrivals, so it is the one a single-goroutine feed will
	// actually hit. Reordered therefore means "this arrival did not advance the
	// frontier", which is a superset of "this arrival was reordered" — a
	// same-tick pair is counted there despite nothing having been reordered.
	// That is deliberate, and it is the lesser of the two available errors:
	// a zero gap is not evidence of sub-millisecond delivery, so counting it in
	// LT1 would overstate the tail of the latency distribution we publish, while
	// counting it in Reordered at worst overstates a diagnostic. Both modes make
	// the same choice — this is a mirror of score.go, not a divergence from it.
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

	if _, duplicate := window.seen[header.IndexInWindow]; duplicate {
		s.duplicates++
		return false, nil
	}

	// Out-of-order is counted but never penalised: arriving late is a delivery
	// observation, not a loss, and the window set makes ordering irrelevant to
	// completeness.
	if s.haveSeq && header.Sequence < s.highestSeq {
		s.outOfOrder++
	}
	if !s.haveSeq || header.Sequence > s.highestSeq {
		s.highestSeq = header.Sequence
		s.haveSeq = true
	}

	window.seen[header.IndexInWindow] = struct{}{}
	if header.IndexInWindow > window.maxIndex {
		window.maxIndex = header.IndexInWindow
	}
	if receivedAt.After(window.last) {
		window.last = receivedAt
	}
	if receivedAt.Before(window.first) {
		window.first = receivedAt
	}
	if !window.completed && len(window.seen) == int(window.length) {
		window.completed = true
	}
	s.received++
	return true, nil
}

// retentionFloor is the oldest arrival still inside the window. A window whose
// newest record arrived before it holds nothing a later record could revise.
func (s *GenericScorer) retentionFloor() time.Time {
	return s.lastArrival.Add(-s.window)
}

// evict folds every window whose newest arrival has fallen below floor into the
// cumulative counters and releases its state. A window's NEWEST arrival is used,
// not its oldest: a window still collecting records is still live, however long
// ago it opened.
//
// One consequence worth stating plainly, because it is the price of bounding and
// not a defect to be fixed later: a straggler that arrives more than the window
// after its window last saw traffic re-creates that window, so the same window id
// is counted twice in Windows and RecordsExpected. Scorer has the identical
// property for FEC sets (see the bitmap guard in Scorer.observe). Both are
// bounded by the same fact — the second lifetime is scored on its own arrivals —
// and neither can be closed without retaining evicted identities forever, which
// is the growth this eviction exists to stop.
func (s *GenericScorer) evict(floor time.Time) {
	kept := s.order[:0]
	for _, id := range s.order {
		window := s.windows[id]
		if window == nil || !window.last.Before(floor) {
			kept = append(kept, id)
			continue
		}
		s.finalize(window)
		delete(s.windows, id)
	}
	s.order = kept
}

// finalize folds one window into the cumulative counters. Every receipt figure
// derived from live window state is folded here, so a window leaving the
// retention window changes what the scorer retains and not what it reports.
func (s *GenericScorer) finalize(window *genericWindow) {
	s.windowsTotal++
	s.recordsExpected += int(window.length)
	if window.completed {
		s.windowsComplete++
		s.fills.observe(window.last.Sub(window.first))
	}
	interior, trailing := window.missing()
	s.interiorMissing += interior
	s.trailingMissing += trailing
}

// missing splits a window's absent indices. Interior loss is a hole below the
// highest index actually seen; trailing loss is the run above it. Splitting them
// is what makes the receipt honest about the tail: without the declared
// WindowLength the trailing run is invisible, because nothing received attests to
// it.
//
// It is one function called from both finalize and Receipt so an evicted window
// and a live one cannot be counted by two subtly different loops.
func (w *genericWindow) missing() (interior, trailing int) {
	for index := uint16(0); index < w.length; index++ {
		if _, seen := w.seen[index]; seen {
			continue
		}
		if index < w.maxIndex {
			interior++
		} else {
			trailing++
		}
	}
	return interior, trailing
}

// GenericRetention describes the per-window state a generic scorer is currently
// holding. It exists so the retention bound can be asserted directly rather than
// inferred from process memory, mirroring Retention and erasure.Tracker.Stats.
//
// It is a separate type from Retention rather than a reuse of it because the
// fields Retention carries — TrackedShreds, TrackedSets, TrackedAttributions —
// name shred concepts that have no counterpart here. Widening Retention with
// generic fields would leave every shred caller reading zeros for things that do
// not apply to it, which is the confusion the Gaps.Reordered note on
// GenericReceipt already has to apologise for.
type GenericRetention struct {
	// Newest is the arrival the window is measured back from.
	Newest time.Time
	// Window is how far behind Newest state is kept.
	Window time.Duration
	// TrackedWindows is the number of live per-window entries held.
	TrackedWindows int
	// TrackedRecords is the total number of per-record index entries held across
	// those windows. It is the figure that actually grows with window length, so
	// a bound on TrackedWindows alone would not prove the state is bounded.
	TrackedRecords int
}

// Retention reports the per-window state this scorer is currently holding.
func (s *GenericScorer) Retention() GenericRetention {
	s.mu.Lock()
	defer s.mu.Unlock()

	held := GenericRetention{
		Newest:         s.lastArrival,
		Window:         s.window,
		TrackedWindows: len(s.windows),
	}
	for _, window := range s.windows {
		held.TrackedRecords += len(window.seen)
	}
	return held
}

// Receipt closes every window against its declared length and reports the
// result. Windows are closed by the declared terminal count, not by a timer, so
// the receipt is a deterministic function of the observed records.
func (s *GenericScorer) Receipt() GenericReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()

	receipt := GenericReceipt{
		Source:            s.source,
		RightsBasis:       s.rightsBasis,
		Windows:           s.windowsTotal + len(s.order),
		WindowsComplete:   s.windowsComplete,
		RecordsExpected:   s.recordsExpected,
		RecordsReceived:   s.received,
		RecordsDuplicate:  s.duplicates,
		RecordsOutOfOrder: s.outOfOrder,
		InteriorMissing:   s.interiorMissing,
		TrailingMissing:   s.trailingMissing,
		Gaps:              s.gaps,
	}
	// The histogram is a fixed-size array, so this is a copy, not an alias: the
	// live windows below are scored into the receipt without being committed to
	// the scorer, which would double-count them once they are finalized for real.
	// Same reason, same shape, as Scorer.receiptFor.
	fills := s.fills
	for _, id := range s.order {
		window := s.windows[id]
		receipt.RecordsExpected += int(window.length)
		if window.completed {
			receipt.WindowsComplete++
			fills.observe(window.last.Sub(window.first))
		}
		interior, trailing := window.missing()
		receipt.InteriorMissing += interior
		receipt.TrailingMissing += trailing
	}
	if receipt.RecordsExpected != 0 {
		receipt.Completeness = float64(receipt.RecordsReceived) / float64(receipt.RecordsExpected)
	}
	receipt.WindowP50 = fills.percentile(50)
	receipt.WindowP95 = fills.percentile(95)
	receipt.WindowP99 = fills.percentile(99)
	receipt.WindowFillsAboveCeiling = fills.overflowed()
	receipt.WindowFillsTotal = fills.count
	return receipt
}

func (r GenericReceipt) String() string {
	rendered := fmt.Sprintf(
		"generic source=%s rights=%s\n"+
			"window_fill p50=%s p95=%s p99=%s\n"+
			"completeness windows=%d complete=%d expected=%d received=%d fraction=%.6f\n"+
			"loss interior=%d trailing=%d duplicates=%d out_of_order=%d\n"+
			"gap_ms <1=%d 1-2.4=%d 2.4-7=%d 7-32=%d >=32=%d",
		r.Source, r.RightsBasis,
		r.WindowP50, r.WindowP95, r.WindowP99,
		r.Windows, r.WindowsComplete, r.RecordsExpected, r.RecordsReceived, r.Completeness,
		r.InteriorMissing, r.TrailingMissing, r.RecordsDuplicate, r.RecordsOutOfOrder,
		r.Gaps.LT1, r.Gaps.From1To2_4, r.Gaps.From2_4To7, r.Gaps.From7To32, r.Gaps.GTE32)
	// Printed rather than left to the JSON field for the same reason the shred
	// receipt prints its own: the human table is what an operator reads in a
	// dispute, and a percentile whose stated error bar may not apply is worse
	// than no percentile at all. Absent unless it fires, so a clean run's
	// receipt is unchanged.
	if caveat := bucketedPercentileCaveat("window_fill", "fill", r.WindowFillsAboveCeiling, r.WindowFillsTotal); caveat != "" {
		rendered += "\n" + caveat
	}
	return rendered
}
