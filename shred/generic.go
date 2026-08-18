package shred

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
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
	Source            string
	RightsBasis       string
	Windows           int
	WindowsComplete   int
	RecordsExpected   int
	RecordsReceived   int
	RecordsDuplicate  int
	RecordsOutOfOrder int
	InteriorMissing   int
	TrailingMissing   int
	Completeness      float64
	WindowP50         time.Duration
	WindowP95         time.Duration
	WindowP99         time.Duration
	Gaps              GapHistogram
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
type GenericScorer struct {
	source      string
	rightsBasis string
	windows     map[uint64]*genericWindow
	order       []uint64
	lastArrival time.Time
	highestSeq  uint64
	haveSeq     bool
	gaps        GapHistogram
	duplicates  int
	outOfOrder  int
	received    int
}

// NewGenericScorer builds a scorer labelled with the provenance of its input.
// Both labels are mandatory and surface verbatim in the receipt: a receipt whose
// input provenance is unstated is exactly the artifact the rights guardrail
// exists to prevent, so there is no unlabelled constructor.
func NewGenericScorer(source, rightsBasis string) *GenericScorer {
	return &GenericScorer{
		source:      source,
		rightsBasis: rightsBasis,
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
	if !s.lastArrival.IsZero() {
		s.gaps.observe(receivedAt.Sub(s.lastArrival))
	}
	s.lastArrival = receivedAt

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

// Receipt closes every window against its declared length and reports the
// result. Windows are closed by the declared terminal count, not by a timer, so
// the receipt is a deterministic function of the observed records.
func (s *GenericScorer) Receipt() GenericReceipt {
	receipt := GenericReceipt{
		Source:            s.source,
		RightsBasis:       s.rightsBasis,
		Windows:           len(s.order),
		RecordsReceived:   s.received,
		RecordsDuplicate:  s.duplicates,
		RecordsOutOfOrder: s.outOfOrder,
		Gaps:              s.gaps,
	}
	latencies := make([]time.Duration, 0, len(s.order))
	for _, id := range s.order {
		window := s.windows[id]
		receipt.RecordsExpected += int(window.length)
		if window.completed {
			receipt.WindowsComplete++
			latencies = append(latencies, window.last.Sub(window.first))
		}
		// Interior loss is a hole below the highest index actually seen;
		// trailing loss is the run above it. Splitting them is what makes the
		// receipt honest about the tail: without the declared WindowLength the
		// trailing run is invisible, because nothing received attests to it.
		for index := uint16(0); index < window.length; index++ {
			if _, seen := window.seen[index]; seen {
				continue
			}
			if index < window.maxIndex {
				receipt.InteriorMissing++
			} else {
				receipt.TrailingMissing++
			}
		}
	}
	if receipt.RecordsExpected != 0 {
		receipt.Completeness = float64(receipt.RecordsReceived) / float64(receipt.RecordsExpected)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	receipt.WindowP50 = percentile(latencies, 50)
	receipt.WindowP95 = percentile(latencies, 95)
	receipt.WindowP99 = percentile(latencies, 99)
	return receipt
}

func (r GenericReceipt) String() string {
	return fmt.Sprintf(
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
}
