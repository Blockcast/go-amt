package shred

import (
	"time"
)

// The synthetic fixture is the default D5 input. The rights guardrail on this
// work says public readability is not evidence of redistribution or
// commercial-demo rights, and no third-party capture may enter the repository
// without a recorded review of its governing terms. No such review exists for
// any candidate feed, so this mode ships synthetic input — which is also the
// better engineering choice, because it lets the framing contract *define* the
// monotonic sequence, window closure and clock basis rather than reverse
// engineering them from someone else's feed.
const (
	GenericSyntheticSource      = "synthetic"
	GenericSyntheticRightsBasis = "synthetic-generated-no-third-party-content"
)

// GenericFixtureSpec describes a deterministic synthetic feed. Every field is an
// exact instruction rather than a probability: the receipt is a regression
// artifact, so the same spec must produce byte-identical output on every run and
// on every machine.
type GenericFixtureSpec struct {
	Windows      int
	WindowLength uint16
	// Interval is the arrival spacing between consecutive records.
	Interval time.Duration
	// DropInterior removes indices strictly below the window's last index, so
	// the loss is provably interior rather than a short tail.
	DropInterior map[uint64][]uint16
	// DropTrailing removes the final n indices of a window. Detecting these is
	// the point of carrying WindowLength on every record.
	DropTrailing map[uint64]uint16
	// Duplicate re-sends the listed indices immediately after their first copy.
	Duplicate map[uint64][]uint16
	// SwapAdjacent delivers index i+1 before index i within the window.
	SwapAdjacent map[uint64][]uint16
}

// GenericRecord is one synthetic record and the arrival instant to score it at.
type GenericRecord struct {
	Payload    []byte
	ReceivedAt time.Time
}

// DefaultGenericFixtureSpec exercises every delivery anomaly the receipt claims
// to distinguish — interior loss, trailing loss, duplication and reordering —
// alongside windows that are simply clean, so the demo receipt shows both.
func DefaultGenericFixtureSpec() GenericFixtureSpec {
	return GenericFixtureSpec{
		Windows:      6,
		WindowLength: 32,
		Interval:     900 * time.Microsecond,
		DropInterior: map[uint64][]uint16{1: {7, 8, 19}},
		DropTrailing: map[uint64]uint16{2: 3},
		Duplicate:    map[uint64][]uint16{3: {0, 15}},
		SwapAdjacent: map[uint64][]uint16{4: {5, 20}},
	}
}

// BuildGenericFixture renders a spec into an ordered record stream. The clock
// starts at a fixed instant so arrival percentiles and gap buckets are
// reproducible; nothing here reads the wall clock.
func (spec GenericFixtureSpec) Build() []GenericRecord {
	start := time.Unix(1_750_000_000, 0).UTC()
	records := make([]GenericRecord, 0, spec.Windows*int(spec.WindowLength))
	var sequence uint64
	clock := start

	emit := func(window uint64, index uint16) {
		payload := AppendGenericHeader(nil, GenericHeader{
			Sequence:      sequence,
			Window:        window,
			IndexInWindow: index,
			WindowLength:  spec.WindowLength,
		})
		// The body is opaque to the scorer; it exists so a record is a
		// realistic datagram rather than a bare header.
		payload = append(payload, byte(window), byte(index>>8), byte(index))
		records = append(records, GenericRecord{Payload: payload, ReceivedAt: clock})
		clock = clock.Add(spec.Interval)
	}

	for w := 0; w < spec.Windows; w++ {
		window := uint64(w)
		dropped := make(map[uint16]struct{})
		for _, index := range spec.DropInterior[window] {
			dropped[index] = struct{}{}
		}
		if tail := spec.DropTrailing[window]; tail > 0 && tail <= spec.WindowLength {
			for index := spec.WindowLength - tail; index < spec.WindowLength; index++ {
				dropped[index] = struct{}{}
			}
		}
		duplicated := make(map[uint16]struct{})
		for _, index := range spec.Duplicate[window] {
			duplicated[index] = struct{}{}
		}
		swapped := make(map[uint16]struct{})
		for _, index := range spec.SwapAdjacent[window] {
			swapped[index] = struct{}{}
		}

		for index := uint16(0); index < spec.WindowLength; index++ {
			// A swap emits the pair in reversed order, so skip the first of the
			// pair here and let the second emit both.
			if _, ok := swapped[index]; ok && index+1 < spec.WindowLength {
				continue
			}
			if prior := index - 1; index > 0 {
				if _, ok := swapped[prior]; ok {
					if _, gone := dropped[index]; !gone {
						sequence++
						emit(window, index)
					}
					if _, gone := dropped[prior]; !gone {
						// The reordered record keeps its original, lower
						// sequence number — that is what makes it detectable as
						// out-of-order rather than as a fresh record.
						saved := sequence
						sequence--
						emit(window, prior)
						sequence = saved
					}
					continue
				}
			}
			if _, gone := dropped[index]; gone {
				sequence++
				continue
			}
			sequence++
			emit(window, index)
			if _, dup := duplicated[index]; dup {
				emit(window, index)
			}
		}
	}
	return records
}

// ReplayGenericFixture scores the default synthetic feed. It is the fixture
// equivalent of ReplayFixture for shred mode.
func ReplayGenericFixture(scorer *GenericScorer) error {
	for _, record := range DefaultGenericFixtureSpec().Build() {
		if _, err := scorer.Observe(record.Payload, record.ReceivedAt); err != nil {
			return err
		}
	}
	return nil
}
