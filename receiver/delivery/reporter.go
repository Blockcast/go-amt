package delivery

import (
	"errors"
	"fmt"
	"sort"
)

// LedgerSample is one destination's delivery counters as read from the fan-out
// ledger. The counters are CUMULATIVE over the life of the fan-out, which is
// the opposite shape from what Tracker.Observe wants, and reconciling the two
// is this file's whole reason for existing.
type LedgerSample struct {
	Destination string
	Bytes       uint64
	Packets     uint64
}

// Sink ships a delivery-session record to whatever accepts billing records.
//
// A Sink must return a non-nil error if it has NOT durably accepted the record.
// Reporter relies on that to honour Emit's retry contract: a record the sink
// rejected is retransmitted verbatim later, because no future record restates
// its bytes.
type Sink interface {
	Ship(Record) error
}

// Reporter drives a Tracker from the fan-out's per-destination ledger.
//
// It exists because the two sides disagree in a way that silently double-bills
// if a caller wires them together naively:
//
//   - Fanout.DestinationStats reports CUMULATIVE process-lifetime totals.
//   - Tracker.Observe takes an INCREMENT and adds it to a running total.
//
// So Observe(sample.Bytes) on a timer re-adds every previously delivered byte
// on every tick, and the error compounds: by tick N a destination is billed
// roughly N times its real traffic. Reporter diffs consecutive samples so
// Observe only ever sees the interval's delta.
//
// Reporter also owns the retry side of Emit's contract. Emit advances the delta
// watermark when it returns, so the record it returns is the only copy of that
// interval — calling Emit again after a failed shipment under-bills by exactly
// the lost interval. Reporter therefore retains a record the sink refused and
// retransmits that same record, and does not emit a new one for that
// destination until the sink accepts it. That bounds the retained set to at
// most one record per destination while never regenerating a record.
//
// Reporter is not safe for concurrent use; drive it from one goroutine (in
// blockcast-shreds, the reporter tick).
type Reporter struct {
	tracker *Tracker
	sink    Sink
	// last is the ledger watermark: the counters already folded into the
	// tracker. Deltas are measured against this, not against zero.
	last map[string]LedgerSample
	// pending holds the record a destination's sink call refused, awaiting
	// verbatim retransmission. At most one entry per destination.
	pending map[string]Record
}

// NewReporter returns a Reporter feeding tracker from ledger samples and
// shipping the resulting records to sink.
func NewReporter(tracker *Tracker, sink Sink) (*Reporter, error) {
	if tracker == nil {
		return nil, errors.New("delivery: tracker is nil")
	}
	if sink == nil {
		return nil, errors.New("delivery: sink is nil")
	}
	return &Reporter{
		tracker: tracker,
		sink:    sink,
		last:    make(map[string]LedgerSample),
		pending: make(map[string]Record),
	}, nil
}

// Tick folds one ledger sample per destination into the tracker and emits a
// periodic record for each.
//
// A destination seen for the first time has a session opened for it, so
// sessions follow the fan-out's destination set rather than needing to be
// declared twice.
//
// Every destination is processed even if an earlier one failed; the errors are
// joined. A single unreachable sink or a single bad destination must not stop
// the other destinations from accounting for their traffic.
func (r *Reporter) Tick(samples []LedgerSample) error {
	var errs []error
	for _, sample := range samples {
		// Anything owed from a previous attempt ships BEFORE any new
		// accounting. Ordering matters: a retained FINAL record has no session
		// behind it any more, so observing first would fail with ErrNoSession
		// and strand that record forever -- and it is the interval least
		// affordable to lose, being the one nothing will ever restate.
		if err := r.drainPending(sample.Destination); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := r.observe(sample); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := r.emitOne(sample.Destination); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CloseAll emits a final record for every open session, folding in one last
// ledger sample first so the closing record carries the tail delta rather than
// discarding it.
//
// Destinations are closed in a deterministic order so a caller comparing
// records across runs sees a stable sequence.
func (r *Reporter) CloseAll(samples []LedgerSample, reason CloseReason) error {
	byDestination := make(map[string]LedgerSample, len(samples))
	for _, sample := range samples {
		byDestination[sample.Destination] = sample
	}

	// The union of three sets, because each can hold a destination the others
	// do not: the caller's current sample set, the destinations we hold a
	// watermark for (an open session whose destination has dropped out of the
	// ledger), and the destinations that still owe a record (a closed session
	// whose final record the sink refused). Missing any of them silently skips
	// either a close or a retry.
	names := make(map[string]struct{}, len(byDestination)+len(r.last)+len(r.pending))
	for destination := range byDestination {
		names[destination] = struct{}{}
	}
	for destination := range r.last {
		names[destination] = struct{}{}
	}
	for destination := range r.pending {
		names[destination] = struct{}{}
	}

	destinations := make([]string, 0, len(names))
	for destination := range names {
		destinations = append(destinations, destination)
	}
	// Deterministic order so a caller comparing records across runs sees a
	// stable sequence.
	sort.Strings(destinations)

	var errs []error
	for _, destination := range destinations {
		sample, ok := byDestination[destination]
		if !ok {
			// No final reading for a destination we were tracking. Close on the
			// watermark rather than skipping the close, so the session still
			// gets its terminating record — and on the watermark specifically,
			// so the closing delta is zero instead of re-billing the ledger.
			previous := r.last[destination]
			sample = LedgerSample{
				Destination: destination,
				Bytes:       previous.Bytes,
				Packets:     previous.Packets,
			}
		}
		if err := r.CloseDestination(sample, reason); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CloseDestination folds a final ledger sample for one destination and emits
// its final record carrying reason.
//
// This is the API a teardown signal drives. Note that blockcast-shreds has no
// per-destination teardown event today: Fanout destinations are configured at
// start and never leave the set, so the only close the sender can currently
// attest to is CloseShutdown. A stale-traffic close is deliberately NOT
// synthesised here — inventing a close from "no bytes moved" would fabricate a
// billing gap the sender cannot actually attest to, which is the same class of
// error as the forgeable AMT Teardown that Tracker.Teardown refuses to treat
// as a close.
func (r *Reporter) CloseDestination(sample LedgerSample, reason CloseReason) error {
	if !reason.Valid() {
		return fmt.Errorf("delivery: invalid close reason %q", string(reason))
	}
	if sample.Destination == "" {
		return errors.New("delivery: ledger sample has no destination")
	}

	// Ship what is owed before anything else, for the same reason as in Tick:
	// once Tracker.Close has removed a session, a retained final record can no
	// longer be regenerated, and observing first would fail with ErrNoSession
	// and strand it.
	if err := r.drainPending(sample.Destination); err != nil {
		return err
	}

	if _, open := r.tracker.SessionID(sample.Destination); !open {
		// No open session. Two very different situations, told apart by whether
		// a watermark exists, and conflating them loses records either way:
		//
		//   watermark present -> the session was already closed by an earlier
		//     attempt whose final record has now shipped. Nothing left to do.
		//     Closing again would either fail or, if observe re-opened a
		//     session first, emit a spurious second final record for a
		//     zero-length session.
		//
		//   watermark absent -> a session was NEVER opened for this
		//     destination, because no periodic tick has run yet. This is the
		//     run-shorter-than-one-report-interval case, and it is the one that
		//     must fall through: the close is where that run's entire traffic
		//     gets billed, so returning early here would discard all of it.
		if _, tracked := r.last[sample.Destination]; tracked {
			// The watermark itself is deliberately NOT dropped. It belongs to
			// the ledger, not the session: the ledger is cumulative over the
			// whole process and does not reset when a session ends, so
			// forgetting it would make a reopened destination re-bill every
			// byte since process start.
			return nil
		}
	}

	if err := r.observe(sample); err != nil {
		return err
	}

	record, err := r.tracker.Close(sample.Destination, reason)
	if err != nil {
		return fmt.Errorf("delivery: close session for %s: %w", sample.Destination, err)
	}
	// The session is gone from the tracker now, so a refused final record can
	// never be regenerated. Retain it for retransmission -- the drain at the
	// top of this method and of Tick is what eventually ships it -- and keep
	// the ledger watermark, so the retry cannot be mistaken for fresh traffic.
	if err := r.sink.Ship(record); err != nil {
		r.pending[sample.Destination] = record
		return fmt.Errorf("delivery: ship final record for %s: %w", sample.Destination, err)
	}
	// The watermark stays, for the reason given above: it tracks the ledger,
	// which outlives the session.
	return nil
}

// Pending reports how many emitted records are still awaiting a sink that will
// accept them. A non-zero value means bytes have been accounted for but not
// yet billed, so it belongs on a dashboard.
func (r *Reporter) Pending() int { return len(r.pending) }

// observe opens a session for a destination that has none, then folds the
// sample's delta into the tracker and advances the ledger watermark.
func (r *Reporter) observe(sample LedgerSample) error {
	if sample.Destination == "" {
		return errors.New("delivery: ledger sample has no destination")
	}

	// Two independent pieces of state, deliberately not conflated:
	//
	//   - whether a SESSION is open, which decides if one must be minted
	//   - whether a WATERMARK exists, which decides the delta baseline
	//
	// They diverge after a close: the session is gone but the watermark must
	// survive, because the ledger it measures against is cumulative over the
	// whole process and does not reset when a session ends. Keying the Open on
	// the watermark instead would re-bill every byte since process start into
	// the first record of the reopened session.
	previous := r.last[sample.Destination]
	if _, open := r.tracker.SessionID(sample.Destination); !open {
		if _, err := r.tracker.Open(sample.Destination); err != nil {
			return fmt.Errorf("delivery: open session for %s: %w", sample.Destination, err)
		}
	}

	bytesDelta := sample.Bytes - previous.Bytes
	packetsDelta := sample.Packets - previous.Packets
	// A cumulative counter that went backwards means the ledger it came from
	// was rebuilt (a new Fanout, or a process restart handing us a fresh
	// ledger) while this Reporter kept its watermark. The current value is then
	// the whole of the new ledger's traffic, so take it as the delta rather
	// than underflowing uint64 into a ~1.8e19 byte over-bill.
	if sample.Bytes < previous.Bytes {
		bytesDelta = sample.Bytes
	}
	if sample.Packets < previous.Packets {
		packetsDelta = sample.Packets
	}

	if err := r.tracker.Observe(sample.Destination, bytesDelta, packetsDelta); err != nil {
		return fmt.Errorf("delivery: observe %s: %w", sample.Destination, err)
	}
	// Advance the watermark only after Observe succeeded, so a failed Observe
	// leaves the delta to be retried on the next sample instead of dropping it.
	r.last[sample.Destination] = sample
	return nil
}

// emitOne emits and ships a new periodic record, provided nothing is owed for
// the destination.
func (r *Reporter) emitOne(destination string) error {
	if record, owed := r.pending[destination]; owed {
		// Do not emit while a record is owed: a new Emit would advance the
		// watermark past traffic whose record has not shipped, and the retained
		// record's bytes would never be restated. The delta stays in the
		// tracker and rolls into the next record instead. Callers drain before
		// reaching here, so this is the case where that drain just failed.
		return fmt.Errorf("delivery: record seq %d for %s still owed; not emitting", record.Seq, destination)
	}

	record, err := r.tracker.Emit(destination)
	if err != nil {
		return fmt.Errorf("delivery: emit for %s: %w", destination, err)
	}
	if err := r.sink.Ship(record); err != nil {
		r.pending[destination] = record
		return fmt.Errorf("delivery: ship record for %s: %w", destination, err)
	}
	return nil
}

// drainPending retransmits a retained record verbatim. It returns nil when
// nothing is owed for the destination.
func (r *Reporter) drainPending(destination string) error {
	record, owed := r.pending[destination]
	if !owed {
		return nil
	}
	if err := r.sink.Ship(record); err != nil {
		return fmt.Errorf("delivery: retransmit record seq %d for %s: %w", record.Seq, destination, err)
	}
	delete(r.pending, destination)
	return nil
}
