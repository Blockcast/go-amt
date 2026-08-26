package delivery

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// LedgerSample is one target's delivery counters as read from the fan-out
// ledger. The counters are CUMULATIVE over the life of the fan-out, which is
// the opposite shape from what Tracker.Observe wants, and reconciling the two
// is this file's whole reason for existing.
//
// TargetID is the identity; Destination is where the bytes went. Keeping them
// apart is load-bearing, because the fan-out permits both of the states that
// collapse if the address is treated as the key (see Target in fanout.go):
//
//   - One target, two addresses over time. A re-grant moves a subscriber to a
//     new endpoint mid-session. Keyed by address that is a brand-new session,
//     so the subscriber is split in two and the first session is never closed.
//   - Two targets, one address. ReconcileDestinations dedupes on target ID
//     alone, so distinct grants sharing an address are valid by construction.
//     Keyed by address they merge into one session and one watermark, silently
//     billing two subscribers as one.
//
// Both are mis-bills that every counter reports as healthy, which is why the
// address is metadata here and never a map key.
type LedgerSample struct {
	// TargetID is the stable billing identity — a broker grant or subscriber
	// ID, from DestinationStat.TargetID. It is required.
	TargetID   string
	Generation uint64
	// Destination is the resolved UDP address, carried through onto the record
	// as endpoint metadata. It is not an identity and must not be used as one.
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
//
// Every map in here is keyed by TARGET ID, never by address — see LedgerSample
// for the two mis-bills that keying by address produces.
type Reporter struct {
	tracker *Tracker
	sink    Sink
	// last is the ledger watermark: the counters already folded into the
	// tracker. Deltas are measured against this, not against zero.
	last map[string]LedgerSample
	// pending holds the record a target's sink call refused, awaiting verbatim
	// retransmission. At most one entry per target.
	pending map[string]Record
}

// sampleKey is deliberately a Reporter-private key space, distinct from
// Tracker's sessionKey. It always includes a generation so CloseAll can decode
// its union-of-state keys back into a LedgerSample; no caller may exchange the
// two encodings.
func sampleKey(targetID string, generation uint64) string {
	return fmt.Sprintf("%s\x00%d", targetID, generation)
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

// Tick folds one ledger sample per target into the tracker and emits a
// periodic record for each.
//
// A target seen for the first time has a session opened for it, so sessions
// follow the fan-out's target set rather than needing to be declared twice.
//
// Every target is processed even if an earlier one failed; the errors are
// joined. A single unreachable sink or a single bad sample must not stop the
// other targets from accounting for their traffic.
func (r *Reporter) Tick(samples []LedgerSample) error {
	var errs []error
	for _, sample := range samples {
		// Anything owed from a previous attempt ships BEFORE any new
		// accounting. Ordering matters: a retained FINAL record has no session
		// behind it any more, so observing first would fail with ErrNoSession
		// and strand that record forever -- and it is the interval least
		// affordable to lose, being the one nothing will ever restate.
		if err := r.drainPending(sample.TargetID, sample.Generation); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := r.observe(sample); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := r.emitOne(sample); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CloseAll emits a final record for every open session, folding in one last
// ledger sample first so the closing record carries the tail delta rather than
// discarding it.
//
// Targets are closed in a deterministic order so a caller comparing records
// across runs sees a stable sequence.
func (r *Reporter) CloseAll(samples []LedgerSample, reason CloseReason) error {
	byTarget := make(map[string]LedgerSample, len(samples))
	for _, sample := range samples {
		byTarget[sampleKey(sample.TargetID, sample.Generation)] = sample
	}

	// The union of three sets, because each can hold a target the others do
	// not: the caller's current sample set, the targets we hold a watermark for
	// (an open session whose target has dropped out of the ledger), and the
	// targets that still owe a record (a closed session whose final record the
	// sink refused). Missing any of them silently skips either a close or a
	// retry.
	names := make(map[string]struct{}, len(byTarget)+len(r.last)+len(r.pending))
	for targetID := range byTarget {
		names[targetID] = struct{}{}
	}
	for key := range r.last {
		names[key] = struct{}{}
	}
	for key := range r.pending {
		names[key] = struct{}{}
	}

	targetIDs := make([]string, 0, len(names))
	for targetID := range names {
		targetIDs = append(targetIDs, targetID)
	}
	// Deterministic order so a caller comparing records across runs sees a
	// stable sequence.
	sort.Strings(targetIDs)

	var errs []error
	for _, key := range targetIDs {
		sample, ok := byTarget[key]
		if !ok {
			// No final reading for a target we were tracking. Close on the
			// watermark rather than skipping the close, so the session still
			// gets its terminating record — and on the watermark specifically,
			// so the closing delta is zero instead of re-billing the ledger.
			// The watermark's address rides along as the record's endpoint
			// metadata: it is the last place this target's bytes actually went.
			previous := r.last[key]
			targetID, generation := sampleKeyParts(key)
			sample = LedgerSample{
				TargetID:    targetID,
				Generation:  generation,
				Destination: previous.Destination,
				Bytes:       previous.Bytes,
				Packets:     previous.Packets,
			}
		}
		if err := r.closeDestination(sample, reason); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func sampleKeyParts(key string) (string, uint64) {
	i := strings.LastIndexByte(key, 0)
	if i < 0 {
		return key, 0
	}
	generation, err := strconv.ParseUint(key[i+1:], 10, 64)
	if err != nil {
		return key[:i], 0
	}
	return key[:i], generation
}

// CloseRemoved closes the sessions of targets that a reconcile removed from the
// served set, as CloseTicketExpired.
//
// The samples must carry the departing targets' FINAL counters, which is why
// Fanout.ReconcileDestinations returns them: they are unreadable once the table
// has been swapped. Passing the counters through is what puts the tail delta —
// the traffic between a target's last periodic record and its removal — on the
// closing record instead of dropping it.
//
// The reason is pinned rather than a parameter. A target leaving a
// broker-derived grant table means the grant backing it lapsed, which is
// exactly CloseTicketExpired; the alternative is a caller reaching for
// CloseShutdown, which is the bug this exists to prevent — it reports a revoked
// grant as a deliberate sender shutdown, and defers the record to process exit.
// A caller closing for some other cause should say so via CloseDestination.
//
// Every target is closed even if an earlier one failed, for the same reason as
// in Tick: one unreachable sink must not strand the other targets' final
// records, which are the intervals nothing will ever restate.
func (r *Reporter) CloseRemoved(samples []LedgerSample) error {
	var errs []error
	for _, sample := range samples {
		if err := r.closeDestination(sample, CloseTicketExpired); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// CloseDestination folds a final ledger sample for one target and emits its
// final record carrying reason.
//
// This is the API a teardown signal drives. Fanout.ReconcileDestinations is the
// producer of that signal — it reports departing targets with their final
// counters, and CloseRemoved is the path from there to here. A stale-traffic
// close is deliberately NOT synthesised here: inventing a close from "no bytes
// moved" would fabricate a billing gap the sender cannot actually attest to,
// which is the same class of error as the forgeable AMT Teardown that
// Tracker.Teardown refuses to treat as a close.
func (r *Reporter) CloseDestination(sample LedgerSample, reason CloseReason) error {
	return r.closeDestination(sample, reason)
}

func (r *Reporter) closeDestination(sample LedgerSample, reason CloseReason) error {
	if !reason.Valid() {
		return fmt.Errorf("delivery: invalid close reason %q", string(reason))
	}
	if sample.TargetID == "" {
		return errors.New("delivery: ledger sample has no target ID")
	}

	// Ship what is owed before anything else, for the same reason as in Tick:
	// once Tracker.Close has removed a session, a retained final record can no
	// longer be regenerated, and observing first would fail with ErrNoSession
	// and strand it.
	if err := r.drainPending(sample.TargetID, sample.Generation); err != nil {
		return err
	}

	if _, open := r.tracker.SessionIDForGeneration(sample.TargetID, sample.Generation); !open {
		// No open session. Two very different situations, told apart by whether
		// a watermark exists, and conflating them loses records either way:
		//
		//   watermark present -> the session was already closed by an earlier
		//     attempt whose final record has now shipped. Nothing left to do.
		//     Closing again would either fail or, if observe re-opened a
		//     session first, emit a spurious second final record for a
		//     zero-length session.
		//
		//   watermark absent -> a session was NEVER opened for this target,
		//     because no periodic tick has run yet. This is the
		//     run-shorter-than-one-report-interval case, and it is the one that
		//     must fall through: the close is where that run's entire traffic
		//     gets billed, so returning early here would discard all of it.
		if _, tracked := r.last[sampleKey(sample.TargetID, sample.Generation)]; tracked {
			// The watermark itself is deliberately NOT dropped. It belongs to
			// the ledger, not the session: the ledger is cumulative over the
			// whole process and does not reset when a session ends, so
			// forgetting it would make a reopened target re-bill every byte
			// since process start.
			return nil
		}
	}

	if err := r.observe(sample); err != nil {
		return err
	}

	record, err := r.tracker.CloseForGeneration(sample.TargetID, sample.Generation, reason)
	if err != nil {
		return fmt.Errorf("delivery: close session for %s: %w", sample.TargetID, err)
	}
	record.Destination = sample.Destination
	// The session is gone from the tracker now, so a refused final record can
	// never be regenerated. Retain it for retransmission -- the drain at the
	// top of this method and of Tick is what eventually ships it -- and keep
	// the ledger watermark, so the retry cannot be mistaken for fresh traffic.
	if err := r.sink.Ship(record); err != nil {
		r.pending[sampleKey(sample.TargetID, sample.Generation)] = record
		return fmt.Errorf("delivery: ship final record for %s: %w", sample.TargetID, err)
	}
	// The watermark stays, for the reason given above: it tracks the ledger,
	// which outlives the session.
	return nil
}

// Pending reports how many emitted records are still awaiting a sink that will
// accept them. A non-zero value means bytes have been accounted for but not
// yet billed, so it belongs on a dashboard.
func (r *Reporter) Pending() int { return len(r.pending) }

// observe opens a session for a target that has none, then folds the sample's
// delta into the tracker and advances the ledger watermark.
func (r *Reporter) observe(sample LedgerSample) error {
	if sample.TargetID == "" {
		return errors.New("delivery: ledger sample has no target ID")
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
	key := sampleKey(sample.TargetID, sample.Generation)
	previous := r.last[key]
	if _, open := r.tracker.SessionIDForGeneration(sample.TargetID, sample.Generation); !open {
		if _, err := r.tracker.OpenForGeneration(sample.TargetID, sample.Generation); err != nil {
			return fmt.Errorf("delivery: open session for %s: %w", sample.TargetID, err)
		}
	}

	bytesDelta := sample.Bytes - previous.Bytes
	packetsDelta := sample.Packets - previous.Packets
	// A cumulative counter that went backwards means the ledger it came from
	// was rebuilt (a new Fanout, or a process restart handing us a fresh
	// ledger) while this Reporter kept its watermark. The current value is then
	// the whole of the new ledger's traffic, so take it as the delta rather
	// than underflowing uint64 into a ~1.8e19 byte over-bill.
	//
	// A target that merely moved to a new address does NOT land here: its
	// counters are carried across the reconcile by pointer, so they stay
	// monotonic and the delta stays honest across the move.
	//
	// A target that was REMOVED and later re-granted does land here, and that
	// is correct: it is served by a fresh counter set starting at zero, so the
	// current value is exactly what the new generation has delivered. The
	// fan-out refuses to re-admit an ID until its previous generation's
	// departure has settled, so by the time a regressed sample arrives under a
	// re-granted ID, the old session is closed and this delta opens the new one
	// rather than extending the old.
	if sample.Bytes < previous.Bytes {
		bytesDelta = sample.Bytes
	}
	if sample.Packets < previous.Packets {
		packetsDelta = sample.Packets
	}

	if err := r.tracker.ObserveForGeneration(sample.TargetID, sample.Generation, bytesDelta, packetsDelta); err != nil {
		return fmt.Errorf("delivery: observe %s: %w", sample.TargetID, err)
	}
	// Advance the watermark only after Observe succeeded, so a failed Observe
	// leaves the delta to be retried on the next sample instead of dropping it.
	r.last[key] = sample
	return nil
}

// emitOne emits and ships a new periodic record, provided nothing is owed for
// the target.
func (r *Reporter) emitOne(sample LedgerSample) error {
	if record, owed := r.pending[sampleKey(sample.TargetID, sample.Generation)]; owed {
		// Do not emit while a record is owed: a new Emit would advance the
		// watermark past traffic whose record has not shipped, and the retained
		// record's bytes would never be restated. The delta stays in the
		// tracker and rolls into the next record instead. Callers drain before
		// reaching here, so this is the case where that drain just failed.
		return fmt.Errorf("delivery: record seq %d for %s still owed; not emitting", record.Seq, sample.TargetID)
	}

	record, err := r.tracker.EmitForGeneration(sample.TargetID, sample.Generation)
	if err != nil {
		return fmt.Errorf("delivery: emit for %s: %w", sample.TargetID, err)
	}
	// Stamp the endpoint the interval's bytes actually went to. A retained
	// record keeps the address it was emitted with even if the target later
	// moves, which is right: the record describes that interval, not the
	// target's current endpoint.
	record.Destination = sample.Destination
	if err := r.sink.Ship(record); err != nil {
		r.pending[sampleKey(sample.TargetID, sample.Generation)] = record
		return fmt.Errorf("delivery: ship record for %s: %w", sample.TargetID, err)
	}
	return nil
}

// drainPending retransmits a retained record verbatim. It returns nil when
// nothing is owed for the target.
func (r *Reporter) drainPending(targetID string, generation uint64) error {
	key := sampleKey(targetID, generation)
	record, owed := r.pending[key]
	if !owed {
		return nil
	}
	if err := r.sink.Ship(record); err != nil {
		return fmt.Errorf("delivery: retransmit record seq %d for %s: %w", record.Seq, targetID, err)
	}
	delete(r.pending, key)
	return nil
}
