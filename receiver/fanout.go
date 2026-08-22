// Package receiver implements the unicast receive and fan-out path used by
// bcast-shred-gw.
package receiver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// FanoutStats is a point-in-time snapshot of the bounded fan-out path.
// EgressPackets and WriteErrors are process-wide totals across every feed and
// every destination; per-feed attribution is reported to an EgressObserver.
type FanoutStats struct {
	QueuedPackets  uint64
	DroppedPackets uint64
	EgressPackets  uint64
	WriteErrors    uint64
}

// EgressObserver receives the per-feed outcome of each fanned-out packet.
// Counts are per destination write, so one received packet reports up to one
// egress per configured destination. Implementations must be safe for
// concurrent use: the fan-out worker calls them from its own goroutine.
type EgressObserver interface {
	AddEgress(feedID string, count uint64) error
	AddWriteErrors(feedID string, count uint64) error
}

// EnqueueResult reports how the bounded ring handled a packet. It exists so the
// ingress caller can tell a real delivery drop (EnqueueOverflow) apart from a
// shutdown-time rejection (EnqueueClosed), which is not a drop.
type EnqueueResult int

const (
	// enqueueUnknown is the zero value and is never returned. It exists so a
	// zero-valued EnqueueResult — a forgotten assignment, or a struct field that
	// was never set — does not silently read as "delivered". Callers branch on
	// delivery outcomes, so the default must be a value that fails loudly rather
	// than the success case.
	enqueueUnknown EnqueueResult = iota
	// EnqueueAccepted means the packet was copied into the ring for delivery.
	EnqueueAccepted
	// EnqueueOverflow means the ring was full and the packet was lost. This is
	// the only outcome that counts toward the documented drop counters.
	EnqueueOverflow
	// EnqueueClosed means the fan-out was already shut down. The packet was not
	// delivered, but it is a shutdown artifact rather than receiver overload,
	// so it must not be charged to the ring-overflow counters.
	EnqueueClosed
)

// String renders the result for logs and test failures.
func (r EnqueueResult) String() string {
	switch r {
	case enqueueUnknown:
		return "unknown"
	case EnqueueAccepted:
		return "accepted"
	case EnqueueOverflow:
		return "overflow"
	case EnqueueClosed:
		return "closed"
	default:
		return fmt.Sprintf("EnqueueResult(%d)", int(r))
	}
}

// queuedPacket carries the originating feed alongside the packet so the worker
// can attribute delivery to a feed. A single process-wide Fanout serves every
// feed, so the worker cannot infer the feed from the packet itself.
type queuedPacket struct {
	feedID string
	packet []byte
}

// Target is one fan-out destination together with the stable identity that the
// delivery ledger keys it by.
//
// ID and Address are separate because they answer different questions and
// change independently. Address is where bytes go; ID is who is being served.
// Under a static --dest-ip-ports list the two are interchangeable, which is why
// the ledger originally keyed on slice position and the billing plane keys on
// the address string. Under a broker-derived grant table they are not:
//
//   - A subscriber can be re-granted a different endpoint. Keyed by address it
//     becomes a different billing subject mid-flight; keyed by ID its counters
//     follow it.
//   - Two grants can resolve to one address (a host behind NAT, or a hostname
//     and its literal IP). Address is then not unique and cannot be a key.
//   - Revoking a grant in the middle of the list shifts every later
//     destination down one position. Keyed by position, every subscriber after
//     the revoked one would inherit its neighbour's packet and byte totals.
//     That is a silent mis-bill, not a metrics wart, which is why position is
//     not a key here at all.
type Target struct {
	// ID is the stable identity of whoever is served — a broker grant or
	// subscriber ID. It must be unique within a target set and non-empty.
	ID string
	// Address is the UDP destination, as host:port.
	Address string
}

// destCounters is one destination's ledger. It is referenced by pointer so a
// reconcile can carry a surviving target's counters into the new table by
// copying the pointer, leaving the running totals untouched and monotonic.
type destCounters struct {
	packets atomic.Uint64
	bytes   atomic.Uint64
	drops   atomic.Uint64
	errors  atomic.Uint64
}

// destination is one entry in a table: identity, where to write, and the
// counters to charge.
type destination struct {
	id       string
	name     string
	addr     *net.UDPAddr
	writer   io.WriteCloser
	counters *destCounters
}

// destTable is an immutable snapshot of the destination set. Once published
// through Fanout.table it is never mutated, so the worker can range over it
// without synchronization; a reconcile builds a whole new one.
type destTable struct {
	entries []destination
}

// ErrTeardownPending reports that a departing target's final counters could not
// be certified before the boundary wait expired. It is raised on two paths, and
// the difference between them is whether the table swap happened.
//
//   - A reconcile removed the target and swapped anyway. The new table is live
//     and every stat the reconcile DID return is final; only the departure set
//     is incomplete, so the caller must not treat the reconcile as having
//     enumerated every closed session.
//   - A reconcile asked to re-admit a target ID whose previous generation has
//     not settled. That one is REFUSED and no swap happens, because serving it
//     would fuse two lifecycles under one ID — see ReconcileDestinations.
//
// Neither is a delivery failure, and in both cases the withheld departures stay
// recoverable: HarvestPendingTeardowns, or the next reconcile, returns them
// once their in-flight packet finishes. Callers already retry this error on
// their grant-poll cycle, which is what makes the refusal safe — the wait is
// bounded by one packet's delivery, not by a grant's lifetime.
//
// The distinction matters because closing a session is irreversible from the
// ledger's point of view. A caller handed a falsely-final sample writes a final
// record short by the in-flight packet and can never repair it; a caller handed
// this error simply has not closed that session yet.
var ErrTeardownPending = errors.New("fan-out: departing target counters are not yet final")

// pendingDeparture is a target removed from the table whose counters are not
// yet certifiably final, together with the delivery bracket that has to close
// before they are.
type pendingDeparture struct {
	entry destination
	// seq is the deliverSeq value observed immediately after the table swap. An
	// even value means no packet was in flight, so the entry was already final
	// when it was parked. An odd value means one packet was mid-deliver and may
	// hold the pre-swap snapshot; the entry becomes final as soon as deliverSeq
	// moves off this exact value, because that is that packet's bracket closing.
	seq uint64
}

// isFinal reports whether the departure's counters can no longer change.
//
// now must be a deliverSeq reading taken after the departure was parked. Once
// this returns true it stays true: the target is absent from every table the
// worker can load from here on, so nothing can charge it again.
func (p pendingDeparture) isFinal(now uint64) bool {
	return p.seq%2 == 0 || now != p.seq
}

// Fanout copies packets into a bounded ring and writes each packet to every
// destination from a dedicated worker. Enqueue never blocks the ingress path.
//
// The UDP path uses ONE socket and a single batched send per packet, never a
// per-destination worker pool. Sharding the send across goroutines is a
// measured regression, not a speedup: on the fan-out harness at N=42 the
// single-socket loop holds p50 161 microseconds while 1-shard and 8-shard
// variants degrade to 276 and 283 microseconds respectively.
type Fanout struct {
	queue    chan queuedPacket
	observer EgressObserver

	udpConn *ipv4.PacketConn
	// next rotates which destination is served first. Without it the send
	// order is fixed, which hands a persistent ~4 microsecond-per-position
	// latency advantage to whichever subscriber sits early in the list. An
	// auditable-SLA product cannot ship a delivery order correlated with
	// subscriber index.
	next int

	// table is the destination set the worker is currently serving. It is
	// swapped wholesale by ReconcileDestinations rather than mutated in place,
	// so the worker never holds a lock on the egress path: it loads the
	// pointer once per packet and that snapshot cannot change underneath it.
	//
	// Loading once per packet is load-bearing, not incidental. Charging the
	// ledger and building the rotated batch must agree on the same destination
	// set, and a second Load mid-packet could observe a reconcile and
	// attribute a send to the wrong subscriber.
	table atomic.Pointer[destTable]

	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup

	// reconcileMu serialises reconciles against each other. The worker does
	// not take it: it reads through table's atomic pointer. This exists only
	// so two concurrent reconciles cannot both read the old table and each
	// write a swap that loses the other's carried-over counters.
	reconcileMu sync.Mutex

	// deliverSeq is a seqlock-style bracket around one packet's delivery:
	// deliver makes it odd before loading the table and even again once it has
	// finished charging the ledger. It is the ONLY signal a reconcile has for
	// "is a worker currently holding a snapshot I just replaced", which is what
	// lets ReconcileDestinations wait out an in-flight packet before reading a
	// departing target's final counters.
	//
	// This costs two uncontended atomic adds per packet on the egress path.
	// That is deliberate and measured against the alternative: the fan-out's
	// own p50 is 161 microseconds at N=42, so a pair of adds is ~0.002% of the
	// packet budget, and it buys an exact final bill instead of one that is
	// short by however many packets were in flight at the swap.
	deliverSeq atomic.Uint64

	// pendingTeardown holds targets that a reconcile removed from the table but
	// whose counters are not yet certifiably final, because a packet was still
	// in flight when the swap landed and had not finished charging by the time
	// the boundary wait gave up. Guarded by reconcileMu.
	//
	// Parking them is what keeps the fall-back honest. The counters outlive the
	// table — the departed entry still points at the same *destCounters — so a
	// departure held here loses nothing by waiting, and once its bracket closes
	// it is final forever: it is absent from every table the worker can now
	// load, so no future deliver can charge it. The alternative, reading anyway
	// and labelling the result FINAL, is the one outcome that cannot be
	// repaired later, because the caller closes the session on it.
	pendingTeardown []pendingDeparture

	queuedPackets  atomic.Uint64
	droppedPackets atomic.Uint64
	egressPackets  atomic.Uint64
	writeErrors    atomic.Uint64

	// sendBatch is writeUDPPacketBatch in production. It is a field so tests
	// can drive partial sends, which is the only condition under which batch
	// slot and destination index diverge observably.
	sendBatch func(*ipv4.PacketConn, []ipv4.Message, bool) (int, error)
}

// DestinationStat is one destination's entry in the delivery ledger.
//
// Packets+Drops equals the number of packets the worker has processed,
// whatever each destination's outcome was. That is what makes the ledger
// auditable — a per-destination shortfall cannot hide as a process-wide
// average.
//
// The equality is exact per destination at any instant, but across
// destinations only once the worker is quiesced. DestinationStats loads each
// counter independently while deliver may be mid-batch, and deliver charges
// its delivered destinations before its dropped ones, so a live snapshot can
// catch some destinations charged for the current packet and others not. A
// reader sampling a running worker is eventually consistent and must not
// alert on a transient cross-destination mismatch.
//
// WriteErrors is a subset of Drops. A drop is "this destination did not get
// this packet"; a write error is the narrower "the write for this destination
// actively failed". They differ because a partial sendmmsg abandons the
// remaining messages in the batch: those destinations are dropped without ever
// being attempted, and blaming them for a fault they did not cause would point
// at the wrong subscriber.
type DestinationStat struct {
	// TargetID is the stable identity this destination is billed and charged
	// under. It survives a reconcile that moves the destination's position or
	// changes its address; the slice position does not, so nothing downstream
	// should key on position.
	TargetID    string
	Destination string
	Packets     uint64
	Bytes       uint64
	Drops       uint64
	WriteErrors uint64
}

// NewFanout starts a bounded fan-out worker for writers. The worker owns and
// closes the writers. queueCapacity must be positive. observer may be nil, in
// which case only the process-wide Stats counters are maintained.
func NewFanout(writers []io.WriteCloser, queueCapacity int, observer EgressObserver) (*Fanout, error) {
	if len(writers) == 0 {
		return nil, errors.New("fan-out requires at least one destination")
	}
	for i, writer := range writers {
		if writer == nil {
			return nil, fmt.Errorf("fan-out destination %d is nil", i)
		}
	}
	if queueCapacity <= 0 {
		return nil, errors.New("fan-out queue capacity must be positive")
	}

	f := &Fanout{
		queue:    make(chan queuedPacket, queueCapacity),
		observer: observer,
	}
	entries := make([]destination, len(writers))
	for i, writer := range writers {
		name := fmt.Sprintf("writer[%d]", i)
		entries[i] = destination{
			id:       strconv.Itoa(i),
			name:     name,
			writer:   writer,
			counters: new(destCounters),
		}
	}
	f.publish(&destTable{entries: entries})
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// publish installs a table and completes any one-time wiring the worker needs.
// It must be called before the worker starts.
func (f *Fanout) publish(table *destTable) {
	f.table.Store(table)
	if f.sendBatch == nil {
		f.sendBatch = writeUDPPacketBatch
	}
}

// DestinationStats returns the per-destination delivery ledger, in the current
// table's order.
//
// This is the per-subscriber accounting surface: process-wide Stats cannot
// answer "is destination 7 actually receiving its stream", and the per-feed
// EgressObserver cannot either, because one feed fans out to every subscriber.
//
// The snapshot is of one table. A concurrent reconcile is not torn across it:
// the whole set either predates the swap or follows it.
func (f *Fanout) DestinationStats() []DestinationStat {
	entries := f.table.Load().entries
	stats := make([]DestinationStat, len(entries))
	for i, entry := range entries {
		stats[i] = DestinationStat{
			TargetID:    entry.id,
			Destination: entry.name,
			Packets:     entry.counters.packets.Load(),
			Bytes:       entry.counters.bytes.Load(),
			Drops:       entry.counters.drops.Load(),
			WriteErrors: entry.counters.errors.Load(),
		}
	}
	return stats
}

// NewUDPFanout starts a bounded fan-out worker over a single UDP socket. Each
// packet is sent to every destination as one batch, with the destination order
// rotated per packet so no subscriber holds a fixed position advantage.
//
// Destinations are addresses without a separate identity, so each is given a
// target ID equal to its position in the list. That is the demo and
// static-config shape. A caller with real subscriber identity — a broker grant
// table — should use NewUDPFanoutTargets so the ledger keys on the grant.
func NewUDPFanout(destinations []string, queueCapacity int, observer EgressObserver) (*Fanout, error) {
	targets := make([]Target, len(destinations))
	for i, destination := range destinations {
		targets[i] = Target{ID: strconv.Itoa(i), Address: destination}
	}
	return NewUDPFanoutTargets(targets, queueCapacity, observer)
}

// NewUDPFanoutTargets starts a bounded UDP fan-out over identified targets.
func NewUDPFanoutTargets(targets []Target, queueCapacity int, observer EgressObserver) (*Fanout, error) {
	if len(targets) == 0 {
		return nil, errors.New("fan-out requires at least one destination")
	}
	if queueCapacity <= 0 {
		return nil, errors.New("fan-out queue capacity must be positive")
	}

	entries, err := resolveTargets(targets, nil)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("open fan-out UDP socket: %w", err)
	}

	f := &Fanout{
		queue:    make(chan queuedPacket, queueCapacity),
		observer: observer,
		udpConn:  ipv4.NewPacketConn(conn),
	}
	f.publish(&destTable{entries: entries})
	f.wg.Add(1)
	go f.run()
	return f, nil
}

// ReconcileDestinations replaces the served target set and reports which
// targets left it.
//
// This is the seam a broker-derived grant table drives: the destination set is
// no longer fixed at construction, so a grant can be issued or revoked while
// the sender runs. It is valid only on a UDP fan-out — the io.WriteCloser
// constructor owns its writers' lifetimes, and swapping those out here would
// leak or double-close them.
//
// Counters follow the TARGET, not its position. A target present in both the
// old and new set keeps the identical *destCounters, so its totals stay
// monotonic across a reconcile that inserts or removes its neighbours. Without
// that, revoking one grant would renumber every later destination and hand
// each one its neighbour's running totals.
//
// The returned stats are the targets that left, each carrying its FINAL
// counters. They are the sender's only authenticated per-destination teardown
// signal: until this existed the set never shrank, so
// delivery.CloseTicketExpired — "the broker grant backing the session lapsed" —
// was a wire-contract value with no reachable producer, and the only close the
// sender could attest to was CloseShutdown. The caller is expected to close
// those sessions; this method does not reach into the billing plane itself.
//
// FINAL is a hard guarantee, which is why the departure set is best-effort
// instead. A returned sample is never short: it is read only after the delivery
// bracket that could still charge it has closed. If a wedged socket keeps that
// bracket open past boundaryTimeout the departure is withheld rather than
// guessed, and the error wraps ErrTeardownPending to say the set is incomplete;
// HarvestPendingTeardowns finishes it. The asymmetry is deliberate: a caller
// that has not yet closed a session can close it later, whereas one that closed
// it on a short sample has written an unrepairable ledger record.
//
// For the same reason, a target ID whose previous generation has not settled is
// REFUSED rather than re-admitted: the whole reconcile returns
// ErrTeardownPending and no swap happens. Serving it would leave one ID naming
// two lifecycles at once — a parked departure holding the old cumulative total
// and a live entry counting from zero — which the billing plane, keyed on
// TargetID, cannot separate. The caller retries; the wait is one packet long.
//
// The counters ride on the return value because this is the last place they
// exist. A departing target is absent from the new table, and DestinationStats
// reads only the current one, so a caller told merely "grant-b left" can no
// longer look up what grant-b was owed: the traffic between its last periodic
// record and its removal would be delivered and never billed. Only the
// reconcile holds both tables, so only the reconcile can answer that, and it
// must hand the answer back rather than leave the caller to race the swap.
func (f *Fanout) ReconcileDestinations(targets []Target) ([]DestinationStat, error) {
	if f.udpConn == nil {
		return nil, errors.New("fan-out: reconcile is only supported on a UDP fan-out")
	}
	if len(targets) == 0 {
		// An empty grant table is refused rather than served. Accepting it
		// would silently stop delivery to everyone while the process kept
		// reporting healthy, and a broker returning nothing is far more often
		// a broker fault than a genuine "no subscribers" state.
		return nil, errors.New("fan-out requires at least one destination")
	}

	f.reconcileMu.Lock()
	defer f.reconcileMu.Unlock()

	// Settle whatever became final since the last reconcile BEFORE looking at
	// the requested set. A departure parked by an earlier reconcile is usually
	// final within one packet's delivery, so by now it almost always is;
	// harvesting here is what keeps the re-admission guard below from refusing
	// a re-grant whose previous generation is already done and merely
	// unharvested.
	settled := f.harvestFinalDepartures()

	// A target ID whose previous generation has NOT settled cannot be
	// re-admitted, because nothing downstream can tell the two lifecycles
	// apart.
	//
	// pendingTeardown holds the old generation's entry keyed by TargetID alone,
	// and a re-admitted ID gets FRESH counters — carry is built from the live
	// table, which no longer holds the departed entry. So admitting it here
	// leaves the old generation's cumulative total parked under the same ID as
	// a new generation counting from zero, and the harvest hands that stale
	// total back as a final sample for an ID that is once again live.
	// Reporter.CloseRemoved looks up only TargetID, so it would close the
	// re-granted session on the old generation's watermark: the new
	// generation's traffic lands in the old session, the old total is re-billed
	// against the advanced watermark, and the session boundary the ledger
	// depends on is gone. None of that is repairable after the record ships.
	//
	// Refusing costs a retry of a reconcile the caller already retries. It is
	// the same trade the boundary wait makes everywhere else here: a deferral
	// the caller can resolve, never a number it cannot.
	if collisions := f.unsettledCollisions(targets); len(collisions) > 0 {
		return settled, fmt.Errorf("%w: target(s) %s cannot be re-admitted until the previous generation's counters settle",
			ErrTeardownPending, strings.Join(collisions, ", "))
	}

	// Read the old table under reconcileMu so two concurrent reconciles cannot
	// both carry counters forward from the same pre-swap snapshot.
	previous := f.table.Load().entries
	carry := make(map[string]*destCounters, len(previous))
	for _, entry := range previous {
		carry[entry.id] = entry.counters
	}

	entries, err := resolveTargets(targets, carry)
	if err != nil {
		return nil, err
	}

	retained := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		retained[entry.id] = struct{}{}
	}
	var departing []destination
	for _, entry := range previous {
		if _, kept := retained[entry.id]; !kept {
			departing = append(departing, entry)
		}
	}

	f.table.Store(&destTable{entries: entries})

	// Park the departures against the delivery bracket that was open at the
	// swap, THEN wait for that bracket to close, THEN read counters.
	//
	// The worker loads the table pointer once per packet, so at the instant of
	// the store a worker already inside deliver holds the OLD snapshot and will
	// still charge a departing target for the packet it is on. Reading straight
	// after the store captures only the charges that happen to have landed by
	// then, which leaves the final bill short by whatever was mid-flight — a
	// silent under-bill, and exactly what this method exists to prevent.
	//
	// awaitDeliveryBoundary closes that window. It is an RCU-style grace
	// period: the reconciling caller waits, the worker never does. Delivery to
	// surviving subscribers continues at full rate throughout, and the wait is
	// bounded by a single packet's delivery, not by the reconcile interval.
	//
	// Reading the sequence AFTER the store is what makes the parked snapshot
	// safe: any deliver that begins from here on necessarily loads the new
	// table and cannot charge a departing target, and an even reading here
	// implies the previous packet's charges are already visible, because the
	// worker's closing increment happens after them.
	//
	// The counters outlive the table — the old entry still points at the same
	// *destCounters — so these reads are well defined, and every field is
	// atomic.
	swapSeq := f.deliverSeq.Load()
	for _, entry := range departing {
		f.pendingTeardown = append(f.pendingTeardown, pendingDeparture{entry: entry, seq: swapSeq})
	}
	f.awaitDeliveryBoundary(swapSeq)

	removed := append(settled, f.harvestFinalDepartures()...)
	if withheld := len(f.pendingTeardown); withheld > 0 {
		// Deliberately NOT returning a sample for these. A short sample the
		// caller believes is final is unrepairable; a withheld one is not.
		return removed, fmt.Errorf("%w: %d departing target(s) still delivering after %s",
			ErrTeardownPending, withheld, boundaryTimeout)
	}
	return removed, nil
}

// unsettledCollisions reports which of targets are asking to re-use a target ID
// whose previous generation is still parked in pendingTeardown. Callers must
// hold reconcileMu.
//
// Duplicates within targets are collapsed so the error names each ID once;
// rejecting the duplicate itself is resolveTargets' job.
func (f *Fanout) unsettledCollisions(targets []Target) []string {
	if len(f.pendingTeardown) == 0 {
		return nil
	}
	unsettled := make(map[string]struct{}, len(f.pendingTeardown))
	for _, pending := range f.pendingTeardown {
		unsettled[pending.entry.id] = struct{}{}
	}

	var collisions []string
	reported := make(map[string]struct{}, len(unsettled))
	for _, target := range targets {
		if _, pending := unsettled[target.ID]; !pending {
			continue
		}
		if _, already := reported[target.ID]; already {
			continue
		}
		reported[target.ID] = struct{}{}
		collisions = append(collisions, target.ID)
	}
	return collisions
}

// harvestFinalDepartures moves every parked departure whose delivery bracket has
// closed out of pendingTeardown and returns it as a final sample. Callers must
// hold reconcileMu.
//
// One deliverSeq reading serves the whole sweep: it is taken after every
// departure here was parked, which is the only precondition isFinal needs.
func (f *Fanout) harvestFinalDepartures() []DestinationStat {
	if len(f.pendingTeardown) == 0 {
		return nil
	}
	now := f.deliverSeq.Load()

	var removed []DestinationStat
	withheld := f.pendingTeardown[:0]
	for _, pending := range f.pendingTeardown {
		if !pending.isFinal(now) {
			withheld = append(withheld, pending)
			continue
		}
		entry := pending.entry
		removed = append(removed, DestinationStat{
			TargetID:    entry.id,
			Destination: entry.name,
			Packets:     entry.counters.packets.Load(),
			Bytes:       entry.counters.bytes.Load(),
			Drops:       entry.counters.drops.Load(),
			WriteErrors: entry.counters.errors.Load(),
		})
	}
	if len(withheld) == 0 {
		// Drop the backing array so a harvested departure's counters and
		// resolved address are not pinned for the process lifetime.
		f.pendingTeardown = nil
	} else {
		f.pendingTeardown = withheld
	}
	return removed
}

// HarvestPendingTeardowns returns the final counters of targets whose removal a
// previous reconcile could not certify, and reports how many remain uncertain.
//
// This is the recovery path for ErrTeardownPending, and the reason that error is
// a deferral rather than a loss: a caller that saw it calls this until the
// remaining count reaches zero, then closes those sessions with counters that
// are genuinely final. The next ReconcileDestinations harvests them too, so a
// caller on a grant-poll loop needs this only to settle the ledger off-cycle.
//
// After Close returns, the worker is stopped and no bracket can still be open,
// so a call here reports every outstanding departure and a remaining count of
// zero. That makes it the last chance to bill a departed target's tail before
// the Reporter closes what is left as SHUTDOWN.
func (f *Fanout) HarvestPendingTeardowns() (removed []DestinationStat, remaining int) {
	f.reconcileMu.Lock()
	defer f.reconcileMu.Unlock()

	removed = f.harvestFinalDepartures()
	return removed, len(f.pendingTeardown)
}

// boundaryTimeout bounds how long a reconcile waits for an in-flight packet to
// finish before it gives up and withholds the departing target's sample.
//
// It is a liveness backstop, not part of the counter contract. Reconcile
// refuses non-UDP fan-outs, so the in-flight work is a bounded sendmmsg rather
// than an arbitrary io.Writer — but a wedged socket must not deadlock the
// broker-grant client that drives reconciles. Expiry costs a deferral
// (ErrTeardownPending), never a wrong number.
const boundaryTimeout = 250 * time.Millisecond

// awaitDeliveryBoundary blocks until the delivery bracket open at started has
// closed, or until boundaryTimeout expires.
//
// started must be a deliverSeq reading taken AFTER the table store, which is
// what makes this terminate: any deliver that begins from there on loads the new
// table and cannot charge a departing target, so the only bracket worth waiting
// for is the one already open.
//
// An even started means the worker is between packets, so there is nothing to
// wait for — the common case, and the reason an idle fan-out does not pay for
// this. An odd started means one packet is in flight; the wait ends as soon as
// that specific bracket closes, so it costs one packet's delivery at most.
//
// This reports nothing. Whether the boundary was actually reached is decided by
// re-reading deliverSeq at harvest time via pendingDeparture.isFinal, so a
// bracket that closes in the window between the deadline and the harvest is
// still counted as final rather than pessimistically withheld.
func (f *Fanout) awaitDeliveryBoundary(started uint64) {
	if started%2 == 0 {
		return
	}
	deadline := time.Now().Add(boundaryTimeout)
	for f.deliverSeq.Load() == started {
		if time.Now().After(deadline) {
			return
		}
		runtime.Gosched()
	}
}

// resolveTargets validates a target set and builds its table entries, reusing
// counters from carry for targets that already existed.
func resolveTargets(targets []Target, carry map[string]*destCounters) ([]destination, error) {
	entries := make([]destination, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.ID == "" {
			return nil, fmt.Errorf("fan-out target for %q has no ID", target.Address)
		}
		if _, duplicate := seen[target.ID]; duplicate {
			// Two entries under one ID would share a ledger row, so their
			// traffic would be summed and neither could be audited alone.
			return nil, fmt.Errorf("fan-out target ID %q appears more than once", target.ID)
		}
		seen[target.ID] = struct{}{}

		address, err := net.ResolveUDPAddr("udp4", target.Address)
		if err != nil {
			return nil, fmt.Errorf("resolve UDP destination %q: %w", target.Address, err)
		}
		if address.IP == nil || address.IP.To4() == nil {
			return nil, fmt.Errorf("UDP destination %q is not IPv4", target.Address)
		}

		counters := carry[target.ID]
		if counters == nil {
			counters = new(destCounters)
		}
		entries = append(entries, destination{
			id:       target.ID,
			name:     address.String(),
			addr:     address,
			counters: counters,
		})
	}
	return entries, nil
}

// Enqueue copies packet into the bounded ring, attributing it to feedID.
//
// The two rejection reasons are reported separately because only one of them is
// a delivery drop. A full ring means the receiver could not keep up and the
// packet was lost; a closed fan-out means the process is shutting down and the
// ingress goroutine has not stopped reading yet. Charging both to the same
// counter lets shutdown inflate the ring-overflow metric, which is documented
// as ring-full only and would then disagree with Stats().DroppedPackets.
func (f *Fanout) Enqueue(feedID string, packet []byte) EnqueueResult {
	owned := queuedPacket{feedID: feedID, packet: append([]byte(nil), packet...)}

	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		return EnqueueClosed
	}

	select {
	case f.queue <- owned:
		f.queuedPackets.Add(1)
		return EnqueueAccepted
	default:
		f.droppedPackets.Add(1)
		return EnqueueOverflow
	}
}

// Stats returns a lock-free snapshot of the fan-out counters.
func (f *Fanout) Stats() FanoutStats {
	return FanoutStats{
		QueuedPackets:  f.queuedPackets.Load(),
		DroppedPackets: f.droppedPackets.Load(),
		EgressPackets:  f.egressPackets.Load(),
		WriteErrors:    f.writeErrors.Load(),
	}
}

// Close drains the ring, closes every destination, and waits for the worker.
func (f *Fanout) Close() error {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.closed = true
		close(f.queue)
		f.mu.Unlock()

		f.wg.Wait()
		if f.udpConn != nil {
			f.closeErr = f.udpConn.Close()
			return
		}
		var errs []error
		for _, entry := range f.table.Load().entries {
			if err := entry.writer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		f.closeErr = errors.Join(errs...)
	})
	return f.closeErr
}

func (f *Fanout) run() {
	defer f.wg.Done()
	for item := range f.queue {
		delivered, failed := f.deliver(item.packet)
		f.egressPackets.Add(delivered)
		f.writeErrors.Add(failed)
		f.report(item.feedID, delivered, failed)
	}
}

// deliver writes one packet to every destination and reports how many landed.
func (f *Fanout) deliver(packet []byte) (delivered, failed uint64) {
	size := uint64(len(packet))
	// Announce that this packet is in flight BEFORE loading the table, and
	// stand it down only after the last counter has been charged. A reconcile
	// that observes an odd sequence knows a worker may still be holding the
	// snapshot it just replaced, and waits for this bracket to close before
	// reading a departing target's final counters. Ordering matters in both
	// directions: incrementing after the Load would let a reconcile read
	// counters for a packet it never saw as in flight, and decrementing before
	// the charges land would do the same.
	f.deliverSeq.Add(1)
	defer f.deliverSeq.Add(1)

	// One Load for the whole packet. Charging and batch construction must
	// agree on the same destination set; re-loading would let a reconcile land
	// mid-packet and attribute a send to the wrong subscriber.
	entries := f.table.Load().entries
	if f.udpConn == nil {
		for _, entry := range entries {
			n, err := entry.writer.Write(packet)
			if err != nil || n != len(packet) {
				// This path attempts every writer, so a failure here is always
				// attributable to the destination that produced it.
				entry.counters.drops.Add(1)
				entry.counters.errors.Add(1)
				failed++
				continue
			}
			entry.counters.packets.Add(1)
			entry.counters.bytes.Add(size)
			delivered++
		}
		return delivered, failed
	}

	count := len(entries)
	messages, offset := f.rotatedMessages(entries, packet)

	written, err := f.sendBatch(f.udpConn, messages, runtime.GOOS == "linux")
	if written < 0 || written > count {
		written = 0
	}
	// Batch position is not destination index: rotatedMessages started this
	// batch at offset, so batch slot i carries destination (offset+i)%count.
	// Charging the ledger by slot would smear a single broken subscriber
	// across every destination as the rotation walks, which is precisely the
	// fault this ledger exists to localise.
	for i := 0; i < written; i++ {
		counters := entries[(offset+i)%count].counters
		counters.packets.Add(1)
		counters.bytes.Add(size)
	}
	for i := written; i < count; i++ {
		entries[(offset+i)%count].counters.drops.Add(1)
	}
	// sendmmsg stops at the first failure and abandons the rest of the batch,
	// so exactly one destination earns the write error; the rest were never
	// attempted and are dropped without blame.
	//
	// written < count is itself the failure signal, and err is not. A partial
	// sendmmsg reports the count with errno 0, so the kernel's error is nil:
	// sendmmsg returns errnoErr(errno) (x/net internal/socket/sys_linux.go),
	// errnoErr(0) is nil (internal/socket/error_unix.go), and ipv4.WriteBatch
	// wraps in an OpError only when that error is non-nil. Gating this on err
	// left WriteErrors permanently zero on Linux — dead for exactly the fault
	// the ledger exists to localise. The clamp above keeps slot written in
	// range, and the non-Linux loop below also leaves the failing message at
	// index written, so this holds on both paths.
	if written < count {
		entries[(offset+written)%count].counters.errors.Add(1)
	}

	delivered = uint64(written)
	failed = uint64(count - written)
	// A batch can report every message written and still surface an error. Do
	// not let that pass as a clean send, or a persistent fault is invisible.
	// This is a process-wide safety net only: with every message written there
	// is no destination to charge, so the ledger stays exact and silent.
	if err != nil && failed == 0 {
		failed = 1
	}
	return delivered, failed
}

// report attributes one packet's delivery outcome to its originating feed.
// Observer errors are deliberately ignored: scoring and accounting must never
// block or discard delivery work, so an unknown feed loses attribution rather
// than stalling the egress path.
func (f *Fanout) report(feedID string, delivered, failed uint64) {
	if f.observer == nil || feedID == "" {
		return
	}
	if delivered > 0 {
		_ = f.observer.AddEgress(feedID, delivered)
	}
	if failed > 0 {
		_ = f.observer.AddWriteErrors(feedID, failed)
	}
}

// rotatedMessages builds the send batch for one packet from entries, returning
// the batch and the destination offset it starts at, and advances the rotation
// by exactly one position.
//
// Every destination appears exactly once per batch, so rotation changes the
// ORDER of a send, never its membership: no destination can be skipped or
// served twice. The batch is ordered starting at f.next, so across count
// consecutive packets each destination leads exactly once.
//
// The returned offset is what lets a caller map a batch slot back to the
// destination it carried; without it a partial send cannot be attributed.
//
// f.next is taken modulo the CURRENT count rather than trusted, because a
// reconcile can shrink the table between packets and leave next past its end.
//
// The caller must be the single fan-out worker goroutine; f.next is
// deliberately unsynchronized because only that goroutine touches it.
func (f *Fanout) rotatedMessages(entries []destination, packet []byte) ([]ipv4.Message, int) {
	count := len(entries)
	offset := f.next % count
	messages := make([]ipv4.Message, count)
	for i := range entries {
		index := (offset + i) % count
		messages[i] = ipv4.Message{Buffers: [][]byte{packet}, Addr: entries[index].addr}
	}
	// Advance once per packet, not once per destination, so the starting
	// offset walks the destination list one position at a time.
	f.next = (offset + 1) % count
	return messages, offset
}

// writeUDPPacketBatch keeps one socket on every platform.
//
// x/net/ipv4 only implements WriteBatch as a real sendmmsg on Linux. Its
// fallback for other platforms writes the FIRST message and returns 1 with no
// error, which on a fan-out means every destination after the first is
// silently dropped while the counters report a clean send. So non-Linux builds
// must loop explicitly rather than trust the batch API.
func writeUDPPacketBatch(conn *ipv4.PacketConn, messages []ipv4.Message, useBatch bool) (int, error) {
	if useBatch {
		return conn.WriteBatch(messages, 0)
	}

	written := 0
	for _, message := range messages {
		if len(message.Buffers) == 0 {
			return written, errors.New("fan-out message has no payload")
		}
		payload := message.Buffers[0]
		if len(payload) == 0 {
			return written, errors.New("fan-out message has an empty payload")
		}
		n, err := conn.WriteTo(payload, nil, message.Addr)
		if err != nil {
			return written, err
		}
		if n != len(payload) {
			return written, io.ErrShortWrite
		}
		written++
	}
	return written, nil
}
