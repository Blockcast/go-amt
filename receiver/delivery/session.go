// Package delivery implements the delivery-session wire contract emitted by
// the unicast fan-out sender. It is the producer side of W3's billing record:
// every subscriber flow carries a session identity, a durable emit sequence,
// a cumulative duration, a delta byte count, and a close reason.
//
// Two semantics in here are load-bearing and asymmetric, because the Traffic
// Ops rollup is MAX(duration_ms) but SUM(bytes_out):
//
//   - DurationMS is CUMULATIVE — every record restates the session's total
//     elapsed time, so a duplicate or retried record is idempotent under MAX.
//   - BytesOut and PacketsOut are DELTAS — each record covers only the
//     interval since the previous record, so replayed records sum correctly
//     provided they are deduplicated by (SessionID, Seq).
//
// Getting that backwards silently double-bills, so both are pinned by tests.
package delivery

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CloseReason explains why a delivery session ended. It travels on the wire so
// an invoice can account for a gap; without it a five-minute hole in a
// subscriber's delivery is indistinguishable from a billing bug.
type CloseReason string

const (
	// CloseHeartbeatAbsent means the subscriber stopped proving liveness.
	CloseHeartbeatAbsent CloseReason = "HEARTBEAT_ABSENT"
	// CloseTicketExpired means the broker grant backing the session lapsed.
	CloseTicketExpired CloseReason = "TICKET_EXPIRED"
	// CloseStaleTimeout means no traffic moved for the stale interval.
	CloseStaleTimeout CloseReason = "STALE_TIMEOUT"
	// CloseBlockOldSources means the source was rejected as too old.
	CloseBlockOldSources CloseReason = "BLOCK_OLD_SOURCES"
	// CloseShutdown means the sender terminated the session deliberately.
	CloseShutdown CloseReason = "SHUTDOWN"
)

// Valid reports whether reason is a close reason the wire contract defines.
func (r CloseReason) Valid() bool {
	switch r {
	case CloseHeartbeatAbsent, CloseTicketExpired, CloseStaleTimeout,
		CloseBlockOldSources, CloseShutdown:
		return true
	default:
		return false
	}
}

// Note there is deliberately no TEARDOWN close reason. An AMT Teardown is
// unauthenticated — any observer that has seen a Membership Query can forge
// one — so it is only ever a liveness hint here (see Tracker.Teardown), never
// a close. Sessions close on heartbeat absence, ticket expiry, or stale
// timeout, all of which the sender can attest to itself.

var (
	// ErrNoSession is returned when a subscriber has no open session.
	ErrNoSession = errors.New("delivery: subscriber has no open session")
	// ErrSessionOpen is returned when opening over a session already open.
	ErrSessionOpen = errors.New("delivery: subscriber already has an open session")
)

// Record is one delivery-session record as it appears on the wire.
//
// Records are deduplicated downstream by (SessionID, Seq). Seq is durable
// across a sender restart, so a replayed record cannot collide with a
// different record under first-write-wins.
//
// A Record is the sender's only copy of the interval it describes: BytesOut
// and PacketsOut are never restated by a later record. A record that fails to
// ship must be retransmitted verbatim, not regenerated — see the retry
// contract on Tracker.Emit.
//
// IDENTITY vs ENDPOINT. SubscriberID is the billing identity — a broker grant
// ID, stable for the life of the grant. Destination is the resolved UDP address
// the bytes went to, and is metadata ONLY: it can change under a subscriber
// mid-session (a re-grant to a new endpoint), and two distinct subscribers may
// legitimately share one address. Keying billing state on the address therefore
// both splits one subscriber across two sessions and merges two subscribers
// into one, so nothing downstream may treat Destination as an identity.
type Record struct {
	SessionID    string `json:"session_id"`
	SubscriberID string `json:"subscriber_id"`
	// Destination is endpoint metadata, not identity — see the note above. It
	// is filled by the ledger side (Reporter), not by Tracker, because the
	// session layer is deliberately address-agnostic.
	Destination string      `json:"destination,omitempty"`
	Seq         uint64      `json:"seq"`
	DurationMS  int64       `json:"duration_ms"`
	BytesOut    uint64      `json:"bytes_out"`
	PacketsOut  uint64      `json:"packets_out"`
	CloseReason CloseReason `json:"close_reason,omitempty"`
	Final       bool        `json:"final"`
	OpenedAt    time.Time   `json:"opened_at"`
	EmittedAt   time.Time   `json:"emitted_at"`
}

// SeqStore reserves durable per-session emit sequence numbers. Implementations
// must not return a sequence number until it has survived to stable storage,
// so a crash between reservation and emission can only skip a sequence number,
// never reuse one.
type SeqStore interface {
	NextSeq(sessionID string) (uint64, error)
	// Retire releases the state held for a session that has closed and will
	// never emit again. Without it a store accumulates one entry per session
	// for the lifetime of the process — and, for a durable store, one record
	// per session in its file forever, since every compaction rewrites what
	// the previous one preserved. Tracker.Close calls it after the final
	// record is built, so no sequence number is ever released before it has
	// been used. It cannot fail: releasing state is an optimisation, and a
	// store that could not release it is merely larger than necessary.
	Retire(sessionID string)
}

type session struct {
	id             string
	subscriberID   string
	openedAt       time.Time
	bytesTotal     uint64
	packetsTotal   uint64
	bytesEmitted   uint64
	packetsEmitted uint64
	lastTeardown   time.Time
}

// Tracker owns per-subscriber delivery-session state for the fan-out sender.
// It is safe for concurrent use.
type Tracker struct {
	mu       sync.Mutex
	sessions map[string]*session
	seqs     SeqStore
	newID    func() (string, error)
	now      func() time.Time
}

func sessionKey(subscriberID string, generation uint64) string {
	if generation == 0 {
		return subscriberID
	}
	return fmt.Sprintf("%s\x00%d", subscriberID, generation)
}

// TrackerOption customizes a Tracker. Options exist so tests can pin time and
// session identity; production callers need none of them.
type TrackerOption func(*Tracker)

// WithClock overrides the Tracker clock.
func WithClock(now func() time.Time) TrackerOption {
	return func(t *Tracker) { t.now = now }
}

// WithIDFunc overrides session UUID minting.
func WithIDFunc(newID func() (string, error)) TrackerOption {
	return func(t *Tracker) { t.newID = newID }
}

// NewTracker returns a Tracker that reserves emit sequence numbers from seqs.
func NewTracker(seqs SeqStore, options ...TrackerOption) (*Tracker, error) {
	if seqs == nil {
		return nil, errors.New("delivery: sequence store is nil")
	}
	tracker := &Tracker{
		sessions: make(map[string]*session),
		seqs:     seqs,
		newID:    NewSessionID,
		now:      time.Now,
	}
	for _, option := range options {
		option(tracker)
	}
	return tracker, nil
}

// Open mints a new session for subscriberID and returns its session UUID.
//
// Every open mints a distinct UUID, including a reopen after a teardown or a
// close. Sessions are never identified by subscriber alone, so two consecutive
// sessions for the same subscriber can never be merged into one billing row.
func (t *Tracker) Open(subscriberID string) (string, error) {
	return t.OpenForGeneration(subscriberID, 0)
}

func (t *Tracker) OpenForGeneration(subscriberID string, generation uint64) (string, error) {
	if subscriberID == "" {
		return "", errors.New("delivery: subscriber ID is empty")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := sessionKey(subscriberID, generation)
	if _, exists := t.sessions[key]; exists {
		return "", fmt.Errorf("%w: %s", ErrSessionOpen, subscriberID)
	}
	id, err := t.newID()
	if err != nil {
		return "", fmt.Errorf("delivery: mint session ID: %w", err)
	}
	t.sessions[key] = &session{
		id:           id,
		subscriberID: subscriberID,
		openedAt:     t.now(),
	}
	return id, nil
}

// Observe accumulates delivered bytes and packets against the open session.
// It is called on the egress path, so it never allocates or does I/O.
func (t *Tracker) Observe(subscriberID string, bytes, packets uint64) error {
	return t.ObserveForGeneration(subscriberID, 0, bytes, packets)
}

func (t *Tracker) ObserveForGeneration(subscriberID string, generation uint64, bytes, packets uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	current, ok := t.sessions[sessionKey(subscriberID, generation)]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNoSession, subscriberID)
	}
	current.bytesTotal += bytes
	current.packetsTotal += packets
	return nil
}

// Teardown records an unauthenticated subscriber-ID teardown hint for every
// live generation of subscriberID. It deliberately does NOT close a session
// and does NOT affect duration, because a teardown signal can be forgeable.
//
// This is the production-safe path for callers that only have a stable broker
// target ID. During a re-grant, old and new generations can briefly coexist;
// without an authenticated generation a caller cannot safely choose one, so it
// conservatively asks the liveness layer to probe both. A hint can only cause
// extra probes, never a billing close. This API intentionally accepts an
// already-resolved broker target ID; it does not decode AMT wire messages or
// invent a target-generation mapping from their IP, port, nonce, or response
// MAC.
//
// Callers should treat a true return as a prompt to run an accelerated liveness
// probe, then close through Close or CloseForGeneration if that probe fails.
func (t *Tracker) Teardown(subscriberID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	hinted := false
	for _, current := range t.sessions {
		if current.subscriberID != subscriberID {
			continue
		}
		current.lastTeardown = now
		hinted = true
	}
	return hinted
}

// TeardownForGeneration records an unauthenticated teardown hint for one
// generation. It deliberately does NOT close the session and does NOT affect
// duration, because a teardown signal can be forgeable. The caller is
// responsible for obtaining TargetID and Generation from an authenticated
// target-source path; this is not an AMT wire-message decoder. Callers should
// treat a true return as a prompt to run an accelerated liveness probe, then
// close through CloseForGeneration if that probe fails.
func (t *Tracker) TeardownForGeneration(subscriberID string, generation uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	current, ok := t.sessions[sessionKey(subscriberID, generation)]
	if !ok {
		return false
	}
	current.lastTeardown = t.now()
	return true
}

// Emit produces a periodic (non-final) record for the open session.
//
// RETRY CONTRACT — read this before writing the retry loop around it. The
// delta watermark advances when Emit RETURNS, not when the record is shipped.
// The returned Record is therefore the only copy of that interval's bytes and
// packets: BytesOut and PacketsOut cover exactly the traffic observed since
// the previous successful Emit, and no later record will ever restate them.
//
// So if shipping fails, retransmit THAT Record verbatim until the sink accepts
// it. Do not call Emit again to obtain a fresh record — the natural reflex and
// the wrong one. The second call returns only the delta accumulated since the
// first, and the first record's bytes are gone, under-billing the subscriber
// by exactly the interval that failed to ship. Nothing reports this; it is
// silent by construction, which is why it is written down here.
//
// Retransmitting is always safe. Records are deduplicated downstream by
// (SessionID, Seq), so a duplicate is discarded rather than counted twice, and
// DurationMS is cumulative so it collapses correctly under MAX.
func (t *Tracker) Emit(subscriberID string) (Record, error) {
	return t.EmitForGeneration(subscriberID, 0)
}

func (t *Tracker) EmitForGeneration(subscriberID string, generation uint64) (Record, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.emitLocked(sessionKey(subscriberID, generation), "", false)
}

// Close produces the final record for the open session and retires it. A
// subsequent Open for the same subscriber mints a fresh session UUID.
//
// The retry contract on Emit applies here too, and matters more: the final
// record carries the last delta and the close reason, and the session is gone
// afterwards, so there is nothing left to re-emit from. Retransmit the
// returned Record verbatim until the sink accepts it.
func (t *Tracker) Close(subscriberID string, reason CloseReason) (Record, error) {
	return t.CloseForGeneration(subscriberID, 0, reason)
}

func (t *Tracker) CloseForGeneration(subscriberID string, generation uint64, reason CloseReason) (Record, error) {
	if !reason.Valid() {
		return Record{}, fmt.Errorf("delivery: invalid close reason %q", string(reason))
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	record, err := t.emitLocked(sessionKey(subscriberID, generation), reason, true)
	if err != nil {
		return Record{}, err
	}
	delete(t.sessions, sessionKey(subscriberID, generation))
	// The sequence number has already been issued and put in the record, so
	// releasing the store's state for it now cannot lose anything. Doing it
	// here rather than leaving it to the caller is what keeps the store from
	// growing for the lifetime of the process.
	t.seqs.Retire(record.SessionID)
	return record, nil
}

// emitLocked builds a record and advances the delta watermark. The caller must
// hold t.mu.
func (t *Tracker) emitLocked(subscriberID string, reason CloseReason, final bool) (Record, error) {
	current, ok := t.sessions[subscriberID]
	if !ok {
		return Record{}, fmt.Errorf("%w: %s", ErrNoSession, subscriberID)
	}

	seq, err := t.seqs.NextSeq(current.id)
	if err != nil {
		return Record{}, fmt.Errorf("delivery: reserve sequence for session %s: %w", current.id, err)
	}

	now := t.now()
	// Duration is cumulative from session open, never from the previous emit,
	// so duplicate records collapse correctly under the MAX rollup.
	duration := now.Sub(current.openedAt)
	if duration < 0 {
		duration = 0
	}

	record := Record{
		SessionID:    current.id,
		SubscriberID: current.subscriberID,
		Seq:          seq,
		DurationMS:   duration.Milliseconds(),
		// Bytes and packets are deltas since the previous record, so replayed
		// records sum correctly under the SUM rollup.
		BytesOut:    current.bytesTotal - current.bytesEmitted,
		PacketsOut:  current.packetsTotal - current.packetsEmitted,
		CloseReason: reason,
		Final:       final,
		OpenedAt:    current.openedAt,
		EmittedAt:   now,
	}

	// Advance the watermark only after the record is fully built, so a failed
	// sequence reservation above cannot silently discard delivered bytes. It
	// advances here rather than on successful shipment because there is no
	// shipment to observe from inside this package — see the retry contract on
	// Emit for what that obliges the caller to do.
	current.bytesEmitted = current.bytesTotal
	current.packetsEmitted = current.packetsTotal
	return record, nil
}

// SessionID returns the open session UUID for subscriberID.
func (t *Tracker) SessionID(subscriberID string) (string, bool) {
	return t.SessionIDForGeneration(subscriberID, 0)
}

func (t *Tracker) SessionIDForGeneration(subscriberID string, generation uint64) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	current, ok := t.sessions[sessionKey(subscriberID, generation)]
	if !ok {
		return "", false
	}
	return current.id, true
}

// Open reports how many sessions are currently open.
func (t *Tracker) OpenSessions() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// NewSessionID mints an RFC 4122 version 4 UUID.
func NewSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40 // version 4
	raw[8] = (raw[8] & 0x3f) | 0x80 // RFC 4122 variant

	var out [36]byte
	hex.Encode(out[0:8], raw[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], raw[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], raw[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], raw[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], raw[10:16])
	return string(out[:]), nil
}
