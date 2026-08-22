package broker

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// This file is the gateway-to-broker *transport* contract: route spelling,
// request/response envelopes, and the error taxonomy. heartbeat.go is the
// *payload* contract. They are versioned independently because they change for
// independent reasons — a new erasure field bumps HeartbeatSchema and leaves
// the routes alone; a route rename bumps TransportSchema and leaves the
// heartbeat body byte-identical.
//
// It lives in go-amt, next to the payload contract and on the client side of
// the wire, for the reason the CTO ratified on BLO-22821: bcast-shred-gw is the
// customer-installed binary and cannot be force-upgraded, while the broker
// redeploys at will. The side that cannot be upgraded in lockstep freezes the
// contract, and the side that can adopts it as a compile-time dependency. That
// is what already paid off for the payload — the broker pins a go-amt version
// and consumes its symbols, so a server-side schema revision surfaces as a
// broker compile error rather than as a wire mismatch a customer discovers.
//
// The concrete mechanism here is the route pair: the broker registers
// PatternMint/PatternRenew/PatternHeartbeat on its mux, and the gateway builds
// request paths with MintPath/RenewPath/HeartbeatPath. Both sides read the same
// constants, so a route rename is a compile-time event on the server and cannot
// become a 404 in production. A hand-mirrored route table on the server side
// would have no such coupling and would drift silently, which is precisely the
// failure the payload split avoided.
//
// # What is deliberately absent
//
// There is no identity field in any request envelope here, and no error code
// for an identity failure. Both absences are load-bearing and are documented at
// Identity and at ErrorCode respectively. Neither is an oversight to be filled
// in by a later revision: adding either one re-opens a failure mode the current
// shape makes unreachable.

const (
	// TransportSchema versions the routes, envelopes, and error taxonomy in
	// this file. Like HeartbeatSchema, any change to the shapes below requires
	// a new schema string rather than a silent edit to this one.
	//
	// It is not carried on the wire. The routes are themselves versioned by
	// their /v1/ prefix, which is the version a request actually selects; this
	// constant exists so both sides can assert at build time that they were
	// compiled against the same revision of the contract, and so a changelog
	// has something to name.
	TransportSchema = "gateway.transport.v1"

	// TicketTTL is the maximum lifetime the broker will grant a ticket.
	//
	// Published here because the renewal *schedule* is a client obligation and
	// a client cannot schedule against a bound it has to guess. The broker
	// clamps every grant to min(cert.NotAfter, now+TicketTTL) — see
	// Ticket.NotAfter for why the certificate half of that clamp is the one
	// that bites — so a gateway must renew well inside this window rather than
	// at its edge.
	TicketTTL = 5 * time.Minute

	// HeartbeatMaxBodyBytes bounds a single heartbeat request body.
	//
	// The broker enforces this at ingest and answers an over-cap body with
	// CodeBodyTooLarge. It is published on the client side at W2b's request so
	// the gateway knows the bound it is held to *before* it serializes: a
	// gateway that discovers the cap only from a 413 has already spent a
	// heartbeat interval's work and, worse, has no way to shrink the report it
	// is holding without dropping delivery data an SLA is computed against.
	//
	// The headroom is real but much narrower than it looks, so it is stated as
	// a measurement rather than an adjective: the widest heartbeat
	// ValidateHeartbeat accepts — MaxFeeds (4096) feeds, each with a
	// MaxFeedIDBytes id, a maximal packet/byte pair, a nanosecond-precision
	// activity window, and a fully-populated erasure.Window at MaxSetsTotal —
	// serializes to 2,752,799 bytes, or 65.6% of this cap. That is pinned by
	// TestHeartbeatBodyFitsUnderCap, which fails if a future field erodes it.
	//
	// 1.52x of headroom against the legal maximum means a gateway that hits
	// this cap has a bug rather than a large deployment, but the margin is thin
	// enough that a per-feed field cannot be added without re-measuring: the
	// spare budget is ~351 bytes per feed report at MaxFeeds, and that is the
	// number a proposed field must be sized against. FeedReport's own doc
	// contemplates a schema-2 window_ms for cross-gateway normalization; it
	// lands on 65.6%, not on an empty cap.
	//
	// The fixture that pins this is required to pass ValidateHeartbeat and
	// CanonicalBytes, which is not ceremony. The first version of that test
	// measured a body with an empty first_packet_at/last_packet_at pair against
	// a nonzero packets count — a body the broker answers invalid_request to —
	// and so reported 1,704,213 bytes / 40.6% for a heartbeat that cannot occur
	// on the wire. A cap test able to measure an illegal body under-measures
	// again the next time a field is added, while staying green.
	//
	// Treat a 413 as a producer bug; in particular do not respond by splitting
	// the report, which would breach the byte-identical replay rule — see
	// ReplayRule and CodeBodyTooLarge.
	HeartbeatMaxBodyBytes = 4 << 20 // 4 MiB

	// MaxRelayIDBytes bounds relay_id, matching MaxFeedIDBytes for feed_id.
	MaxRelayIDBytes = 128
)

// Route patterns, in the exact spelling the broker registers on a
// net/http.ServeMux. The method is part of the pattern (Go 1.22+ routing), so
// registering these rejects a wrong-method request with 405 without a handler
// branch.
//
// Every route is POST, including the two that read like resource creation and
// the one that reads like a submission, because all three mutate broker state
// and none is safely repeatable by an intermediary. See Identity for why there
// is no intermediary in a compliant deployment anyway.
const (
	PatternMint      = "POST /v1/tickets"
	PatternRenew     = "POST /v1/tickets/{ticket_id}/renew"
	PatternHeartbeat = "POST /v1/heartbeat"
)

// RenewTicketIDParam is the wildcard name inside PatternRenew. The broker reads
// the ticket id with r.PathValue(broker.RenewTicketIDParam) rather than
// re-spelling "ticket_id", so the wildcard cannot drift from the pattern.
const RenewTicketIDParam = "ticket_id"

// MintPath returns the request path for a mint. It is a function rather than a
// constant so that all three builders are called the same way at the call site.
func MintPath() string { return "/v1/tickets" }

// HeartbeatPath returns the request path for a heartbeat ingest.
func HeartbeatPath() string { return "/v1/heartbeat" }

// RenewPath returns the request path for renewing ticketID.
//
// The id is path-escaped, which matters less for defence than for honesty: a
// ticket id is broker-issued and ValidateTicket constrains it to a canonical
// UUID, so an id needing escaping is already a bug on one side or the other.
// Escaping means that bug surfaces as a 404 from the broker rather than as a
// silently different path — an unescaped "../heartbeat" would otherwise
// resolve, on any client that normalizes before sending, to a route the caller
// did not name.
func RenewPath(ticketID string) string {
	return MintPath() + "/" + url.PathEscape(ticketID) + "/renew"
}

// Identity documents the one thing this contract most needs a reader to
// understand, and it is a negative: no request envelope in this file carries an
// identity field, and there is no error code for an identity failure.
//
// # Identity is ambient, never an input
//
// The gateway's identity is the client certificate that terminated the TLS
// connection. The broker derives every identity-shaped value from it — the
// gateway UUID, the entitlement it checks, and the plane binding it records
// from the peer address — so MintRequest carries only the two facts the
// certificate cannot supply, and RenewRequest carries nothing at all.
//
// The rule is that an assertion which must agree is never an input. Heartbeat's
// gw_uuid is the single field that looks like an exception and is in fact the
// pattern: the broker cross-checks it against the certificate and rejects
// disagreement as a forgery signal. It is a value the producer must state
// correctly and gains nothing by stating, which is the opposite of a selector.
// A gw_uuid, source_ip, or on_behalf_of field in a *request envelope* would be
// a tenant selector wearing an assertion's clothes, and the first handler that
// trusted one would be an authorization bypass.
//
// # There is therefore no identity error to model
//
// The broker admits identity inside its tls.Config's VerifyConnection callback,
// so a certificate with a missing SPIFFE SAN, a dual emit, the wrong root, or
// an unknown CA fails the *TLS handshake*. The HTTP handler never runs. The
// client-visible result is a transport error — Go reports "remote error: tls:
// bad certificate" — and not a status code, which is why ErrorCode has no
// entry for it and StatusForCode cannot produce one.
//
// This is a feature rather than a gap: it is what makes "no fail-open branch is
// reachable" true by construction instead of by review. Specifying an identity
// error body would describe an unreachable path and invite someone to build the
// application-level identity gate that makes it reachable. Handle identity
// failure as a transport failure — see RetryTransportFailure for the posture.
//
// # No proxy hop
//
// The gateway connects directly to the broker's TLS listener. TLS terminated
// upstream by a shared ingress makes r.TLS the proxy's certificate and the peer
// address the proxy's address, which destroys both the identity above and the
// plane binding derived from the peer. There is no header path — no
// X-Forwarded-Client-Cert equivalent — precisely so that deploying behind a
// terminating proxy fails closed at the handshake rather than silently
// attributing every gateway's traffic to the proxy.
//
// # Certificate rotation requires a new connection
//
// This one is a gateway obligation that no amount of broker-side care can
// enforce, and it is the failure mode most likely to reach production
// undetected.
//
// Go's http.Client holds keep-alive connections whose client certificate was
// selected at handshake time. Rotating the certificate on disk, or even
// swapping it in the tls.Config, does not affect a connection that is already
// open: the broker keeps observing the *previous* certificate. Because Mint and
// Renew clamp not_after against the presented certificate's NotAfter, a gateway
// that rotates at ~50% of a 24h certificate and holds its connection open keeps
// receiving tickets clamped to the *expiring* certificate — and in that
// certificate's final minutes it receives tickets that are already expired,
// while its own state reports renewal success.
//
// A gateway MUST therefore force a new TLS connection after rotating, before
// its next Mint or Renew — with net/http, by calling CloseIdleConnections on
// the transport — and SHOULD verify the rotation took by confirming that the
// not_after it is granted advances past the old certificate's expiry.
//
// Identity is a documentation anchor and has no behaviour.
type Identity struct{}

// MintRequest asks the broker for a ticket admitting this gateway to one feed.
//
// The envelope is this small because identity is ambient: the gateway UUID, its
// entitlement, the plane binding, and the certificate expiry the grant is
// clamped against are all derived by the broker from the connection. See
// Identity.
//
// Mint is idempotent — see MintIdempotency, which is the rule that makes
// RetryTransportFailure safe to apply to this route.
type MintRequest struct {
	// FeedID names the feed to admit. Bounded by MaxFeedIDBytes, matching the
	// feed_id in FeedReport so a feed nameable in one contract is nameable in
	// the other.
	FeedID string `json:"feed_id"`

	// RelayID names the relay the gateway intends to draw the feed from.
	//
	// It is not part of the idempotency key. A Mint naming a different relay
	// for a feed this gateway already holds a ticket for re-binds the relay and
	// returns the existing ticket; it does not mint a second one. See
	// MintIdempotency.
	RelayID string `json:"relay_id"`
}

// MintIdempotency states what a repeat Mint does, which is the rule that makes
// retrying a Mint safe.
//
// # The rule
//
// Mint is idempotent on (gw_uuid, feed_id) for as long as that gateway holds an
// active ticket for that feed. A Mint naming a feed the gateway already holds
// returns the existing ticket — same ticket_id, same not_after — with an
// ordinary 2xx, and consumes no additional seat. Once the ticket is no longer
// active, the next Mint issues a fresh one.
//
// Three consequences the broker must implement and the gateway may rely on:
//
//   - The returned ticket is unchanged, not extended. Mint is not a renewal
//     backdoor; Renew is the only path that advances not_after. A gateway that
//     re-minted instead of renewing would otherwise hold a seat indefinitely
//     without ever exercising the clamp at Ticket.NotAfter.
//   - The idempotency lookup happens *before* the concurrency-cap check. A
//     gateway at its cap that retries a Mint for a feed it already holds must
//     receive its existing ticket, not CodeConcurrencyCapped. Checking the cap
//     first would 409 a gateway against its own ticket — the precise failure
//     this rule exists to prevent, one step removed.
//   - relay_id is outside the key. Keying on (gw_uuid, feed_id, relay_id)
//     would leave a deliberate relay switch minting a second seat while the
//     first orphans to TicketTTL, which is the same orphan in a narrower case.
//     The binding recorded is the one from the most recent accepted Mint, so a
//     retry replaying identical bytes is a no-op and a relay switch takes
//     effect without a new seat.
//
// # Why it is forced rather than chosen
//
// RetryTransportFailure is RetryBackoff, so a Mint whose response is lost to a
// timeout or a broker restart mid-flight *is* retried. Without idempotency the
// broker mints T2, and the gateway holds T2 while being unable to renew or
// release T1 because it never learned that id. T1 orphans for up to TicketTTL,
// and a gateway near its cap then receives CodeConcurrencyCapped against its
// own orphan: an operator sees a licensing conflict that is not one, and
// raising the cap does not clear it.
//
// The alternative — each Mint is a distinct seat, and the client must not retry
// Mint on transport failure — was rejected because it is not implementable. A
// client cannot distinguish "the request never reached the broker", which is
// safe to retry, from "the response was lost", which is not; both present as
// the same transport error. Any rule whose correctness depends on that
// distinction is one the client cannot honour, so the constraint has to live on
// the server, exactly as it does for heartbeats.
//
// That is ReplayRule's reasoning one plane over. There a uniqueness constraint
// on (gw_uuid, sent_at) makes a heartbeat retry safe by construction rather
// than by client care; here the same shape protects licensed seats instead of
// ledger rows.
//
// MintIdempotency is a documentation anchor and has no behaviour.
type MintIdempotency struct{}

// RenewRequest is the renew envelope and is deliberately empty: the ticket is
// named in the path and everything else is ambient.
//
// It exists as a named type rather than as "send no body" so that the contract
// has somewhere to grow a field without a route change, and so both sides
// serialize the same "{}" rather than disagreeing about whether an empty body
// or an empty object is meant.
type RenewRequest struct{}

// Ticket is the response to both Mint and Renew. One type rather than two
// identical ones, because a renewed ticket is not distinguishable from a fresh
// one and a client that branched on which call produced it would be modelling a
// difference the broker does not make.
//
// A Ticket returned by Mint is not necessarily newly issued: a repeat Mint for
// a feed the gateway already holds returns the existing one. See
// MintIdempotency.
type Ticket struct {
	// TicketID is a canonical, non-nil, lowercase UUID — the same spelling
	// rule as gw_uuid, for the same reason: one identity, one spelling.
	TicketID string `json:"ticket_id"`

	// NotAfter is when this ticket stops admitting traffic, as a canonical UTC
	// timestamp in the exact spelling described on HeartbeatSchema.
	//
	// It is min(certificate.NotAfter, now+TicketTTL) and the client must
	// schedule against the value it is *given*, never against TicketTTL. The
	// two diverge exactly when the certificate is closer to expiry than
	// TicketTTL, which is both the case a naive scheduler gets wrong and the
	// case that only occurs near a rotation boundary — so it is missed in
	// testing and hit in production. See Identity on rotation.
	NotAfter string `json:"not_after"`
}

// HeartbeatAccepted is the response to a successful heartbeat ingest.
//
// It is empty, and 2xx means "recorded or already recorded". The broker
// deduplicates on (gw_uuid, sent_at) as a uniqueness constraint, so a replayed
// heartbeat is a success rather than a conflict — see ReplayRule.
//
// # One request per heartbeat, never a stream
//
// Each heartbeat is a complete, independent POST carrying one fully-serialized
// body, bounded by HeartbeatMaxBodyBytes. There is no long-lived streaming
// channel, no chunked multi-report connection, and no batching of several
// windows into one request.
//
// This is a constraint rather than a default. The broker's ingest entry point
// takes an already-buffered body, so a stream does not fit it — but the deeper
// reason is that the dedup constraint at ReplayRule is keyed on one
// (gw_uuid, sent_at) per recorded unit. A stream would either need framing the
// contract does not define, or would coalesce several windows behind a single
// sent_at, which silently collapses distinct delivery windows in the ledger.
// A gateway with a backlog of undelivered heartbeats sends them as separate
// requests, each retaining its original sent_at.
type HeartbeatAccepted struct{}

// ReplayRule states the heartbeat retry obligation, which is the one rule here
// that a correct-looking client breaks silently.
//
// A heartbeat retry MUST replay the identical body, byte for byte, including
// sent_at. It must not re-stamp sent_at, re-serialize, or re-drain the reporter
// to build a fresher report.
//
// The reason is that server-side dedup is a uniqueness constraint —
// effectively UNIQUE (gw_uuid, sent_at) — and not a read-then-write, because a
// retry and its original can land on different broker replicas where a
// read-then-write would race. A client that re-stamps sent_at on retry defeats
// that constraint *silently*: both rows insert, and the same delivery window is
// counted twice in an append-only ledger where it can never be deleted, only
// superseded. Nothing on either side reports an error; the first symptom is a
// billing dispute.
//
// The practical shape is to serialize once with CanonicalBytes, hold those
// bytes, and resend exactly them until the broker answers 2xx or the report is
// abandoned. Concretely: prepare the bytes outside the retry loop, never
// inside it. Abandoning a heartbeat is correct and loses one window of
// counters; splitting or rebuilding it corrupts the ledger, so when the two
// are in tension prefer the loss.
//
// ReplayRule is a documentation anchor and has no behaviour.
type ReplayRule struct{}

// ErrorCode is the machine-readable half of an error response. Clients branch
// on this and never on Message.
//
// The taxonomy is closed: a client that receives an unknown code must treat it
// as RetryNever rather than guessing, because the codes that are safe to retry
// are exactly the ones enumerated here.
//
// There is no identity or authentication code, and its absence is structural
// rather than an omission — identity failures never reach a handler. See
// Identity.
type ErrorCode string

const (
	// CodeInvalidRequest is a malformed or unacceptable envelope: bad JSON, a
	// missing feed_id, an over-long relay_id. Deterministic in the request, so
	// retrying it unchanged cannot succeed.
	CodeInvalidRequest ErrorCode = "invalid_request"

	// CodeEntitlementDenied means this gateway is not entitled to the feed it
	// asked for. A licensing state, not a transient one.
	CodeEntitlementDenied ErrorCode = "entitlement_denied"

	// CodePlaneBindingMismatch means the connection's peer address does not
	// match the plane binding recorded for this gateway. Retrying from the same
	// place produces the same answer; it clears when the binding or the network
	// path is corrected, which is an operator action.
	CodePlaneBindingMismatch ErrorCode = "plane_binding_mismatch"

	// CodeConcurrencyCapped means the account is at its concurrent-session cap.
	//
	// This is the one code whose HTTP status is a deliberate choice rather than
	// the obvious one: it is 409, not 429. A licensing-state conflict that
	// landed in a client's generic rate-limit backoff would be retried into
	// silence — backed off, aggregated with unrelated 429s, and never surfaced
	// to the operator who could raise the cap. It carries Retry-After and must
	// be honoured on its own path. See RetryAfterHeader and ParseRetryAfter.
	//
	// It must never be returned for a feed the gateway already holds an active
	// ticket for: the idempotency lookup precedes the cap check, so a retried
	// Mint cannot be capped against its own ticket. See MintIdempotency.
	CodeConcurrencyCapped ErrorCode = "concurrency_capped"

	// CodeTicketNotRenewable means the named ticket cannot be renewed: it is
	// not active, or it is not this gateway's.
	//
	// Those two conditions are deliberately indistinguishable, and the status
	// is 404 for both. Separating them would make Renew an existence oracle for
	// other subscribers' ticket ids. The client's response is the same either
	// way — mint a fresh ticket — so no information is lost by conflating them.
	CodeTicketNotRenewable ErrorCode = "ticket_not_renewable"

	// CodeBodyTooLarge means the request body exceeded HeartbeatMaxBodyBytes.
	//
	// Not retryable, and specifically not retryable by splitting the report:
	// splitting produces different bytes under a different sent_at and breaches
	// ReplayRule. Abandon the window and fix the producer.
	CodeBodyTooLarge ErrorCode = "body_too_large"

	// CodePublicationFailed is a broker-side failure to publish an accepted
	// change. It is the broker's fault and is transient, so it is the one code
	// that takes ordinary backoff.
	CodePublicationFailed ErrorCode = "publication_failed"
)

// ErrorResponse is the body accompanying every 4xx and 5xx from the broker.
type ErrorResponse struct {
	// Code is the closed-taxonomy discriminator clients branch on.
	Code ErrorCode `json:"code"`

	// Message is human-readable and unstable. It is for logs and operators;
	// parsing it is a bug, which is why every behavioural distinction the
	// client needs is reachable from Code alone.
	Message string `json:"message"`
}

// Retry classifies what a client may do with a failed request. It is part of
// the contract rather than a client-side judgement call so that two independent
// gateway implementations cannot disagree about which failures are safe to
// repeat.
type Retry uint8

const (
	// RetryNever is a terminal answer for this request as written. Retrying it
	// unchanged produces the same result and only adds load; the fix is an
	// operator or producer change.
	RetryNever Retry = iota

	// RetryAfterHeader means retry only after the delay in the response's
	// Retry-After header, on a path separate from generic backoff so the
	// condition stays visible to operators. Currently CodeConcurrencyCapped
	// alone. Read the delay with ParseRetryAfter, never with a bare
	// strconv.Atoi — see RetryAfterHeaderName for why that distinction bites.
	RetryAfterHeader

	// RetryBackoff means retry with ordinary jittered exponential backoff.
	RetryBackoff
)

// RetryAfterHeaderName is the response header carrying the delay for
// RetryAfterHeader, named as a constant for the same reason RenewTicketIDParam
// is: the broker writes it and the gateway reads it, and a re-spelling on
// either side is a silent miss rather than a compile error.
const RetryAfterHeaderName = "Retry-After"

// The Retry-After format is pinned to delta-seconds, and this is the one wire
// detail in this file whose drift mode is silent in the dangerous direction.
//
// RFC 9110 §10.2.3 permits both "Retry-After: 120" and an HTTP-date. A broker
// emitting an HTTP-date against a gateway reaching for strconv.Atoi yields 0,
// and the gateway retries immediately — turning the deliberate 409-not-429
// choice at CodeConcurrencyCapped, whose whole purpose was to keep a licensing
// conflict gentle and visible, into a *tighter* loop than the generic backoff
// it was chosen over. Nothing errors; an operator just sees a hot client.
//
// Delta-seconds is the pinned form because a gateway already cannot trust its
// own clock well enough for sent_at freshness to be checkable (see Heartbeat),
// so an absolute deadline would resolve against a clock this contract declines
// to rely on anywhere else.
const (
	// MinRetryAfterSeconds is the smallest meaningful delay. Zero or negative
	// means "retry now", which is precisely the hot loop above, so it is
	// rejected rather than honoured.
	MinRetryAfterSeconds = 1

	// MaxRetryAfterSeconds bounds the delay at TicketTTL. A wait longer than a
	// ticket's maximum lifetime cannot be about ticket availability, so a
	// larger value is clamped rather than obeyed.
	MaxRetryAfterSeconds = int64(TicketTTL / time.Second)
)

// ParseRetryAfter reads the delay a RetryAfterHeader response carries.
//
// It returns ok=false for a missing, malformed, non-integer, zero, or negative
// value — including a well-formed HTTP-date, which this contract does not use.
// A caller that gets ok=false MUST fall back to its ordinary jittered backoff
// and MUST NOT retry immediately; that fallback is the entire point of
// returning a boolean rather than a zero duration a caller might sleep on.
//
// A value above MaxRetryAfterSeconds is clamped to it and returns ok=true: the
// broker asking for a longer wait than a ticket can live is honoured as far as
// it can be, rather than discarded down to generic backoff.
//
// Both sides use this rather than each parsing the header, so the format can
// only be got wrong in one place.
func ParseRetryAfter(header http.Header) (time.Duration, bool) {
	raw := strings.TrimSpace(header.Get(RetryAfterHeaderName))
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < MinRetryAfterSeconds {
		return 0, false
	}
	if seconds > MaxRetryAfterSeconds {
		seconds = MaxRetryAfterSeconds
	}
	return time.Duration(seconds) * time.Second, true
}

// FormatRetryAfter renders d in the pinned delta-seconds form, rounding up so a
// sub-second remainder never becomes a shorter wait than intended and a delay
// below one second never becomes 0.
//
// The broker writes the header with it. It clamps to MaxRetryAfterSeconds so a
// value ParseRetryAfter would clamp on read is never emitted in the first
// place.
func FormatRetryAfter(d time.Duration) string {
	seconds := int64((d + time.Second - 1) / time.Second)
	if seconds < MinRetryAfterSeconds {
		seconds = MinRetryAfterSeconds
	}
	if seconds > MaxRetryAfterSeconds {
		seconds = MaxRetryAfterSeconds
	}
	return strconv.FormatInt(seconds, 10)
}

// RetryTransportFailure is the posture for a failure that produced no status
// code at all: TLS handshake failure, connection refused, timeout.
//
// It is RetryBackoff, and that is a deliberate choice given that a rejected
// certificate is *also* a transport failure and is not transient. The
// alternative — treating handshake failures as terminal — would strand a
// gateway across an ordinary broker restart or certificate-rotation race, which
// is the common case, in order to react faster to the rare misconfiguration.
// Backing off is correct for both; what distinguishes them is that a gateway
// stuck at maximum backoff on repeated handshake failure has a certificate
// problem, and the gateway should say so in its logs rather than infer
// terminality and stop.
const RetryTransportFailure = RetryBackoff

// statusByCode is the single source for both directions of the code/status
// mapping. Keeping one table means StatusForCode and CodeForStatus cannot drift
// into disagreeing, which they would if each carried its own switch.
//
// Note that it is deliberately not injective: CodeEntitlementDenied and
// CodePlaneBindingMismatch share 403. There is therefore no inverse
// CodeForStatus function, and that is the intended shape rather than a missing
// convenience: the status is a transport-level summary and the body's Code is
// the discriminator. A client that recovered the code from the status would be
// unable to tell those two apart, and would branch on a distinction it had
// guessed rather than one it had read.
var statusByCode = map[ErrorCode]struct {
	status int
	retry  Retry
}{
	CodeInvalidRequest:       {http.StatusBadRequest, RetryNever},
	CodeEntitlementDenied:    {http.StatusForbidden, RetryNever},
	CodePlaneBindingMismatch: {http.StatusForbidden, RetryNever},
	CodeConcurrencyCapped:    {http.StatusConflict, RetryAfterHeader},
	CodeTicketNotRenewable:   {http.StatusNotFound, RetryNever},
	CodeBodyTooLarge:         {http.StatusRequestEntityTooLarge, RetryNever},
	CodePublicationFailed:    {http.StatusServiceUnavailable, RetryBackoff},
}

// ErrUnknownErrorCode reports a code outside the closed taxonomy.
var ErrUnknownErrorCode = errors.New("unknown broker error code")

// StatusForCode returns the HTTP status the broker answers with for code.
//
// The broker uses it to write responses and the gateway's tests use it to
// assert against them, so a status change is a one-line change in one table
// rather than a coordinated edit on both sides.
func StatusForCode(code ErrorCode) (int, error) {
	entry, ok := statusByCode[code]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnknownErrorCode, code)
	}
	return entry.status, nil
}

// RetryForCode returns what a client may do with a response carrying code.
//
// An unrecognized code is RetryNever with an error: a client that met a code
// from a newer broker must not guess that it is safe to repeat.
func RetryForCode(code ErrorCode) (Retry, error) {
	entry, ok := statusByCode[code]
	if !ok {
		return RetryNever, fmt.Errorf("%w: %q", ErrUnknownErrorCode, code)
	}
	return entry.retry, nil
}

// ValidateMintRequest checks a mint envelope against the bounds both sides are
// held to.
//
// The gateway calls it before sending and the broker calls it on ingest. That
// is not redundant: the client call turns a server round-trip into a local
// error, and the server call is the one that actually enforces, because the
// broker cannot assume the client ran it.
func ValidateMintRequest(req MintRequest) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidTransport, fmt.Sprintf(format, args...))
	}
	if req.FeedID == "" || !utf8.ValidString(req.FeedID) || len(req.FeedID) > MaxFeedIDBytes {
		return invalid("feed_id must be non-empty, valid UTF-8, and at most %d bytes", MaxFeedIDBytes)
	}
	if req.RelayID == "" || !utf8.ValidString(req.RelayID) || len(req.RelayID) > MaxRelayIDBytes {
		return invalid("relay_id must be non-empty, valid UTF-8, and at most %d bytes", MaxRelayIDBytes)
	}
	return nil
}

// ValidateTicket checks a ticket response.
//
// The gateway calls it on every Mint and Renew reply. A ticket whose not_after
// it cannot parse is a ticket it cannot schedule renewal against, and silently
// falling back to TicketTTL there would reintroduce exactly the clamp bug
// described at Ticket.NotAfter — so this is a hard failure rather than a
// degraded mode.
func ValidateTicket(ticket Ticket) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidTransport, fmt.Sprintf(format, args...))
	}
	if err := validateCanonicalUUID(ticket.TicketID); err != nil {
		return invalid("ticket_id must be a canonical, non-nil, lowercase UUID: %s", err)
	}
	if _, err := parseCanonicalUTCTimestamp(ticket.NotAfter); err != nil {
		return invalid("not_after must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	return nil
}

// ErrInvalidTransport wraps every validation failure in this file, mirroring
// ErrInvalidHeartbeat, so callers match the class rather than message text.
var ErrInvalidTransport = errors.New("invalid gateway transport envelope")
