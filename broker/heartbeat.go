// Package broker defines the gateway-to-session-broker control-plane wire
// contract for bcast-shred-gw.
//
// This package is deliberately transport-free: it is types plus validation,
// with no mTLS session, no HTTP client, and no I/O. The session broker's
// heartbeat ingest (W2b deliverable 6) does not exist yet, so the receiver
// cannot be written against a live endpoint. Publishing the payload contract
// on its own lets the producer freeze first and the consumer implement against
// a pinned schema instead of a guess.
//
// Two fields here are load-bearing beyond liveness:
//
//   - Version is the only field-rollback lever the deployed binary has. W4
//     enforces a minimum supported version at the billing edge, so a heartbeat
//     that omits it is not recallable and is rejected rather than accepted with
//     an empty string.
//   - FeedReport.Erasure is the receiver-computed delivery report the customer
//     audits its own SLA against. It is the same erasure.Window the binary
//     exposes on /metrics, carried verbatim so the two surfaces cannot diverge.
package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/blockcast/go-amt/erasure"
)

const (
	// HeartbeatSchema versions the envelope below. Any change to the field set
	// requires a new schema string, not a silent edit to this one.
	//
	// Every timestamp in this envelope (sent_at, first_packet_at,
	// last_packet_at) is UTC in one exact spelling, which is narrower than
	// "RFC 3339" and is the spelling a non-Go implementer most often gets
	// wrong:
	//
	//   - The zone is the literal "Z". "+00:00" is a valid RFC 3339 UTC
	//     spelling and is REJECTED here.
	//   - Fractional seconds are present only when non-zero, and carry no
	//     trailing zeros. "…:00Z" is required; "…:00.000Z" is REJECTED.
	//     "…:59.5Z" is required; "…:59.500Z" is REJECTED.
	//
	// This is Go's time.RFC3339Nano output, and the reason for it is that the
	// broker's ledger diffs heartbeats byte-for-byte: one instant must have
	// exactly one spelling. Producers in other languages must trim rather than
	// use their default ISO-8601 output — JavaScript's toISOString() emits
	// ".000Z" and Python's isoformat() emits "+00:00", and both are rejected.
	// Go producers should call FormatTimestamp instead of formatting inline.
	//
	// The gap_ms_hist keys are the second Go-specific spelling, and unlike the
	// timestamp rule this one CANNOT be enforced by validation. Two of the five
	// fixed bucket names contain < and >, which encoding/json escapes by
	// default, so they appear on the wire as "\u003c1" and "\u003e=32" — never
	// as the raw characters. A producer that emits the semantically identical
	// "<1" and ">=32" (the default byte form for JavaScript, Python, Rust, and
	// for a Go producer using json.Encoder with SetEscapeHTML(false)) decodes
	// to exactly the same document and passes every check here, yet is not
	// byte-identical.
	//
	// Because validation operates on decoded structs, it is structurally blind
	// to this: there is no check that could reject the unescaped form. Byte
	// diffability is therefore a BROKER obligation, not a producer one — the
	// ledger canonicalizes on ingest by re-encoding through CanonicalBytes
	// rather than diffing the bytes as received. Producers are not required to
	// match Go's escaping, and are not penalized for failing to. See
	// CanonicalBytes for the single implementation both sides share.
	//
	// Ingest bounds are declared together on this contract so a producer can
	// discover them without reading the validator: at most MaxFeeds feed
	// reports per heartbeat, at most MaxVersionBytes in version, at most
	// MaxFeedIDBytes in each feed_id, at most MaxSetsTotal in each feed's
	// erasure.sets_total, and at most MaxWindowMS in each feed's
	// erasure.window_ms.
	HeartbeatSchema = "blockcast.shred-gw-heartbeat.v1"

	// HeartbeatInterval is the fixed v1 emission cadence.
	HeartbeatInterval = 30 * time.Second

	// erasureReportSchema is the newest per-feed delivery report schema ingest
	// understands, and the one erasure's producer emits. Bounded rather than
	// open-ended so an envelope cannot smuggle a future report shape past a
	// broker that does not know the shape's rules.
	erasureReportSchema = 2

	// erasureReportSchemaFloor is the oldest per-feed report schema ingest
	// still accepts. Ingest accepts the closed range
	// [erasureReportSchemaFloor, erasureReportSchema].
	//
	// The range exists because the schema check is exact-match, so a
	// single-value pin makes any bump a flag day — and one that cannot be made
	// atomic. The validator and the producers sit on opposite sides of a module
	// boundary consumed as a version pin, and the producers are independently
	// deployed fleet software, so there is no ordering in which both move at
	// once: whichever moves first rejects the other. Rejection is also
	// whole-heartbeat rather than per-feed, since this error exits
	// ValidateHeartbeat, so one report at the wrong schema discards the
	// liveness and delivery evidence for up to MaxFeeds-1 well-formed feeds
	// that did nothing wrong. For a register whose job is reproducing a
	// historical delivery record, that is evidence loss for as long as the
	// version skew lasts. Accepting a range costs one comparison; a flag day
	// costs the record.
	//
	// RETIRING A SCHEMA is therefore gated on producer evidence, not on a
	// date: raise this floor only once a census shows no deployed producer
	// still emits the schema being dropped. A wall-clock expiry does not
	// remove the flag day, it just relocates it to a moment when nobody is
	// watching. See the census gate on FeedReport.Erasure for what has to be
	// observable before the floor can move to 2.
	erasureReportSchemaFloor = 1

	// erasureWindowSchema is the schema from which erasure.window_start and
	// erasure.window_ms are REQUIRED, and below which they must be absent.
	//
	// Held separately from the floor and the newest schema so the two
	// questions stay independent: which schemas ingest tolerates is a
	// deployment fact that changes as the fleet moves, whereas which schema
	// introduced these fields is a permanent fact about the wire format.
	// Collapsing them into one constant would make the field rules silently
	// follow the deployment window.
	erasureWindowSchema = 2

	// erasureFractionEpsilon bounds the disagreement tolerated between a
	// reported ErasureFraction and the ratio recomputed from the two integers
	// it derives from.
	//
	// A Go producer using erasure.Fraction agrees exactly. The tolerance exists
	// for producers that serialize the ratio at fixed decimal precision, whose
	// worst-case rounding error is half an ulp of the last place they emit:
	// 5e-7 for the %.6f / toFixed(6) / round(x, 6) that a non-Go producer
	// reaches for by default. At 1e-6 that case is admitted, which is what the
	// rationale above claims; the previous 1e-9 admitted only ~10-significant-
	// digit output and rejected six-decimal producers for most ratios (1/3 and
	// 2/7 among them).
	//
	// It cannot mask a wrong integer, but only because SetsTotal is bounded.
	// The smallest nonzero disagreement a miscounted set can produce is
	// 1/SetsTotal, so an off-by-one survives this check exactly when
	// 1/SetsTotal <= erasureFractionEpsilon — that is, from SetsTotal = 1e6
	// upward. The honest in-process producer never reaches that, but the reason
	// this recompute exists at all is that ingest is untrusted, and an untrusted
	// producer picks SetsTotal freely. MaxSetsTotal is what makes the claim hold
	// for every accepted heartbeat rather than only for well-behaved ones. See
	// MinFractionDecimalPlaces.
	erasureFractionEpsilon = 1e-6

	// MinFractionDecimalPlaces is the precision a producer should serialize
	// erasure_fraction at so that ingest accepts it for any ratio.
	//
	// It is guidance, not an enforceable rule, and the distinction matters
	// because the failure it prevents is data-dependent. Validation checks only
	// that the reported fraction agrees with sets_erased / sets_total within
	// erasureFractionEpsilon, so coarser output is accepted whenever the ratio
	// happens to be exactly representable at the precision emitted: 2/50 at two
	// decimal places (0.04) and 1/2 at one (0.5) both pass. The first window
	// that erases 1 set in 3 is what fails a three-decimal producer, so a
	// producer team can ship coarse output, pass every smoke test built on round
	// ratios, and break in production.
	//
	// Emitting fewer places than this is therefore not rejected as such — it is
	// rejected for the ratios it cannot represent. Nor could validation reject
	// it as such: it operates on decoded structs, and "0.04", "0.040000" and
	// "4e-2" decode to the same float64, so the digit count the producer wrote
	// is not recoverable at the point the check runs. This is the same
	// structural blindness the gap_ms_hist escaping rule has, and it has the
	// same resolution: the broker canonicalizes the value in CanonicalBytes
	// rather than asking the producer to match Go byte-for-byte.
	//
	// Go producers should call erasure.Fraction and are float64-exact.
	MinFractionDecimalPlaces = 6

	// MaxSetsTotal bounds each feed's erasure.sets_total, and exists so
	// erasureFractionEpsilon cannot hide a miscounted set.
	//
	// It is derived from the tolerance rather than picked: an off-by-one erased
	// set moves the fraction by 1/SetsTotal, which the check catches only while
	// 1/SetsTotal > erasureFractionEpsilon. That makes 999,999 — one below
	// 1/erasureFractionEpsilon — the largest sets_total for which the recompute
	// still has teeth, and TestMaxSetsTotalIsTheLargestBoundThatCatchesAnOffByOne
	// pins both sides of that boundary so widening the tolerance cannot silently
	// unbound this.
	//
	// The bound is far above anything a real window reaches, so it costs an
	// honest gateway nothing — but the margin must be measured against the
	// window that actually fills sets_total, which is the receiver's
	// --report-interval drain, not HeartbeatInterval. Those are independently
	// configured, and --report-interval is legal up to five minutes, so the
	// worst case is the long one: production carries 64 shreds per FEC set —
	// 32 data plus 32 coding, verified against 1,044,775 consecutive datagrams
	// in the notes on shred.WireHeaderSize — so 999,999 sets over a five-minute
	// window is 213,333 shreds per second on a single feed, against the 30,000
	// shred/s the receiver sizes its buffers for. That is 7.1x of headroom, not
	// the ~71x that measuring against a 30-second heartbeat would suggest. Put
	// the other way: 30,000 shred/s for a full five-minute window is 140,625
	// sets, 14% of the bound.
	//
	// A producer whose own window somehow exceeds this must drain and emit the
	// report anyway, never clamp sets_total to the bound. Clamping fabricates a
	// delivery figure — it silently rewrites the denominator an SLA is computed
	// against — whereas an over-bound report is rejected loudly at ingest and
	// the operator finds out. Reaching the bound at the sizing rate takes about
	// 35 minutes of accumulation, which is a drain delayed past seven times the
	// maximum legal interval; at that point the reporter ticker has stopped
	// firing and the lost report is not the incident.
	MaxSetsTotal = 999_999

	// MaxWindowMS bounds erasure.window_ms.
	//
	// Deliberately far above the five-minute maximum drain interval rather
	// than equal to it. window_ms is MEASURED elapsed, not the configured
	// interval, and the two diverge upward exactly under load: one serial
	// ticker drains every feed and Go's ticker drops ticks when the receiver
	// is slow, so a gateway configured at the legal maximum legitimately
	// reports longer windows precisely when the box is struggling — the
	// condition an SLA dispute is about. A bound at the configured maximum
	// would reject those heartbeats wholesale, which is the same
	// confidently-clean-feed failure that pinning the drain interval was
	// rejected for, reached through the validator instead.
	//
	// 40 minutes is chosen to sit above the point where MaxSetsTotal binds
	// first: at the 30,000 shred/s rate the receiver sizes for, 999,999 sets
	// accumulate in about 35 minutes. So a drain delayed far enough to matter
	// is rejected by the count bound, whose message names the delivery figure
	// an operator needs, rather than by a duration bound that only reports
	// that the clock looked odd. This is a sanity bound against a garbage or
	// hostile value, not an assertion about scheduling.
	//
	// A producer whose own window exceeds this must emit the report anyway and
	// never clamp window_ms, for the same reason sets_total must not be
	// clamped: clamping fabricates the interval an SLA is normalized against,
	// whereas an over-bound report is rejected loudly and the operator finds
	// out.
	MaxWindowMS = 2_400_000

	// MaxVersionBytes bounds the version string.
	MaxVersionBytes = 128

	// MaxFeedIDBytes bounds each feed_id.
	MaxFeedIDBytes = 128

	// MaxFeeds bounds the per-heartbeat fan-out. The real defence against an
	// oversized body is a transport-level limit, which does not exist yet on
	// the ingest side; this keeps every ingest bound declared in one place and
	// documents the expected order of magnitude.
	//
	// Exported because a gateway with more feeds than this is rejected, and a
	// non-Go producer has no other way to discover the bound it is being held
	// to.
	MaxFeeds = 4096
)

// ErrInvalidHeartbeat wraps every validation failure so callers can match the
// class without matching message text.
var ErrInvalidHeartbeat = errors.New("invalid gateway heartbeat")

// version is stamped at build time:
//
//	go build -ldflags "-X github.com/blockcast/go-amt/broker.version=v1.4.0"
//
// The default is deliberately not a plausible release string: an unstamped
// build must be obvious in the broker's records rather than blending in with
// stamped ones.
var version = "dev-unstamped"

// Version returns the build-stamped version string reported in every
// heartbeat.
func Version() string { return version }

// FeedReport is one feed's slice of a heartbeat: the liveness counters the
// broker meters on, plus the receiver-computed delivery report.
//
// FirstPacketAt and LastPacketAt are canonical UTC timestamps in the exact
// spelling described on HeartbeatSchema, or both empty when the feed has not
// yet received a packet. They are reported per feed rather than per gateway so
// a single dead feed is visible behind otherwise healthy aggregate traffic.
//
// The pair and Packets state one fact together, so they are validated together:
// an empty pair requires Packets == 0, and a populated pair requires
// Packets > 0. Bytes must be 0 when Packets is 0, but is *not* required to be
// positive when Packets is — a zero-length UDP datagram is legal and counts as
// a packet that carried no bytes.
//
// Erasure is the receiver's delivery report for the feed, and carries its own
// schema number distinct from this envelope's. Ingest accepts the closed range
// [erasureReportSchemaFloor, erasureReportSchema]; the number decides how the
// counts must be read, so it is validated together with the fields it governs
// (see validateReportWindowBounds).
//
// From schema 2, sets_total and sets_erased are a COUNTER DELTA over the
// half-open interval [window_start, window_start + window_ms), and a broker
// deduplicates on (feed_id, window_start) before summing. Delta rather than
// gauge deliberately: a gauge would forbid the cross-heartbeat aggregation
// billing needs, whereas a delta plus an identity makes a repeat identifiable
// and idempotent to drop. Both halves are needed. The receiver's metrics
// surface republishes the last drained window on every scrape, and the drain
// interval is independent of HeartbeatInterval and legal up to five minutes,
// so at the maximum the same window is carried by ten consecutive heartbeats:
// summing without deduplicating overstates delivery ten-fold, and refusing to
// sum at all leaves billing unable to aggregate. window_ms alone would not
// settle it, since ten identical windows each reporting the same duration are
// indistinguishable from ten genuinely distinct ones — which is why the
// identity ships alongside the duration rather than after it.
//
// window_ms is measured elapsed, not the producer's configured interval, and
// window_start is a timestamp rather than a counter because a counter resets
// on restart and can then collide across distinct windows. See erasure.Window
// for both arguments in full, and MaxWindowMS for why the duration's bound is
// far above the maximum configured interval rather than equal to it.
//
// Schema 1 carried neither field, and a broker cannot recover the interval for
// such a report: first_packet_at and last_packet_at bound observed traffic
// rather than the scoring window, and while the duration is nominally
// arrivals/r_mean, the numerator is the tracker's accepted-shred count rather
// than Packets, so this contract does not license that division. For a feed
// that received nothing r_mean is 0 and the duration is unrecoverable by any
// route — precisely the silent feed an SLA dispute is about. A broker must
// therefore keep SLA math for a schema-1 report per-gateway, and must not
// normalize its counts against a window of a different length. Schema 2 is
// what lifts that restriction, and it is the reason schema 1 is on a
// retirement path rather than supported indefinitely.
//
// RETIREMENT GATE for schema 1: raise erasureReportSchemaFloor to 2 only on
// evidence that no deployed producer still emits schema 1 — not on a date. The
// evidence has to be a census of PRODUCERS, and the per-producer signal
// already exists: each gateway publishes the schema of its last drained window
// as the report_schema gauge on its own /metrics (receiver.ReceiverMetrics).
// What does not exist is an aggregate view of it — either central scraping of
// that gauge across the fleet, or a broker-side record of the per-feed schema
// each ingest accepted. Either satisfies the gate; neither is in place, so the
// floor stays at 1. Building one is a precondition for the floor moving, not a
// follow-up to it, because a census that cannot see a straggler is
// indistinguishable from one that found none.
//
// Until then the range costs one comparison and buys the fleet an upgrade
// window it cannot otherwise have.
type FeedReport struct {
	FeedID        string         `json:"feed_id"`
	Packets       uint64         `json:"packets"`
	Bytes         uint64         `json:"bytes"`
	FirstPacketAt string         `json:"first_packet_at"`
	LastPacketAt  string         `json:"last_packet_at"`
	Erasure       erasure.Window `json:"erasure"`
}

// Heartbeat is the 30s gateway-to-broker liveness and delivery message.
//
// Feeds is a slice rather than a map keyed by feed ID so that ordering is an
// explicit property of the wire form: ValidateHeartbeat requires it sorted by
// FeedID, which makes two heartbeats with the same content byte-identical and
// therefore diffable in the broker's ledger.
//
// SentAt carries no freshness or clock-skew bound, deliberately. Validation is
// a pure function of the payload and cannot see the receive time, so deciding
// how stale a heartbeat may be — and how far a gateway's clock may drift — is
// the broker's policy call at ingest, not this contract's.
//
// Decoding into this struct is NOT verbatim retention. The decode is
// deliberately permissive — a field a newer gateway adds is dropped silently
// rather than rejected, because refusing to parse would stop a v2 gateway
// heartbeating to a v1 broker at all, a worse failure for a liveness message.
// The consequence is that re-encoding a decoded Heartbeat cannot reproduce an
// unknown field that was never retained. W4a must persist the raw request body
// (json.RawMessage or the untouched bytes) if it needs the object back exactly
// as sent; CanonicalBytes is for diffing, not for archival.
//
// CanonicalBytes has no caller in this repository yet, so the ingest sequence
// it belongs to is stated here rather than left to be inferred. A broker
// receiving a heartbeat must, in this order:
//
//  1. Decode the request body into a Heartbeat.
//  2. Call ValidateHeartbeat and reject on error. Canonicalization is not a
//     substitute: it normalizes the form of a report, not its truth.
//  3. Call CanonicalBytes and store what it returns as the ledger's diffable
//     form, alongside the raw body if verbatim retention is needed.
//
// Step 2 before step 3 is partly enforced rather than only documented, and the
// split matters because the enforced part is narrow. CanonicalBytes recomputes
// erasure_fraction, so it refuses a heartbeat whose fraction disagrees with its
// own integers instead of overwriting the evidence, and it re-bounds sets_total
// and re-checks the window's three floats for finiteness because that refusal
// depends on both. Everything else is honour-system: sets_erased <= sets_total,
// the [0,1] range of the fraction, the feed-activity pairing, the UUID, the
// schema string, the field bounds — none of it is re-checked here, so every
// field CanonicalBytes emits beyond erasure_fraction is exactly as trustworthy
// as step 2 made it. A caller that skips step 2 gets canonical bytes, not
// validated ones.
type Heartbeat struct {
	Schema  string       `json:"schema"`
	GWUUID  string       `json:"gw_uuid"`
	Version string       `json:"version"`
	SentAt  string       `json:"sent_at"`
	Feeds   []FeedReport `json:"feeds"`
}

// CanonicalBytes renders hb in the one byte form the broker's ledger diffs
// against, and is the single implementation both sides share.
//
// It exists because byte diffability cannot be a producer obligation, and there
// are two independent reasons for that, both of which it closes:
//
//   - Spelling. The gap_ms_hist keys contain < and >, encoding/json escapes
//     them by default, and a producer in any other language emits the unescaped
//     form. Re-encoding through Go's marshaller normalizes it.
//   - Value. erasure_fraction is a float the producer serializes at a precision
//     of its choosing, so a Go producer emitting 0.3333333333333333 and a
//     six-decimal producer emitting 0.333333 describe the same 1-of-3 window
//     and both pass ValidateHeartbeat, which only requires agreement within
//     erasureFractionEpsilon. Marshalling as received would preserve that
//     difference. CanonicalBytes therefore recomputes the fraction from
//     sets_erased and sets_total, which are the authoritative integers
//     validateErasureReport already checks it against.
//
// In both cases the two forms decode to the same document and both pass
// ValidateHeartbeat — validation operates on decoded structs and is
// structurally blind to escaping and to emitted precision alike — so a ledger
// that diffed bytes as received would report two identical reports as
// different, with nothing for the producer to have done differently and no
// check able to warn it. Canonicalizing on ingest removes both hazards for
// every producer at once.
//
// Recomputing is only safe if it cannot launder a wrong number, so a fraction
// that disagrees with its integers by more than the tolerance is rejected
// rather than replaced: a misbehaving producer must not be able to reach a
// valid-looking ledger entry by way of this function. That check is a
// consistency check, not a validity check, and the difference is worth stating
// because "refuses a heartbeat whose fraction disagrees with its own integers"
// reads like the latter: a report claiming sets_erased 40 of sets_total 10 with
// erasure_fraction 4.0 is internally consistent and canonicalizes cleanly here,
// while ValidateHeartbeat rejects it. Agreeing with integers the producer lied
// about in both places is the correct behaviour for a consistency check, and it
// is the reason step 2 is not optional. The one thing this check does need is a
// bounded denominator, which is why SetsTotal is re-bounded here rather than
// taken on trust from a step that may have been skipped.
//
// Beyond that field CanonicalBytes canonicalizes form, not truth — see the
// numbered ingest sequence on Heartbeat for the order it must be called in.
func CanonicalBytes(hb Heartbeat) ([]byte, error) {
	canonicalizeFailed := func(index int, feedID string, format string, args ...any) error {
		return fmt.Errorf("%w: canonicalizing heartbeat: feeds[%d] (%s): %s",
			ErrInvalidHeartbeat, index, feedID, fmt.Sprintf(format, args...))
	}

	if len(hb.Feeds) > 0 {
		// hb arrives by value but Feeds shares the caller's backing array, so
		// recomputing in place would rewrite the caller's heartbeat. Copying
		// also keeps a nil Feeds nil, since the envelope's wire form for a
		// gateway subscribed to nothing is "feeds":null rather than [].
		feeds := make([]FeedReport, len(hb.Feeds))
		copy(feeds, hb.Feeds)
		for i := range feeds {
			window := &feeds[i].Erasure
			// The disagreement check below is only as strong as its denominator
			// is bounded: an off-by-one moves the fraction by 1/SetsTotal, so
			// from SetsTotal = 1e6 upward the tolerance admits a miscounted set
			// and the recompute would overwrite the producer's wrong fraction
			// with a valid-looking one — laundering the very evidence this
			// function refuses to discard. ValidateHeartbeat rejects such a
			// report at step 2, but the whole point of recomputing here is to
			// be the cheap backstop for when step 2 was skipped, so the bound
			// has to be repeated rather than assumed. See MaxSetsTotal.
			if window.SetsTotal > MaxSetsTotal {
				return nil, canonicalizeFailed(i, feeds[i].FeedID,
					"erasure.sets_total %d exceeds MaxSetsTotal %d, so the fraction check below cannot detect an off-by-one; ValidateHeartbeat must run first",
					window.SetsTotal, MaxSetsTotal)
			}
			// The three floats are checked before the comparison below, which
			// NaN would pass vacuously and then have the recompute silently
			// replace. r_mean and r_peak_100ms are not recomputed, but they are
			// checked here too: encoding/json refuses them anyway, and its
			// error names neither the field nor the feed, which is unactionable
			// across MaxFeeds reports.
			if err := requireFinite("erasure.erasure_fraction", window.ErasureFraction); err != nil {
				return nil, canonicalizeFailed(i, feeds[i].FeedID, "%s", err)
			}
			if err := requireFinite("erasure.r_mean", window.RMean); err != nil {
				return nil, canonicalizeFailed(i, feeds[i].FeedID, "%s", err)
			}
			if err := requireFinite("erasure.r_peak_100ms", window.RPeak100MS); err != nil {
				return nil, canonicalizeFailed(i, feeds[i].FeedID, "%s", err)
			}
			expected := erasure.Fraction(window.SetsErased, window.SetsTotal)
			if math.Abs(window.ErasureFraction-expected) > erasureFractionEpsilon {
				return nil, canonicalizeFailed(i, feeds[i].FeedID,
					"erasure.erasure_fraction %v disagrees with sets_erased %d / sets_total %d (= %v); ValidateHeartbeat must run first",
					window.ErasureFraction, window.SetsErased, window.SetsTotal, expected)
			}
			window.ErasureFraction = expected
		}
		hb.Feeds = feeds
	}

	encoded, err := json.Marshal(hb)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalizing heartbeat: %s", ErrInvalidHeartbeat, err)
	}
	return encoded, nil
}

// ValidateHeartbeat rejects non-canonical or incomplete wire data.
//
// It is written to be run by both sides: the gateway calls it before sending
// so a malformed heartbeat fails at the producer where the context is, and the
// broker calls it on ingest so a hand-rolled or downgraded client cannot
// admit a shape the ledger cannot reproduce.
func ValidateHeartbeat(hb Heartbeat) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidHeartbeat, fmt.Sprintf(format, args...))
	}

	if hb.Schema != HeartbeatSchema {
		return invalid("schema must be %q", HeartbeatSchema)
	}
	if err := validateCanonicalUUID(hb.GWUUID); err != nil {
		return invalid("gw_uuid must be a canonical, non-nil, lowercase UUID: %s", err)
	}
	// An empty version is not a degraded heartbeat, it is an unrecallable one.
	if hb.Version == "" || !utf8.ValidString(hb.Version) || len(hb.Version) > MaxVersionBytes {
		return invalid("version must be non-empty, valid UTF-8, and at most %d bytes", MaxVersionBytes)
	}
	if _, err := parseCanonicalUTCTimestamp(hb.SentAt); err != nil {
		return invalid("sent_at must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	if len(hb.Feeds) > MaxFeeds {
		return invalid("feeds must contain at most %d entries, got %d", MaxFeeds, len(hb.Feeds))
	}

	var previousFeedID string
	for i, feed := range hb.Feeds {
		if feed.FeedID == "" || !utf8.ValidString(feed.FeedID) || len(feed.FeedID) > MaxFeedIDBytes {
			return invalid("feeds[%d].feed_id must be non-empty, valid UTF-8, and at most %d bytes", i, MaxFeedIDBytes)
		}
		// Sorted-and-strictly-increasing rejects duplicates and unsorted input
		// in one comparison. Duplicates matter independently of ordering: two
		// reports for one feed would double-count delivery in the ledger.
		if i > 0 && feed.FeedID <= previousFeedID {
			return invalid("feeds must be sorted by feed_id and unique, got %q after %q", feed.FeedID, previousFeedID)
		}
		previousFeedID = feed.FeedID

		if err := validateFeedActivity(feed); err != nil {
			return invalid("feeds[%d] (%s): %s", i, feed.FeedID, err)
		}
		if err := validateErasureReport(feed.Erasure); err != nil {
			return invalid("feeds[%d] (%s): %s", i, feed.FeedID, err)
		}
	}

	return nil
}

// validateErasureReport checks the delivery report a customer audits its SLA
// against.
//
// ErasureFraction is a pure function of SetsErased and SetsTotal, so on
// untrusted ingest it is recomputed rather than trusted: a downgraded or
// hand-rolled producer must not be able to ship a report whose headline number
// disagrees with the integers beneath it, because whichever field the billing
// edge happens to read would then decide the outcome. This is not reachable
// from our own tracker — it is reachable from any other producer, which is the
// threat model for the ingest side.
//
// The same threat model is why SetsTotal is bounded: an untrusted producer that
// could name any denominator could pick one large enough for
// erasureFractionEpsilon to swallow a miscounted set. See MaxSetsTotal.
//
// The accepted schema is a RANGE, [erasureReportSchemaFloor,
// erasureReportSchema], rather than a single pinned value. See
// erasureReportSchemaFloor for why a single value makes every bump a flag day
// that cannot be made atomic, and validateReportWindowBounds for the field
// rules that keep the schema number load-bearing across that range.
func validateErasureReport(window erasure.Window) error {
	if window.Schema < erasureReportSchemaFloor || window.Schema > erasureReportSchema {
		return fmt.Errorf("erasure.schema must be within [%d,%d], got %d",
			erasureReportSchemaFloor, erasureReportSchema, window.Schema)
	}
	if err := validateReportWindowBounds(window); err != nil {
		return err
	}
	if window.SetsTotal > MaxSetsTotal {
		return fmt.Errorf("erasure.sets_total must be at most %d, got %d", MaxSetsTotal, window.SetsTotal)
	}
	if window.SetsErased > window.SetsTotal {
		return fmt.Errorf("erasure.sets_erased %d exceeds sets_total %d", window.SetsErased, window.SetsTotal)
	}

	// NaN fails every ordered comparison, so a range check alone would admit
	// it. encoding/json cannot decode a NaN literal, but ValidateHeartbeat also
	// runs in-process on the producer side, where a NaN can be assigned
	// directly.
	if err := requireFinite("erasure.erasure_fraction", window.ErasureFraction); err != nil {
		return err
	}
	if err := requireFinite("erasure.r_mean", window.RMean); err != nil {
		return err
	}
	if err := requireFinite("erasure.r_peak_100ms", window.RPeak100MS); err != nil {
		return err
	}

	if window.ErasureFraction < 0 || window.ErasureFraction > 1 {
		return fmt.Errorf("erasure.erasure_fraction must be within [0,1], got %v", window.ErasureFraction)
	}
	if expected := erasure.Fraction(window.SetsErased, window.SetsTotal); math.Abs(window.ErasureFraction-expected) > erasureFractionEpsilon {
		return fmt.Errorf("erasure.erasure_fraction %v disagrees with sets_erased %d / sets_total %d (= %v)",
			window.ErasureFraction, window.SetsErased, window.SetsTotal, expected)
	}
	if window.RMean < 0 || window.RPeak100MS < 0 {
		return fmt.Errorf("erasure.r_mean and erasure.r_peak_100ms must not be negative, got %v and %v",
			window.RMean, window.RPeak100MS)
	}
	if window.GraceMS < 0 {
		return fmt.Errorf("erasure.grace_ms must not be negative, got %d", window.GraceMS)
	}
	return nil
}

func requireFinite(field string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return fmt.Errorf("%s must be a finite number, got %v", field, value)
	}
	return nil
}

// validateReportWindowBounds enforces the window fields PER SCHEMA, which is
// what keeps the schema number meaningful now that ingest accepts a range of
// them rather than one pinned value.
//
// Below erasureWindowSchema the fields must be ABSENT; from it they are
// REQUIRED. Enforcing both directions is the point. A range of accepted
// schemas is only safe if the number still decides the shape, and it would
// stop deciding anything if either direction were dropped:
//
//   - Absent-when-required would let a producer claim the newer schema and
//     omit the very fields the bump exists to add, and a consumer that
//     branches on the number would then normalize against a zero interval and
//     deduplicate on an empty identity — collapsing every window of that feed
//     onto one key.
//   - Present-when-absent-expected is the subtler one, and it is not merely
//     untidy. A schema-1 report carrying a window would be a report whose
//     number says "these counts are comparable within one producer only"
//     while its body says otherwise. Since a consumer decides how to treat
//     the counts from the number, the two would disagree about the same
//     bytes. Rejecting costs nothing — no producer emits that shape — and
//     keeps one reading of every accepted report.
//
// Note that "absent" is judged on the DECODED struct, so a JSON document that
// omits the keys and one that sends them at their zero values are the same
// thing here. That is deliberate: validation is structurally blind to the
// difference (see HeartbeatSchema on why byte-level distinctions are a broker
// obligation, not a producer one), so the rule is written in terms of what it
// can actually see. erasure.Window tags both fields omitempty so the
// canonical form of a schema-1 report is unchanged from before the fields
// existed.
func validateReportWindowBounds(window erasure.Window) error {
	if window.Schema < erasureWindowSchema {
		if window.WindowStart != "" || window.WindowMS != 0 {
			return fmt.Errorf(
				"erasure.window_start and erasure.window_ms must be absent at erasure.schema %d (they are introduced at schema %d), got %q and %d",
				window.Schema, erasureWindowSchema, window.WindowStart, window.WindowMS)
		}
		return nil
	}

	// Positive rather than non-negative: zero is what an absent field decodes
	// to, so admitting it here would silently re-open the absent-when-required
	// hole this function exists to close. A producer whose measured window
	// truncates below a millisecond reports the 1ms floor instead of zero; see
	// erasure.Tracker.DrainWindow.
	if window.WindowMS <= 0 || window.WindowMS > MaxWindowMS {
		return fmt.Errorf("erasure.window_ms must be within [1,%d], got %d", MaxWindowMS, window.WindowMS)
	}
	if _, err := parseCanonicalUTCTimestamp(window.WindowStart); err != nil {
		return fmt.Errorf("erasure.window_start must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	return nil
}

// validateFeedActivity enforces the two-state contract that the packet-time
// pair and the packet counter state jointly.
//
// Either the feed has seen no packet — both timestamps empty and Packets zero —
// or it has seen at least one: both timestamps canonical, first not after last,
// and Packets positive. A half-populated pair is rejected because it is
// ambiguous: the broker cannot tell "never received" from "lost the first
// timestamp". The counters are covered by the same rule for the same reason,
// since "packets=1200, never received a packet" is ambiguous in exactly the way
// the timestamp rule exists to prevent.
//
// Bytes is required to be zero only when Packets is. The converse is
// deliberately not enforced: a zero-length UDP datagram is legal, so a feed can
// hold a positive packet count with no payload bytes.
func validateFeedActivity(feed FeedReport) error {
	if feed.FirstPacketAt == "" && feed.LastPacketAt == "" {
		if feed.Packets != 0 {
			return fmt.Errorf("packets is %d but the feed reports never having received a packet", feed.Packets)
		}
		if feed.Bytes != 0 {
			return fmt.Errorf("bytes is %d but packets is 0", feed.Bytes)
		}
		return nil
	}
	if feed.FirstPacketAt == "" || feed.LastPacketAt == "" {
		return errors.New("first_packet_at and last_packet_at must both be set or both be empty")
	}
	if feed.Packets == 0 {
		return errors.New("packets is 0 but the feed reports a first and last packet time")
	}

	first, err := parseCanonicalUTCTimestamp(feed.FirstPacketAt)
	if err != nil {
		return fmt.Errorf("first_packet_at must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	last, err := parseCanonicalUTCTimestamp(feed.LastPacketAt)
	if err != nil {
		return fmt.Errorf("last_packet_at must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	if last.Before(first) {
		return errors.New("last_packet_at must not precede first_packet_at")
	}
	return nil
}

// canonicalTimestampRule spells out the accepted timestamp form in validation
// errors, so a rejected producer can fix its formatter from the broker's logs
// without reading this package. See HeartbeatSchema for the rationale.
const canonicalTimestampRule = `zone must be "Z" (not "+00:00"), and fractional seconds present only if non-zero with trailing zeros trimmed`

// FormatTimestamp renders t in the canonical form ValidateHeartbeat accepts —
// see HeartbeatSchema for the exact spelling and why it is narrower than
// RFC 3339. Callers should use it rather than formatting inline, so the
// producer cannot drift from the validator.
//
// It is a Go-only convenience. Producers in other languages must implement the
// documented rule directly; their default ISO-8601 output is rejected.
func FormatTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseCanonicalUTCTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("timestamp is not canonical UTC")
	}
	return parsed, nil
}

// validateCanonicalUUID accepts only the canonical lowercase 8-4-4-4-12 form
// and rejects the nil UUID.
//
// This is a handful of lines rather than a google/uuid dependency on purpose:
// the deliverable is one static CGO_ENABLED=0 binary, and uuid.Parse also
// accepts urn: and braced forms that would let two spellings of the same
// gateway identity into the ledger.
func validateCanonicalUUID(value string) error {
	const canonicalLen = 36
	if len(value) != canonicalLen {
		return errors.New("wrong length")
	}

	allZero := true
	for i := 0; i < canonicalLen; i++ {
		c := value[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return errors.New("misplaced separator")
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9':
			if c != '0' {
				allZero = false
			}
		case c >= 'a' && c <= 'f':
			allZero = false
		default:
			return errors.New("not lowercase hex")
		}
	}
	if allZero {
		return errors.New("nil UUID")
	}
	return nil
}
