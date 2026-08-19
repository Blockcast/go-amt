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
	HeartbeatSchema = "blockcast.shred-gw-heartbeat.v1"

	// HeartbeatInterval is the fixed v1 emission cadence.
	HeartbeatInterval = 30 * time.Second

	// erasureReportSchema is the per-feed delivery report schema this envelope
	// carries. Pinned so an envelope cannot smuggle a future report shape past
	// a broker that only understands v1.
	erasureReportSchema = 1

	// erasureFractionEpsilon bounds the disagreement tolerated between a
	// reported ErasureFraction and the ratio recomputed from the two integers
	// it derives from. A Go producer using erasure.Fraction agrees exactly;
	// the tolerance exists for producers that serialise fewer significant
	// digits than a float64 round-trips.
	erasureFractionEpsilon = 1e-9

	maxVersionBytes = 128
	maxFeedIDBytes  = 128

	// maxFeeds bounds the per-heartbeat fan-out. The real defence against an
	// oversized body is a transport-level limit, which does not exist yet on
	// the ingest side; this keeps every ingest bound declared in one place and
	// documents the expected order of magnitude.
	maxFeeds = 4096
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
type Heartbeat struct {
	Schema  string       `json:"schema"`
	GWUUID  string       `json:"gw_uuid"`
	Version string       `json:"version"`
	SentAt  string       `json:"sent_at"`
	Feeds   []FeedReport `json:"feeds"`
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
	if hb.Version == "" || !utf8.ValidString(hb.Version) || len(hb.Version) > maxVersionBytes {
		return invalid("version must be non-empty, valid UTF-8, and at most %d bytes", maxVersionBytes)
	}
	if _, err := parseCanonicalUTCTimestamp(hb.SentAt); err != nil {
		return invalid("sent_at must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	if len(hb.Feeds) > maxFeeds {
		return invalid("feeds must contain at most %d entries, got %d", maxFeeds, len(hb.Feeds))
	}

	var previousFeedID string
	for i, feed := range hb.Feeds {
		if feed.FeedID == "" || !utf8.ValidString(feed.FeedID) || len(feed.FeedID) > maxFeedIDBytes {
			return invalid("feeds[%d].feed_id must be non-empty, valid UTF-8, and at most %d bytes", i, maxFeedIDBytes)
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
func validateErasureReport(window erasure.Window) error {
	if window.Schema != erasureReportSchema {
		return fmt.Errorf("erasure.schema must be %d", erasureReportSchema)
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
