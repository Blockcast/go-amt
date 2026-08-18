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
	"time"
	"unicode/utf8"

	"github.com/blockcast/go-amt/erasure"
)

const (
	// HeartbeatSchema versions the envelope below. Any change to the field set
	// requires a new schema string, not a silent edit to this one.
	HeartbeatSchema = "blockcast.shred-gw-heartbeat.v1"

	// HeartbeatInterval is the fixed v1 emission cadence.
	HeartbeatInterval = 30 * time.Second

	// erasureReportSchema is the per-feed delivery report schema this envelope
	// carries. Pinned so an envelope cannot smuggle a future report shape past
	// a broker that only understands v1.
	erasureReportSchema = 1

	maxVersionBytes = 128
	maxFeedIDBytes  = 128
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
// FirstPacketAt and LastPacketAt are canonical RFC 3339 UTC timestamps, or
// both empty when the feed has not yet received a packet. They are reported
// per feed rather than per gateway so a single dead feed is visible behind
// otherwise healthy aggregate traffic.
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
		return invalid("gw_uuid must be a canonical, non-nil, lowercase UUID")
	}
	// An empty version is not a degraded heartbeat, it is an unrecallable one.
	if hb.Version == "" || !utf8.ValidString(hb.Version) || len(hb.Version) > maxVersionBytes {
		return invalid("version must be non-empty, valid UTF-8, and at most %d bytes", maxVersionBytes)
	}
	if _, err := parseCanonicalUTCTimestamp(hb.SentAt); err != nil {
		return invalid("sent_at must be a canonical RFC 3339 UTC timestamp")
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

		if err := validateFeedTimestamps(feed); err != nil {
			return invalid("feeds[%d] (%s): %s", i, feed.FeedID, err)
		}
		if feed.Erasure.Schema != erasureReportSchema {
			return invalid("feeds[%d] (%s): erasure.schema must be %d", i, feed.FeedID, erasureReportSchema)
		}
		if feed.Erasure.SetsErased > feed.Erasure.SetsTotal {
			return invalid("feeds[%d] (%s): erasure.sets_erased %d exceeds sets_total %d",
				i, feed.FeedID, feed.Erasure.SetsErased, feed.Erasure.SetsTotal)
		}
	}

	return nil
}

// validateFeedTimestamps enforces the two-state contract on the packet-time
// pair: either the feed has seen no packet (both empty) or it has seen at
// least one (both canonical, first not after last). A half-populated pair is
// rejected because it is ambiguous — the broker cannot tell "never received"
// from "lost the first timestamp".
func validateFeedTimestamps(feed FeedReport) error {
	if feed.FirstPacketAt == "" && feed.LastPacketAt == "" {
		return nil
	}
	if feed.FirstPacketAt == "" || feed.LastPacketAt == "" {
		return errors.New("first_packet_at and last_packet_at must both be set or both be empty")
	}

	first, err := parseCanonicalUTCTimestamp(feed.FirstPacketAt)
	if err != nil {
		return errors.New("first_packet_at must be a canonical RFC 3339 UTC timestamp")
	}
	last, err := parseCanonicalUTCTimestamp(feed.LastPacketAt)
	if err != nil {
		return errors.New("last_packet_at must be a canonical RFC 3339 UTC timestamp")
	}
	if last.Before(first) {
		return errors.New("last_packet_at must not precede first_packet_at")
	}
	return nil
}

// FormatTimestamp renders t in the canonical form ValidateHeartbeat accepts.
// Callers should use it rather than formatting inline, so the producer cannot
// drift from the validator.
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
