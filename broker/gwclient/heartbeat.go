// Package gwclient is the gateway side of the broker control plane: it
// assembles a broker.Heartbeat from the receiver's live state and POSTs it.
//
// # Why this is not in package broker
//
// broker is deliberately transport-free — "types plus validation, with no mTLS
// session, no HTTP client, and no I/O" (see its package doc). That invariant is
// what lets the broker import the contract without inheriting a client. The
// producer needs an HTTP client, so it lives one package down rather than
// violating it. broker stays importable by the server; gwclient is the half
// only a gateway runs.
//
// # What this package is careful about
//
// Three of the contract's rules are the kind a correct-looking client breaks
// silently, so each is implemented once, here, rather than left to callers:
//
//   - Version provenance. Heartbeat.Version is broker.Version() and is not
//     settable by a caller. go-amt has two Version() functions and the other
//     one, amt.Version at gateway.go:79, is the Rust library's version reached
//     through CGO. Picking it would still validate, would break the
//     version-to-report_schema mapping a fleet census reads, and would put a
//     CGO edge into a binary whose whole deliverable is CGO_ENABLED=0. Not
//     accepting the string from a caller is what makes that unreachable rather
//     than merely discouraged.
//   - Replay. broker.ReplayRule requires a retry to resend identical bytes,
//     including sent_at, because server-side dedup is a uniqueness constraint
//     on (gw_uuid, sent_at). Send therefore takes bytes that were canonicalized
//     once, and never rebuilds them.
//   - Validate-before-send. broker.ValidateHeartbeat runs on the producer so a
//     malformed heartbeat fails here, where the feed and the counters are in
//     scope, instead of as an opaque 4xx.
package gwclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blockcast/go-amt/broker"
	"github.com/blockcast/go-amt/receiver"
)

// maxErrorBodyBytes bounds how much of an error response is read before the
// body is abandoned. The broker's error envelope is small; anything larger is
// a misrouted proxy page, and reading it in full would let a hostile or broken
// endpoint size the gateway's memory.
const maxErrorBodyBytes = 8 << 10

// FeedSource supplies the per-feed state one heartbeat reports.
//
// *receiver.ReceiverMetrics satisfies this. It is an interface so the producer
// is testable without a UDP socket, and so the coupling runs one way: the
// receiver knows nothing about the broker contract.
type FeedSource interface {
	Snapshot() []receiver.FeedSnapshot
}

// Producer builds and sends gateway heartbeats.
type Producer struct {
	gwUUID   string
	endpoint string
	client   *http.Client
	source   FeedSource
	now      func() time.Time
	log      *slog.Logger
}

// Option configures a Producer.
type Option func(*Producer)

// WithHTTPClient replaces the default client. The default has a timeout
// shorter than broker.HeartbeatInterval so a stalled request cannot outlive the
// beat that issued it and overlap the next one.
func WithHTTPClient(client *http.Client) Option {
	return func(p *Producer) {
		if client != nil {
			p.client = client
		}
	}
}

// WithClock replaces the time source, for tests that pin sent_at.
func WithClock(now func() time.Time) Option {
	return func(p *Producer) {
		if now != nil {
			p.now = now
		}
	}
}

// WithLogger replaces the logger.
func WithLogger(log *slog.Logger) Option {
	return func(p *Producer) {
		if log != nil {
			p.log = log
		}
	}
}

// NewProducer returns a Producer that reports source's feeds as gwUUID to the
// broker rooted at baseURL.
//
// baseURL is a scheme and authority — the heartbeat route is appended from
// broker.HeartbeatPath so the gateway and the broker's mux read the same
// constant and a route rename cannot become a 404.
//
// Note there is no version parameter, and adding one would be a regression:
// see the package doc.
func NewProducer(gwUUID, baseURL string, source FeedSource, opts ...Option) (*Producer, error) {
	if source == nil {
		return nil, errors.New("gwclient: feed source is nil")
	}
	// Validated here rather than at first send: a malformed UUID is a config
	// error that should fail at startup, not 30 seconds later on a path where
	// the only symptom is a rejected heartbeat.
	if err := broker.ValidateHeartbeat(broker.Heartbeat{
		Schema:  broker.HeartbeatSchema,
		GWUUID:  gwUUID,
		Version: broker.Version(),
		SentAt:  broker.FormatTimestamp(time.Unix(0, 0)),
	}); err != nil {
		return nil, fmt.Errorf("gwclient: %w", err)
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("gwclient: parse broker base URL %q: %w", baseURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("gwclient: broker base URL %q needs a scheme and host", baseURL)
	}

	producer := &Producer{
		gwUUID:   gwUUID,
		endpoint: strings.TrimRight(parsed.String(), "/") + broker.HeartbeatPath(),
		client:   &http.Client{Timeout: broker.HeartbeatInterval - 5*time.Second},
		source:   source,
		now:      time.Now,
		log:      slog.Default(),
	}
	for _, opt := range opts {
		opt(producer)
	}
	return producer, nil
}

// Build assembles the current heartbeat and validates it.
//
// Version comes from broker.Version() and sent_at from the producer's clock.
// A feed that has received nothing is reported with empty packet timestamps and
// zero counters, which is the contract's "never received a packet" state — it
// is not omitted, because a silent feed is exactly what an SLA dispute is
// about and omission would make it indistinguishable from an unconfigured one.
//
// Build returns an error rather than a partial heartbeat when validation fails.
// Rejection is whole-heartbeat by design in ValidateHeartbeat, so one bad feed
// discards the beat; the error names the feed, and the caller's next beat is
// 30 seconds away.
func (p *Producer) Build() (broker.Heartbeat, error) {
	snapshot := p.source.Snapshot()
	feeds := make([]broker.FeedReport, 0, len(snapshot))
	for _, feed := range snapshot {
		report := broker.FeedReport{
			FeedID:  feed.FeedID,
			Packets: feed.Liveness.Packets,
			Bytes:   feed.Liveness.Bytes,
			Erasure: feed.Window,
		}
		// Both or neither, per the contract's two-state rule: a half-populated
		// pair is rejected as ambiguous. They move together here so a feed that
		// somehow held one zero timestamp cannot produce that shape.
		if !feed.Liveness.FirstAt.IsZero() && !feed.Liveness.LastAt.IsZero() {
			report.FirstPacketAt = broker.FormatTimestamp(feed.Liveness.FirstAt)
			report.LastPacketAt = broker.FormatTimestamp(feed.Liveness.LastAt)
		}
		feeds = append(feeds, report)
	}

	heartbeat := broker.Heartbeat{
		Schema: broker.HeartbeatSchema,
		GWUUID: p.gwUUID,
		// AC2: the build-stamped Go symbol, never amt.Version() and never a
		// caller-supplied string. See the package doc for why this is not a
		// parameter.
		Version: broker.Version(),
		SentAt:  broker.FormatTimestamp(p.now()),
		Feeds:   feeds,
	}
	if err := broker.ValidateHeartbeat(heartbeat); err != nil {
		return broker.Heartbeat{}, err
	}
	return heartbeat, nil
}

// Send POSTs body, which must be the output of broker.CanonicalBytes.
//
// body is passed in rather than built here so a caller that retries resends the
// identical bytes, per broker.ReplayRule: re-stamping sent_at on a retry
// defeats the broker's (gw_uuid, sent_at) dedup silently and double-counts a
// delivery window in an append-only ledger.
//
// The returned broker.Retry classifies a failure using the contract's own
// taxonomy, so a caller can distinguish "retry this" from "this will never be
// accepted" without matching on message text. The classification comes from the
// response's Code via broker.RetryForCode, not from the status: the taxonomy is
// the contract's discriminator and Message is documented as unstable. An
// unrecognized code stays RetryNever, per RetryForCode — a code from a newer
// broker must not be guessed safe to repeat. A transport failure classifies as
// broker.RetryTransportFailure.
func (p *Producer) Send(ctx context.Context, body []byte) (broker.Retry, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return broker.RetryTransportFailure, fmt.Errorf("gwclient: build heartbeat request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := p.client.Do(request)
	if err != nil {
		return broker.RetryTransportFailure, fmt.Errorf("gwclient: post heartbeat: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxErrorBodyBytes))
		_ = response.Body.Close()
	}()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return broker.RetryNever, nil
	}

	var envelope broker.ErrorResponse
	// A body that is absent, oversized or not the documented envelope leaves
	// Code empty, which RetryForCode rejects as unknown — the safe direction.
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxErrorBodyBytes))
	if readErr == nil {
		_ = json.Unmarshal(payload, &envelope)
	}

	retry, codeErr := broker.RetryForCode(envelope.Code)
	if codeErr != nil {
		return broker.RetryNever, fmt.Errorf(
			"gwclient: heartbeat rejected with status %d and unusable error code %q: %w",
			response.StatusCode, envelope.Code, codeErr)
	}

	// RetryAfterHeader is a distinct class from RetryBackoff on purpose, so the
	// condition stays visible to operators. Surface the delay the broker asked
	// for rather than collapsing it into generic backoff.
	if retry == broker.RetryAfterHeader {
		if delay, ok := broker.ParseRetryAfter(response.Header); ok {
			return retry, fmt.Errorf(
				"gwclient: heartbeat rejected (%s, status %d), retry after %s: %s",
				envelope.Code, response.StatusCode, delay, envelope.Message)
		}
		// The class demands a delay the broker did not supply. Guessing one
		// would reproduce the tight-loop failure ParseRetryAfter's comment
		// warns about, so treat it as backoff instead.
		return broker.RetryBackoff, fmt.Errorf(
			"gwclient: heartbeat rejected (%s, status %d) with no usable %s header: %s",
			envelope.Code, response.StatusCode, broker.RetryAfterHeaderName, envelope.Message)
	}

	return retry, fmt.Errorf("gwclient: heartbeat rejected (%s, status %d): %s",
		envelope.Code, response.StatusCode, envelope.Message)
}

// SendOnce builds, canonicalizes and sends exactly one heartbeat.
func (p *Producer) SendOnce(ctx context.Context) error {
	heartbeat, err := p.Build()
	if err != nil {
		return err
	}
	// Canonicalized once, outside any retry, per broker.ReplayRule.
	body, err := broker.CanonicalBytes(heartbeat)
	if err != nil {
		return err
	}
	_, err = p.Send(ctx, body)
	return err
}

// Run emits a heartbeat every broker.HeartbeatInterval until ctx is cancelled.
//
// A failed beat is logged and ABANDONED rather than retried into the next one.
// That is the contract's stated preference: broker.ReplayRule says abandoning a
// heartbeat loses one window of counters, while splitting or rebuilding one
// corrupts the ledger, "so when the two are in tension prefer the loss". The
// next tick builds a fresh heartbeat with its own sent_at, which is a new
// report rather than a retry of the old one.
//
// Run returns nil on cancellation: a cancelled heartbeat loop is a shutdown,
// not a failure.
func (p *Producer) Run(ctx context.Context) error {
	ticker := time.NewTicker(broker.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.SendOnce(ctx); err != nil {
				// Context cancellation races the in-flight request during
				// shutdown; that is not a heartbeat failure worth reporting.
				if ctx.Err() != nil {
					return nil
				}
				p.log.Warn("gateway heartbeat abandoned", "error", err)
			}
		}
	}
}
