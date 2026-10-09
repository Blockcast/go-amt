package delivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/blockcast/go-amt/receiver/delivery/cdnilog"
)

// DefaultCollectorEndpoint is the in-namespace magma collector. The relay
// namespace is network-isolated from Traffic Ops by a default-deny netpol, so
// a direct POST to TO is not a shorter path, it is a path that times out
// (BLO-10320 / BLO-10815). Records reach TO only via this collector, which
// forwards DELIVERY_SESSION-tier records to POST /cdni/delivery-session.
const DefaultCollectorEndpoint = "blockcastd:50052"

// TransportShredUnicast tags records from the Solana shred unicast fan-out.
//
// ⚠ Traffic Ops validates transport against a CLOSED vocabulary —
// tc.ValidCDNIDeliveryTransport accepts "amt" and "moq-unicast" and nothing
// else (lib/go-tc/cdni_logs.go) — so until that vocabulary carries this token
// a record stamped with it is rejected 400 "transport %q is not supported".
// The two existing tokens are both wrong for this producer: the shred class is
// not AMT (GATE 0 removed multicast for it) and it is not MoQ, and tagging it
// "moq-unicast" would make shred traffic indistinguishable from moq-relay
// traffic in the invoice rollup. Stamping an honest token that TO must learn is
// the lesser error — but it is NOT the default, and deliberately so: see
// CollectorConfig.Transport.
const TransportShredUnicast = "shred-unicast"

// collectorBatchSource names this producer in CDNILogBatch.source.
const collectorBatchSource = "go-amt-shreds"

// collectorRecordType is the batch's record_type, matching the tier the
// records carry.
const collectorRecordType = "cdni_delivery_session_v1"

// defaultCollectorTimeout bounds one SubmitLogBatch call. Reporter drives Ship
// from the single reporter-tick goroutine, so a call that hung unbounded would
// stall every other target's accounting behind it.
const defaultCollectorTimeout = 10 * time.Second

// CollectorConfig configures a CollectorSink.
//
// Every identity-bearing field is required and has NO fallback. In particular
// there is deliberately no os.Hostname() default for GatewayID: a hostname that
// happens to resolve is how a misconfigured relay bills traffic under another
// gateway's identity while every flag reads as configured.
type CollectorConfig struct {
	// Endpoint is the collector's host:port. Empty means
	// DefaultCollectorEndpoint.
	Endpoint string
	// GatewayID is the batch's declared producer identity. Required. magma
	// checks it against the mTLS-authenticated caller.
	GatewayID string
	// NetworkID is the orc8r network. Optional.
	NetworkID string
	// ContentID is s_ccid, the content collection the fan-out serves. Required:
	// TO's validateDeliverySessionContentID rejects an empty one, and an
	// unattributable billing row is the failure this field exists to prevent.
	ContentID string
	// LatencyTier is the commercial tier this feed is sold under. Required
	// because it sits in the invoice rollup's GROUP BY: an empty one does not
	// degrade gracefully, it collapses every session into a single NULL tier.
	LatencyTier string
	// Transport tags the delivery class. Required, with NO default, because
	// every token this producer could default to is wrong in a way that only
	// shows up at runtime: TransportShredUnicast is rejected 400 by today's
	// Traffic Ops vocabulary, and the two tokens TO does accept misattribute
	// shred traffic. A default would turn that into a permanent nack loop —
	// Reporter re-ships the pending record every tick, so the ledger grows a
	// duplicate line per interval per destination while the target bills
	// nothing. Making the operator state the token fails at startup instead.
	Transport string
	// ClientVersion is the producer version, forward-compat for TO's minimum
	// -version rejection. Optional.
	ClientVersion string
	// ClientCert and ClientKey are the relay's mTLS identity. Both required:
	// this path carries billing identity and must not run over
	// insecure.NewCredentials().
	ClientCert string
	ClientKey  string
	// CABundle is an additional root for verifying the collector. Empty uses
	// the system pool alone.
	CABundle string
	// Timeout bounds one submission. Zero means defaultCollectorTimeout.
	Timeout time.Duration
}

// Validate checks the config as a set, at construction, so a misconfiguration
// fails at startup rather than 30 seconds later as a rejected batch.
func (c CollectorConfig) Validate() error {
	switch {
	case c.GatewayID == "":
		return errors.New("delivery: collector requires a gateway ID")
	case c.ContentID == "":
		return errors.New("delivery: collector requires a content ID (s_ccid); Traffic Ops rejects a record without one")
	case c.LatencyTier == "":
		return errors.New("delivery: collector requires a latency tier; it is in the invoice rollup's GROUP BY and an empty one collapses every session into one NULL tier")
	case c.Transport == "":
		return fmt.Errorf("delivery: collector requires a transport token (%q for the shred fan-out); Traffic Ops validates it against a closed vocabulary, so a defaulted one nacks every record forever instead of failing here", TransportShredUnicast)
	case c.ClientCert == "" || c.ClientKey == "":
		return errors.New("delivery: collector requires a client certificate and key; this path carries billing identity and will not run unauthenticated")
	}
	return nil
}

// CollectorSink ships delivery-session records to magma's
// CDNILogService/SubmitLogBatch, which forwards DELIVERY_SESSION-tier records
// to Traffic Ops.
//
// ONE RECORD PER BATCH. Sink.Ship takes a single Record and must not return
// until that record is durably accepted, so there is no window in which a
// second record could be coalesced into the same call. Reporter emits at most
// one record per target per tick, so the call rate is targets-per-interval and
// batching would buy little. Widening this means widening the Sink interface,
// which also owns Reporter's verbatim-retransmit contract — do that together or
// not at all.
type CollectorSink struct {
	conn    *grpc.ClientConn
	client  cdnilog.CDNILogServiceClient
	config  CollectorConfig
	timeout time.Duration
	// batchSeq makes batch IDs unique within the process. They are diagnostic
	// correlation handles, not a dedup key: TO deduplicates on
	// (server_session_id, track, seq), so a retransmitted record under a fresh
	// batch ID still collapses onto the original row.
	batchSeq atomic.Uint64
}

// NewCollectorSink dials the collector over mTLS and returns a Sink.
func NewCollectorSink(config CollectorConfig) (*CollectorSink, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Endpoint == "" {
		config.Endpoint = DefaultCollectorEndpoint
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultCollectorTimeout
	}

	creds, err := collectorCredentials(config)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(config.Endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("delivery: dial collector %s: %w", config.Endpoint, err)
	}
	return &CollectorSink{
		conn:    conn,
		client:  cdnilog.NewCDNILogServiceClient(conn),
		config:  config,
		timeout: timeout,
	}, nil
}

// Close releases the collector connection.
func (s *CollectorSink) Close() error { return s.conn.Close() }

// Ship submits one record and returns nil ONLY once the collector reports it
// durably accepted.
//
// "Durably accepted" means success AND persisted. The two are not the same
// claim and the proto says so outright: success without persisted means the
// batch was accepted for ASYNCHRONOUS forwarding and "the gateway must retain
// and retry its WAL copy" (CDNILogBatch LogAck.persisted; see also
// RecordDisposition.ACCEPTED, which is explicitly not a durability receipt).
// Reporter treats a nil return as "never retransmit this record", and the
// record is the sender's only copy of its interval — no later record restates
// those bytes. Reading success alone as acceptance is therefore exactly how an
// interval gets silently unbilled, which is the BLO-18944 defect.
func (s *CollectorSink) Ship(record Record) error {
	batch := s.batch(record)

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	ack, err := s.client.SubmitLogBatch(ctx, batch)
	if err != nil {
		return fmt.Errorf("delivery: submit record seq %d for session %s: %w", record.Seq, record.SessionID, err)
	}
	return ackAccepted(ack, record)
}

// ackAccepted reports whether the collector durably accepted the single record
// the batch carried.
func ackAccepted(ack *cdnilog.LogAck, record Record) error {
	where := fmt.Sprintf("record seq %d for session %s", record.Seq, record.SessionID)
	if !ack.GetSuccess() {
		return fmt.Errorf("delivery: collector rejected %s (retryability %s): %s",
			where, ack.GetRetryability(), ack.GetMessage())
	}
	// Per-record outcomes are emitted only when something in the batch was not
	// accepted, and then for EVERY record — so an empty list here is not
	// evidence of acceptance and is deliberately not read as one. A populated
	// list, though, states this record's disposition explicitly.
	outcomes := ack.GetOutcomes()
	stated := false
	for _, outcome := range outcomes {
		if outcome.GetRecordIndex() != 0 {
			continue
		}
		stated = true
		switch outcome.GetDisposition() {
		case cdnilog.RecordDisposition_ACCEPTED, cdnilog.RecordDisposition_DUPLICATE:
			// DUPLICATE means an identical replay is already stored, which is
			// exactly what a verbatim retransmission is meant to produce.
		default:
			// An unset disposition arriving alongside reason codes is NOT read
			// as ACCEPTED: unset is the proto3 default and indistinguishable
			// from "the producer never set it", so this fails toward
			// not-accepted, same as an empty outcomes list is not acceptance.
			return fmt.Errorf("delivery: collector did not accept %s: disposition %s %v",
				where, outcome.GetDisposition(), outcome.GetReasonCodes())
		}
	}
	// A populated list that never mentions record 0 is the same shape of
	// ambiguity as an unset disposition, and is treated the same way. The batch
	// carried exactly one record, so a list that exists at all must name it;
	// falling through to the weaker checks instead would make a collector that
	// renumbered or dropped the entry indistinguishable from one that accepted
	// the record. Unreachable for a well-behaved collector, which is the point
	// — this reads the ill-behaved one as not-accepted rather than as silence.
	if len(outcomes) > 0 && !stated {
		return fmt.Errorf("delivery: collector returned %d outcomes for %s but none for record 0; treating as not accepted",
			len(outcomes), where)
	}
	// The version-independent check for whether anything went missing: a server
	// too old to populate outcomes still reports how many records it took.
	if processed := ack.GetRecordsProcessed(); processed != 1 {
		return fmt.Errorf("delivery: collector processed %d of 1 records for %s", processed, where)
	}
	if !ack.GetPersisted() {
		return fmt.Errorf("delivery: collector accepted %s for asynchronous forwarding but did not persist it; retaining for retransmission", where)
	}
	return nil
}

// batch wraps one record as a DELIVERY_SESSION-tier CDNILogBatch.
func (s *CollectorSink) batch(record Record) *cdnilog.CDNILogBatch {
	now := time.Now()
	return &cdnilog.CDNILogBatch{
		BatchId:     fmt.Sprintf("%s-%d-%d", s.config.GatewayID, now.UnixNano(), s.batchSeq.Add(1)),
		Source:      collectorBatchSource,
		GatewayId:   s.config.GatewayID,
		NetworkId:   s.config.NetworkID,
		BatchTimeNs: now.UnixNano(),
		Count:       1,
		RecordType:  collectorRecordType,
		Records: []*cdnilog.CDNILogRecord{{
			TimestampNs: record.EmittedAt.UnixNano(),
			// magma routes on sub-message presence, but the tier is the
			// architectural lock: a populated sub-message under the wrong tier
			// label is forwarded with a warning, and a tier label with no
			// sub-message is dropped outright. Set both, always together.
			RecordTier:      cdnilog.RecordTier_DELIVERY_SESSION,
			SSid:            record.SessionID,
			SCcid:           s.config.ContentID,
			XTcGatewayId:    s.config.GatewayID,
			XTcNetworkId:    s.config.NetworkID,
			XTcLogSource:    collectorBatchSource,
			DeliverySession: s.config.deliverySession(record),
		}},
	}
}

// deliverySession maps one Record onto the wire type Traffic Ops reads.
//
// The field names are the CDNi logging vocabulary (s_sid, s_ccid, s_sdur_ms,
// sc_total_bytes); magma renames them to TO's descriptive JSON keys on the
// forward (protoDeliverySessionToTO). Three mappings are load-bearing:
//
//   - SSdurMs is CUMULATIVE and ScTotalBytes/ObjectsOut are DELTAS, because
//     TO's rollup is MAX(duration_ms) but SUM(bytes_out). Record already
//     carries them in exactly those shapes; this must not "normalise" either.
//   - SessionStartMs/SessionEndMs come from OpenedAt/EmittedAt, which makes
//     (end - start) the same cumulative elapsed time as DurationMS. TO cross
//     -checks those against each other and 400s when they disagree by more
//     than one interim period, so deriving the window any other way breaks
//     ingest rather than merely losing precision.
//   - Closed carries Final, the terminal marker TO's rollup prefers over
//     max(seq). Without it a session bills as "first window only, never
//     closed".
//
// THERE IS NO SUBSCRIBER FIELD, structurally: DeliverySession declares none,
// because TO resolves the billing subject server-side from the mTLS identity
// and silently discards anything body-supplied (BLO-37512). Record.SubscriberID
// is producer-internal — it keys the open-session map and the local ledger —
// and must not be smuggled onto the wire through Track, ClientVersion or any
// other free-form field. TestDeliverySessionCarriesNoSubscriberIdentity pins
// that against the marshalled bytes rather than against this comment.
func (c CollectorConfig) deliverySession(record Record) *cdnilog.DeliverySession {
	return &cdnilog.DeliverySession{
		SSid:  record.SessionID,
		SCcid: c.ContentID,
		// Track is deliberately empty. The shred fan-out has no track
		// dimension, and TO's natural key (server_session_id, track, seq) is
		// well-formed with an empty one. Synthesising a value would invent a
		// billing dimension the producer cannot attest to.
		Transport:      c.Transport,
		CIp:            clientIP(record.Destination),
		SessionStartMs: unixMilli(record.OpenedAt),
		SessionEndMs:   unixMilli(record.EmittedAt),
		SSdurMs:        record.DurationMS,
		ScTotalBytes:   int64(record.BytesOut),
		ObjectsOut:     int64(record.PacketsOut),
		Seq:            int64(record.Seq),
		Closed:         record.Final,
		CloseReason:    string(record.CloseReason),
		LatencyTier:    c.LatencyTier,
		ClientVersion:  c.ClientVersion,
	}
}

// clientIP strips the port from a destination. Record.Destination is a resolved
// UDP address; DeliverySession carries no client_port, so the port is dropped
// rather than folded into c_ip, where it would read as part of the address.
func clientIP(destination string) string {
	if destination == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		return destination
	}
	return host
}

// unixMilli converts a timestamp to Unix milliseconds, mapping the zero time to
// 0 rather than to the large negative value time.Time's epoch would give. TO
// rejects a negative session_start_ms, so a zero OpenedAt must fail that check
// as a missing value, not pass as an implausible one.
func unixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// collectorCredentials builds the mTLS transport credentials.
//
// There is no insecure path and no flag that produces one. This mirrors
// heartbeatHTTPClient in cmd/blockcast-shreds: client certificate required,
// system roots plus an optional additional bundle.
func collectorCredentials(config CollectorConfig) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("delivery: load collector client certificate: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("delivery: load system certificate pool: %w", err)
	}
	if config.CABundle != "" {
		pem, err := os.ReadFile(config.CABundle)
		if err != nil {
			return nil, fmt.Errorf("delivery: read collector CA bundle: %w", err)
		}
		if ok := roots.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("delivery: collector CA bundle %q contains no certificates", config.CABundle)
		}
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
	}), nil
}
