package delivery

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/blockcast/go-amt/receiver/delivery/cdnilog"
)

// toDeliverySession mirrors magma's TOCDNIDeliverySession — the struct magma
// marshals and POSTs to Traffic Ops, read at magma main 2026-10-08
// (cdn/cloud/go/services/cdn/trafficops/cdni_delivery_session.go:93).
//
// ⚠ These are Traffic Ops' LEGACY key spellings, not its canonical ones.
// tc.CDNIDeliverySession's own tags are the CDNi abbreviations (s_sid, s_ccid,
// s_sdur_ms, sc_total_bytes, c_ip); its UnmarshalJSON accepts
// server_session_id / content_id / duration_ms / bytes_out / client_ip as
// Legacy* aliases, and that alias path is the one magma's forward actually
// travels. Mirroring magma rather than tc is therefore deliberate: it is the
// bytes this producer's records are really decoded from. latency_tier,
// close_reason, client_version and the session_start_ms/session_end_ms/
// objects_out/seq/closed set are spelled identically on both sides.
//
// ⚠ WHAT THIS DOES AND DOES NOT PROVE. It is a hand-mirrored struct, not an
// import of tc, because pulling trafficcontrol into go-amt's module graph to
// assert twenty JSON tags is not a trade worth making. So it proves the mapping
// populates every key TO requires and that the rename magma performs
// (protoDeliverySessionToTO) lands them in the right places — and it does NOT
// prove TO's own validator accepts the result, nor that this mirror still
// matches magma. The four fields with a different spelling on each side
// (server_session_id / content_id / duration_ms / bytes_out vs s_sid / s_ccid /
// s_sdur_ms / sc_total_bytes) are precisely the ones the BLO-10898 row-0
// failure was about, so they are the ones worth mirroring by hand and
// re-checking against both repos when this test is next touched.
type toDeliverySession struct {
	ServerSessionID string `json:"server_session_id"`
	Transport       string `json:"transport"`
	ContentID       string `json:"content_id"`
	ClientIP        string `json:"client_ip,omitempty"`
	SessionStartMs  int64  `json:"session_start_ms"`
	SessionEndMs    int64  `json:"session_end_ms"`
	DurationMs      int64  `json:"duration_ms"`
	BytesOut        int64  `json:"bytes_out"`
	ObjectsOut      int64  `json:"objects_out"`
	Track           string `json:"track,omitempty"`
	Seq             int    `json:"seq"`
	Closed          bool   `json:"closed"`
	LatencyTier     string `json:"latency_tier,omitempty"`
	CloseReason     string `json:"close_reason,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
}

// forwardToTO applies the rename magma performs on the way to Traffic Ops, so
// the round trip below exercises the whole producer-to-TO field path rather
// than only the half this repo owns. Kept in lockstep with
// magma cdn/cloud/go/services/cdn/servicers/cdni_log_to_to.go
// protoDeliverySessionToTO, including its s_ccid-then-ccid fallback.
func forwardToTO(session *cdnilog.DeliverySession) toDeliverySession {
	contentID := session.GetSCcid()
	if contentID == "" {
		contentID = session.GetCcid()
	}
	return toDeliverySession{
		ServerSessionID: session.GetSSid(),
		Transport:       session.GetTransport(),
		ContentID:       contentID,
		ClientIP:        session.GetCIp(),
		SessionStartMs:  session.GetSessionStartMs(),
		SessionEndMs:    session.GetSessionEndMs(),
		DurationMs:      session.GetSSdurMs(),
		BytesOut:        session.GetScTotalBytes(),
		ObjectsOut:      session.GetObjectsOut(),
		Track:           session.GetTrack(),
		Seq:             int(session.GetSeq()),
		Closed:          session.GetClosed(),
		LatencyTier:     session.GetLatencyTier(),
		CloseReason:     session.GetCloseReason(),
		ClientVersion:   session.GetClientVersion(),
	}
}

func testCollectorConfig() CollectorConfig {
	return CollectorConfig{
		Endpoint:      DefaultCollectorEndpoint,
		GatewayID:     "gw-0001",
		NetworkID:     "blockcast",
		ContentID:     "solana-mainnet-shreds",
		LatencyTier:   "tier-1",
		Transport:     TransportShredUnicast,
		ClientVersion: "go-amt/0.1.0",
		ClientCert:    "unused-in-mapping-tests",
		ClientKey:     "unused-in-mapping-tests",
	}
}

func testRecord() Record {
	opened := time.Unix(1_700_000_000, 0).UTC()
	return Record{
		SessionID:    "0f9a1b2c-3d4e-4f50-9a1b-2c3d4e5f6071",
		SubscriberID: "grant-abc123",
		Destination:  "198.51.100.7:9001",
		Seq:          4,
		DurationMS:   60_000,
		BytesOut:     4096,
		PacketsOut:   32,
		CloseReason:  CloseHeartbeatAbsent,
		Final:        true,
		OpenedAt:     opened,
		EmittedAt:    opened.Add(60 * time.Second),
	}
}

// TestMappedRecordCarriesEveryFieldTrafficOpsRequires is the BLO-41429
// regression test. Posted verbatim, a delivery.Record is a 400 on two counts:
// its session_id key is not server_session_id, and it carries no content_id at
// all. Every required field must survive the mapping with a non-zero value.
func TestMappedRecordCarriesEveryFieldTrafficOpsRequires(t *testing.T) {
	config := testCollectorConfig()
	record := testRecord()

	session := forwardToTO(config.deliverySession(record))

	if session.ServerSessionID != record.SessionID {
		t.Fatalf("server_session_id = %q, want %q", session.ServerSessionID, record.SessionID)
	}
	// TO rejects a non-UUID server_session_id outright on some transports, and
	// the dedup key is useless without it; an empty one is the row-0 failure.
	if len(session.ServerSessionID) != 36 {
		t.Fatalf("server_session_id %q is not UUID-shaped", session.ServerSessionID)
	}
	if session.ContentID != config.ContentID {
		t.Fatalf("content_id = %q, want %q", session.ContentID, config.ContentID)
	}
	if session.SessionStartMs != record.OpenedAt.UnixMilli() {
		t.Fatalf("session_start_ms = %d, want %d", session.SessionStartMs, record.OpenedAt.UnixMilli())
	}
	if session.SessionEndMs != record.EmittedAt.UnixMilli() {
		t.Fatalf("session_end_ms = %d, want %d", session.SessionEndMs, record.EmittedAt.UnixMilli())
	}
	if session.ObjectsOut != int64(record.PacketsOut) {
		t.Fatalf("objects_out = %d, want %d", session.ObjectsOut, record.PacketsOut)
	}
	if !session.Closed {
		t.Fatal("closed = false for a final record")
	}
	if session.Seq != int(record.Seq) {
		t.Fatalf("seq = %d, want %d", session.Seq, record.Seq)
	}
	if session.DurationMs != record.DurationMS {
		t.Fatalf("duration_ms = %d, want %d", session.DurationMs, record.DurationMS)
	}
	if session.BytesOut != int64(record.BytesOut) {
		t.Fatalf("bytes_out = %d, want %d", session.BytesOut, record.BytesOut)
	}
	if session.CloseReason != string(record.CloseReason) {
		t.Fatalf("close_reason = %q, want %q", session.CloseReason, record.CloseReason)
	}
	if session.LatencyTier != config.LatencyTier {
		t.Fatalf("latency_tier = %q, want %q", session.LatencyTier, config.LatencyTier)
	}
	// The port is dropped rather than folded into c_ip, where it would read as
	// part of the address: DeliverySession carries no client_port.
	if session.ClientIP != "198.51.100.7" {
		t.Fatalf("client_ip = %q, want %q", session.ClientIP, "198.51.100.7")
	}

	// TO cross-checks duration_ms against the session window and 400s when they
	// disagree by more than one interim period. They agree by construction only
	// because the window is OpenedAt..EmittedAt; deriving it any other way
	// breaks ingest rather than merely losing precision.
	if window := session.SessionEndMs - session.SessionStartMs; window != session.DurationMs {
		t.Fatalf("session window %dms disagrees with duration_ms %d", window, session.DurationMs)
	}

	// And it must survive the JSON encoding TO actually decodes.
	body, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded toDeliverySession
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != session {
		t.Fatalf("round trip changed the record:\n got %+v\nwant %+v", decoded, session)
	}
}

// TestDeliverySessionCarriesNoSubscriberIdentity pins BLO-37512 structurally.
//
// Traffic Ops resolves the billing subject server-side from the mTLS identity
// and SILENTLY DISCARDS any body-supplied subscriber_id, so a producer that
// sends one gets no error and no effect. The proto has no subscriber field at
// all, which makes the direct mistake impossible — but it does not stop a
// future edit from smuggling the subscriber into track, client_version or
// close_reason, where it would look authoritative and still be discarded.
//
// So this asserts over the MARSHALLED BYTES rather than over named fields: the
// subscriber ID must not appear anywhere in the wire form, by any route.
func TestDeliverySessionCarriesNoSubscriberIdentity(t *testing.T) {
	config := testCollectorConfig()
	record := testRecord()
	if record.SubscriberID == "" {
		t.Fatal("test record has no subscriber ID, so this test would pass vacuously")
	}

	session := config.deliverySession(record)
	wire, err := proto.Marshal(session)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(wire), record.SubscriberID) {
		t.Fatalf("subscriber ID %q appears in the marshalled DeliverySession", record.SubscriberID)
	}

	// The enclosing batch too: the record envelope has free-form fields of its
	// own (x_tc_* extensions, headers) that would carry it just as far.
	sink := &CollectorSink{config: config}
	batch, err := proto.Marshal(sink.batch(record))
	if err != nil {
		t.Fatalf("marshal batch: %v", err)
	}
	if strings.Contains(string(batch), record.SubscriberID) {
		t.Fatalf("subscriber ID %q appears in the marshalled CDNILogBatch", record.SubscriberID)
	}
}

// TestBatchIsStampedDeliverySessionTier pins the two halves magma's router
// needs. It routes on sub-message presence, but the tier label is the
// architectural lock: a tier with no sub-message is DROPPED outright, and a
// sub-message under the wrong tier is forwarded only with a warning. Setting
// one without the other is a silent half-failure either way.
func TestBatchIsStampedDeliverySessionTier(t *testing.T) {
	config := testCollectorConfig()
	sink := &CollectorSink{config: config}
	batch := sink.batch(testRecord())

	if got := len(batch.GetRecords()); got != 1 {
		t.Fatalf("batch carries %d records, want 1", got)
	}
	if batch.GetBatchId() == "" {
		t.Fatal("batch_id is empty; magma's Validate rejects the batch")
	}
	if batch.GetGatewayId() != config.GatewayID {
		t.Fatalf("gateway_id = %q, want %q", batch.GetGatewayId(), config.GatewayID)
	}
	if batch.GetCount() != 1 {
		t.Fatalf("count = %d, want 1", batch.GetCount())
	}
	record := batch.GetRecords()[0]
	if record.GetRecordTier() != cdnilog.RecordTier_DELIVERY_SESSION {
		t.Fatalf("record_tier = %s, want DELIVERY_SESSION", record.GetRecordTier())
	}
	if record.GetDeliverySession() == nil {
		t.Fatal("record carries tier DELIVERY_SESSION but no delivery_session sub-message; magma drops it")
	}
}

// TestShipAcceptsOnlyDurablyPersistedAcks is the AC-4 pin: Reporter reads a nil
// error as "durably accepted, never retransmit", and the record is the sender's
// only copy of its interval. Every ack shape short of success AND persisted
// must therefore be an error.
func TestShipAcceptsOnlyDurablyPersistedAcks(t *testing.T) {
	record := testRecord()
	for _, testCase := range []struct {
		name    string
		ack     *cdnilog.LogAck
		wantErr bool
	}{{
		name: "success and persisted",
		ack:  &cdnilog.LogAck{Success: true, Persisted: true, RecordsProcessed: 1},
	}, {
		// The one that matters most: the collector took the batch for
		// ASYNCHRONOUS forwarding and the proto says in as many words that the
		// gateway must retain and retry its copy. Reading success alone as
		// acceptance is how an interval goes silently unbilled.
		name:    "success but not persisted",
		ack:     &cdnilog.LogAck{Success: true, Persisted: false, RecordsProcessed: 1},
		wantErr: true,
	}, {
		name:    "failure",
		ack:     &cdnilog.LogAck{Success: false, Retryability: cdnilog.Retryability_RETRYABILITY_RETRYABLE, Message: "wal fault"},
		wantErr: true,
	}, {
		// records_processed is the version-independent check: a collector too
		// old to populate outcomes still reports how many records it took.
		name:    "nothing processed",
		ack:     &cdnilog.LogAck{Success: true, Persisted: true, RecordsProcessed: 0},
		wantErr: true,
	}, {
		name: "duplicate replay",
		ack: &cdnilog.LogAck{Success: true, Persisted: true, RecordsProcessed: 1, Outcomes: []*cdnilog.RecordOutcome{
			{RecordIndex: 0, Disposition: cdnilog.RecordDisposition_DUPLICATE},
		}},
	}, {
		name: "rejected record",
		ack: &cdnilog.LogAck{Success: true, Persisted: true, RecordsProcessed: 1, Outcomes: []*cdnilog.RecordOutcome{
			{RecordIndex: 0, Disposition: cdnilog.RecordDisposition_REJECTED, ReasonCodes: []string{"RECORD_ENCODE_FAILED"}},
		}},
		wantErr: true,
	}, {
		// Reason codes alongside an unset disposition: unset is the proto3
		// default and indistinguishable from "never set", so this must fail
		// toward not-accepted rather than read as ACCEPTED.
		name: "reason codes with unset disposition",
		ack: &cdnilog.LogAck{Success: true, Persisted: true, RecordsProcessed: 1, Outcomes: []*cdnilog.RecordOutcome{
			{RecordIndex: 0, ReasonCodes: []string{"SOMETHING_NEW"}},
		}},
		wantErr: true,
	}, {
		// The MUST NOT the proto calls out by name, and the PR's whole thesis:
		// ACCEPTED is an acknowledgement that the record was taken, NOT a
		// durability receipt. Without this row a regression adding
		// `case ACCEPTED: return nil` to the switch passes the entire table,
		// because every other ACCEPTED-bearing row also has Persisted: true.
		name: "accepted but not persisted",
		ack: &cdnilog.LogAck{Success: true, Persisted: false, RecordsProcessed: 1, Outcomes: []*cdnilog.RecordOutcome{
			{RecordIndex: 0, Disposition: cdnilog.RecordDisposition_ACCEPTED},
		}},
		wantErr: true,
	}, {
		// A list that exists must name the only record the batch carried. A
		// collector that renumbered or dropped the entry would otherwise be
		// indistinguishable from one that stayed silent, i.e. from acceptance.
		name: "outcomes naming no record 0",
		ack: &cdnilog.LogAck{Success: true, Persisted: true, RecordsProcessed: 1, Outcomes: []*cdnilog.RecordOutcome{
			{RecordIndex: 1, Disposition: cdnilog.RecordDisposition_ACCEPTED},
		}},
		wantErr: true,
	}} {
		t.Run(testCase.name, func(t *testing.T) {
			err := ackAccepted(testCase.ack, record)
			if testCase.wantErr && err == nil {
				t.Fatal("accepted a record the collector did not durably store")
			}
			if !testCase.wantErr && err != nil {
				t.Fatalf("rejected a durably accepted record: %v", err)
			}
		})
	}
}

// TestNackedMappedRecordIsRetransmittedVerbatim is the other half of AC 4,
// across the mapping: a collector nack must leave the record pending, and the
// retransmission must map to the identical (s_sid, seq) and the identical
// bytes. Regenerating rather than retransmitting under-bills by exactly the
// lost interval, because no later record restates those bytes.
func TestNackedMappedRecordIsRetransmittedVerbatim(t *testing.T) {
	config := testCollectorConfig()
	reporter, sink := newTestReporter(t)

	sink.failing = true
	sample := LedgerSample{TargetID: "grant-abc123", Destination: "198.51.100.7:9001", Bytes: 4096, Packets: 32}
	if err := reporter.Tick([]LedgerSample{sample}); err == nil {
		t.Fatal("Tick succeeded against a nacking collector")
	}
	if reporter.Pending() != 1 {
		t.Fatalf("Pending() = %d after a nack, want 1", reporter.Pending())
	}

	// No further traffic; the collector recovers and the pending record ships.
	sink.failing = false
	if err := reporter.Tick([]LedgerSample{sample}); err != nil {
		t.Fatalf("Tick after recovery: %v", err)
	}
	if reporter.Pending() != 0 {
		t.Fatalf("Pending() = %d after recovery, want 0", reporter.Pending())
	}

	shipped := sink.forTarget("grant-abc123")
	if len(shipped) == 0 {
		t.Fatal("nothing shipped after recovery")
	}
	retransmitted := forwardToTO(config.deliverySession(shipped[0]))
	if retransmitted.BytesOut != int64(sample.Bytes) {
		t.Fatalf("retransmitted bytes_out = %d, want the whole refused interval %d", retransmitted.BytesOut, sample.Bytes)
	}
	if retransmitted.ObjectsOut != int64(sample.Packets) {
		t.Fatalf("retransmitted objects_out = %d, want %d", retransmitted.ObjectsOut, sample.Packets)
	}
	if retransmitted.ServerSessionID == "" || retransmitted.ContentID == "" {
		t.Fatal("retransmitted record lost a required field through the mapping")
	}
}

// TestMappedRollupReconstructsTruthFromDuplicates replays mapped records
// through the documented Traffic Ops rollup — MAX(duration_ms), SUM(bytes_out),
// dedup on (server_session_id, track, seq) — and asserts the totals equal what
// was delivered. It is TestRollupReconstructsTruthFromDuplicates's assertion
// moved across the mapping, which is where it can now break: the two shapes are
// asymmetric, so a mapping that "normalised" either one silently double-bills
// or under-bills while every field still looks populated.
func TestMappedRollupReconstructsTruthFromDuplicates(t *testing.T) {
	config := testCollectorConfig()
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	tracker := newTestTracker(t, clock, nil)

	if _, err := tracker.Open("grant-abc123"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	var emitted []Record
	const rounds = 4
	for round := 0; round < rounds; round++ {
		if err := tracker.Observe("grant-abc123", 100, 1); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		clock.Add(15 * time.Second)
		record, err := tracker.Emit("grant-abc123")
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
		emitted = append(emitted, record)
	}
	final, err := tracker.Close("grant-abc123", CloseHeartbeatAbsent)
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	emitted = append(emitted, final)

	// An outage replays records: duplicate one, re-send the terminal, reverse.
	replayed := append([]Record(nil), emitted...)
	replayed = append(replayed, emitted[1], emitted[1], final)
	for i, j := 0, len(replayed)-1; i < j; i, j = i+1, j-1 {
		replayed[i], replayed[j] = replayed[j], replayed[i]
	}

	seen := make(map[string]struct{})
	var totalBytes, totalObjects, maxDuration int64
	var closeReason string
	var sawClosed bool
	for _, record := range replayed {
		session := forwardToTO(config.deliverySession(record))
		key := session.ServerSessionID + "\x00" + session.Track + "\x00" + strconv.Itoa(session.Seq)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		totalBytes += session.BytesOut
		totalObjects += session.ObjectsOut
		if session.DurationMs > maxDuration {
			maxDuration = session.DurationMs
		}
		if session.Closed {
			sawClosed = true
			closeReason = session.CloseReason
		}
	}

	if totalBytes != rounds*100 {
		t.Fatalf("SUM(bytes_out) = %d, want %d", totalBytes, rounds*100)
	}
	if totalObjects != rounds {
		t.Fatalf("SUM(objects_out) = %d, want %d", totalObjects, rounds)
	}
	if maxDuration != rounds*15_000 {
		t.Fatalf("MAX(duration_ms) = %d, want %d", maxDuration, rounds*15_000)
	}
	// Without a closed=true terminal row the rollup falls back to max(seq) and
	// bills the session as "first window only, never closed".
	if !sawClosed {
		t.Fatal("no closed=true terminal record survived the mapping")
	}
	if closeReason != string(CloseHeartbeatAbsent) {
		t.Fatalf("close_reason = %q, want %q", closeReason, CloseHeartbeatAbsent)
	}
}

// TestCollectorConfigRefusesUnauthenticatedOrUnattributableConfig pins AC 5 and
// the content/tier requirements. Each of these produces a billing row that is
// either unattributable or unauthenticated, and every one of them otherwise
// looks configured.
func TestCollectorConfigRefusesUnauthenticatedOrUnattributableConfig(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*CollectorConfig)
	}{
		{"no gateway ID", func(c *CollectorConfig) { c.GatewayID = "" }},
		{"no content ID", func(c *CollectorConfig) { c.ContentID = "" }},
		{"no latency tier", func(c *CollectorConfig) { c.LatencyTier = "" }},
		// Not unattributable but unshippable, and in the same way that only
		// shows up at runtime: Traffic Ops validates transport against a closed
		// vocabulary, so a config that reaches Ship with an empty one nacks
		// every record forever while the ledger grows a duplicate line per
		// tick. There is deliberately no default to fall back on.
		{"no transport", func(c *CollectorConfig) { c.Transport = "" }},
		{"no client certificate", func(c *CollectorConfig) { c.ClientCert = "" }},
		{"no client key", func(c *CollectorConfig) { c.ClientKey = "" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := testCollectorConfig()
			testCase.mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("accepted a config that produces an unattributable or unauthenticated billing row")
			}
		})
	}
	if err := testCollectorConfig().Validate(); err != nil {
		t.Fatalf("rejected a complete config: %v", err)
	}
}

// TestZeroTimestampsMapToZeroNotToTheEpochOffset guards the one conversion with
// a silent wrong answer: time.Time's zero value is year 1, so UnixMilli gives a
// large NEGATIVE number. Traffic Ops rejects a negative session_start_ms, which
// is the right outcome — but it must arrive as a missing value, not as an
// implausible one that a future tolerance change could start accepting.
func TestZeroTimestampsMapToZeroNotToTheEpochOffset(t *testing.T) {
	config := testCollectorConfig()
	record := testRecord()
	record.OpenedAt = time.Time{}
	record.EmittedAt = time.Time{}

	session := config.deliverySession(record)
	if session.GetSessionStartMs() != 0 {
		t.Fatalf("session_start_ms = %d for a zero time, want 0", session.GetSessionStartMs())
	}
	if session.GetSessionEndMs() != 0 {
		t.Fatalf("session_end_ms = %d for a zero time, want 0", session.GetSessionEndMs())
	}
}
