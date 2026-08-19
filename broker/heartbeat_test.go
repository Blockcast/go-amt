package broker

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
)

const (
	testGWUUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	testSentAt = "2026-08-18T06:00:00Z"
)

func validHeartbeat() Heartbeat {
	return Heartbeat{
		Schema:  HeartbeatSchema,
		GWUUID:  testGWUUID,
		Version: "v1.4.0",
		SentAt:  testSentAt,
		Feeds: []FeedReport{
			{
				FeedID:        "feed-a",
				Packets:       1200,
				Bytes:         1_440_000,
				FirstPacketAt: "2026-08-18T05:59:30Z",
				LastPacketAt:  "2026-08-18T05:59:59.5Z",
				Erasure: erasure.Window{
					SetsTotal:       50,
					SetsErased:      2,
					ErasureFraction: 0.04,
					RMean:           40,
					RPeak100MS:      60,
					GapMSHist: erasure.GapHistogram{
						LT1:        7,
						From1To2_4: 5,
						From2_4To7: 3,
						From7To32:  1,
						GTE32:      1,
					},
					GraceMS: 400,
					Schema:  1,
				},
			},
		},
	}
}

// TestHeartbeatSerializesTheExactContract pins the full wire form, key set
// included. It compares the entire decoded document rather than field-by-field
// so that ADDING a field fails this test too: the broker's ledger has to be
// able to reproduce a historical window, and a field that appears without a
// schema bump silently breaks that.
func TestHeartbeatSerializesTheExactContract(t *testing.T) {
	payload, err := json.Marshal(validHeartbeat())
	if err != nil {
		t.Fatal(err)
	}

	var contract map[string]any
	if err := json.Unmarshal(payload, &contract); err != nil {
		t.Fatal(err)
	}

	wantContract := map[string]any{
		"schema":  "blockcast.shred-gw-heartbeat.v1",
		"gw_uuid": testGWUUID,
		"version": "v1.4.0",
		"sent_at": testSentAt,
		"feeds": []any{
			map[string]any{
				"feed_id":         "feed-a",
				"packets":         float64(1200),
				"bytes":           float64(1_440_000),
				"first_packet_at": "2026-08-18T05:59:30Z",
				"last_packet_at":  "2026-08-18T05:59:59.5Z",
				"erasure": map[string]any{
					"sets_total":       float64(50),
					"sets_erased":      float64(2),
					"erasure_fraction": 0.04,
					"r_mean":           float64(40),
					"r_peak_100ms":     float64(60),
					"gap_ms_hist": map[string]any{
						"<1":    float64(7),
						"1-2.4": float64(5),
						"2.4-7": float64(3),
						"7-32":  float64(1),
						">=32":  float64(1),
					},
					"grace_ms": float64(400),
					"schema":   float64(1),
				},
			},
		},
	}

	if !reflect.DeepEqual(contract, wantContract) {
		t.Fatalf("serialized heartbeat = %#v, want %#v", contract, wantContract)
	}
}

// canonicalWire is the exact serialization of validHeartbeat(), written out by
// hand rather than produced by json.Marshal.
//
// Pinning the literal bytes is the point: a test that marshals and compares
// against its own output cannot fail, because encoding/json emits fields in
// declaration order both times. Only an external expectation catches a
// reordered struct, a renamed tag, or a changed number format.
//
// Note the < and > escapes: encoding/json HTML-escapes < and > in the
// histogram keys by default. Those escapes are part of the canonical byte form
// this contract freezes. Any producer that emits the semantically identical
// literal "<1" and ">=32" — including a Go producer using json.Encoder with
// SetEscapeHTML(false) — decodes to the same document but does NOT match
// byte-for-byte, which is what the ledger's diffability rests on.
const canonicalWire = `{"schema":"blockcast.shred-gw-heartbeat.v1","gw_uuid":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","version":"v1.4.0","sent_at":"2026-08-18T06:00:00Z","feeds":[{"feed_id":"feed-a","packets":1200,"bytes":1440000,"first_packet_at":"2026-08-18T05:59:30Z","last_packet_at":"2026-08-18T05:59:59.5Z","erasure":{"sets_total":50,"sets_erased":2,"erasure_fraction":0.04,"r_mean":40,"r_peak_100ms":60,"gap_ms_hist":{"\u003c1":7,"1-2.4":5,"2.4-7":3,"7-32":1,"\u003e=32":1},"grace_ms":400,"schema":1}}]}`

// TestHeartbeatMarshalsToTheCanonicalBytes pins the wire form against a
// hand-written literal, so a change to field order, tag spelling, or escaping
// fails here rather than silently redefining the contract.
func TestHeartbeatMarshalsToTheCanonicalBytes(t *testing.T) {
	encoded, err := json.Marshal(validHeartbeat())
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != canonicalWire {
		t.Fatalf("wire form changed:\n got %s\nwant %s", encoded, canonicalWire)
	}
}

// TestCanonicalWireSurvivesDecodeAndReEncode is the useful half of the old
// round-trip test, made able to fail: the input is the hand-written literal
// above rather than the encoder's own output, so this asserts that a broker
// re-encoding a *known-canonical* payload reproduces it exactly.
func TestCanonicalWireSurvivesDecodeAndReEncode(t *testing.T) {
	var decoded Heartbeat
	if err := json.Unmarshal([]byte(canonicalWire), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHeartbeat(decoded); err != nil {
		t.Fatalf("canonical wire failed validation: %v", err)
	}

	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != canonicalWire {
		t.Fatalf("round trip changed the wire form:\n got %s\nwant %s", reencoded, canonicalWire)
	}
}

// TestDecodeAndReEncodeSilentlyDropsUnknownFields pins the forward-compat
// behaviour, and exists to correct a claim this package previously made.
//
// An earlier version of this test asserted that decode-then-re-encode is what
// "lets W4a retain the heartbeat verbatim in a JSONB column". That is false. A
// plain decode drops fields the struct does not know about, and does so without
// an error, so a v1 broker persisting the re-encoded form silently truncates a
// v2 gateway's heartbeat and nothing surfaces it.
//
// The permissive decode is deliberate — hard-rejecting unknown fields would
// stop a newer gateway from heartbeating to an older broker at all, which is a
// worse failure for a liveness message. The consequence is simply that
// re-encoding is NOT verbatim retention: W4a must persist the raw request
// bytes (json.RawMessage or the untouched body) if it wants the object back
// exactly as sent.
func TestDecodeAndReEncodeSilentlyDropsUnknownFields(t *testing.T) {
	// A v2 gateway sends everything v1 knows, plus one field it does not.
	const fromNewerGateway = `{"schema":"blockcast.shred-gw-heartbeat.v1","gw_uuid":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","version":"v2.0.0","sent_at":"2026-08-18T06:00:00Z","feeds":[{"feed_id":"feed-a","packets":1200,"bytes":1440000,"first_packet_at":"2026-08-18T05:59:30Z","last_packet_at":"2026-08-18T05:59:59.5Z","dropped_packets":99,"erasure":{"sets_total":50,"sets_erased":2,"erasure_fraction":0.04,"r_mean":40,"r_peak_100ms":60,"gap_ms_hist":{"\u003c1":7,"1-2.4":5,"2.4-7":3,"7-32":1,"\u003e=32":1},"grace_ms":400,"schema":1}}]}`

	var decoded Heartbeat
	if err := json.Unmarshal([]byte(fromNewerGateway), &decoded); err != nil {
		t.Fatalf("a v1 broker must still accept a v2 heartbeat: %v", err)
	}
	if err := ValidateHeartbeat(decoded); err != nil {
		t.Fatalf("the known fields are still valid: %v", err)
	}

	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reencoded), "dropped_packets") {
		t.Fatal("dropped_packets survived the re-encode; update the retention guidance " +
			"on this test and in the package doc, because verbatim retention is now possible")
	}
	if string(reencoded) == fromNewerGateway {
		t.Fatal("re-encode reproduced the input byte-for-byte, so it IS verbatim retention")
	}
}

// TestEmptyFeedListMarshalsAsNullNotAbsent documents the one wire wart in the
// envelope: a gateway subscribed to nothing emits "feeds":null, not "feeds":[].
// Pinned deliberately — the broker must treat null and [] alike on ingest.
func TestEmptyFeedListMarshalsAsNullNotAbsent(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds = nil

	payload, err := json.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"feeds":null`) {
		t.Fatalf("expected feeds to serialize as null, got %s", payload)
	}
	if err := ValidateHeartbeat(hb); err != nil {
		t.Fatalf("a gateway with no feeds is still valid liveness: %v", err)
	}
}

func TestValidateHeartbeatAcceptsValidInput(t *testing.T) {
	if err := ValidateHeartbeat(validHeartbeat()); err != nil {
		t.Fatalf("ValidateHeartbeat(valid) = %v, want nil", err)
	}
}

func TestValidateHeartbeatRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Heartbeat)
	}{
		{"wrong schema", func(h *Heartbeat) { h.Schema = "blockcast.shred-gw-heartbeat.v2" }},
		{"empty schema", func(h *Heartbeat) { h.Schema = "" }},
		{"empty version", func(h *Heartbeat) { h.Version = "" }},
		{"oversized version", func(h *Heartbeat) { h.Version = strings.Repeat("v", maxVersionBytes+1) }},
		{"invalid utf8 version", func(h *Heartbeat) { h.Version = "v1.\xff0" }},
		{"nil uuid", func(h *Heartbeat) { h.GWUUID = "00000000-0000-0000-0000-000000000000" }},
		{"uppercase uuid", func(h *Heartbeat) { h.GWUUID = strings.ToUpper(testGWUUID) }},
		{"braced uuid", func(h *Heartbeat) { h.GWUUID = "{" + testGWUUID + "}" }},
		{"urn uuid", func(h *Heartbeat) { h.GWUUID = "urn:uuid:" + testGWUUID }},
		{"empty uuid", func(h *Heartbeat) { h.GWUUID = "" }},
		{"non-utc sent_at", func(h *Heartbeat) { h.SentAt = "2026-08-18T06:00:00+02:00" }},
		{"non-canonical sent_at", func(h *Heartbeat) { h.SentAt = "2026-08-18 06:00:00" }},
		{"empty sent_at", func(h *Heartbeat) { h.SentAt = "" }},
		{"empty feed id", func(h *Heartbeat) { h.Feeds[0].FeedID = "" }},
		{"oversized feed id", func(h *Heartbeat) { h.Feeds[0].FeedID = strings.Repeat("f", maxFeedIDBytes+1) }},
		{"wrong erasure schema", func(h *Heartbeat) { h.Feeds[0].Erasure.Schema = 2 }},
		{"erased exceeds total", func(h *Heartbeat) { h.Feeds[0].Erasure.SetsErased = h.Feeds[0].Erasure.SetsTotal + 1 }},
		{"first packet time without last", func(h *Heartbeat) { h.Feeds[0].LastPacketAt = "" }},
		{"last packet time without first", func(h *Heartbeat) { h.Feeds[0].FirstPacketAt = "" }},
		{"last packet precedes first", func(h *Heartbeat) {
			h.Feeds[0].FirstPacketAt, h.Feeds[0].LastPacketAt = h.Feeds[0].LastPacketAt, h.Feeds[0].FirstPacketAt
		}},
		{"non-canonical packet time", func(h *Heartbeat) { h.Feeds[0].FirstPacketAt = "2026-08-18T05:59:30+00:00" }},
		// The packet-time pair and the counters state one fact together. Both
		// halves of the divorce are rejected: a populated pair with no packets,
		// and a packet count with no pair.
		{"counters zeroed but packet times populated", func(h *Heartbeat) {
			h.Feeds[0].Packets = 0
			h.Feeds[0].Bytes = 0
		}},
		{"packets counted but never received one", func(h *Heartbeat) {
			h.Feeds[0].FirstPacketAt = ""
			h.Feeds[0].LastPacketAt = ""
		}},
		{"bytes counted but never received a packet", func(h *Heartbeat) {
			h.Feeds[0].FirstPacketAt = ""
			h.Feeds[0].LastPacketAt = ""
			h.Feeds[0].Packets = 0
		}},
		// ErasureFraction is the field the customer's SLA is audited against,
		// and it derives from two fields that are already validated. An
		// untrusted producer must not be able to make the two disagree.
		{"erasure fraction contradicts its own integers", func(h *Heartbeat) {
			h.Feeds[0].Erasure.SetsTotal = 50
			h.Feeds[0].Erasure.SetsErased = 25
			h.Feeds[0].Erasure.ErasureFraction = 0.0
		}},
		{"negative erasure fraction", func(h *Heartbeat) { h.Feeds[0].Erasure.ErasureFraction = -5 }},
		{"erasure fraction above one", func(h *Heartbeat) { h.Feeds[0].Erasure.ErasureFraction = 1.5 }},
		{"NaN erasure fraction", func(h *Heartbeat) { h.Feeds[0].Erasure.ErasureFraction = math.NaN() }},
		{"infinite r_mean", func(h *Heartbeat) { h.Feeds[0].Erasure.RMean = math.Inf(1) }},
		{"negative grace", func(h *Heartbeat) { h.Feeds[0].Erasure.GraceMS = -1000 }},
		{"negative r_mean", func(h *Heartbeat) { h.Feeds[0].Erasure.RMean = -42 }},
		{"negative r_peak", func(h *Heartbeat) { h.Feeds[0].Erasure.RPeak100MS = -1 }},
		{"unsorted feeds", func(h *Heartbeat) {
			h.Feeds = append(h.Feeds, h.Feeds[0])
			h.Feeds[0].FeedID = "feed-z"
			h.Feeds[1].FeedID = "feed-a"
		}},
		{"duplicate feeds", func(h *Heartbeat) { h.Feeds = append(h.Feeds, h.Feeds[0]) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hb := validHeartbeat()
			test.mutate(&hb)
			if err := ValidateHeartbeat(hb); err == nil {
				t.Fatalf("ValidateHeartbeat(%s) = nil, want an error", test.name)
			}
		})
	}
}

// TestValidateHeartbeatAcceptsAFeedThatHasReceivedNothing covers the other
// half of the packet-time pair contract: both empty is a real, expected state
// for a feed that is subscribed but silent.
func TestValidateHeartbeatAcceptsAFeedThatHasReceivedNothing(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds[0].FirstPacketAt = ""
	hb.Feeds[0].LastPacketAt = ""
	hb.Feeds[0].Packets = 0
	hb.Feeds[0].Bytes = 0

	if err := ValidateHeartbeat(hb); err != nil {
		t.Fatalf("a silent feed must still validate: %v", err)
	}
}

// TestValidateHeartbeatAcceptsZeroLengthDatagrams covers the one asymmetry in
// the counter contract: Bytes must be zero when Packets is, but a positive
// Packets does not require positive Bytes. A zero-length UDP datagram is legal
// and must not be mistaken for a malformed report.
func TestValidateHeartbeatAcceptsZeroLengthDatagrams(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds[0].Packets = 3
	hb.Feeds[0].Bytes = 0

	if err := ValidateHeartbeat(hb); err != nil {
		t.Fatalf("a feed carrying only zero-length datagrams must validate: %v", err)
	}
}

// TestValidateHeartbeatAcceptsIdenticalFirstAndLastPacket covers the
// single-packet feed, where first == last is correct rather than degenerate.
func TestValidateHeartbeatAcceptsIdenticalFirstAndLastPacket(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds[0].LastPacketAt = hb.Feeds[0].FirstPacketAt

	if err := ValidateHeartbeat(hb); err != nil {
		t.Fatalf("a single-packet feed must validate: %v", err)
	}
}

func TestValidateHeartbeatErrorsAreMatchable(t *testing.T) {
	hb := validHeartbeat()
	hb.Schema = "nope"

	err := ValidateHeartbeat(hb)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ErrInvalidHeartbeat) {
		t.Fatalf("error %v does not wrap ErrInvalidHeartbeat", err)
	}
}

func TestFormatTimestampProducesValidatorAcceptedForm(t *testing.T) {
	// A non-UTC zone with sub-second precision exercises both normalization
	// paths at once.
	zone := time.FixedZone("UTC+2", 2*60*60)
	stamp := FormatTimestamp(time.Date(2026, 8, 18, 8, 0, 0, 500_000_000, zone))

	hb := validHeartbeat()
	hb.SentAt = stamp
	if err := ValidateHeartbeat(hb); err != nil {
		t.Fatalf("FormatTimestamp produced %q, which the validator rejects: %v", stamp, err)
	}
	if want := "2026-08-18T06:00:00.5Z"; stamp != want {
		t.Fatalf("FormatTimestamp = %q, want %q", stamp, want)
	}
}

// TestVersionDefaultIsObviouslyUnstamped guards the recall lever: an unstamped
// build must be distinguishable in the broker's records from a real release,
// so W4's minimum-version enforcement cannot be satisfied by an accident.
func TestVersionDefaultIsObviouslyUnstamped(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version() must never be empty; it is the field-rollback lever")
	}
	if !strings.Contains(Version(), "unstamped") {
		t.Fatalf("Version() = %q, want a default that reads as unstamped", Version())
	}
}

func TestValidateCanonicalUUID(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"canonical", testGWUUID, true},
		{"all hex letters", "abcdefab-cdef-abcd-efab-cdefabcdefab", true},
		{"digits with one nonzero", "00000000-0000-0000-0000-000000000001", true},
		{"nil uuid", "00000000-0000-0000-0000-000000000000", false},
		{"uppercase", "3F2504E0-4F89-41D3-9A0C-0305E82C3301", false},
		{"too short", "3f2504e0-4f89-41d3-9a0c-0305e82c330", false},
		{"too long", testGWUUID + "0", false},
		{"misplaced separator", "3f2504e04-f89-41d3-9a0c-0305e82c3301", false},
		{"non-hex character", "3f2504e0-4f89-41d3-9a0c-0305e82c33g1", false},
		{"empty", "", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCanonicalUUID(test.value)
			if test.valid && err != nil {
				t.Fatalf("validateCanonicalUUID(%q) = %v, want nil", test.value, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("validateCanonicalUUID(%q) = nil, want an error", test.value)
			}
		})
	}
}

func TestHeartbeatIntervalMatchesSpec(t *testing.T) {
	if HeartbeatInterval != 30*time.Second {
		t.Fatalf("HeartbeatInterval = %v, want 30s", HeartbeatInterval)
	}
}
