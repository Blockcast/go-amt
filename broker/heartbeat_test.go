package broker

import (
	"encoding/json"
	"errors"
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

// TestHeartbeatRoundTripsThroughTheWire guards the consumer half: a broker
// that decodes and re-encodes must get the same bytes back, which is what lets
// W4a retain the object verbatim in a JSONB column.
func TestHeartbeatRoundTripsThroughTheWire(t *testing.T) {
	original, err := json.Marshal(validHeartbeat())
	if err != nil {
		t.Fatal(err)
	}

	var decoded Heartbeat
	if err := json.Unmarshal(original, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHeartbeat(decoded); err != nil {
		t.Fatalf("decoded heartbeat failed validation: %v", err)
	}

	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(reencoded) != string(original) {
		t.Fatalf("round trip changed the wire form:\n got %s\nwant %s", reencoded, original)
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
