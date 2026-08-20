package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
// Note the < and > escapes: encoding/json HTML-escapes < and > in the histogram
// keys by default, so this is what a Go producer puts on the wire. It is NOT
// what every producer must put on the wire. A producer emitting the
// semantically identical literal "<1" and ">=32" — including a Go producer
// using json.Encoder with SetEscapeHTML(false) — decodes to the same document,
// passes validation, and is not penalized for the difference. The ledger's
// diffability rests on the broker re-encoding through CanonicalBytes, not on
// the producer reproducing these bytes; see HeartbeatSchema and CanonicalBytes.
// What this literal freezes is Go's own output, which is the form
// CanonicalBytes converges every producer onto.
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
			"on this test and on the Heartbeat doc, because verbatim retention is now possible")
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

// TestErasureFractionToleranceAdmitsRoundedProducers pins the epsilon against
// the rationale it carries, in both directions.
//
// The tolerance exists so a producer serializing the ratio at fixed decimal
// precision is not rejected for rounding. It must therefore admit the
// MinFractionDecimalPlaces case (%.6f / toFixed(6) / round(x, 6), the default
// for a non-Go producer) while still rejecting a fraction that disagrees with
// the integers beneath it by more than rounding can explain. An earlier 1e-9
// bound satisfied only the second half and rejected six-decimal producers for
// any ratio not exactly representable at that precision.
//
// The rule is agreement within the tolerance, NOT a decimal-place count, so the
// table pins both sides of that distinction: coarse output is accepted for a
// ratio it can represent exactly and rejected for one it cannot. That is why
// MinFractionDecimalPlaces is documented as guidance rather than as an
// enforced floor — see its doc comment.
func TestErasureFractionToleranceAdmitsRoundedProducers(t *testing.T) {
	roundTo := func(v float64, places int) float64 {
		t.Helper()
		var out float64
		if err := json.Unmarshal([]byte(fmt.Sprintf("%.*f", places, v)), &out); err != nil {
			t.Fatalf("re-parsing a rounded fraction: %v", err)
		}
		return out
	}

	tests := []struct {
		name         string
		erased       uint64
		total        uint64
		fraction     func(exact float64) float64
		wantAccepted bool
	}{
		{
			name: "exact go producer", erased: 2, total: 50,
			fraction:     func(exact float64) float64 { return exact },
			wantAccepted: true,
		},
		{
			// The case the tolerance is documented to exist for. 1/3 is not
			// representable at any finite decimal precision, so this is the
			// shape a 1e-9 bound rejected.
			name: "repeating ratio at the documented precision", erased: 1, total: 3,
			fraction:     func(exact float64) float64 { return roundTo(exact, MinFractionDecimalPlaces) },
			wantAccepted: true,
		},
		{
			name: "another repeating ratio at the documented precision", erased: 2, total: 7,
			fraction:     func(exact float64) float64 { return roundTo(exact, MinFractionDecimalPlaces) },
			wantAccepted: true,
		},
		{
			// Four places coarser than the contract asks for, and accepted
			// anyway, because 2/50 is exactly representable at two. Pinned so
			// the accepted-coarse case is deliberate rather than incidental:
			// this is the whole reason MinFractionDecimalPlaces cannot be
			// described as a floor validation enforces. A producer shipping two
			// decimal places passes here and fails the row below.
			name: "terminating ratio coarser than the documented precision", erased: 2, total: 50,
			fraction:     func(exact float64) float64 { return roundTo(exact, 2) },
			wantAccepted: true,
		},
		{
			// One decimal place coarser than the contract requires, on a ratio
			// that does not terminate there: the producer has under-serialized
			// and is told so. This case is also what stops the tolerance being
			// widened without a doc change.
			name: "coarser than the documented precision", erased: 1, total: 3,
			fraction:     func(exact float64) float64 { return roundTo(exact, MinFractionDecimalPlaces-1) },
			wantAccepted: false,
		},
		{
			name: "just inside the tolerance", erased: 2, total: 50,
			fraction:     func(exact float64) float64 { return exact + erasureFractionEpsilon/2 },
			wantAccepted: true,
		},
		{
			name: "just outside the tolerance", erased: 2, total: 50,
			fraction:     func(exact float64) float64 { return exact + erasureFractionEpsilon*2 },
			wantAccepted: false,
		},
		{
			// The tolerance must never mask a miscounted set. The smallest
			// disagreement a wrong integer can produce here is 1/50.
			name: "off by one erased set", erased: 2, total: 50,
			fraction:     func(_ float64) float64 { return erasure.Fraction(3, 50) },
			wantAccepted: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hb := validHeartbeat()
			hb.Feeds[0].Erasure.SetsErased = test.erased
			hb.Feeds[0].Erasure.SetsTotal = test.total
			hb.Feeds[0].Erasure.ErasureFraction = test.fraction(erasure.Fraction(test.erased, test.total))

			err := ValidateHeartbeat(hb)
			if accepted := err == nil; accepted != test.wantAccepted {
				t.Fatalf("accepted = %v, want %v (fraction %v for %d/%d): %v",
					accepted, test.wantAccepted, hb.Feeds[0].Erasure.ErasureFraction,
					test.erased, test.total, err)
			}
		})
	}
}

// TestCanonicalBytesNormalizesProducerEscaping pins the resolution of the one
// contract rule validation cannot enforce.
//
// A non-Go producer emits the gap_ms_hist keys unescaped. That payload decodes
// to an identical document and passes validation, but its raw bytes differ from
// Go's, so a ledger diffing bytes as received would report two identical
// reports as different. Canonicalizing on ingest is the broker-side obligation
// documented on HeartbeatSchema; this test is what says it actually holds.
func TestCanonicalBytesNormalizesProducerEscaping(t *testing.T) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(validHeartbeat()); err != nil {
		t.Fatal(err)
	}
	fromNonGoProducer := bytes.TrimSpace(buf.Bytes())

	// Precondition: this really is the hazard, not an already-identical form.
	if bytes.Equal(fromNonGoProducer, []byte(canonicalWire)) {
		t.Fatal("the unescaped form is byte-identical to canonicalWire, so the escaping " +
			"hazard this test exists for is gone; simplify HeartbeatSchema's doc accordingly")
	}
	if !bytes.Contains(fromNonGoProducer, []byte(`"<1"`)) {
		t.Fatalf("expected the unescaped histogram key on the non-Go wire form, got %s", fromNonGoProducer)
	}

	var decoded Heartbeat
	if err := json.Unmarshal(fromNonGoProducer, &decoded); err != nil {
		t.Fatalf("a non-Go producer's heartbeat must still decode: %v", err)
	}
	if err := ValidateHeartbeat(decoded); err != nil {
		t.Fatalf("the unescaped form is semantically identical and must validate: %v", err)
	}

	canonical, err := CanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != canonicalWire {
		t.Fatalf("canonicalization did not converge on the ledger's byte form:\n got %s\nwant %s",
			canonical, canonicalWire)
	}
}

// TestCanonicalBytesNormalizesProducerFractionPrecision covers the second
// convergence hazard, which the escaping fix above does not touch.
//
// Escaping is a spelling difference. erasure_fraction is a value difference: a
// Go producer emits the float64-exact ratio and a producer using %.6f emits six
// digits, both describe the same window, and both pass validation because the
// tolerance is there precisely to admit the second one. Marshalling as received
// would then hand the ledger two different byte strings for one report — the
// exact failure CanonicalBytes exists to prevent, reached by a different route.
//
// The sibling test above cannot see this, because it re-encodes validHeartbeat()
// whose 2/50 fraction is identical on both sides.
func TestCanonicalBytesNormalizesProducerFractionPrecision(t *testing.T) {
	// A window that erases 1 set in 3: a ratio no decimal precision represents.
	const erased, total = 1, 3

	withFraction := func(fraction float64) Heartbeat {
		hb := validHeartbeat()
		hb.Feeds[0].Erasure.SetsErased = erased
		hb.Feeds[0].Erasure.SetsTotal = total
		hb.Feeds[0].Erasure.ErasureFraction = fraction
		return hb
	}

	exact := erasure.Fraction(erased, total)
	var sixDecimals float64
	if err := json.Unmarshal([]byte(fmt.Sprintf("%.*f", MinFractionDecimalPlaces, exact)), &sixDecimals); err != nil {
		t.Fatal(err)
	}

	// Precondition: this really is the hazard. Both producers are accepted, and
	// their raw encodings differ.
	fromGo, fromSixDecimals := withFraction(exact), withFraction(sixDecimals)
	if err := ValidateHeartbeat(fromGo); err != nil {
		t.Fatalf("the float64-exact producer must validate: %v", err)
	}
	if err := ValidateHeartbeat(fromSixDecimals); err != nil {
		t.Fatalf("the six-decimal producer must validate; that is what the tolerance is for: %v", err)
	}
	rawGo, err := json.Marshal(fromGo)
	if err != nil {
		t.Fatal(err)
	}
	rawSixDecimals, err := json.Marshal(fromSixDecimals)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rawGo, rawSixDecimals) {
		t.Fatal("the two producers already encode identically, so the precision hazard this " +
			"test exists for is gone; simplify CanonicalBytes' doc accordingly")
	}

	canonicalGo, err := CanonicalBytes(fromGo)
	if err != nil {
		t.Fatal(err)
	}
	canonicalSixDecimals, err := CanonicalBytes(fromSixDecimals)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonicalGo, canonicalSixDecimals) {
		t.Fatalf("canonicalization did not converge:\n go %s\nsix %s", canonicalGo, canonicalSixDecimals)
	}
	// Assert the rendered value, not just that the two agree: converging on a
	// wrongly-rounded number would also satisfy the comparison above.
	if want := `"erasure_fraction":0.3333333333333333,`; !bytes.Contains(canonicalGo, []byte(want)) {
		t.Fatalf("canonical form must carry the float64-exact ratio %s, got %s", want, canonicalGo)
	}
}

// TestCanonicalBytesRefusesToLaunderADisagreeingFraction pins the guard that
// makes the recompute above safe.
//
// Recomputing a field means overwriting what the producer said, and for a
// producer whose fraction contradicts its own integers that would replace
// evidence of a misbehaving producer with a plausible number — reachable by
// canonicalizing before validating, which is exactly the ordering mistake the
// numbered sequence on Heartbeat warns about. So the disagreement is an error
// rather than a silent correction.
func TestCanonicalBytesRefusesToLaunderADisagreeingFraction(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds[0].Erasure.SetsTotal = 50
	hb.Feeds[0].Erasure.SetsErased = 25
	hb.Feeds[0].Erasure.ErasureFraction = 0 // truthfully 0.5

	// Precondition: validation rejects this, so CanonicalBytes is only ever
	// reached with it by a caller that skipped step 2.
	if err := ValidateHeartbeat(hb); err == nil {
		t.Fatal("validation must already reject a fraction that contradicts its integers")
	}

	encoded, err := CanonicalBytes(hb)
	if err == nil {
		t.Fatalf("CanonicalBytes(disagreeing fraction) = %s, want an error", encoded)
	}
	if encoded != nil {
		t.Fatalf("a failed canonicalization must not return bytes, got %s", encoded)
	}
	if !errors.Is(err, ErrInvalidHeartbeat) {
		t.Fatalf("error must match ErrInvalidHeartbeat so callers can classify it, got %v", err)
	}
	// Assert the rendered message, including the values interpolated into it: a
	// Contains check on a fragment that spans no verb would pass even if every
	// %v were mis-specified.
	const want = "feeds[0] (feed-a): erasure.erasure_fraction 0 disagrees with " +
		"sets_erased 25 / sets_total 50 (= 0.5); ValidateHeartbeat must run first"
	if got := err.Error(); !strings.Contains(got, want) {
		t.Fatalf("error message must name the disagreement and the fix:\n got %s\nwant substring %s", got, want)
	}
	if strings.ContainsAny(err.Error(), "%") {
		t.Fatalf("error message carries an unrendered format directive: %s", err)
	}
}

// TestCanonicalBytesDoesNotMutateTheCallersHeartbeat guards the aliasing trap in
// the recompute: Heartbeat is passed by value, but Feeds is a slice, so writing
// through hb.Feeds[i] would rewrite the caller's own heartbeat. A producer that
// canonicalized for logging would silently have its outbound report edited.
func TestCanonicalBytesDoesNotMutateTheCallersHeartbeat(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds[0].Erasure.SetsErased = 1
	hb.Feeds[0].Erasure.SetsTotal = 3
	// A six-decimal fraction: accepted, and different from what CanonicalBytes
	// will emit, so an in-place recompute would be visible here.
	var sixDecimals float64
	if err := json.Unmarshal([]byte("0.333333"), &sixDecimals); err != nil {
		t.Fatal(err)
	}
	hb.Feeds[0].Erasure.ErasureFraction = sixDecimals

	if _, err := CanonicalBytes(hb); err != nil {
		t.Fatal(err)
	}
	if got := hb.Feeds[0].Erasure.ErasureFraction; got != sixDecimals {
		t.Fatalf("CanonicalBytes rewrote the caller's fraction to %v, want %v left untouched", got, sixDecimals)
	}
}

// TestCanonicalBytesPreservesTheEmptyFeedWireForm pairs with
// TestEmptyFeedListMarshalsAsNullNotAbsent: the ledger's byte form for a
// gateway subscribed to nothing must be the same "feeds":null the envelope
// documents, so the feed copy in CanonicalBytes must not turn a nil slice into
// an empty one.
func TestCanonicalBytesPreservesTheEmptyFeedWireForm(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds = nil

	encoded, err := CanonicalBytes(hb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"feeds":null`) {
		t.Fatalf("expected feeds to canonicalize as null, got %s", encoded)
	}
}

// TestCanonicalBytesRejectsUnmarshalableInput pins the failure modes
// CanonicalBytes has, and the reason its doc tells callers to validate first.
//
// encoding/json cannot represent NaN or ±Inf, and both are reachable in-process
// on the producer side where a float is assigned directly rather than decoded.
// A caller that canonicalizes before validating gets an ErrInvalidHeartbeat
// rather than a partial buffer or a silently dropped field.
//
// The two rows are not redundant. A non-finite erasure_fraction is caught by an
// explicit guard before the recompute, because NaN passes the disagreement
// comparison vacuously — every comparison against NaN is false — and would then
// have the recompute quietly replace it with a finite number, marshal cleanly,
// and land in the ledger. A non-finite r_mean is not recomputed at all and is
// caught by json.Marshal itself, which is the branch that keeps the error wrap
// on the marshal call live.
func TestCanonicalBytesRejectsUnmarshalableInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Heartbeat)
	}{
		{"NaN erasure fraction", func(h *Heartbeat) { h.Feeds[0].Erasure.ErasureFraction = math.NaN() }},
		{"infinite erasure fraction", func(h *Heartbeat) { h.Feeds[0].Erasure.ErasureFraction = math.Inf(1) }},
		{"NaN r_mean", func(h *Heartbeat) { h.Feeds[0].Erasure.RMean = math.NaN() }},
		{"infinite r_peak", func(h *Heartbeat) { h.Feeds[0].Erasure.RPeak100MS = math.Inf(-1) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hb := validHeartbeat()
			test.mutate(&hb)

			encoded, err := CanonicalBytes(hb)
			if err == nil {
				t.Fatalf("CanonicalBytes(%s) = %s, want an error", test.name, encoded)
			}
			if !errors.Is(err, ErrInvalidHeartbeat) {
				t.Fatalf("error must match ErrInvalidHeartbeat so callers can classify it, got %v", err)
			}
			if encoded != nil {
				t.Fatalf("a failed canonicalization must not return bytes, got %s", encoded)
			}
		})
	}
}

// TestMaxSetsTotalIsTheLargestBoundThatCatchesAnOffByOne pins the derivation
// MaxSetsTotal's doc claims, which is the whole reason the bound exists.
//
// erasureFractionEpsilon's rationale asserts the tolerance "cannot mask a wrong
// integer". That is only true while the smallest disagreement a miscounted set
// can produce, 1/sets_total, still exceeds the tolerance. So the two constants
// are coupled, and a future widening of the tolerance must either move the
// bound or retract the claim — this test is what forces that choice instead of
// letting the claim quietly become false.
//
// The behavioural half asserts the REASON for each rejection, not just that one
// happened. Without that, the bound would confound the measurement: past
// MaxSetsTotal every heartbeat is rejected by the bound, so a test that only
// checked "rejected" would stay green even if the fraction recompute had been
// deleted outright.
func TestMaxSetsTotalIsTheLargestBoundThatCatchesAnOffByOne(t *testing.T) {
	// The arithmetic the doc derives the constant from.
	if smallest := 1 / float64(MaxSetsTotal); smallest <= erasureFractionEpsilon {
		t.Fatalf("an off-by-one at sets_total=%d moves the fraction by %v, which the %v tolerance "+
			"already swallows: MaxSetsTotal is too large for erasureFractionEpsilon",
			MaxSetsTotal, smallest, erasureFractionEpsilon)
	}
	if next := 1 / float64(uint64(MaxSetsTotal)+1); next > erasureFractionEpsilon {
		t.Fatalf("sets_total=%d would still catch an off-by-one (%v > %v), so MaxSetsTotal is "+
			"lower than it needs to be and the doc's derivation is wrong",
			uint64(MaxSetsTotal)+1, next, erasureFractionEpsilon)
	}

	// At the bound, a miscounted set is still caught, and caught by the
	// recompute rather than by the bound.
	atBound := validHeartbeat()
	atBound.Feeds[0].Erasure.SetsTotal = MaxSetsTotal
	atBound.Feeds[0].Erasure.SetsErased = 1
	atBound.Feeds[0].Erasure.ErasureFraction = erasure.Fraction(2, MaxSetsTotal)

	err := ValidateHeartbeat(atBound)
	if err == nil {
		t.Fatalf("an off-by-one erased set at sets_total=%d must be rejected", MaxSetsTotal)
	}
	if !strings.Contains(err.Error(), "disagrees with sets_erased") {
		t.Fatalf("rejected for the wrong reason; the recompute must be what fires: %v", err)
	}

	// An honest report at the bound is still accepted, so the bound is a cap on
	// untrusted input and not a cap on legitimate traffic.
	honest := atBound
	honest.Feeds[0].Erasure.ErasureFraction = erasure.Fraction(1, MaxSetsTotal)
	if err := ValidateHeartbeat(honest); err != nil {
		t.Fatalf("a correct report at exactly sets_total=%d must validate: %v", MaxSetsTotal, err)
	}

	// One past the bound, the report is refused outright rather than accepted
	// with a fraction the tolerance can no longer police.
	overBound := validHeartbeat()
	overBound.Feeds[0].Erasure.SetsTotal = MaxSetsTotal + 1
	overBound.Feeds[0].Erasure.SetsErased = 1
	overBound.Feeds[0].Erasure.ErasureFraction = erasure.Fraction(2, MaxSetsTotal+1)

	err = ValidateHeartbeat(overBound)
	if err == nil {
		t.Fatalf("sets_total=%d exceeds MaxSetsTotal and must be rejected", MaxSetsTotal+1)
	}
	if want := fmt.Sprintf("erasure.sets_total must be at most %d, got %d", MaxSetsTotal, MaxSetsTotal+1); !strings.Contains(err.Error(), want) {
		t.Fatalf("error must name the bound a rejected producer is being held to:\n got %s\nwant substring %s", err, want)
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
		{"oversized version", func(h *Heartbeat) { h.Version = strings.Repeat("v", MaxVersionBytes+1) }},
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
		{"oversized feed id", func(h *Heartbeat) { h.Feeds[0].FeedID = strings.Repeat("f", MaxFeedIDBytes+1) }},
		{"wrong erasure schema", func(h *Heartbeat) { h.Feeds[0].Erasure.Schema = 2 }},
		{"erased exceeds total", func(h *Heartbeat) { h.Feeds[0].Erasure.SetsErased = h.Feeds[0].Erasure.SetsTotal + 1 }},
		// sets_total is the denominator the fraction recompute polices against,
		// so an unbounded one lets an untrusted producer choose a denominator
		// large enough for the tolerance to swallow a miscounted set. See
		// TestMaxSetsTotalIsTheLargestBoundThatCatchesAnOffByOne.
		{"oversized sets_total", func(h *Heartbeat) {
			h.Feeds[0].Erasure.SetsTotal = MaxSetsTotal + 1
			h.Feeds[0].Erasure.SetsErased = 1
			h.Feeds[0].Erasure.ErasureFraction = erasure.Fraction(1, MaxSetsTotal+1)
		}},
		{"first packet time without last", func(h *Heartbeat) { h.Feeds[0].LastPacketAt = "" }},
		{"last packet time without first", func(h *Heartbeat) { h.Feeds[0].FirstPacketAt = "" }},
		{"last packet precedes first", func(h *Heartbeat) {
			h.Feeds[0].FirstPacketAt, h.Feeds[0].LastPacketAt = h.Feeds[0].LastPacketAt, h.Feeds[0].FirstPacketAt
		}},
		{"non-canonical packet time", func(h *Heartbeat) { h.Feeds[0].FirstPacketAt = "2026-08-18T05:59:30+00:00" }},
		// The fan-out cap. Feed IDs are zero-padded so the generated slice is
		// sorted and unique, and the oversize branch is what fails rather than
		// the ordering check.
		{"too many feeds", func(h *Heartbeat) {
			feeds := make([]FeedReport, 0, MaxFeeds+1)
			for i := 0; i <= MaxFeeds; i++ {
				feed := h.Feeds[0]
				feed.FeedID = fmt.Sprintf("feed-%06d", i)
				feeds = append(feeds, feed)
			}
			h.Feeds = feeds
		}},
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
		{"infinite r_peak", func(h *Heartbeat) { h.Feeds[0].Erasure.RPeak100MS = math.Inf(1) }},
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

// TestNonCanonicalLastPacketTimeIsRejectedByItsOwnBranch cannot be a row in the
// table above, and the reason is worth stating.
//
// The table asserts only that validation rejects. That is enough for every case
// in it except this one: a LastPacketAt that fails to parse leaves the zero
// time.Time, which precedes FirstPacketAt, so the ordering guard rejects the
// same input for a different reason. Delete the parse check and a table row
// stays green — it would pin nothing. Asserting the message is what ties this
// case to the branch it was written for.
func TestNonCanonicalLastPacketTimeIsRejectedByItsOwnBranch(t *testing.T) {
	hb := validHeartbeat()
	// Trailing zeros in the fractional part: valid RFC 3339, not canonical here.
	hb.Feeds[0].LastPacketAt = "2026-08-18T05:59:59.500Z"

	err := ValidateHeartbeat(hb)
	if err == nil {
		t.Fatal("ValidateHeartbeat(non-canonical last_packet_at) = nil, want an error")
	}
	if !strings.Contains(err.Error(), "last_packet_at must be a canonical UTC timestamp") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
	if !strings.Contains(err.Error(), canonicalTimestampRule) {
		t.Fatalf("error must carry the rule a rejected producer needs: %v", err)
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

// TestCanonicalBytesRebindsTheBoundItsRecomputeDependsOn pins the interaction
// between two of this contract's guards: the recompute in CanonicalBytes only
// detects a lie while 1/SetsTotal exceeds the tolerance, so it has to enforce
// MaxSetsTotal itself rather than inherit it from a ValidateHeartbeat call that
// may never have happened. Without the bound the function silently overwrites
// an inflated fraction with a valid-looking one — laundering exactly the
// evidence its doc says it refuses to discard.
func TestCanonicalBytesRebindsTheBoundItsRecomputeDependsOn(t *testing.T) {
	// sets_erased is 100; the producer claims a fraction for 101. At this
	// denominator the difference is 2e-7, well inside erasureFractionEpsilon.
	hb := validHeartbeat()
	hb.Feeds[0].Erasure.SetsTotal = 5_000_000
	hb.Feeds[0].Erasure.SetsErased = 100
	hb.Feeds[0].Erasure.ErasureFraction = erasure.Fraction(101, 5_000_000)

	if lie := math.Abs(hb.Feeds[0].Erasure.ErasureFraction - erasure.Fraction(100, 5_000_000)); lie > erasureFractionEpsilon {
		t.Fatalf("test is not exercising the masking regime: the off-by-one moves the fraction by %v, "+
			"which the %v tolerance already catches", lie, erasureFractionEpsilon)
	}

	if err := ValidateHeartbeat(hb); err == nil {
		t.Fatal("ValidateHeartbeat must reject an over-bound sets_total")
	}

	encoded, err := CanonicalBytes(hb)
	if err == nil {
		t.Fatalf("CanonicalBytes accepted a report whose fraction its own tolerance cannot police, "+
			"and rewrote it to a valid-looking ledger entry: %s", encoded)
	}
	if !strings.Contains(err.Error(), "exceeds MaxSetsTotal") {
		t.Fatalf("rejected for the wrong reason; the bound must be what fires: %v", err)
	}
	if !strings.Contains(err.Error(), "feed-a") {
		t.Fatalf("error must name the offending feed: %v", err)
	}

	// The bound is a cap on untrusted input, not on legitimate traffic: an
	// honest report at exactly the bound still canonicalizes.
	atBound := validHeartbeat()
	atBound.Feeds[0].Erasure.SetsTotal = MaxSetsTotal
	atBound.Feeds[0].Erasure.SetsErased = 1
	atBound.Feeds[0].Erasure.ErasureFraction = erasure.Fraction(1, MaxSetsTotal)
	if _, err := CanonicalBytes(atBound); err != nil {
		t.Fatalf("a correct report at exactly sets_total=%d must canonicalize: %v", MaxSetsTotal, err)
	}
}

// TestCanonicalBytesNamesTheFeedAndFieldForEveryNonFiniteFloat covers the three
// floats in the window, not just the one the recompute reads. encoding/json
// refuses NaN and Inf anyway, but its error names neither the field nor the
// feed, which is unactionable when a heartbeat can carry MaxFeeds reports.
func TestCanonicalBytesNamesTheFeedAndFieldForEveryNonFiniteFloat(t *testing.T) {
	tests := []struct {
		field string
		set   func(w *erasure.Window)
	}{
		{"erasure.erasure_fraction", func(w *erasure.Window) { w.ErasureFraction = math.NaN() }},
		{"erasure.r_mean", func(w *erasure.Window) { w.RMean = math.NaN() }},
		{"erasure.r_mean", func(w *erasure.Window) { w.RMean = math.Inf(1) }},
		{"erasure.r_peak_100ms", func(w *erasure.Window) { w.RPeak100MS = math.Inf(1) }},
		{"erasure.r_peak_100ms", func(w *erasure.Window) { w.RPeak100MS = math.Inf(-1) }},
	}

	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			hb := validHeartbeat()
			test.set(&hb.Feeds[0].Erasure)

			_, err := CanonicalBytes(hb)
			if err == nil {
				t.Fatal("a non-finite float must be refused")
			}
			if !strings.Contains(err.Error(), test.field) {
				t.Fatalf("error must name the offending field %q, got: %v", test.field, err)
			}
			if !strings.Contains(err.Error(), "feed-a") {
				t.Fatalf("error must name the offending feed, got: %v", err)
			}
			if strings.Contains(err.Error(), "json: unsupported value") {
				t.Fatalf("the generic marshal error is unactionable and must not be what surfaces: %v", err)
			}
			if !errors.Is(err, ErrInvalidHeartbeat) {
				t.Fatalf("error must wrap ErrInvalidHeartbeat, got: %v", err)
			}
		})
	}
}

// TestCanonicalBytesChecksConsistencyNotValidity pins the boundary the doc on
// CanonicalBytes now states outright. A report whose integers are themselves
// invalid but whose fraction agrees with them canonicalizes cleanly: the
// recompute is a consistency check, and a producer that lied consistently in
// both places is caught by ValidateHeartbeat, not here. This is the reason step
// 2 is not optional, so it is worth failing loudly if the behaviour ever
// silently changes in either direction.
func TestCanonicalBytesChecksConsistencyNotValidity(t *testing.T) {
	hb := validHeartbeat()
	hb.Feeds[0].Erasure.SetsTotal = 10
	hb.Feeds[0].Erasure.SetsErased = 40
	hb.Feeds[0].Erasure.ErasureFraction = 4.0

	if err := ValidateHeartbeat(hb); err == nil {
		t.Fatal("ValidateHeartbeat must reject sets_erased > sets_total")
	}

	encoded, err := CanonicalBytes(hb)
	if err != nil {
		t.Fatalf("CanonicalBytes performs a consistency check, not a validity check, so an "+
			"internally consistent report must pass it: %v", err)
	}
	if !bytes.Contains(encoded, []byte(`"erasure_fraction":4`)) {
		t.Fatalf("the consistent-but-invalid fraction must survive unchanged: %s", encoded)
	}
}

// TestMaxSetsTotalExceedsTheLongestLegalWindow guards the *other* axis of the
// constant's derivation: TestMaxSetsTotalIsTheLargestBoundThatCatchesAnOffByOne
// pins it against the tolerance from below, and this pins it against real
// traffic from above. It exists because the doc's margin was once computed
// against HeartbeatInterval, which is not the window that fills sets_total, and
// overstated the headroom by 10x as a result.
func TestMaxSetsTotalExceedsTheLongestLegalWindow(t *testing.T) {
	// Mirrors cmd/blockcast-shreds/main.go: maxReportInterval caps
	// --report-interval, and 30k shred/s is the rate that file sizes buffers
	// against. They live in package main and cannot be imported here, so raising
	// either without updating this test is what this assertion is here to catch.
	const (
		maxReportInterval = 5 * time.Minute
		sizingShredRate   = 30_000
		shredsPerSet      = 64
	)

	worstCase := uint64(sizingShredRate * maxReportInterval.Seconds() / shredsPerSet)
	if worstCase >= MaxSetsTotal {
		t.Fatalf("a full %v window at %d shred/s accumulates %d sets, which meets or exceeds "+
			"MaxSetsTotal %d: honest traffic would now be rejected at ingest",
			maxReportInterval, sizingShredRate, worstCase, MaxSetsTotal)
	}

	// The margin the doc quotes. Pinned so the prose and the constant cannot
	// drift apart again.
	if margin := float64(MaxSetsTotal) / float64(worstCase); margin < 7.0 || margin > 7.2 {
		t.Fatalf("headroom over the longest legal window is %.2fx, but the doc on MaxSetsTotal "+
			"claims 7.1x; update whichever is wrong", margin)
	}
}
