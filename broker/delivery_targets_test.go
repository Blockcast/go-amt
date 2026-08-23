package broker

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	targetIDA = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	targetIDB = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
)

func validDeliveryTargetsRead() DeliveryTargetsRead {
	return DeliveryTargetsRead{
		FeedID:      "solana-mainnet",
		Targets:     []DeliveryTarget{{TargetID: targetIDA, Addr: "203.0.113.7:9001"}},
		EvaluatedAt: "2026-08-23T15:04:05Z",
	}
}

// TestDeliveryTargetsPatternAndBuilderAgree is the same anti-drift assertion
// TestRoutePatternsAndBuildersAgree makes for the gateway routes, applied to
// the sender route: register the pattern on a real mux, send at the
// builder-produced path, and check it lands with the wildcard readable.
//
// String-comparing the constants would be circular — it would pass if the
// pattern and the builder were wrong in the same way.
func TestDeliveryTargetsPatternAndBuilderAgree(t *testing.T) {
	var landed bool
	var observedFeedID string

	mux := http.NewServeMux()
	mux.HandleFunc(PatternDeliveryTargets, func(w http.ResponseWriter, r *http.Request) {
		landed = true
		observedFeedID = r.PathValue(DeliveryTargetsFeedIDParam)
	})

	req := httptest.NewRequest(http.MethodGet, DeliveryTargetsPath("solana-mainnet"), nil)
	mux.ServeHTTP(httptest.NewRecorder(), req)

	if !landed {
		t.Fatalf("GET %s did not land on the delivery-targets handler", DeliveryTargetsPath("solana-mainnet"))
	}
	if observedFeedID != "solana-mainnet" {
		t.Errorf("feed_id wildcard = %q, want %q", observedFeedID, "solana-mainnet")
	}
}

// TestDeliveryTargetsRejectsWrongMethod pins that the method is part of the
// pattern, so a POST at the read's path is a 405 without a handler branch —
// the same property the three POST routes rely on in reverse.
func TestDeliveryTargetsRejectsWrongMethod(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc(PatternDeliveryTargets, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran for a POST; method is not part of the pattern")
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DeliveryTargetsPath("solana-mainnet"), nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST at the read path = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// TestDeliveryTargetsPathEscapesFeedID pins the RenewPath property: a feed_id
// that would otherwise traverse resolves to a path the caller did not name.
func TestDeliveryTargetsPathEscapesFeedID(t *testing.T) {
	got := DeliveryTargetsPath("../tickets")
	if strings.Contains(got, "../") {
		t.Errorf("DeliveryTargetsPath(%q) = %q, which traverses", "../tickets", got)
	}
}

// TestDeliveryTargetsEmptySetSurvivesRoundTrip is the assertion this contract
// most exists for.
//
// An authoritative "zero entitled subscribers" and a failed read demand
// opposite actions from the sender — hold-and-stop versus hold-and-retry — and
// encoding/json will happily collapse them, because a nil slice marshals to
// "null" and unmarshals back to something len() calls 0. So this pins the wire
// bytes, not just the Go value: an empty set must serialize as "[]" and must
// still validate on the way back in.
func TestDeliveryTargetsEmptySetSurvivesRoundTrip(t *testing.T) {
	read := validDeliveryTargetsRead()
	read.Targets = []DeliveryTarget{}

	encoded, err := json.Marshal(read)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"targets":[]`) {
		t.Fatalf("empty set encoded as %s, want a literal []", encoded)
	}

	var decoded DeliveryTargetsRead
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Targets == nil {
		t.Fatal("empty set decoded to a nil Targets, erasing the authoritative-zero distinction")
	}
	if len(decoded.Targets) != 0 {
		t.Fatalf("len(Targets) = %d, want 0", len(decoded.Targets))
	}
	if err := ValidateDeliveryTargetsRead(decoded); err != nil {
		t.Fatalf("an authoritative empty set must validate, got %v", err)
	}
}

// TestDeliveryTargetsNullTargetsIsRejected is the other half of the above, and
// it is the one that matters for safety.
//
// A broker bug emitting "null" would decode to len 0 and, if accepted, read as
// "this feed has no subscribers" — tearing down every destination on the feed.
// It must instead fail validation, which routes it into the read-failure path
// where the sender holds its table.
func TestDeliveryTargetsNullTargetsIsRejected(t *testing.T) {
	var decoded DeliveryTargetsRead
	if err := json.Unmarshal([]byte(`{"feed_id":"solana-mainnet","targets":null,"evaluated_at":"2026-08-23T15:04:05Z"}`), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Targets != nil {
		t.Fatal("precondition failed: null did not decode to a nil slice")
	}

	err := ValidateDeliveryTargetsRead(decoded)
	if err == nil {
		t.Fatal("null targets must not validate; it is indistinguishable from an authoritative empty set once accepted")
	}
	if !errors.Is(err, ErrInvalidTransport) {
		t.Errorf("error %v does not wrap ErrInvalidTransport", err)
	}
}

// TestDeliveryTargetsAllowsSharedAddress pins that Addr is not a key: several
// seats behind one NAT legitimately share an address, and only TargetID is
// required to be unique.
func TestDeliveryTargetsAllowsSharedAddress(t *testing.T) {
	read := validDeliveryTargetsRead()
	read.Targets = []DeliveryTarget{
		{TargetID: targetIDA, Addr: "203.0.113.7:9001"},
		{TargetID: targetIDB, Addr: "203.0.113.7:9001"},
	}

	if err := ValidateDeliveryTargetsRead(read); err != nil {
		t.Fatalf("two targets sharing one address must validate, got %v", err)
	}
}

func TestValidateDeliveryTargetsRead(t *testing.T) {
	// Takes a slice rather than variadic on purpose: a variadic call with no
	// arguments yields a *nil* slice, so "empty set" and "absent set" would be
	// the same case — the exact conflation this contract exists to prevent,
	// and one this helper got wrong on the first draft.
	withTargets := func(targets []DeliveryTarget) DeliveryTargetsRead {
		read := validDeliveryTargetsRead()
		read.Targets = targets
		return read
	}
	withFeedID := func(feedID string) DeliveryTargetsRead {
		read := validDeliveryTargetsRead()
		read.FeedID = feedID
		return read
	}
	withEvaluatedAt := func(ts string) DeliveryTargetsRead {
		read := validDeliveryTargetsRead()
		read.EvaluatedAt = ts
		return read
	}

	for _, tc := range []struct {
		name    string
		read    DeliveryTargetsRead
		wantErr bool
	}{
		{"valid", validDeliveryTargetsRead(), false},
		{"authoritative empty set", withTargets([]DeliveryTarget{}), false},
		{"nil targets", withTargets(nil), true},

		{"empty feed_id", withFeedID(""), true},
		{"feed_id at bound", withFeedID(strings.Repeat("f", MaxFeedIDBytes)), false},
		{"feed_id over bound", withFeedID(strings.Repeat("f", MaxFeedIDBytes+1)), true},
		{"invalid utf8 feed_id", withFeedID("\xff\xfe"), true},

		{"non-canonical evaluated_at zone", withEvaluatedAt("2026-08-23T15:04:05+00:00"), true},
		{"empty evaluated_at", withEvaluatedAt(""), true},

		{"uppercase target_id", withTargets([]DeliveryTarget{{TargetID: strings.ToUpper(targetIDA), Addr: "203.0.113.7:9001"}}), true},
		{"nil uuid target_id", withTargets([]DeliveryTarget{{TargetID: "00000000-0000-0000-0000-000000000000", Addr: "203.0.113.7:9001"}}), true},
		{"repeated target_id", withTargets([]DeliveryTarget{
			{TargetID: targetIDA, Addr: "203.0.113.7:9001"},
			{TargetID: targetIDA, Addr: "203.0.113.8:9001"},
		}), true},

		{"addr without port", withTargets([]DeliveryTarget{{TargetID: targetIDA, Addr: "203.0.113.7"}}), true},
		{"addr with zero port", withTargets([]DeliveryTarget{{TargetID: targetIDA, Addr: "203.0.113.7:0"}}), true},
		{"unspecified addr", withTargets([]DeliveryTarget{{TargetID: targetIDA, Addr: "0.0.0.0:9001"}}), true},
		{"hostname rather than ip", withTargets([]DeliveryTarget{{TargetID: targetIDA, Addr: "subscriber.example:9001"}}), true},
		{"ipv6 addr", withTargets([]DeliveryTarget{{TargetID: targetIDA, Addr: "[2001:db8::1]:9001"}}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateDeliveryTargetsRead(tc.read)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if !errors.Is(err, ErrInvalidTransport) {
					t.Errorf("error %v does not wrap ErrInvalidTransport", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

// TestSenderSchemaIsIndependentOfTransportSchema pins the reason this contract
// is a separate file: the two surfaces have different upgrade coupling, so a
// sender-side revision must be able to move without implying a breaking change
// to the customer-installed gateway binary.
func TestSenderSchemaIsIndependentOfTransportSchema(t *testing.T) {
	if SenderTransportSchema == TransportSchema {
		t.Fatalf("SenderTransportSchema and TransportSchema are both %q; they version independently evolving surfaces and must differ", SenderTransportSchema)
	}
}

// TestDeliveryTargetsRouteDoesNotCollideWithFrozenRoutes pins the claim
// BLO-29787 turned on: the sender read is a *new* surface and does not disturb
// any of the three patterns transport.go froze. Registering all four on one mux
// must not panic, and each must still land where it says.
func TestDeliveryTargetsRouteDoesNotCollideWithFrozenRoutes(t *testing.T) {
	const ticketID = targetIDA

	landed := ""
	mux := http.NewServeMux()
	mux.HandleFunc(PatternMint, func(w http.ResponseWriter, r *http.Request) { landed = "mint" })
	mux.HandleFunc(PatternRenew, func(w http.ResponseWriter, r *http.Request) { landed = "renew" })
	mux.HandleFunc(PatternHeartbeat, func(w http.ResponseWriter, r *http.Request) { landed = "heartbeat" })
	mux.HandleFunc(PatternDeliveryTargets, func(w http.ResponseWriter, r *http.Request) { landed = "delivery-targets" })

	for _, tc := range []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodPost, MintPath(), "mint"},
		{http.MethodPost, RenewPath(ticketID), "renew"},
		{http.MethodPost, HeartbeatPath(), "heartbeat"},
		{http.MethodGet, DeliveryTargetsPath("solana-mainnet"), "delivery-targets"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			landed = ""
			mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil))
			if landed != tc.want {
				t.Errorf("%s %s landed on %q, want %q", tc.method, tc.path, landed, tc.want)
			}
		})
	}
}
