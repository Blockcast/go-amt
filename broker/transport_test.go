package broker

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
)

// TestRoutePatternsAndBuildersAgree is the test this whole file exists for.
//
// The contract's central claim is that the broker registering PatternX and the
// gateway building XPath() cannot drift, because both read the same constants.
// Asserting that by string-comparing the constants would be circular — it would
// pass if both were wrong in the same way. So this registers the patterns on a
// real net/http.ServeMux, sends requests at the builder-produced paths, and
// checks that each lands on the handler it named. A rename that updated a
// pattern without its builder fails here.
func TestRoutePatternsAndBuildersAgree(t *testing.T) {
	const ticketID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

	var landed string
	var observedTicketID string

	mux := http.NewServeMux()
	mux.HandleFunc(PatternMint, func(w http.ResponseWriter, r *http.Request) {
		landed = "mint"
	})
	mux.HandleFunc(PatternRenew, func(w http.ResponseWriter, r *http.Request) {
		landed = "renew"
		observedTicketID = r.PathValue(RenewTicketIDParam)
	})
	mux.HandleFunc(PatternHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		landed = "heartbeat"
	})

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"mint", MintPath(), "mint"},
		{"renew", RenewPath(ticketID), "renew"},
		{"heartbeat", HeartbeatPath(), "heartbeat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			landed, observedTicketID = "", ""

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, tc.path, nil))

			if recorder.Code != http.StatusOK {
				t.Fatalf("POST %s: status = %d, want %d (route not registered by its own builder)",
					tc.path, recorder.Code, http.StatusOK)
			}
			if landed != tc.want {
				t.Errorf("POST %s landed on %q, want %q", tc.path, landed, tc.want)
			}
		})
	}

	// The wildcard name is read back through RenewTicketIDParam rather than a
	// re-spelled literal, so this also pins that the constant matches the
	// pattern's {ticket_id}.
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, RenewPath(ticketID), nil))
	if observedTicketID != ticketID {
		t.Errorf("r.PathValue(%q) = %q, want %q", RenewTicketIDParam, observedTicketID, ticketID)
	}
}

// TestRoutesRejectWrongMethod pins that the method is carried in the pattern,
// so a GET is refused by the mux with 405 and no handler branch is needed. A
// pattern that dropped its method verb would answer 200 here.
func TestRoutesRejectWrongMethod(t *testing.T) {
	mux := http.NewServeMux()
	handled := false
	for _, pattern := range []string{PatternMint, PatternRenew, PatternHeartbeat} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { handled = true })
	}

	for _, path := range []string{MintPath(), RenewPath("3f2504e0-4f89-41d3-9a0c-0305e82c3301"), HeartbeatPath()} {
		handled = false
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: status = %d, want %d", path, recorder.Code, http.StatusMethodNotAllowed)
		}
		if handled {
			t.Errorf("GET %s reached a handler; method is not pinned in the pattern", path)
		}
	}
}

// TestRenewPathEscapesTicketID pins the escaping documented on RenewPath: a
// ticket id containing a separator must not silently resolve to a different
// route. ValidateTicket already rejects such an id, so this guards the case
// where a caller skipped validation.
func TestRenewPathEscapesTicketID(t *testing.T) {
	path := RenewPath("../heartbeat")
	if strings.Contains(path, "../") {
		t.Fatalf("RenewPath left a traversal sequence unescaped: %q", path)
	}

	mux := http.NewServeMux()
	landedOnRenew := false
	mux.HandleFunc(PatternRenew, func(w http.ResponseWriter, r *http.Request) {
		landedOnRenew = true
		// The escaped id must decode back to exactly what was passed in, not
		// to a traversed path.
		if got := r.PathValue(RenewTicketIDParam); got != "../heartbeat" {
			t.Errorf("PathValue = %q, want %q", got, "../heartbeat")
		}
	})
	mux.HandleFunc(PatternHeartbeat, func(w http.ResponseWriter, r *http.Request) {
		t.Error("a traversing ticket id reached the heartbeat route")
	})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))

	if !landedOnRenew {
		t.Fatalf("POST %s did not reach the renew route (status %d)", path, recorder.Code)
	}
}

// TestRequestEnvelopesCarryNoIdentityFields encodes W2b's first veto item as a
// property rather than a promise: identity is ambient, so no *request* envelope
// may carry an identity-shaped field. A future field named gw_uuid, source_ip,
// or on_behalf_of on MintRequest would be a tenant selector wearing an
// assertion's clothes, and the first handler that trusted one would be an
// authorization bypass.
//
// Heartbeat is deliberately not covered here — its gw_uuid is the documented
// exception, an assertion the broker cross-checks against the certificate.
func TestRequestEnvelopesCarryNoIdentityFields(t *testing.T) {
	forbidden := map[string]bool{
		"gw_uuid":       true,
		"gateway_uuid":  true,
		"st_uuid":       true,
		"source_ip":     true,
		"src_ip":        true,
		"peer_ip":       true,
		"on_behalf_of":  true,
		"tenant":        true,
		"tenant_id":     true,
		"account":       true,
		"account_id":    true,
		"identity":      true,
		"subject":       true,
		"cert":          true,
		"certificate":   true,
		"client_cert":   true,
		"spiffe_id":     true,
		"plane_binding": true,
	}

	for _, envelope := range []any{MintRequest{}, RenewRequest{}} {
		typ := reflect.TypeOf(envelope)
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if forbidden[name] {
				t.Errorf("%s carries identity-shaped field %q; identity is ambient (see Identity)",
					typ.Name(), name)
			}
		}
	}
}

// TestRenewRequestIsEmpty pins that renew takes no inputs. If a field is ever
// added, the author must revisit whether it is genuinely not derivable from the
// connection or the path.
func TestRenewRequestIsEmpty(t *testing.T) {
	if fields := reflect.TypeOf(RenewRequest{}).NumField(); fields != 0 {
		t.Errorf("RenewRequest has %d field(s), want 0: everything is ambient or in the path", fields)
	}

	// It must still serialize as an object, not as null, so both sides agree
	// on what an empty renew body looks like.
	encoded, err := json.Marshal(RenewRequest{})
	if err != nil {
		t.Fatalf("marshal RenewRequest: %v", err)
	}
	if string(encoded) != "{}" {
		t.Errorf("RenewRequest marshalled to %s, want {}", encoded)
	}
}

// allErrorCodes is the closed taxonomy, listed independently of statusByCode so
// that the two can be checked against each other. A new code added to the
// package without a status/retry entry fails TestErrorTaxonomyIsClosed.
var allErrorCodes = []ErrorCode{
	CodeInvalidRequest,
	CodeEntitlementDenied,
	CodePlaneBindingMismatch,
	CodeConcurrencyCapped,
	CodeTicketNotRenewable,
	CodeBodyTooLarge,
	CodePublicationFailed,
}

func TestErrorTaxonomyIsClosed(t *testing.T) {
	if len(allErrorCodes) != len(statusByCode) {
		t.Fatalf("taxonomy size mismatch: %d declared codes vs %d table entries; "+
			"a code was added without a status/retry mapping (or vice versa)",
			len(allErrorCodes), len(statusByCode))
	}
	for _, code := range allErrorCodes {
		if _, ok := statusByCode[code]; !ok {
			t.Errorf("code %q has no status/retry mapping", code)
		}
	}
}

// TestStatusAndRetryForCode pins the exact wire behaviour of every code. These
// are values the broker writes and the gateway branches on, so each is spelled
// out rather than derived.
func TestStatusAndRetryForCode(t *testing.T) {
	for _, tc := range []struct {
		code       ErrorCode
		wantStatus int
		wantRetry  Retry
	}{
		{CodeInvalidRequest, http.StatusBadRequest, RetryNever},
		{CodeEntitlementDenied, http.StatusForbidden, RetryNever},
		{CodePlaneBindingMismatch, http.StatusForbidden, RetryNever},
		// 409 rather than 429 is the deliberate one — see CodeConcurrencyCapped.
		{CodeConcurrencyCapped, http.StatusConflict, RetryAfterHeader},
		{CodeTicketNotRenewable, http.StatusNotFound, RetryNever},
		{CodeBodyTooLarge, http.StatusRequestEntityTooLarge, RetryNever},
		{CodePublicationFailed, http.StatusServiceUnavailable, RetryBackoff},
	} {
		t.Run(string(tc.code), func(t *testing.T) {
			status, err := StatusForCode(tc.code)
			if err != nil {
				t.Fatalf("StatusForCode(%q): unexpected error %v", tc.code, err)
			}
			if status != tc.wantStatus {
				t.Errorf("StatusForCode(%q) = %d, want %d", tc.code, status, tc.wantStatus)
			}

			retry, err := RetryForCode(tc.code)
			if err != nil {
				t.Fatalf("RetryForCode(%q): unexpected error %v", tc.code, err)
			}
			if retry != tc.wantRetry {
				t.Errorf("RetryForCode(%q) = %v, want %v", tc.code, retry, tc.wantRetry)
			}
		})
	}
}

// TestConcurrencyCappedIsNot429 states the rate-limit trap as its own
// assertion, because the whole point of the choice is that 429 is what someone
// would otherwise reach for. A future edit to 429 would drop this code into a
// client's generic rate-limit backoff and retry a licensing conflict into
// silence.
func TestConcurrencyCappedIsNot429(t *testing.T) {
	status, err := StatusForCode(CodeConcurrencyCapped)
	if err != nil {
		t.Fatalf("StatusForCode: %v", err)
	}
	if status == http.StatusTooManyRequests {
		t.Fatal("concurrency_capped must not be 429: a licensing-state conflict " +
			"routed into generic rate-limit backoff is retried into silence")
	}
}

// TestNoIdentityFailureStatus encodes W2b's second veto item. Identity is
// admitted in VerifyConnection, so an identity failure fails the TLS handshake
// and never reaches a handler. A code mapping to 401 or 407 would describe an
// unreachable path and invite an application-level identity gate that makes it
// reachable.
func TestNoIdentityFailureStatus(t *testing.T) {
	for _, code := range allErrorCodes {
		status, err := StatusForCode(code)
		if err != nil {
			t.Fatalf("StatusForCode(%q): %v", code, err)
		}
		if status == http.StatusUnauthorized || status == http.StatusProxyAuthRequired {
			t.Errorf("code %q maps to %d; identity failures never reach a handler (see Identity)",
				code, status)
		}
	}
}

// TestUnknownErrorCodeIsNeverRetried pins the closed-taxonomy rule: a code from
// a newer broker must not be guessed at. Defaulting an unknown failure to
// retryable is how a client turns one broker-side change into a retry storm.
func TestUnknownErrorCodeIsNeverRetried(t *testing.T) {
	const unknown ErrorCode = "some_future_code"

	if _, err := StatusForCode(unknown); !errors.Is(err, ErrUnknownErrorCode) {
		t.Errorf("StatusForCode(unknown) error = %v, want ErrUnknownErrorCode", err)
	}

	retry, err := RetryForCode(unknown)
	if !errors.Is(err, ErrUnknownErrorCode) {
		t.Errorf("RetryForCode(unknown) error = %v, want ErrUnknownErrorCode", err)
	}
	if retry != RetryNever {
		t.Errorf("RetryForCode(unknown) = %v, want RetryNever", retry)
	}
}

// TestTransportFailurePostureIsBackoff pins the documented reasoning at
// RetryTransportFailure: a rejected certificate and an ordinary broker restart
// are indistinguishable at this layer, and backing off is correct for both.
func TestTransportFailurePostureIsBackoff(t *testing.T) {
	if RetryTransportFailure != RetryBackoff {
		t.Errorf("RetryTransportFailure = %v, want RetryBackoff: treating handshake "+
			"failure as terminal strands a gateway across a broker restart",
			RetryTransportFailure)
	}
}

// testRelayID is a canonical, non-nil, lowercase UUID — the only shape
// MintRequest.RelayID accepts. It is the same literal the broker's own suite
// uses, so a value that travels between the two suites is not silently a
// different shape.
const testRelayID = "0198a654-9f3e-7c1a-b2ee-224d8e1c9a02"

func TestValidateMintRequest(t *testing.T) {
	// Every case starts from a fully valid envelope and perturbs one field, so
	// a case named for feed_id is not quietly also failing on dst_port. The
	// port cases perturb the port and leave the ids alone for the same reason.
	req := func(mutate func(*MintRequest)) MintRequest {
		r := MintRequest{FeedID: "feed-a", RelayID: testRelayID, DstPort: 41234}
		mutate(&r)
		return r
	}
	unchanged := func(*MintRequest) {}

	for _, tc := range []struct {
		name    string
		req     MintRequest
		wantErr bool
	}{
		{"valid", req(unchanged), false},
		{"empty feed_id", req(func(r *MintRequest) { r.FeedID = "" }), true},
		{"empty relay_id", req(func(r *MintRequest) { r.RelayID = "" }), true},
		{"feed_id at bound", req(func(r *MintRequest) { r.FeedID = strings.Repeat("f", MaxFeedIDBytes) }), false},
		{"feed_id over bound", req(func(r *MintRequest) { r.FeedID = strings.Repeat("f", MaxFeedIDBytes+1) }), true},

		// relay_id is a canonical, non-nil, lowercase UUID and nothing else.
		// The first case is the literal this suite used to send: it is the
		// value a gateway conforming to the OLD client contract would have
		// produced, and the broker refused it with invalid_request (BLO-31098).
		{"relay_id free-form label (the pre-BLO-31098 fixture)", req(func(r *MintRequest) { r.RelayID = "relay-a" }), true},
		{"relay_id uppercase UUID", req(func(r *MintRequest) { r.RelayID = strings.ToUpper(testRelayID) }), true},
		{"relay_id nil UUID", req(func(r *MintRequest) { r.RelayID = "00000000-0000-0000-0000-000000000000" }), true},
		{"relay_id braced", req(func(r *MintRequest) { r.RelayID = "{" + testRelayID + "}" }), true},
		{"relay_id urn prefixed", req(func(r *MintRequest) { r.RelayID = "urn:uuid:" + testRelayID }), true},
		{"relay_id hex without separators", req(func(r *MintRequest) { r.RelayID = strings.ReplaceAll(testRelayID, "-", "") }), true},
		{"relay_id misplaced separator", req(func(r *MintRequest) { r.RelayID = "0198a6549-f3e-7c1a-b2ee-224d8e1c9a02" }), true},
		{"invalid utf8 feed_id", req(func(r *MintRequest) { r.FeedID = "\xff\xfe" }), true},
		{"invalid utf8 relay_id", req(func(r *MintRequest) { r.RelayID = "\xff\xfe" }), true},

		// dst_port. Zero is called out separately from the rest of the
		// out-of-range set because it is the one an omitted field decodes to:
		// it is the value a client that never heard of this field sends, and
		// admitting it is the defaulting BLO-30634 refused.
		{"dst_port zero (omitted by an unmigrated client)", req(func(r *MintRequest) { r.DstPort = 0 }), true},
		{"dst_port at lower bound", req(func(r *MintRequest) { r.DstPort = MinDstPort }), false},
		{"dst_port at upper bound", req(func(r *MintRequest) { r.DstPort = MaxDstPort }), false},
		{"dst_port just over upper bound", req(func(r *MintRequest) { r.DstPort = MaxDstPort + 1 }), true},
		{"dst_port negative", req(func(r *MintRequest) { r.DstPort = -1 }), true},
		{"dst_port wildly out of range", req(func(r *MintRequest) { r.DstPort = 1 << 20 }), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateMintRequest(tc.req)
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
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestMintRequestDstPortBoundsAreThePortSpace pins the bounds to the actual UDP
// port range rather than to whatever the constants happen to say. Widening
// MaxDstPort past 65535 would let the broker mint a ticket carrying a port no
// datagram can be addressed to; narrowing the range would refuse ports gateways
// legitimately bind, including the whole ephemeral range.
func TestMintRequestDstPortBoundsAreThePortSpace(t *testing.T) {
	if MinDstPort != 1 {
		t.Errorf("MinDstPort = %d, want 1: port 0 is not a deliverable destination", MinDstPort)
	}
	if MaxDstPort != 65535 {
		t.Errorf("MaxDstPort = %d, want 65535: the UDP port space is 16 bits", MaxDstPort)
	}
}

// TestMintRequestFieldsAreExactlyTheContract is the companion to
// TestRequestEnvelopesCarryNoIdentityFields: that test rejects a known list of
// identity-shaped names, this one rejects *anything* unlisted. BLO-30636 added
// the first input to this envelope, and the risk it opens is that the next
// field rides in behind it under a name nobody thought to forbid. A new field
// here is a contract change and must fail until it is deliberately admitted.
func TestMintRequestFieldsAreExactlyTheContract(t *testing.T) {
	want := []string{"feed_id", "relay_id", "dst_port"}

	typ := reflect.TypeOf(MintRequest{})
	var got []string
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		got = append(got, name)
	}

	if !slices.Equal(got, want) {
		t.Errorf("MintRequest fields = %v, want exactly %v; a new field is a contract change (see Identity)", got, want)
	}
}

// TestTransportSchemaTracksEnvelopeChanges pins the schema string against the
// revision that introduced dst_port. TransportSchema's own doc requires a new
// string for any shape change, and the constant is the only thing a broker can
// assert at build time to prove it compiled against the contract it thinks it
// did — so leaving it at v1 after changing MintRequest is the exact silent edit
// it exists to prevent.
func TestTransportSchemaTracksEnvelopeChanges(t *testing.T) {
	if got, want := TransportSchema, "gateway.transport.v2"; got != want {
		t.Errorf("TransportSchema = %q, want %q: adding MintRequest.DstPort is a shape change", got, want)
	}
}

func TestValidateTicket(t *testing.T) {
	const validUUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

	for _, tc := range []struct {
		name    string
		ticket  Ticket
		wantErr bool
	}{
		{"valid", Ticket{TicketID: validUUID, NotAfter: "2026-08-22T05:00:00Z"}, false},
		{"valid with fractional", Ticket{TicketID: validUUID, NotAfter: "2026-08-22T05:00:00.5Z"}, false},
		{"empty ticket_id", Ticket{TicketID: "", NotAfter: "2026-08-22T05:00:00Z"}, true},
		{"nil uuid", Ticket{TicketID: "00000000-0000-0000-0000-000000000000", NotAfter: "2026-08-22T05:00:00Z"}, true},
		{"uppercase uuid", Ticket{TicketID: "3F2504E0-4F89-41D3-9A0C-0305E82C3301", NotAfter: "2026-08-22T05:00:00Z"}, true},
		{"empty not_after", Ticket{TicketID: validUUID, NotAfter: ""}, true},
		// The two non-canonical UTC spellings the payload contract also
		// rejects: one instant must have exactly one spelling across both.
		{"offset zone", Ticket{TicketID: validUUID, NotAfter: "2026-08-22T05:00:00+00:00"}, true},
		{"trailing zeros", Ticket{TicketID: validUUID, NotAfter: "2026-08-22T05:00:00.000Z"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTicket(tc.ticket)
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
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestTicketNotAfterSharesHeartbeatTimestampRule pins that a timestamp
// FormatTimestamp produces is accepted by ValidateTicket, so a Go client has
// one correct way to spell a timestamp across both contracts.
func TestTicketNotAfterSharesHeartbeatTimestampRule(t *testing.T) {
	parsed, err := parseCanonicalUTCTimestamp("2026-08-22T05:00:00Z")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ticket := Ticket{
		TicketID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		NotAfter: FormatTimestamp(parsed),
	}
	if err := ValidateTicket(ticket); err != nil {
		t.Errorf("FormatTimestamp output rejected by ValidateTicket: %v", err)
	}
}

// TestEnvelopesRoundTrip pins the JSON field names, which are the actual wire
// contract. A struct-field rename that forgot its tag would pass every other
// test in this file and break every non-Go implementer.
func TestEnvelopesRoundTrip(t *testing.T) {
	t.Run("MintRequest", func(t *testing.T) {
		encoded, err := json.Marshal(MintRequest{FeedID: "feed-a", RelayID: testRelayID, DstPort: 41234})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if got, want := string(encoded), `{"feed_id":"feed-a","relay_id":"`+testRelayID+`","dst_port":41234}`; got != want {
			t.Errorf("MintRequest = %s, want %s", got, want)
		}

		// The round trip has to come back with the port intact, not merely
		// marshal to the right name: a decode that dropped dst_port would
		// leave the broker validating a zero it never received.
		var decoded MintRequest
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if want := (MintRequest{FeedID: "feed-a", RelayID: testRelayID, DstPort: 41234}); decoded != want {
			t.Errorf("round trip = %#v, want %#v", decoded, want)
		}
	})

	t.Run("Ticket", func(t *testing.T) {
		encoded, err := json.Marshal(Ticket{
			TicketID: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
			NotAfter: "2026-08-22T05:00:00Z",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `{"ticket_id":"3f2504e0-4f89-41d3-9a0c-0305e82c3301","not_after":"2026-08-22T05:00:00Z"}`
		if string(encoded) != want {
			t.Errorf("Ticket = %s, want %s", encoded, want)
		}
	})

	t.Run("ErrorResponse", func(t *testing.T) {
		encoded, err := json.Marshal(ErrorResponse{
			Code:    CodeConcurrencyCapped,
			Message: "account at concurrent-session cap",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		want := `{"code":"concurrency_capped","message":"account at concurrent-session cap"}`
		if string(encoded) != want {
			t.Errorf("ErrorResponse = %s, want %s", encoded, want)
		}

		var decoded ErrorResponse
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if decoded.Code != CodeConcurrencyCapped {
			t.Errorf("round-tripped code = %q, want %q", decoded.Code, CodeConcurrencyCapped)
		}
	})
}

// TestHeartbeatBodyFitsUnderCap checks the claim made at HeartbeatMaxBodyBytes:
// the widest heartbeat the broker will accept still fits, so hitting the cap is
// a producer bug rather than a large deployment.
//
// The fixture is required to pass ValidateHeartbeat and CanonicalBytes, and
// that requirement is the substance of this test rather than a formality. Its
// first version measured a body with an empty first_packet_at/last_packet_at
// pair against packets = 1<<40, which ValidateHeartbeat rejects for breaking
// the feed-activity pairing rule — so it pinned 1,704,213 bytes / 40.6% for a
// heartbeat that cannot occur on the wire, and understated the real maximum by
// more than a megabyte. It was green the whole time, and mutation-checking it
// would not have helped: that proves a test reacts to a change in the code, not
// that its fixture is reachable. Asserting the fixture's own legality is what
// closes that, and it must stay for the next field that lands here.
//
// Every field is at its maximum legal width, because the claim is about the
// supremum over accepted bodies and not about a realistic one — ingest is
// untrusted (see validateErasureReport), so any body the validator admits is a
// body the cap must survive.
func TestHeartbeatBodyFitsUnderCap(t *testing.T) {
	// sets_erased = 163 against MaxSetsTotal is the pair maximizing the two
	// fields' combined width: it is the widest erasure_fraction the exact ratio
	// can produce (0.00016300016300016301, 22 bytes), and the 3 bytes it gives
	// back on the integer do not pay for the 4 it buys. Using the exact ratio
	// also keeps CanonicalBytes, which recomputes the fraction, in agreement.
	const setsErased = 163

	feeds := make([]FeedReport, 0, MaxFeeds)
	for i := 0; i < MaxFeeds; i++ {
		// Distinct, sorted, maximal-length feed ids.
		id := strings.Repeat("f", MaxFeedIDBytes-8) + string(rune('a'+i/(26*26*26)%26)) +
			string(rune('a'+i/(26*26)%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i%26))
		feeds = append(feeds, FeedReport{
			FeedID:  id,
			Packets: math.MaxUint64,
			Bytes:   math.MaxUint64,
			// Nanosecond precision with no trailing zeros is the widest
			// timestamp parseCanonicalUTCTimestamp accepts; last must not
			// precede first.
			FirstPacketAt: "2026-08-22T05:00:00.123456789Z",
			LastPacketAt:  "2026-08-22T05:00:00.987654321Z",
			Erasure: erasure.Window{
				// Both at their maximal legal width, like every other field
				// here: WindowStart takes the widest timestamp
				// parseCanonicalUTCTimestamp accepts, WindowMS the widest
				// integer validateErasureReport admits.
				WindowStart:     "2026-08-22T05:00:00.123456789Z",
				WindowMS:        MaxWindowMS,
				SetsTotal:       MaxSetsTotal,
				SetsErased:      setsErased,
				ErasureFraction: erasure.Fraction(setsErased, MaxSetsTotal),
				RMean:           math.MaxFloat64,
				RPeak100MS:      math.MaxFloat64,
				GapMSHist: erasure.GapHistogram{
					LT1:        math.MaxUint64,
					From1To2_4: math.MaxUint64,
					From2_4To7: math.MaxUint64,
					From7To32:  math.MaxUint64,
					GTE32:      math.MaxUint64,
				},
				GraceMS: math.MaxInt64,
				Schema:  erasureReportSchema,
			},
		})
	}

	heartbeat := Heartbeat{
		Schema:  HeartbeatSchema,
		GWUUID:  "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Version: strings.Repeat("v", MaxVersionBytes),
		SentAt:  "2026-08-22T05:00:00.123456789Z",
		Feeds:   feeds,
	}

	// The fixture must be a body the broker would accept. Without this, the
	// measurement below is of nothing in particular.
	if err := ValidateHeartbeat(heartbeat); err != nil {
		t.Fatalf("the cap fixture is not a legal heartbeat, so the bytes it "+
			"measures cannot occur on the wire: %v", err)
	}
	canonical, err := CanonicalBytes(heartbeat)
	if err != nil {
		t.Fatalf("the cap fixture is not canonicalizable, so it is not the "+
			"form a gateway would send: %v", err)
	}

	// A gateway sends CanonicalBytes output; an untrusted producer may send
	// anything encoding/json accepts. The cap must hold for both, so measure
	// the larger.
	encoded, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	widest := len(encoded)
	if len(canonical) > widest {
		widest = len(canonical)
	}

	if widest >= HeartbeatMaxBodyBytes {
		t.Fatalf("a %d-feed heartbeat is %d bytes, at or over the %d-byte cap; "+
			"the cap no longer leaves room for a legal full-width report",
			MaxFeeds, widest, HeartbeatMaxBodyBytes)
	}

	// Pin the documented figures. HeartbeatMaxBodyBytes quotes the byte count,
	// the percentage, and a ~283-byte-per-feed spare budget that a proposed
	// per-feed field is meant to be sized against; a change here that leaves
	// that prose stale is the drift this guards.
	const wantBytes = 3_031_327
	if widest != wantBytes {
		t.Errorf("widest legal heartbeat = %d bytes (%.1f%% of cap, %.2fx headroom, "+
			"%d bytes/feed spare), want %d — update the measurement at "+
			"HeartbeatMaxBodyBytes rather than this constant alone",
			widest, 100*float64(widest)/float64(HeartbeatMaxBodyBytes),
			float64(HeartbeatMaxBodyBytes)/float64(widest),
			(HeartbeatMaxBodyBytes-widest)/MaxFeeds, wantBytes)
	}
	t.Logf("widest legal heartbeat: %d bytes, %.1f%% of the %d-byte cap, %.2fx headroom, %d bytes/feed spare",
		widest, 100*float64(widest)/float64(HeartbeatMaxBodyBytes), HeartbeatMaxBodyBytes,
		float64(HeartbeatMaxBodyBytes)/float64(widest), (HeartbeatMaxBodyBytes-widest)/MaxFeeds)
}

// TestCapFixtureIllegalityIsCaught is the regression guard for the defect the
// cap test shipped with: a fixture that measures fine and is rejected on the
// wire. It reconstructs the original shape — an empty activity pair against a
// nonzero packet count — and asserts ValidateHeartbeat refuses it, so the
// legality assertion above is known to have teeth rather than assumed to.
func TestCapFixtureIllegalityIsCaught(t *testing.T) {
	original := Heartbeat{
		Schema:  HeartbeatSchema,
		GWUUID:  "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
		Version: strings.Repeat("v", MaxVersionBytes),
		SentAt:  "2026-08-22T05:00:00Z",
		Feeds: []FeedReport{{
			FeedID:  strings.Repeat("f", MaxFeedIDBytes),
			Packets: 1 << 40,
			Bytes:   1 << 50,
		}},
	}

	err := ValidateHeartbeat(original)
	if err == nil {
		t.Fatal("ValidateHeartbeat accepted a feed reporting packets with an " +
			"empty first/last packet pair; the cap test's legality assertion " +
			"no longer proves anything")
	}
	if !errors.Is(err, ErrInvalidHeartbeat) {
		t.Errorf("error = %v, want it to wrap ErrInvalidHeartbeat", err)
	}
}

// TestParseRetryAfterRejectsHTTPDate is the named case for the drift this
// helper exists to stop.
//
// RFC 9110 §10.2.3 permits an HTTP-date, and a client reaching for
// strconv.Atoi on one gets 0 and retries immediately — making the 409-not-429
// choice at CodeConcurrencyCapped a tighter loop than the generic backoff it
// was chosen over, with nothing erroring. ParseRetryAfter must refuse it and
// report ok=false so the caller falls back to backoff.
func TestParseRetryAfterRejectsHTTPDate(t *testing.T) {
	header := http.Header{}
	header.Set(RetryAfterHeaderName, "Fri, 31 Dec 1999 23:59:59 GMT")

	delay, ok := ParseRetryAfter(header)
	if ok {
		t.Fatalf("ParseRetryAfter accepted an HTTP-date and returned %v; the "+
			"contract pins delta-seconds and a caller must fall back to backoff", delay)
	}
	if delay != 0 {
		t.Errorf("delay = %v on a rejected header, want 0 so it cannot be slept on", delay)
	}
}

func TestParseRetryAfter(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		setHeader bool
		wantDelay time.Duration
		wantOK    bool
	}{
		{name: "absent", setHeader: false},
		{name: "empty", value: "", setHeader: true},
		{name: "whitespace only", value: "   ", setHeader: true},
		{name: "minimum", value: "1", setHeader: true, wantDelay: time.Second, wantOK: true},
		{name: "ordinary", value: "120", setHeader: true, wantDelay: 120 * time.Second, wantOK: true},
		{name: "surrounding whitespace tolerated", value: " 30 ", setHeader: true, wantDelay: 30 * time.Second, wantOK: true},
		{name: "at TicketTTL", value: "300", setHeader: true, wantDelay: TicketTTL, wantOK: true},
		// Above the bound is clamped rather than discarded: the broker asking
		// for a longer wait than a ticket can live is honoured as far as it can
		// be. Discarding it down to generic backoff would retry sooner than the
		// broker asked.
		{name: "above TicketTTL clamps", value: "99999", setHeader: true, wantDelay: TicketTTL, wantOK: true},
		// Zero and negative are the hot-loop values, and are refused rather
		// than honoured.
		{name: "zero", value: "0", setHeader: true},
		{name: "negative", value: "-5", setHeader: true},
		{name: "fractional", value: "1.5", setHeader: true},
		{name: "not a number", value: "soon", setHeader: true},
		{name: "trailing garbage", value: "120s", setHeader: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := http.Header{}
			if test.setHeader {
				header.Set(RetryAfterHeaderName, test.value)
			}

			delay, ok := ParseRetryAfter(header)
			if ok != test.wantOK {
				t.Fatalf("ParseRetryAfter(%q) ok = %v, want %v", test.value, ok, test.wantOK)
			}
			if delay != test.wantDelay {
				t.Errorf("ParseRetryAfter(%q) = %v, want %v", test.value, delay, test.wantDelay)
			}
			if !ok && delay != 0 {
				t.Errorf("delay = %v with ok=false, want 0 so a caller cannot sleep on it", delay)
			}
		})
	}
}

// TestFormatRetryAfterRoundTripsThroughParse pins the two halves together: the
// broker writes with FormatRetryAfter and the gateway reads with
// ParseRetryAfter, so anything the former emits must be something the latter
// accepts. A format change on one side that skipped the other would show up
// here rather than as an immediate-retry loop in production.
func TestFormatRetryAfterRoundTripsThroughParse(t *testing.T) {
	tests := []struct {
		name  string
		given time.Duration
		want  time.Duration
	}{
		{name: "whole seconds", given: 45 * time.Second, want: 45 * time.Second},
		// Rounded up, so a remainder never shortens the wait.
		{name: "sub-second remainder rounds up", given: 1500 * time.Millisecond, want: 2 * time.Second},
		// Never emitted as 0, which would be the hot loop.
		{name: "below a second floors to the minimum", given: time.Millisecond, want: time.Second},
		{name: "zero floors to the minimum", given: 0, want: time.Second},
		{name: "negative floors to the minimum", given: -time.Hour, want: time.Second},
		{name: "at TicketTTL", given: TicketTTL, want: TicketTTL},
		{name: "above TicketTTL clamps on write", given: 24 * time.Hour, want: TicketTTL},
		// The rounding step adds just under a second, so every duration in the
		// top second of the range overflowed int64 and wrapped negative, which
		// the old floor-after-rounding order then emitted as the *minimum*.
		{name: "maximum duration clamps instead of overflowing", given: math.MaxInt64, want: TicketTTL},
		{name: "first duration that overflows the rounding step", given: time.Duration(math.MaxInt64) - time.Second + 2, want: TicketTTL},
		{name: "last duration that does not", given: time.Duration(math.MaxInt64) - time.Second + 1, want: TicketTTL},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := http.Header{}
			header.Set(RetryAfterHeaderName, FormatRetryAfter(test.given))

			delay, ok := ParseRetryAfter(header)
			if !ok {
				t.Fatalf("FormatRetryAfter(%v) = %q, which ParseRetryAfter rejects",
					test.given, header.Get(RetryAfterHeaderName))
			}
			if delay != test.want {
				t.Errorf("round-tripped %v = %v, want %v", test.given, delay, test.want)
			}
		})
	}
}

// TestFormatRetryAfterNeverInverts is the property behind the table above, and
// it is the one that would have caught the overflow without anyone thinking to
// try math.MaxInt64.
//
// The table pins named points; this pins the relation between them: asking for
// a longer delay must never produce a shorter emitted one. That is the whole
// purpose of a clamp, so any arithmetic that silently wraps — the round-up
// overflowing int64 being the instance that shipped — violates it somewhere,
// wherever the wrap happens to land.
//
// The sweep is deliberately weighted at the top of the range. Overflow is a
// boundary defect and uniform sampling across 292 years of nanoseconds would
// essentially never land in the one second where it lives.
func TestFormatRetryAfterNeverInverts(t *testing.T) {
	const maxDuration = time.Duration(math.MaxInt64)

	durations := []time.Duration{
		-time.Hour, 0, time.Nanosecond, time.Millisecond, time.Second,
		time.Second + time.Nanosecond, 45 * time.Second, TicketTTL - time.Nanosecond,
		TicketTTL, TicketTTL + time.Nanosecond, time.Hour, 24 * time.Hour,
	}
	// The overflow window is the top second of the range, so walk its edges
	// directly rather than hoping to sample into it.
	for offset := time.Duration(0); offset <= 2*time.Second; offset += 250 * time.Millisecond {
		durations = append(durations, maxDuration-offset)
	}
	durations = append(durations, maxDuration-time.Second+1, maxDuration-time.Second+2, maxDuration-1)

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	prev := int64(-1)
	prevGiven := time.Duration(0)
	for _, given := range durations {
		emitted, err := strconv.ParseInt(FormatRetryAfter(given), 10, 64)
		if err != nil {
			t.Fatalf("FormatRetryAfter(%v) = %q, not an integer: %v", given, FormatRetryAfter(given), err)
		}
		if emitted < MinRetryAfterSeconds || emitted > MaxRetryAfterSeconds {
			t.Errorf("FormatRetryAfter(%v) = %d, outside [%d, %d]",
				given, emitted, MinRetryAfterSeconds, MaxRetryAfterSeconds)
		}
		if emitted < prev {
			t.Errorf("inversion: FormatRetryAfter(%v) = %d but the shorter %v gave %d; "+
				"a longer requested delay must never emit a shorter one",
				given, emitted, prevGiven, prev)
		}
		prev, prevGiven = emitted, given
	}
}

// TestRetryAfterBoundsAgreeWithTicketTTL keeps the delay ceiling tied to the
// thing it is about. A Retry-After longer than a ticket's maximum lifetime
// cannot be about ticket availability, so the bound is derived from TicketTTL
// rather than written out — and this fails if someone unpins them.
func TestRetryAfterBoundsAgreeWithTicketTTL(t *testing.T) {
	if got, want := MaxRetryAfterSeconds, int64(TicketTTL/time.Second); got != want {
		t.Errorf("MaxRetryAfterSeconds = %d, want %d (TicketTTL)", got, want)
	}
	if MinRetryAfterSeconds < 1 {
		t.Errorf("MinRetryAfterSeconds = %d, want >= 1; 0 means retry-now, which "+
			"is the loop CodeConcurrencyCapped's 409 exists to avoid", MinRetryAfterSeconds)
	}
}

// TestOnlyConcurrencyCappedUsesRetryAfterHeader pins the one-code claim in
// RetryAfterHeader's doc and at CodeConcurrencyCapped. If a second code is
// later routed off generic backoff, that is a contract decision that should
// come with its own Retry-After reasoning rather than arriving silently.
func TestOnlyConcurrencyCappedUsesRetryAfterHeader(t *testing.T) {
	for code := range statusByCode {
		retry, err := RetryForCode(code)
		if err != nil {
			t.Fatalf("RetryForCode(%q): %v", code, err)
		}
		if retry == RetryAfterHeader && code != CodeConcurrencyCapped {
			t.Errorf("%q is classified RetryAfterHeader; only %q is documented to be",
				code, CodeConcurrencyCapped)
		}
	}

	retry, err := RetryForCode(CodeConcurrencyCapped)
	if err != nil {
		t.Fatalf("RetryForCode(%q): %v", CodeConcurrencyCapped, err)
	}
	if retry != RetryAfterHeader {
		t.Errorf("%q retry = %v, want RetryAfterHeader", CodeConcurrencyCapped, retry)
	}
}
