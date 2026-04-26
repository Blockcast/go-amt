package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// TestInitDropCounters_AllFourSeriesAtZero asserts the BLO-610 acceptance
// floor: after InitDropCounters runs, all four amt_relay_drops_total series
// are present in the registry at value 0 for the configured relay label.
//
// Spec: runbooks/amt-relay-drops-spec.md §"Wiring into the existing /metrics endpoint"
// Acceptance: BLO-610 — "Unit test asserting all four series at zero
// post-startup is sufficient for this child to land".
func TestInitDropCounters_AllFourSeriesAtZero(t *testing.T) {
	const relayID = "test-relay.bcast.id"

	InitDropCounters(relayID)

	want := map[string]bool{
		DropReasonSocketOverrun:    false,
		DropReasonNoDownstreamSub:  false,
		DropReasonGatewayTableMiss: false,
		DropReasonRateLimit:        false,
	}

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	for _, mf := range mfs {
		if mf.GetName() != "amt_relay_drops_total" {
			continue
		}
		if mf.GetType() != dto.MetricType_COUNTER {
			t.Fatalf("amt_relay_drops_total: type = %v, want COUNTER", mf.GetType())
		}
		for _, m := range mf.GetMetric() {
			var reason, relay string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "reason":
					reason = lp.GetValue()
				case "relay":
					relay = lp.GetValue()
				}
			}
			if relay != relayID {
				continue
			}
			if _, ok := want[reason]; !ok {
				t.Errorf("unexpected reason label %q (cardinality must be exactly 4)", reason)
				continue
			}
			if got := m.GetCounter().GetValue(); got != 0 {
				t.Errorf("reason=%s value=%v, want 0 at startup", reason, got)
			}
			want[reason] = true
		}
	}

	for reason, seen := range want {
		if !seen {
			t.Errorf("series for reason=%q with relay=%q missing from /metrics output (InitDropCounters must materialize all four)", reason, relayID)
		}
	}
}

// TestHelp asserts the byte-for-byte help string the spec mandates so the
// dashboard description and the exposed metric stay in sync.
func TestHelp(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	const want = "AMT relay drops by reason. See runbooks/amt-relay-drops-spec.md."
	for _, mf := range mfs {
		if mf.GetName() != "amt_relay_drops_total" {
			continue
		}
		if got := mf.GetHelp(); got != want {
			t.Errorf("help = %q, want %q", got, want)
		}
		return
	}
	t.Fatalf("amt_relay_drops_total not registered")
}

// TestIncSocketOverrun_ZeroIsNoop ensures the SO_RXQ_OVFL delta-of-zero
// path does not materialize a spurious increment, which would inflate the
// dashboard's recv-rate-difference cross-check during steady state.
func TestIncSocketOverrun_ZeroIsNoop(t *testing.T) {
	const relayID = "test-relay-zero.bcast.id"
	InitDropCounters(relayID)

	IncSocketOverrun(0)

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "amt_relay_drops_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var reason, relay string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "reason":
					reason = lp.GetValue()
				case "relay":
					relay = lp.GetValue()
				}
			}
			if relay == relayID && reason == DropReasonSocketOverrun {
				if v := m.GetCounter().GetValue(); v != 0 {
					t.Errorf("IncSocketOverrun(0) leaked %v into counter; want 0", v)
				}
			}
		}
	}
}

// TestPromhttpExposition_AllFourSeriesEmittedAtZero materializes the exact
// text the spec's acceptance check exercises:
//
//	curl localhost:<metrics-port>/metrics | grep amt_relay_drops_total
//
// We attach promhttp.Handler() to a httptest server and assert the four
// "reason=...,relay=..." lines render with value 0. This is the sufficient
// evidence shape BLO-610 acceptance asks for (no live binary required).
func TestPromhttpExposition_AllFourSeriesEmittedAtZero(t *testing.T) {
	const relayID = "test-relay-promhttp.bcast.id"
	InitDropCounters(relayID)

	srv := httptest.NewServer(promhttp.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	wantLines := []string{
		`amt_relay_drops_total{reason="socket_overrun",relay="test-relay-promhttp.bcast.id"} 0`,
		`amt_relay_drops_total{reason="no_downstream_subscriber",relay="test-relay-promhttp.bcast.id"} 0`,
		`amt_relay_drops_total{reason="gateway_table_miss",relay="test-relay-promhttp.bcast.id"} 0`,
		`amt_relay_drops_total{reason="rate_limit",relay="test-relay-promhttp.bcast.id"} 0`,
	}
	for _, line := range wantLines {
		if !strings.Contains(out, line) {
			t.Errorf("/metrics missing line %q\n--- exposition ---\n%s", line, grepLines(out, "amt_relay_drops_total"))
		}
	}

	wantHelp := `# HELP amt_relay_drops_total AMT relay drops by reason. See runbooks/amt-relay-drops-spec.md.`
	if !strings.Contains(out, wantHelp) {
		t.Errorf("/metrics missing HELP line %q", wantHelp)
	}
	wantType := `# TYPE amt_relay_drops_total counter`
	if !strings.Contains(out, wantType) {
		t.Errorf("/metrics missing TYPE line %q", wantType)
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

// TestReasonConstantsByteForByte guards against silent drift in the four
// label strings (e.g. "socket-overrun" vs "socket_overrun"), which would
// break the dashboard query without breaking the build.
func TestReasonConstantsByteForByte(t *testing.T) {
	want := []struct {
		name, value string
	}{
		{"DropReasonSocketOverrun", "socket_overrun"},
		{"DropReasonNoDownstreamSub", "no_downstream_subscriber"},
		{"DropReasonGatewayTableMiss", "gateway_table_miss"},
		{"DropReasonRateLimit", "rate_limit"},
	}
	got := []string{
		DropReasonSocketOverrun,
		DropReasonNoDownstreamSub,
		DropReasonGatewayTableMiss,
		DropReasonRateLimit,
	}
	for i, w := range want {
		if got[i] != w.value {
			t.Errorf("%s = %q, want %q", w.name, got[i], w.value)
		}
		if strings.ContainsAny(got[i], "- ") {
			t.Errorf("%s = %q contains a hyphen or space; spec mandates underscore_separated", w.name, got[i])
		}
	}
}
