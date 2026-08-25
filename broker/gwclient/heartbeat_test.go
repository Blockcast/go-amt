package gwclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blockcast/go-amt/broker"
	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/receiver"
)

const testGWUUID = "6f1d3c9e-0b2a-4e7d-8c51-2a9f4d7b6e30"

type fakeSource struct{ feeds []receiver.FeedSnapshot }

func (f fakeSource) Snapshot() []receiver.FeedSnapshot { return f.feeds }

// drainedWindow returns a window shaped exactly as erasure.Tracker.DrainWindow
// produces one, so a test that needs a *valid* report does not hand-roll a
// shape ingest would reject.
func drainedWindow(t *testing.T) erasure.Window {
	t.Helper()
	windowStart := time.Unix(1750000000, 0).UTC()
	tracker, err := erasure.NewTracker(50*time.Millisecond, windowStart)
	if err != nil {
		t.Fatal(err)
	}
	window, err := tracker.DrainWindow(windowStart.Add(30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return window
}

func newTestProducer(t *testing.T, baseURL string, feeds []receiver.FeedSnapshot, opts ...Option) *Producer {
	t.Helper()
	producer, err := NewProducer(testGWUUID, baseURL, fakeSource{feeds: feeds},
		append([]Option{WithClock(func() time.Time { return time.Unix(1750000030, 0).UTC() })}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return producer
}

// TestHeartbeatVersionIsBrokerVersion is BLO-30039's named signal: the emitted
// version must be the build-stamped broker symbol rather than a caller-supplied
// string.
//
// The "rather than a caller-supplied string" half is enforced structurally —
// NewProducer takes no version parameter, so there is no value a caller could
// supply. This test pins the positive statement and, below, the specific wrong
// symbol the issue calls out.
func TestHeartbeatVersionIsBrokerVersion(t *testing.T) {
	producer := newTestProducer(t, "https://broker.example", []receiver.FeedSnapshot{{
		FeedID: "feed-a",
		Window: drainedWindow(t),
	}})

	heartbeat, err := producer.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if heartbeat.Version != broker.Version() {
		t.Errorf("Heartbeat.Version = %q, want broker.Version() = %q",
			heartbeat.Version, broker.Version())
	}

	// The issue names picking the other Version() — amt.Version() at
	// gateway.go:79, the Rust library's version reached through CGO — as "worse
	// than a typo", because it would still validate while breaking the
	// version-to-report_schema mapping a fleet census reads.
	//
	// That symbol is deliberately NOT imported here, and cannot be: gateway.go
	// is behind `//go:build ... && cgo && !purego`, so amt.Version does not
	// exist in the CGO_ENABLED=0 build this binary ships as. Importing it to
	// assert against it would itself introduce the CGO edge the last acceptance
	// criterion forbids. The mistake is therefore unreachable in the shipped
	// configuration by construction rather than by assertion — and reachable
	// only in a cgo-enabled build, which is what the compile-time argument
	// below covers instead.
	//
	// The stronger guarantee is structural: NewProducer has no version
	// parameter, so there is no value any caller — including a cgo build — can
	// inject. A regression that added one would have to change the signature,
	// which is a review-visible event rather than a silent wrong-symbol swap.
	if heartbeat.Version == "" {
		t.Error("Heartbeat.Version is empty; an empty version is an unrecallable heartbeat")
	}
}

// TestBuildProducesAnIngestibleHeartbeat runs the producer's output through the
// contract's own validator, which is the same check the broker applies.
func TestBuildProducesAnIngestibleHeartbeat(t *testing.T) {
	window := drainedWindow(t)
	first := time.Unix(1750000001, 0).UTC()
	last := time.Unix(1750000029, 500000000).UTC()

	producer := newTestProducer(t, "https://broker.example", []receiver.FeedSnapshot{
		{
			FeedID:   "feed-live",
			Liveness: receiver.FeedLiveness{Packets: 12, Bytes: 14400, FirstAt: first, LastAt: last},
			Window:   window,
		},
		{
			// A configured feed that has received nothing: reported, not
			// omitted, with the contract's "never received a packet" shape.
			FeedID: "feed-silent",
			Window: window,
		},
	})

	heartbeat, err := producer.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if err := broker.ValidateHeartbeat(heartbeat); err != nil {
		t.Fatalf("ValidateHeartbeat() error = %v", err)
	}
	if _, err := broker.CanonicalBytes(heartbeat); err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}

	if got := len(heartbeat.Feeds); got != 2 {
		t.Fatalf("feeds = %d, want 2 (a silent feed must be reported, not omitted)", got)
	}
	live := heartbeat.Feeds[0]
	if live.Packets != 12 || live.Bytes != 14400 {
		t.Errorf("feed-live counters = (%d, %d), want (12, 14400)", live.Packets, live.Bytes)
	}
	if live.FirstPacketAt != broker.FormatTimestamp(first) || live.LastPacketAt != broker.FormatTimestamp(last) {
		t.Errorf("feed-live packet times = (%q, %q), want (%q, %q)",
			live.FirstPacketAt, live.LastPacketAt,
			broker.FormatTimestamp(first), broker.FormatTimestamp(last))
	}
	silent := heartbeat.Feeds[1]
	if silent.FirstPacketAt != "" || silent.LastPacketAt != "" || silent.Packets != 0 || silent.Bytes != 0 {
		t.Errorf("feed-silent = %+v, want the zero/never-received shape", silent)
	}
}

// TestBuildRejectsANeverDrainedFeed pins the startup hazard this producer has
// to be deployed against.
//
// A feed whose window has never been drained holds the zero erasure.Window,
// whose Schema is 0, and ValidateHeartbeat rejects any schema outside [1,2].
// Rejection is whole-heartbeat, so ONE never-drained feed discards the liveness
// of every other feed in the beat. The reporter that publishes windows is a
// plain ticker whose first tick is one --report-interval away, and that
// interval is legal up to five minutes, so without an explicit drain at
// startup a gateway emits nothing valid for up to ten consecutive heartbeats.
//
// cmd/blockcast-shreds closes that gap by draining once before the heartbeat
// loop starts. This test states the consequence if that drain is ever removed,
// so the coupling is visible from the producer's own tests rather than only
// from the gateway's wiring.
func TestBuildRejectsANeverDrainedFeed(t *testing.T) {
	producer := newTestProducer(t, "https://broker.example", []receiver.FeedSnapshot{{
		FeedID: "feed-never-drained",
		// Zero Window: Schema 0, which is what metrics.Snapshot returns for a
		// feed PublishWindow has not been called for yet.
	}})

	_, err := producer.Build()
	if err == nil {
		t.Fatal("Build() succeeded for a never-drained feed; the schema-0 window " +
			"must not reach the wire")
	}
	if !errors.Is(err, broker.ErrInvalidHeartbeat) {
		t.Errorf("Build() error = %v, want it to wrap broker.ErrInvalidHeartbeat", err)
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("Build() error = %v, want it to name the erasure schema", err)
	}
}

// TestSendReplaysIdenticalBytes covers broker.ReplayRule, whose violation is
// silent: re-stamping sent_at on a retry defeats the broker's
// (gw_uuid, sent_at) dedup and double-counts a delivery window in an
// append-only ledger.
func TestSendReplaysIdenticalBytes(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != broker.HeartbeatPath() {
			t.Errorf("POST path = %q, want %q", r.URL.Path, broker.HeartbeatPath())
		}
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		bodies = append(bodies, body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	producer := newTestProducer(t, server.URL, []receiver.FeedSnapshot{{
		FeedID: "feed-a",
		Window: drainedWindow(t),
	}}, WithHTTPClient(server.Client()))

	heartbeat, err := producer.Build()
	if err != nil {
		t.Fatal(err)
	}
	body, err := broker.CanonicalBytes(heartbeat)
	if err != nil {
		t.Fatal(err)
	}

	for attempt := range 2 {
		retry, err := producer.Send(context.Background(), body)
		if err != nil {
			t.Fatalf("attempt %d: Send() error = %v", attempt, err)
		}
		if retry != broker.RetryNever {
			t.Errorf("attempt %d: Send() retry = %v, want RetryNever on success", attempt, retry)
		}
	}

	if len(bodies) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(bodies))
	}
	if string(bodies[0]) != string(bodies[1]) {
		t.Errorf("replayed body differs from the original:\n first: %s\nsecond: %s",
			bodies[0], bodies[1])
	}
}

func TestNewProducerRejectsInsecureBrokerURL(t *testing.T) {
	_, err := NewProducer(testGWUUID, "http://broker.example", fakeSource{})
	if err == nil {
		t.Fatal("NewProducer accepted an http broker URL")
	}
	if !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("NewProducer error = %v, want an https requirement", err)
	}
}

// TestSendClassifiesFailuresFromTheCodeTaxonomy checks that the retry class
// comes from the response's Code rather than its status, and that an
// unrecognized code is not guessed safe to repeat.
func TestSendClassifiesFailuresFromTheCodeTaxonomy(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		code       broker.ErrorCode
		status     int
		retryAfter string
		wantRetry  broker.Retry
		wantErr    bool
	}{
		{
			name:      "unknown code is never retried",
			code:      "code_from_a_newer_broker",
			status:    http.StatusBadRequest,
			wantRetry: broker.RetryNever,
			wantErr:   true,
		},
		{
			name:       "concurrency cap surfaces the broker's delay",
			code:       broker.CodeConcurrencyCapped,
			status:     http.StatusConflict,
			retryAfter: "120",
			wantRetry:  broker.RetryAfterHeader,
			wantErr:    true,
		},
		{
			name:      "publication failure takes ordinary backoff",
			code:      broker.CodePublicationFailed,
			status:    http.StatusServiceUnavailable,
			wantRetry: broker.RetryBackoff,
			wantErr:   true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if testCase.retryAfter != "" {
					w.Header().Set(broker.RetryAfterHeaderName, testCase.retryAfter)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(testCase.status)
				_ = json.NewEncoder(w).Encode(broker.ErrorResponse{
					Code: testCase.code, Message: "rejected in test",
				})
			}))
			defer server.Close()

			producer := newTestProducer(t, server.URL, []receiver.FeedSnapshot{{
				FeedID: "feed-a",
				Window: drainedWindow(t),
			}}, WithHTTPClient(server.Client()))

			retry, err := producer.Send(context.Background(), []byte(`{}`))
			if testCase.wantErr && err == nil {
				t.Fatal("Send() error = nil, want an error")
			}
			if retry != testCase.wantRetry {
				t.Errorf("Send() retry = %v, want %v (err = %v)", retry, testCase.wantRetry, err)
			}
		})
	}
}

// TestNewProducerRejectsBadConfigAtStartup keeps a misconfiguration from
// surfacing 30 seconds later as an unexplained rejected heartbeat.
func TestNewProducerRejectsBadConfigAtStartup(t *testing.T) {
	source := fakeSource{}
	for _, testCase := range []struct{ name, gwUUID, baseURL string }{
		{"uppercase uuid", strings.ToUpper(testGWUUID), "https://broker.example"},
		{"nil uuid", "00000000-0000-0000-0000-000000000000", "https://broker.example"},
		{"empty uuid", "", "https://broker.example"},
		{"schemeless url", testGWUUID, "broker.example"},
		{"empty url", testGWUUID, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewProducer(testCase.gwUUID, testCase.baseURL, source); err == nil {
				t.Fatalf("NewProducer(%q, %q) error = nil, want an error",
					testCase.gwUUID, testCase.baseURL)
			}
		})
	}
}

// TestSendOnceIsRaceFreeAgainstLiveIngest exercises the producer's read of the
// receiver's metrics *concurrently with the ingest path that writes them*, so
// the CI race lane (`go test -race -tags purego ./...`) has something to
// observe on this path.
//
// This test exists because the lane's green tick was previously meaningless
// here: every other test in this file drives fakeSource, whose Snapshot is a
// field read with no writer, so -race saw no concurrent access to report and
// the ticker-vs-Snapshot concurrency was argued structurally rather than
// observed. That is the same shape as this row's other silent-inert failures —
// a check that passes while measuring nothing.
//
// It therefore uses the REAL *receiver.ReceiverMetrics rather than fakeSource:
// the pairing under test is Snapshot's RLock against ObserveIngress's and
// PublishWindow's Lock, and a fake cannot exercise a lock it does not have.
// SendOnce is called in a loop rather than via Run because Run ticks on
// broker.HeartbeatInterval (30s); SendOnce is exactly what that tick invokes,
// so the loop covers the same read path without a 30-second test.
//
// Assertions are deliberately weak — counters are racing by construction, so
// pinning a value would make this flaky. Correctness here is "the race detector
// reports nothing and every beat validates", not a particular count.
func TestSendOnceIsRaceFreeAgainstLiveIngest(t *testing.T) {
	const feedID = "feed-a"

	metrics, err := receiver.NewReceiverMetrics(prometheus.NewRegistry(), []string{feedID})
	if err != nil {
		t.Fatal(err)
	}
	// Seed one valid window so the first beat validates: a zero window is
	// schema 0, which ValidateHeartbeat rejects — the generic-mode failure
	// this PR's other commit rejects at startup.
	if err := metrics.PublishWindow(feedID, drainedWindow(t)); err != nil {
		t.Fatal(err)
	}

	var accepted atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var beat broker.Heartbeat
		if err := json.NewDecoder(r.Body).Decode(&beat); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Validate server-side: a beat assembled from a torn read would fail
		// here, so this is the assertion that a race would actually trip.
		if err := broker.ValidateHeartbeat(beat); err != nil {
			t.Errorf("server received an invalid heartbeat: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		accepted.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	producer, err := NewProducer(testGWUUID, server.URL, metrics, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writers sync.WaitGroup
	// Two writer classes, because they take the write lock on different state:
	// ObserveIngress mutates liveness, PublishWindow replaces the window.
	writers.Add(2)
	go func() {
		defer writers.Done()
		for i := 0; i < 300; i++ {
			if err := metrics.ObserveIngress(feedID, 1316, time.Now()); err != nil {
				t.Errorf("ObserveIngress: %v", err)
				return
			}
		}
	}()
	go func() {
		defer writers.Done()
		window := drainedWindow(t)
		for i := 0; i < 300; i++ {
			if err := metrics.PublishWindow(feedID, window); err != nil {
				t.Errorf("PublishWindow: %v", err)
				return
			}
		}
	}()

	var readers sync.WaitGroup
	readers.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer readers.Done()
			for j := 0; j < 50; j++ {
				if err := producer.SendOnce(ctx); err != nil {
					t.Errorf("SendOnce: %v", err)
					return
				}
			}
		}()
	}

	writers.Wait()
	readers.Wait()

	if got := accepted.Load(); got != 100 {
		t.Fatalf("accepted heartbeats = %d, want 100", got)
	}
}
