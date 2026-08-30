package gwclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blockcast/go-amt/broker"
)

func validTargetRead() broker.DeliveryTargetsRead {
	return broker.DeliveryTargetsRead{
		FeedID:      "feed-a",
		Targets:     []broker.DeliveryTarget{{TargetID: "11111111-1111-4111-8111-111111111111", Addr: "127.0.0.1:9000"}},
		EvaluatedAt: "2026-08-27T00:00:00Z",
	}
}

func TestDeliveryTargetReaderReadsAndConverts(t *testing.T) {
	read := validTargetRead()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != broker.DeliveryTargetsPath("feed-a") {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(read)
	}))
	defer server.Close()

	reader, err := NewDeliveryTargetReader(server.URL, "feed-a", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	targets := ReceiverTargets(got)
	if len(targets) != 1 || targets[0].ID != read.Targets[0].TargetID || targets[0].Address != read.Targets[0].Addr {
		t.Fatalf("unexpected converted targets: %#v", targets)
	}
}

func TestDeliveryTargetReaderPreservesAuthoritativeEmptySet(t *testing.T) {
	read := validTargetRead()
	read.Targets = []broker.DeliveryTarget{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(read)
	}))
	defer server.Close()

	reader, err := NewDeliveryTargetReader(server.URL, "feed-a", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Read(context.Background())
	if err != nil || got.Targets == nil || len(ReceiverTargets(got)) != 0 {
		t.Fatalf("empty target set was not preserved: %#v, %v", got, err)
	}
}

func TestDeliveryTargetReaderRejectsMismatchedFeedID(t *testing.T) {
	read := validTargetRead()
	read.FeedID = "feed-b"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(read)
	}))
	defer server.Close()

	reader, err := NewDeliveryTargetReader(server.URL, "feed-a", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "does not match requested feed_id") {
		t.Fatalf("mismatched feed ID error = %v", err)
	}
}

func TestDeliveryTargetReaderRejectsBadResponseAndHTTPFailure(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"http failure": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusServiceUnavailable) }),
		"malformed":    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{")) }),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			reader, err := NewDeliveryTargetReader(server.URL, "feed-a", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := reader.Read(context.Background()); err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("expected a concrete read error")
			}
		})
	}
}
