package receiver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewHealthRejectsInvalidFreshness(t *testing.T) {
	for _, maxAge := range []time.Duration{0, -time.Nanosecond} {
		if _, err := NewHealth(maxAge); err == nil {
			t.Fatalf("NewHealth(%s) succeeded, want error", maxAge)
		}
	}
}

func TestHealthFreshness(t *testing.T) {
	health, err := NewHealth(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	health.now = func() time.Time { return now.Add(-5 * time.Second) }

	if health.HealthyAt(now) {
		t.Fatal("zero-state health is healthy")
	}
	health.MarkReceived()
	if !health.HealthyAt(now) {
		t.Fatal("packet at freshness limit is unhealthy")
	}
	if health.HealthyAt(now.Add(time.Nanosecond)) {
		t.Fatal("packet beyond freshness limit is healthy")
	}
}

func TestHealthKeepsNewestPacketTimestamp(t *testing.T) {
	health, err := NewHealth(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	health.now = func() time.Time { return now }
	health.MarkReceived()
	health.now = func() time.Time { return now.Add(time.Second) }
	health.MarkReceived()

	if !health.HealthyAt(now.Add(2 * time.Second)) {
		t.Fatal("latest local receipt timestamp was not retained")
	}
}

func TestHealthTreatsClockRegressionAsFresh(t *testing.T) {
	now := time.Unix(100, 0)
	health, err := NewHealth(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	health.now = func() time.Time { return now }
	health.MarkReceived()

	if !health.HealthyAt(now.Add(-time.Hour)) {
		t.Fatal("local clock regression made a fresh receipt unhealthy")
	}
}

func TestHealthConcurrentAccess(t *testing.T) {
	now := time.Now()
	health, err := NewHealth(time.Second)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			health.MarkReceived()
		}
	}()
	for i := 0; i < 100; i++ {
		_ = health.HealthyAt(now)
	}
	<-done
}

func TestHealthHandler(t *testing.T) {
	now := time.Unix(100, 0)
	health, err := NewHealth(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	health.now = func() time.Time { return now }

	assertHealthResponse(t, health, http.StatusServiceUnavailable, "{\"status\":\"unhealthy\"}\n")
	health.MarkReceived()
	assertHealthResponse(t, health, http.StatusOK, "{\"status\":\"ok\"}\n")
	now = now.Add(time.Hour + time.Nanosecond)
	assertHealthResponse(t, health, http.StatusServiceUnavailable, "{\"status\":\"unhealthy\"}\n")
}

func assertHealthResponse(t *testing.T, handler http.Handler, wantStatus int, wantBody string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d", recorder.Code, wantStatus)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := recorder.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
}
