package receiver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthHandlerTracksIngressFreshness(t *testing.T) {
	now := time.Unix(100, 0)
	health, err := NewHealth(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	health.now = func() time.Time { return now }

	assertHealth(t, health, http.StatusServiceUnavailable, `{"status":"unhealthy"}`+"\n")
	health.MarkReceived(now)
	assertHealth(t, health, http.StatusOK, `{"status":"ok"}`+"\n")
	now = now.Add(time.Second + time.Nanosecond)
	assertHealth(t, health, http.StatusServiceUnavailable, `{"status":"unhealthy"}`+"\n")
}

func TestNewHealthRejectsNonPositiveAge(t *testing.T) {
	for _, age := range []time.Duration{0, -time.Nanosecond} {
		if _, err := NewHealth(age); err == nil {
			t.Fatalf("NewHealth(%s) succeeded", age)
		}
	}
}

func assertHealth(t *testing.T, handler http.Handler, wantStatus int, wantBody string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d", recorder.Code, wantStatus)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Body.String(); got != wantBody {
		t.Fatalf("body = %q, want %q", got, wantBody)
	}
}
