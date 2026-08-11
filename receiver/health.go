package receiver

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Health tracks ingress freshness for the receiver health endpoint.
type Health struct {
	mu           sync.RWMutex
	maxPacketAge time.Duration
	lastPacketAt time.Time
	now          func() time.Time
}

// NewHealth constructs ingress health state. maxPacketAge must be positive.
func NewHealth(maxPacketAge time.Duration) (*Health, error) {
	if maxPacketAge <= 0 {
		return nil, errors.New("maximum packet age must be positive")
	}
	return &Health{maxPacketAge: maxPacketAge, now: time.Now}, nil
}

// MarkReceived records a successfully received ingress packet using the local
// monotonic clock.
func (h *Health) MarkReceived() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastPacketAt = h.now()
}

// HealthyAt reports whether a packet has arrived within the freshness limit.
// A packet exactly at the limit is still healthy.
func (h *Health) HealthyAt(now time.Time) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	age := now.Sub(h.lastPacketAt)
	return !h.lastPacketAt.IsZero() && age <= h.maxPacketAge
}

// ServeHTTP exposes ingress freshness as a JSON health check.
func (h *Health) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusOK
	response := healthResponse{Status: "ok"}
	if !h.HealthyAt(h.now()) {
		status = http.StatusServiceUnavailable
		response.Status = "unhealthy"
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

type healthResponse struct {
	Status string `json:"status"`
}
