package gwclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blockcast/go-amt/broker"
	"github.com/blockcast/go-amt/receiver"
)

const maxDeliveryTargetsBodyBytes = 1 << 20

// DeliveryTargetReader reads the broker's authoritative target snapshot.
type DeliveryTargetReader struct {
	endpoint string
	feedID   string
	client   *http.Client
}

// NewDeliveryTargetReader creates a reader rooted at an HTTPS broker URL.
func NewDeliveryTargetReader(baseURL, feedID string, client *http.Client) (*DeliveryTargetReader, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("gwclient: invalid broker base URL %q", baseURL)
	}
	if strings.TrimSpace(feedID) == "" {
		return nil, fmt.Errorf("gwclient: feed ID is empty")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &DeliveryTargetReader{
		endpoint: strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/") + broker.DeliveryTargetsPath(feedID),
		feedID:   feedID,
		client:   client,
	}, nil
}

// Read fetches and validates one broker target snapshot. A nil error with an
// empty Targets slice is authoritative and must not be treated as a failed read.
func (r *DeliveryTargetReader) Read(ctx context.Context) (broker.DeliveryTargetsRead, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint, nil)
	if err != nil {
		return broker.DeliveryTargetsRead{}, fmt.Errorf("build delivery-target request: %w", err)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return broker.DeliveryTargetsRead{}, fmt.Errorf("read delivery targets: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return broker.DeliveryTargetsRead{}, fmt.Errorf("delivery-target read returned HTTP %d", response.StatusCode)
	}
	var read broker.DeliveryTargetsRead
	if err := json.NewDecoder(io.LimitReader(response.Body, maxDeliveryTargetsBodyBytes)).Decode(&read); err != nil {
		return broker.DeliveryTargetsRead{}, fmt.Errorf("decode delivery targets: %w", err)
	}
	if err := broker.ValidateDeliveryTargetsRead(read); err != nil {
		return broker.DeliveryTargetsRead{}, fmt.Errorf("validate delivery targets: %w", err)
	}
	if read.FeedID != r.feedID {
		return broker.DeliveryTargetsRead{}, fmt.Errorf("validate delivery targets: response feed_id %q does not match requested feed_id %q", read.FeedID, r.feedID)
	}
	return read, nil
}

// ReceiverTargets converts a validated broker response to fan-out targets.
func ReceiverTargets(read broker.DeliveryTargetsRead) []receiver.Target {
	targets := make([]receiver.Target, 0, len(read.Targets))
	for _, target := range read.Targets {
		targets = append(targets, receiver.Target{ID: target.TargetID, Address: target.Addr})
	}
	return targets
}
