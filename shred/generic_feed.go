package shred

import (
	"fmt"
	"strings"
	"time"
)

// GenericFeedScorer keeps one generic scorer per configured feed.
//
// Unlike FeedScorer it computes no union across feeds. Cross-feed
// first-arrival-wins deduplication is the D4 second-feed claim; reporting a
// union here would assert that two feeds carry the same generic stream, which
// nothing in this mode establishes.
type GenericFeedScorer struct {
	names []string
	feeds map[string]*GenericScorer
}

func NewGenericFeedScorer(names []string, source, rightsBasis string) *GenericFeedScorer {
	feeds := make(map[string]*GenericScorer, len(names))
	for _, name := range names {
		feeds[name] = NewGenericScorer(source, rightsBasis)
	}
	return &GenericFeedScorer{names: append([]string(nil), names...), feeds: feeds}
}

func (s *GenericFeedScorer) Observe(feed string, packet []byte, receivedAt time.Time) (bool, error) {
	scorer := s.feeds[feed]
	if scorer == nil {
		return false, fmt.Errorf("unknown feed %q", feed)
	}
	return scorer.Observe(packet, receivedAt)
}

// ReceiptString renders every feed's receipt. It is the generic half of the
// session-scorer seam the demo command drives, so that command needs one mode
// switch at construction and none in its packet loop.
func (s *GenericFeedScorer) ReceiptString() string {
	var output strings.Builder
	for i, name := range s.names {
		if i != 0 {
			output.WriteString("\n")
		}
		fmt.Fprintf(&output, "feed name=%s\n%s", name, s.feeds[name].Receipt())
	}
	return output.String()
}

// ReceiptString lets the shred-mode scorer satisfy the same seam.
func (s *FeedScorer) ReceiptString() string { return s.Receipt().String() }
