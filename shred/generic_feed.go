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

// GenericFeedEntry is one feed's generic receipt, named.
type GenericFeedEntry struct {
	Name    string         `json:"name"`
	Receipt GenericReceipt `json:"receipt"`
}

// GenericFeedReceipt is the closing receipt for generic mode.
//
// It carries no union across feeds, deliberately: see GenericFeedScorer. The
// shred-mode UnionReceipt reports one, and the absence here is the honest
// difference between the two modes rather than an omission.
type GenericFeedReceipt struct {
	Feeds []GenericFeedEntry `json:"feeds"`
}

func (r GenericFeedReceipt) String() string {
	var output strings.Builder
	for i, feed := range r.Feeds {
		if i != 0 {
			output.WriteString("\n")
		}
		fmt.Fprintf(&output, "feed name=%s\n%s", feed.Name, feed.Receipt)
	}
	return output.String()
}

// Receipt collects every feed's receipt. It is the generic half of the
// session-scorer seam the demo command drives, so that command needs one mode
// switch at construction and none in its packet loop. Returning a struct rather
// than a string is what lets --json compose with --mode generic.
func (s *GenericFeedScorer) Receipt() GenericFeedReceipt {
	receipt := GenericFeedReceipt{Feeds: make([]GenericFeedEntry, 0, len(s.names))}
	for _, name := range s.names {
		receipt.Feeds = append(receipt.Feeds, GenericFeedEntry{Name: name, Receipt: s.feeds[name].Receipt()})
	}
	return receipt
}

// SessionReceipt is the seam the demo command drives, and the only reason it
// returns fmt.Stringer rather than each mode's concrete receipt: Go will not
// accept a covariant return, so widening here is what lets one interface cover
// both modes — and therefore what lets --json compose with --mode instead of
// --json being a shred-only flag.
func (s *GenericFeedScorer) SessionReceipt() fmt.Stringer { return s.Receipt() }

// SessionReceipt lets the shred-mode scorer satisfy the same seam.
func (s *FeedScorer) SessionReceipt() fmt.Stringer { return s.Receipt() }
