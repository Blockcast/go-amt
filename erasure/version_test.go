package erasure_test

import (
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
)

// TestTrackerVersionZeroJoinsASignedSet pins the cmd/shred-merger wildcard: a
// set whose shreds arrive partly as signed (v4) and partly as unsigned (v3)
// frames is ONE set, in either arrival order, or a merger output that mixes
// wire versions would score every set erased.
func TestTrackerVersionZeroJoinsASignedSet(t *testing.T) {
	for _, signedFirst := range []bool{true, false} {
		start := time.Unix(100, 0)
		tracker, err := erasure.NewTracker(time.Millisecond, start)
		if err != nil {
			t.Fatal(err)
		}
		for index := uint8(0); index < 32; index++ {
			version := uint64(7)
			if (index < 16) != signedFirst {
				version = 0
			}
			tracker.ObserveVersion(header(10, 0, index), version, start)
		}
		tracker.Observe(header(11, 0, 0), start.Add(time.Millisecond))
		if got := drain(t, tracker, start.Add(time.Second)); got.SetsTotal != 1 || got.SetsErased != 0 {
			t.Fatalf("signedFirst=%v: %+v, want one complete set", signedFirst, got)
		}
	}
}
