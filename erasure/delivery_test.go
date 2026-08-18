package erasure_test

import (
	"math"
	"runtime"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
)

const peakBucket = 100 * time.Millisecond

// referenceDelivery is the slice-based computation the tracker used before the
// delivery counters were streamed: it holds every arrival for the window and
// derives the three delivery outputs from that slice at drain time. It exists
// so the streaming fold can be compared against the shape it replaced rather
// than against hand-computed constants.
func referenceDelivery(arrivals []time.Time, windowStart, cutoff time.Time) (rMean, rPeak float64, gaps erasure.GapHistogram) {
	buckets := make(map[int64]uint64)
	var lastArrival time.Time
	for _, arrival := range arrivals {
		if !arrival.Before(cutoff) {
			continue
		}
		rMean++
		bucket := arrival.UnixNano() / peakBucket.Nanoseconds()
		buckets[bucket]++
		if rate := float64(buckets[bucket]) / peakBucket.Seconds(); rate > rPeak {
			rPeak = rate
		}
		if !lastArrival.IsZero() {
			gaps = referenceGap(gaps, arrival.Sub(lastArrival))
		}
		lastArrival = arrival
	}
	rMean /= cutoff.Sub(windowStart).Seconds()
	return rMean, rPeak, gaps
}

func referenceGap(gaps erasure.GapHistogram, gap time.Duration) erasure.GapHistogram {
	switch {
	case gap < time.Millisecond:
		gaps.LT1++
	case gap < 2400*time.Microsecond:
		gaps.From1To2_4++
	case gap < 7*time.Millisecond:
		gaps.From2_4To7++
	case gap < 32*time.Millisecond:
		gaps.From7To32++
	default:
		gaps.GTE32++
	}
	return gaps
}

// observeSequence drives arrivals through a tracker, giving each one a distinct
// position so none is rejected as a duplicate. All positions share one slot, so
// no boundary is ever established and erasure scoring stays out of the way.
func observeSequence(t *testing.T, tracker *erasure.Tracker, arrivals []time.Time) {
	t.Helper()
	for index, arrival := range arrivals {
		header := header(1, uint32(index/64), uint8(index%64))
		if !tracker.Observe(header, arrival) {
			t.Fatalf("arrival %d at %s was rejected", index, arrival)
		}
	}
}

func TestTrackerStreamedDeliveryMatchesSliceComputation(t *testing.T) {
	base := time.Unix(2000, 0)
	// A whole second is exactly on a 100 ms bucket edge, which is why the
	// off-edge cases below are offset from it.
	offEdge := base.Add(37 * time.Millisecond)

	tests := []struct {
		name    string
		offsets []time.Duration
	}{
		{name: "no arrivals"},
		{name: "single arrival contributes no gap", offsets: []time.Duration{0}},
		{
			name:    "gap bucket lower edges are inclusive",
			offsets: []time.Duration{0, time.Millisecond, 2*time.Millisecond + 400*time.Microsecond, 7 * time.Millisecond, 32 * time.Millisecond},
		},
		{
			name:    "gap bucket upper edges fall to the lower bucket",
			offsets: []time.Duration{0, time.Millisecond - time.Nanosecond, 2400*time.Microsecond - time.Nanosecond, 7*time.Millisecond - time.Nanosecond, 32*time.Millisecond - time.Nanosecond},
		},
		{
			name:    "burst inside one peak bucket",
			offsets: []time.Duration{0, time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond, 4 * time.Millisecond},
		},
		{
			name:    "burst split across a peak bucket edge",
			offsets: []time.Duration{0, peakBucket - time.Nanosecond, peakBucket, peakBucket + time.Millisecond},
		},
		{
			name:    "arrivals land exactly on successive peak bucket edges",
			offsets: []time.Duration{0, peakBucket, 2 * peakBucket, 3 * peakBucket},
		},
		{
			name:    "long idle gap between two bursts",
			offsets: []time.Duration{0, time.Millisecond, 5 * time.Second, 5*time.Second + 500*time.Microsecond},
		},
	}

	for _, test := range tests {
		for _, start := range []struct {
			name string
			at   time.Time
		}{{name: "bucket aligned", at: base}, {name: "off bucket edge", at: offEdge}} {
			t.Run(test.name+"/"+start.name, func(t *testing.T) {
				arrivals := make([]time.Time, 0, len(test.offsets))
				for _, offset := range test.offsets {
					arrivals = append(arrivals, start.at.Add(offset))
				}
				cutoff := start.at.Add(30 * time.Second)

				tracker, err := erasure.NewTracker(0, start.at)
				if err != nil {
					t.Fatal(err)
				}
				observeSequence(t, tracker, arrivals)
				got := drain(t, tracker, cutoff)

				wantMean, wantPeak, wantGaps := referenceDelivery(arrivals, start.at, cutoff)
				if math.Abs(got.RMean-wantMean) > 1e-12 {
					t.Errorf("r_mean = %v, want %v", got.RMean, wantMean)
				}
				if got.RPeak100MS != wantPeak {
					t.Errorf("r_peak_100ms = %v, want %v", got.RPeak100MS, wantPeak)
				}
				if got.GapMSHist != wantGaps {
					t.Errorf("gap_ms_hist = %+v, want %+v", got.GapMSHist, wantGaps)
				}
			})
		}
	}
}

// The peak bucket is keyed on absolute time, so the same burst must report the
// same peak no matter where the report window happens to start.
func TestTrackerPeakIsIndependentOfWindowPhase(t *testing.T) {
	burstAt := time.Unix(2100, 0).Add(37 * time.Millisecond)
	var peaks []float64
	for _, phase := range []time.Duration{0, 13 * time.Millisecond, 51 * time.Millisecond, 99 * time.Millisecond} {
		start := burstAt.Add(-phase)
		tracker, err := erasure.NewTracker(0, start)
		if err != nil {
			t.Fatal(err)
		}
		arrivals := make([]time.Time, 0, 8)
		for index := 0; index < 8; index++ {
			arrivals = append(arrivals, burstAt.Add(time.Duration(index)*time.Millisecond))
		}
		observeSequence(t, tracker, arrivals)
		peaks = append(peaks, drain(t, tracker, start.Add(30*time.Second)).RPeak100MS)
	}
	for _, peak := range peaks {
		if peak != peaks[0] {
			t.Fatalf("peak varied with window phase: %v", peaks)
		}
	}
	if peaks[0] != 80 {
		t.Fatalf("peak = %v, want 80", peaks[0])
	}
}

func heapHeld() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// driveOneWindow observes shreds arrivals spread evenly over windowSeconds in a
// single report window, advancing the slot every full FEC set so slot state is
// reclaimed and the delivery counters are the only term under test. It returns
// the heap bytes the tracker holds at the end of the window, before any drain.
func driveOneWindow(t *testing.T, shreds int, windowSeconds int) uint64 {
	t.Helper()
	start := time.Unix(3000, 0)
	tracker, err := erasure.NewTracker(0, start)
	if err != nil {
		t.Fatal(err)
	}
	step := time.Duration(int64(windowSeconds) * int64(time.Second) / int64(shreds))

	before := heapHeld()
	for index := 0; index < shreds; index++ {
		header := header(uint64(index/64)+1, 0, uint8(index%64))
		if !tracker.Observe(header, start.Add(time.Duration(index)*step)) {
			t.Fatalf("arrival %d was rejected", index)
		}
	}
	after := heapHeld()
	runtime.KeepAlive(tracker)

	if after < before {
		return 0
	}
	return after - before
}

// One 24-byte timestamp per shred per window pinned steady-state RSS to the
// busiest window a feed had ever seen: 8.21 MB at 10k shreds/s, 38.48 MB at
// 50k. The delivery counters are a fixed-size fold, so held memory must no
// longer scale with the shred count.
func TestTrackerArrivalsMemoryIsConstantInShredCount(t *testing.T) {
	if testing.Short() {
		t.Skip("drives 1.95M observations")
	}
	const windowSeconds = 30
	// Generous next to the fixed-size counters, and far below the 8.21 MB the
	// slice form held at 10k/s. What remains is scoring state: one score event
	// per completed FEC set, which is shred count / 64 and untouched here.
	const ceiling = 3 << 20

	held := make(map[int]uint64)
	for _, rate := range []int{5_000, 10_000, 50_000} {
		shreds := rate * windowSeconds
		held[rate] = driveOneWindow(t, shreds, windowSeconds)
		t.Logf("%6d shreds/s (%8d shreds): held %.2f MB", rate, shreds, float64(held[rate])/(1<<20))
		if held[rate] > ceiling {
			t.Errorf("at %d shreds/s the tracker held %.2f MB, want at most %.2f MB",
				rate, float64(held[rate])/(1<<20), float64(ceiling)/(1<<20))
		}
	}

	// The scale-free statement: the marginal cost of a shred. The slice form
	// spent 24 bytes each; anything near that means per-shred retention is back.
	lowShreds, highShreds := 5_000*windowSeconds, 50_000*windowSeconds
	var marginal float64
	if held[50_000] > held[5_000] {
		marginal = float64(held[50_000]-held[5_000]) / float64(highShreds-lowShreds)
	}
	t.Logf("marginal cost = %.3f bytes/shred (slice form was 24)", marginal)
	if marginal > 4 {
		t.Errorf("marginal retention = %.3f bytes/shred, want well under the 24 the slice form cost", marginal)
	}
}

// drainMallocs returns the number of heap allocations one DrainWindow call
// makes on a window that already holds shreds arrivals.
func drainMallocs(t *testing.T, shreds int) uint64 {
	t.Helper()
	start := time.Unix(5000, 0)
	tracker, err := erasure.NewTracker(0, start)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < shreds; index++ {
		header := header(uint64(index/64)+1, 0, uint8(index%64))
		if !tracker.Observe(header, start.Add(time.Duration(index)*time.Millisecond)) {
			t.Fatalf("arrival %d was rejected", index)
		}
	}

	cutoff := start.Add(time.Duration(shreds)*time.Millisecond + time.Second)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := tracker.DrainWindow(cutoff); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(tracker)
	return after.Mallocs - before.Mallocs
}

// DrainWindow used to build a fresh rate-bucket map and walk the arrival slice
// on every call, so both its time and its allocation count scaled with the
// shreds the window had seen. Measuring at two sizes an order of magnitude
// apart is what makes this bind: a single small window lets escape analysis
// stack-allocate the map, and the test passes against the very code it is
// supposed to reject.
func TestDrainWindowDoesNotAllocatePerWindow(t *testing.T) {
	small, large := drainMallocs(t, 1_000), drainMallocs(t, 100_000)
	t.Logf("DrainWindow allocations: %d at 1k arrivals, %d at 100k", small, large)
	if large > small {
		t.Errorf("DrainWindow allocated %d objects at 100k arrivals versus %d at 1k; cost scales with shred count", large, small)
	}
	if large > 4 {
		t.Errorf("DrainWindow allocated %d objects, want a fixed handful at most", large)
	}
}
