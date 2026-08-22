package main

import (
	"os"
	"testing"
	"time"

	"github.com/blockcast/go-amt/shred"
)

// TestEmittedDatagramsParseAsForwarderShreds is the framing contract. The
// receiver hardcodes shred.FormatForwarder, so a datagram this command emits has
// to survive the exact parser the receiver runs; anything else lands in
// shreds_unparsed_total and is never scored, which would present as a flat RSS
// for the reason "nothing was measured" rather than "memory is bounded".
//
// Asserting through the exported shred.Parse rather than a local re-decode is
// deliberate: a local one would agree with the encoder by construction and pass
// while the receiver rejected every packet.
func TestEmittedDatagramsParseAsForwarderShreds(t *testing.T) {
	packet := make([]byte, 1200)
	sendTime := time.Unix(1700000000, 0)

	for n := uint64(0); n < 4*setsPerSlot*dataShredsPerFECSet; n++ {
		encodeDataShred(packet, n, sendTime)
		header, err := shred.Parse(packet, shred.FormatForwarder)
		if err != nil {
			t.Fatalf("shred %d: Parse() = %v; the receiver would count this unparsed and score nothing", n, err)
		}
		if header.Kind != shred.KindData {
			t.Fatalf("shred %d: Kind = %v, want data", n, header.Kind)
		}
		if want := uint8(n % dataShredsPerFECSet); header.IndexWithinSet != want {
			t.Fatalf("shred %d: IndexWithinSet = %d, want %d", n, header.IndexWithinSet, want)
		}
	}
}

// TestIdentitiesAreUniqueAcrossTheRun is the property the whole soak rests on,
// and the one the obvious implementation gets wrong.
//
// Scorer keys per-shred state on (slot, fec_set_index, index_within_set). A
// generator that repeats an identity — replaying a fixed capture in a loop being
// the tempting one — produces a dedup hit that overwrites one map entry instead
// of adding one, so held state stays flat no matter how long the run is. RSS
// would then plateau for a reason that has nothing to do with the retention
// bound, and the soak would report a pass having exercised nothing.
//
// So uniqueness is asserted directly, over more shreds than a slot's worth so
// that the slot component is observed rolling over rather than assumed to.
func TestIdentitiesAreUniqueAcrossTheRun(t *testing.T) {
	const shreds = 50_000

	type identity struct {
		slot           uint64
		fecSetIndex    uint32
		indexWithinSet uint8
	}
	seen := make(map[identity]uint64, shreds)
	packet := make([]byte, 64)
	sendTime := time.Unix(1700000000, 0)

	for n := uint64(0); n < shreds; n++ {
		encodeDataShred(packet, n, sendTime)
		header, err := shred.Parse(packet, shred.FormatForwarder)
		if err != nil {
			t.Fatalf("shred %d: Parse() = %v", n, err)
		}
		key := identity{header.Slot, header.FECSetIndex, header.IndexWithinSet}
		if previous, exists := seen[key]; exists {
			t.Fatalf("shred %d repeats the identity of shred %d (%+v); a repeated identity is a dedup hit, "+
				"so held state would stop growing for a reason unrelated to the retention bound", n, previous, key)
		}
		seen[key] = n
	}
	if len(seen) != shreds {
		t.Fatalf("recorded %d distinct identities across %d shreds", len(seen), shreds)
	}
	// The slot must actually advance. If it did not, uniqueness above would be
	// carried entirely by fec_set_index and the run would exhaust the identity
	// space it was meant to walk.
	first, last := make([]byte, 64), make([]byte, 64)
	encodeDataShred(first, 0, sendTime)
	encodeDataShred(last, shreds-1, sendTime)
	firstHeader, _ := shred.Parse(first, shred.FormatForwarder)
	lastHeader, _ := shred.Parse(last, shred.FormatForwarder)
	if lastHeader.Slot <= firstHeader.Slot {
		t.Fatalf("slot did not advance across %d shreds: %d -> %d", shreds, firstHeader.Slot, lastHeader.Slot)
	}
}

// TestCompleteFECSets checks the synthetic feed presents whole 32-shred sets.
// A feed of permanently-incomplete sets would score every set erased and hold
// set state to the end of the window for sets that never complete, which is a
// different memory profile from the one a real feed produces.
func TestCompleteFECSets(t *testing.T) {
	scorer := shred.NewScorerWithRetention(shred.FormatForwarder, 2*time.Second)
	packet := make([]byte, 1200)
	base := time.Unix(1700000000, 0)

	const sets = 4
	for n := uint64(0); n < sets*dataShredsPerFECSet; n++ {
		encodeDataShred(packet, n, base)
		// One millisecond apart, inside the window, so nothing is evicted mid-test
		// and the receipt covers every set fed.
		if _, err := scorer.Observe(packet, base.Add(time.Duration(n)*time.Millisecond)); err != nil {
			t.Fatalf("shred %d: Observe() = %v", n, err)
		}
	}

	receipt := scorer.Receipt()
	if receipt.SetsTotal != sets {
		t.Fatalf("SetsTotal = %d, want %d", receipt.SetsTotal, sets)
	}
	if receipt.SetsErased != 0 {
		t.Fatalf("SetsErased = %d, want 0; every set was fed all %d data shreds", receipt.SetsErased, dataShredsPerFECSet)
	}
	if receipt.MeanShredsPerSet != dataShredsPerFECSet {
		t.Fatalf("MeanShredsPerSet = %v, want %d", receipt.MeanShredsPerSet, dataShredsPerFECSet)
	}
}

// TestEmitReportsAchievedRateNotTarget pins the reporting half of the first
// acceptance criterion. A driver that echoed its --rate back would read as
// having sustained a rate it never reached.
func TestEmitReportsAchievedRateNotTarget(t *testing.T) {
	out, err := os.CreateTemp(t.TempDir(), "soak")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	// A target far above what the loop can reach, so achieved and target must
	// differ and the reported number has to be the measured one.
	if err := emit(discardWriter{}, 1_000_000_000, 2000, 128, 0, out); err != nil {
		t.Fatalf("emit() = %v", err)
	}
	contents, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	report := string(contents)
	if !contains(report, "sent=2000") {
		t.Fatalf("report does not carry the sent count: %q", report)
	}
	if !contains(report, "achieved_rate=") || !contains(report, "target_rate=1000000000/s") {
		t.Fatalf("report must carry both the achieved and the target rate, distinctly: %q", report)
	}
	if contains(report, "achieved_rate=1000000000.0/s") {
		t.Fatalf("achieved rate echoed the target rather than measuring: %q", report)
	}
}

type discardWriter struct{}

func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
