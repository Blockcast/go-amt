package erasure

import "testing"

// The coherence rule in extendRun anchors each step on its PREDECESSOR, not on
// the slot that opened the run. Two docstrings used to claim the opener, and
// nothing discriminated the two readings: the existing coherence test spaces its
// slots far enough apart to fail either rule, so it passed without pinning
// which one was implemented (Ally review on go-amt#47).
//
// These tests pin the difference in both directions — the case predecessor
// anchoring must accept, and the reach it costs — so the semantic cannot drift
// again without a failure that says which way it drifted.

// TestRampingFeedAtRealisticSlotSpacingStillResyncs is the guard that makes the
// choice of anchor load-bearing rather than stylistic.
//
// Opener anchoring caps the per-observation step at maxSlotJump/(threshold-1) =
// 273 slots. Real capture data advances 69-364 slots between consecutive
// observations, so a feed in the upper half of its own normal range could never
// assemble a run and would never recover — the permanent blackout the guard
// exists to prevent. This test drives 364 and fails if the anchor is hoisted
// into extendRun's else branch to match the old docstring.
func TestRampingFeedAtRealisticSlotSpacingStillResyncs(t *testing.T) {
	const step = 364 // top of the observed 69-364 range

	var count int
	var anchor uint64
	slot := uint64(1_000_000)

	best := 0
	for i := 0; i < 4*slotResyncThreshold; i++ {
		if n := extendRun(&count, &anchor, slot); n > best {
			best = n
		}
		slot += step
	}

	if best < slotResyncThreshold {
		t.Fatalf("a feed ramping %d slots per observation reached a run of only %d, "+
			"never the %d needed to resync: such a feed can never recover its frontier. "+
			"This is what anchoring the run on its opener costs — the per-observation "+
			"step would be capped at %d, below the 69-364 range real traffic occupies.",
			step, best, slotResyncThreshold, maxSlotJump/(slotResyncThreshold-1))
	}
}

// TestCoherentRunChainsRatherThanClusters states the reach the chain costs, so
// the weaker-than-documented property is written down as an assertion rather
// than left in prose. Steps of exactly maxSlotJump are the boundary case the
// opener and predecessor readings disagree about most sharply.
func TestCoherentRunChainsRatherThanClusters(t *testing.T) {
	var count int
	var anchor uint64
	const opener = uint64(1_000_000)
	slot := opener

	for i := 0; i < slotResyncThreshold; i++ {
		count2 := extendRun(&count, &anchor, slot)
		if count2 != i+1 {
			t.Fatalf("step %d: run length = %d, want %d — a chain of exactly "+
				"maxSlotJump steps must keep extending", i, count2, i+1)
		}
		slot += maxSlotJump
	}

	// The run reached the threshold having drifted far beyond one maxSlotJump
	// from where it started. That is the documented-and-now-accurate reach.
	drift := anchor - opener
	wantDrift := uint64((slotResyncThreshold - 1) * maxSlotJump)
	if drift != wantDrift {
		t.Errorf("run of %d ended %d slots from its opener, want %d",
			slotResyncThreshold, drift, wantDrift)
	}
	if drift <= maxSlotJump {
		t.Errorf("drift %d did not exceed maxSlotJump %d, so this test is no longer "+
			"exercising the case the opener and predecessor readings disagree about",
			drift, maxSlotJump)
	}
}

// TestScatteredNoiseNeverAccumulates pins the property the coherence rule exists
// for, and which survives predecessor anchoring unchanged. Without this, the two
// tests above could be satisfied by deleting the gate entirely.
func TestScatteredNoiseNeverAccumulates(t *testing.T) {
	var count int
	var anchor uint64
	slot := uint64(1_000_000)

	for i := 0; i < 8*slotResyncThreshold; i++ {
		if n := extendRun(&count, &anchor, slot); n != 1 {
			t.Fatalf("observation %d: unrelated slots more than maxSlotJump apart "+
				"produced a run of %d; scattered noise must perpetually restart its "+
				"own run and never accumulate toward a resync", i, n)
		}
		slot += maxSlotJump + 1
	}
}
