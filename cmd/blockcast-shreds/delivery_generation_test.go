package main

import (
	"testing"

	"github.com/blockcast/go-amt/receiver"
)

// TestLedgerSamplesPreserveTargetGeneration guards the production adapter
// between the fan-out ledger and Reporter. A generation is nonzero for every
// broker-target entry; dropping it here silently routes the sample to the
// legacy generation-zero session, so a generation-stamped removal cannot
// close the session that received the traffic.
func TestLedgerSamplesPreserveTargetGeneration(t *testing.T) {
	fanout, err := receiver.NewUDPFanoutTargets([]receiver.Target{
		{ID: "grant-a", Address: "127.0.0.1:20001"},
	}, 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()

	stats := fanout.DestinationStats()
	if len(stats) != 1 {
		t.Fatalf("DestinationStats returned %d entries, want 1", len(stats))
	}
	if stats[0].Generation == 0 {
		t.Fatal("fan-out assigned the broker target a zero generation")
	}

	samples := ledgerSamples(fanout)
	if len(samples) != 1 {
		t.Fatalf("ledgerSamples returned %d entries, want 1", len(samples))
	}
	if samples[0].Generation != stats[0].Generation {
		t.Fatalf("ledger sample generation = %d, want %d", samples[0].Generation, stats[0].Generation)
	}
}
