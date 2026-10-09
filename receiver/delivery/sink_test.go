package delivery

import "testing"

// TestEmptyTeeSinkShipsNowhereAndSaysSo is the guard against the worst failure
// this package can have. TeeSink is an exported slice type, so a caller can
// build one without NewTeeSink — and a range over an empty slice returns nil
// having shipped the record nowhere. Reporter reads that nil as "durably
// accepted, never retransmit", so the zero value bills nothing while the WAL,
// the counters and every log line read healthy.
func TestEmptyTeeSinkShipsNowhereAndSaysSo(t *testing.T) {
	for name, tee := range map[string]TeeSink{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tee.Ship(testRecord()); err == nil {
				t.Fatal("empty tee reported a record durably accepted, having shipped it nowhere")
			}
		})
	}
}

// TestTeeSinkFansOutAndStopsAtTheFirstFailure pins the two properties Reporter
// depends on: every member sees the record, and a partial fan-out is reported
// as a failure so the record stays pending rather than being billed as
// delivered by the members that did accept it.
func TestTeeSinkFansOutAndStopsAtTheFirstFailure(t *testing.T) {
	first, second := &captureSink{}, &captureSink{}
	tee, err := NewTeeSink(first, second)
	if err != nil {
		t.Fatalf("NewTeeSink() error = %v", err)
	}
	if err := tee.Ship(testRecord()); err != nil {
		t.Fatalf("Ship() error = %v", err)
	}
	if len(first.shipped) != 1 || len(second.shipped) != 1 {
		t.Fatalf("fan-out reached %d and %d members, want 1 and 1", len(first.shipped), len(second.shipped))
	}

	// Second member fails: the first has already accepted, so this is exactly
	// the partial fan-out that must NOT report success.
	second.failing = true
	if err := tee.Ship(testRecord()); err == nil {
		t.Fatal("a partial fan-out reported the record durably accepted")
	}
}

// TestNewTeeSinkRefusesAnUnusableSet keeps the constructor's own checks honest
// now that Ship carries the empty guard too; the two are not redundant,
// because the constructor is the only thing that catches a nil member before
// it panics mid-fan-out.
func TestNewTeeSinkRefusesAnUnusableSet(t *testing.T) {
	if _, err := NewTeeSink(); err == nil {
		t.Fatal("NewTeeSink() accepted an empty sink set")
	}
	if _, err := NewTeeSink(&captureSink{}, nil); err == nil {
		t.Fatal("NewTeeSink() accepted a nil member")
	}
}
