package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/blockcast/go-amt/receiver"
)

// TestDestinationCountWarningFiresOnlyAboveTheThreshold pins the boundary of
// the in-code N bound.
//
// Before this guard the N~65 revisit trigger existed only in the W2c AC6 design
// record: nothing in the binary bounded N, so the deliberate "unicast first"
// decision would have become permanent architecture the moment an operator
// added a 66th --dest-ip-ports entry and nobody happened to remember the
// document. The boundary is asserted from both sides so it cannot drift off the
// constant it derives from.
//
// Asserted through destinationCountWarning rather than through run for the same
// reason as retentionWarning: a long destination list is a VALID config, so
// driving it through run would parse, fall through to listenAndScore, bind
// sockets and block until the package test timeout.
func TestDestinationCountWarningFiresOnlyAboveTheThreshold(t *testing.T) {
	for _, testCase := range []struct {
		count int
		want  bool
	}{
		{0, false},
		{1, false},
		{receiver.RevisitThresholdDestinations - 1, false},
		// Exactly at the threshold is still silent: the warning is for crossing
		// it, and firing AT it would make the documented figure mean "54".
		{receiver.RevisitThresholdDestinations, false},
		{receiver.RevisitThresholdDestinations + 1, true},
		{receiver.MulticastCrossoverDestinations, true},
		{200, true},
	} {
		warning := destinationCountWarning(testCase.count)
		if got := warning != ""; got != testCase.want {
			t.Errorf("destinationCountWarning(%d) warned = %v, want %v (threshold is %d)",
				testCase.count, got, testCase.want, receiver.RevisitThresholdDestinations)
			continue
		}
		if !testCase.want {
			continue
		}
		// A warning an operator cannot act on is noise that trains them to
		// ignore the one run where it matters. It has to name the knob, the
		// count that crossed, the crossover being approached, and where the
		// decision is recorded — otherwise "too many destinations" is a dead end.
		for _, needed := range []string{"--dest-ip-ports", "BLO-25708", "n65-revisit-trigger",
			// The guard warns and continues. Saying so is what stops an operator
			// reading this as a startup failure and rolling back a healthy feed.
			"Starting anyway"} {
			if !strings.Contains(warning, needed) {
				t.Errorf("warning for N=%d omits %q, so the operator cannot tell what "+
					"crossed which bound or where to escalate: %s", testCase.count, needed, warning)
			}
		}
		// The trigger is cited once. Two mentions means the message was edited
		// into naming it twice, which is how a warning starts reading as a wall
		// of text an operator skips.
		if got := strings.Count(warning, "BLO-25708"); got != 1 {
			t.Errorf("warning for N=%d cites BLO-25708 %d times, want exactly 1: %s",
				testCase.count, got, warning)
		}
		// Built with Sprintf, so assert the RENDERED form: an over-doubled
		// escape ships literal "%%" to an operator's journal while every other
		// assertion here still passes. This is the bug that pattern already
		// produced once in retentionWarning.
		if strings.Contains(warning, "%%") || strings.Contains(warning, "%d") {
			t.Errorf("warning for N=%d leaks a format verb, so a Sprintf argument is "+
				"missing or an escape is over-doubled: %s", testCase.count, warning)
		}
		// The rendered numbers must be the constants, not stale literals.
		for _, figure := range []string{
			strconv.Itoa(testCase.count),
			strconv.Itoa(receiver.RevisitThresholdDestinations),
			strconv.Itoa(receiver.MulticastCrossoverDestinations),
		} {
			if !strings.Contains(warning, figure) {
				t.Errorf("warning for N=%d does not quote %q, so the message and the "+
					"constants have diverged: %s", testCase.count, figure, warning)
			}
		}
	}
}

// TestDestinationCountWarningIsSilentAtRealisticDeployments is the paired
// negative: today's fan-out serves a handful of validators, and the common case
// must emit nothing at all. A warning present in every startup log is one
// nobody reads by the time N actually matters.
func TestDestinationCountWarningIsSilentAtRealisticDeployments(t *testing.T) {
	for _, count := range []int{0, 1, 2, 8, 42} {
		if warning := destinationCountWarning(count); warning != "" {
			t.Fatalf("destinationCountWarning(%d) warns at a routine destination count, "+
				"which would train operators to ignore it: %s", count, warning)
		}
	}
}
