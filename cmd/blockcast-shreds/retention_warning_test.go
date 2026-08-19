package main

import (
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/shred"
)

// TestRetentionWarningFiresExactlyAboveTheLadder pins the boundary of the one
// documented exception to the receipt's accuracy claim.
//
// --retain is validated for positivity only, and the README advises widening it
// when feeds can be seconds apart. Above shred.CompletionCeiling every
// completion collapses into the overflow bucket, which reports its floor, so
// percentiles understate with no bound — against a documented 0.78%
// overstatement in the other direction. The window is still a legal
// configuration (dedup, erasure, gaps and means stay exact), so this warns
// rather than rejecting; the test exists so the boundary cannot drift away from
// the ladder it is derived from.
//
// Note this asserts through retentionWarning rather than through run: an
// above-ceiling window is a VALID config, so driving it through run would parse,
// fall through to listenAndScore, bind sockets and block until the test timeout.
// That is the same failure shape TestUndefinedFlagIsRejected produced once
// --retain became a real flag, and it is why the check is a pure function.
func TestRetentionWarningFiresExactlyAboveTheLadder(t *testing.T) {
	for _, testCase := range []struct {
		window time.Duration
		want   bool
	}{
		{shred.DefaultRetention, false},
		{shred.CompletionCeiling - time.Microsecond, false},
		{shred.CompletionCeiling, true},
		{shred.CompletionCeiling + time.Microsecond, true},
		{8 * time.Second, true},
	} {
		warning := retentionWarning(testCase.window)
		if got := warning != ""; got != testCase.want {
			t.Errorf("retentionWarning(%s) warned = %v, want %v (ceiling is %s)",
				testCase.window, got, testCase.want, shred.CompletionCeiling)
			continue
		}
		if !testCase.want {
			continue
		}
		// A warning an operator cannot act on is noise. It has to name the knob,
		// the ceiling it crossed, and which direction the error now runs.
		for _, needed := range []string{"--retain", "understate", shred.CompletionCeiling.String(),
			// The hint must say it is a hint. Without this the operator reads a
			// silent startup as proof the percentiles are bounded, which is the
			// false-reassurance this warning previously created.
			"not a bound", "completions_above_ceiling"} {
			if !strings.Contains(warning, needed) {
				t.Errorf("warning for %s omits %q, so the operator cannot tell what "+
					"crossed which bound: %s", testCase.window, needed, warning)
			}
		}
		// The message is built with Sprintf and quotes a percentage, so it is one
		// stray escape away from shipping "0.78%%" to an operator's journal. Assert
		// the rendered form rather than the format string: this caught exactly that
		// during development, where every other assertion here passed.
		if strings.Contains(warning, "%%") {
			t.Errorf("warning for %s renders a literal %%%%, so a percent escape is "+
				"over-doubled in the format string: %s", testCase.window, warning)
		}
		if !strings.Contains(warning, "0.78%") {
			t.Errorf("warning for %s does not quote the documented error bound in "+
				"readable form: %s", testCase.window, warning)
		}
	}
}

// TestRetentionWarningIsSilentAtTheDefaultWindow is the paired negative: the
// default configuration must never emit this warning, or it becomes background
// noise that operators learn to ignore before the one run where it matters.
//
// The old name said "...AtEveryDefaultWindowCompletion", which asserted a
// property this function does not have and cannot have. Silence here does NOT
// mean the default window's completions all fit the ladder — they need not, and
// TestDefaultWindowStillProducesCompletionsAboveTheCeiling in the shred package
// shows a 6.2s span at the 2s default. All this pins is the warning's boundary
// against the window; the understatement signal itself is on the receipt.
func TestRetentionWarningIsSilentAtTheDefaultWindow(t *testing.T) {
	if warning := retentionWarning(shred.DefaultRetention); warning != "" {
		t.Fatalf("the default --retain warns, which would train operators to ignore "+
			"it: %s", warning)
	}
}
