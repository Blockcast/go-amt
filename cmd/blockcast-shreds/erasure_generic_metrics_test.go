package main

import (
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/receiver/config"
	"github.com/blockcast/go-amt/shred"
)

// erasureSeriesNames is every series in the bcast_shred_gw_erasure_* family.
// It is spelled out rather than derived from a prefix scan so that a family
// member added later and not considered here fails the shred-mode half below,
// instead of being silently admitted by a prefix match that only ever asserts
// "at least one".
var erasureSeriesNames = []string{
	"bcast_shred_gw_erasure_sets",
	"bcast_shred_gw_erasure_fraction",
	"bcast_shred_gw_erasure_grace_milliseconds",
	"bcast_shred_gw_erasure_slot_rejections_total",
	"bcast_shred_gw_erasure_frontier_resyncs_total",
}

// scrapeErasureLines returns every exposition line, comment or sample, whose
// metric name starts with the erasure prefix.
//
// HELP and TYPE lines are included deliberately: a registered-but-unpublished
// collector still emits them, so a sample-only assertion would pass on a
// family that is half present.
func scrapeErasureLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		name := line
		if after, ok := strings.CutPrefix(line, "# HELP "); ok {
			name = after
		} else if after, ok := strings.CutPrefix(line, "# TYPE "); ok {
			name = after
		} else if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(name, "bcast_shred_gw_erasure") {
			lines = append(lines, line)
		}
	}
	return lines
}

// runAndScrape serves one feed under mode until /metrics answers, then stops.
func runAndScrape(t *testing.T, mode scoring) string {
	t.Helper()
	silenceStdout(t)

	feedAddress := freeLocalAddr(t, "udp")
	httpAddress := freeLocalAddr(t, "tcp")
	stop := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- listenAndScore(
			[]feed{{name: "default", address: feedAddress}}, nil, httpAddress, 30*time.Second, true,
			config.DefaultErasureGrace, 40*time.Millisecond, shred.DefaultRetention, stop, mode,
			billing{}, heartbeatConfig{})
	}()

	var text string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if body, ok := scrapeSnapshot(t, httpAddress); ok {
			text = body
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	if err := <-finished; err != nil {
		t.Fatalf("listenAndScore(%v): %v", mode.mode, err)
	}
	if text == "" {
		t.Fatalf("mode %q: /metrics never answered", mode.mode)
	}
	return text
}

// TestGenericModeExportsNoErasureSeries pins both halves of the contract: the
// erasure family is ABSENT in generic mode, and unchanged in shred mode.
//
// Absent rather than zero is the whole point. Generic mode does no erasure
// coding -- shred.Parse rejects a generic record and listenAndScore builds no
// trackers -- so a registered family sits at erasure_fraction=0 for the life of
// the process, which reads as a genuinely perfect feed. That is the same false
// attestation publishWindows refuses to publish on a failed drain and
// heartbeatOptions refuses to send for generic mode; this is the /metrics path
// of the same argument (BLO-28910).
//
// The shred half is the control, and it is the load-bearing one: an assertion
// that the series are missing in generic mode passes just as well if they are
// missing everywhere. It asserts the PRE-TRAFFIC zero state specifically -- no
// packet is ever sent here -- because a shred feed that has received nothing
// must still report zeros rather than disappear.
func TestGenericModeExportsNoErasureSeries(t *testing.T) {
	t.Run("generic mode exports none", func(t *testing.T) {
		text := runAndScrape(t, scoring{
			mode:        "generic",
			sourceLabel: "synthetic",
			rightsBasis: "synthetic-generated-no-third-party-content",
		})
		if lines := scrapeErasureLines(text); len(lines) != 0 {
			t.Fatalf("generic mode exported %d erasure lines, want 0:\n%s",
				len(lines), strings.Join(lines, "\n"))
		}
		// Control: the scrape is a real one, not an empty body that would make
		// the assertion above vacuous.
		if _, ok := scrapeText(text, "bcast_shred_gw_ingress_packets_total", `feed="default"`); !ok {
			t.Fatal("generic mode exported no ingress_packets_total; the scrape proves nothing")
		}
	})

	t.Run("shred mode exports all, at zero", func(t *testing.T) {
		text := runAndScrape(t, scoring{mode: "shred"})
		for _, name := range erasureSeriesNames {
			if _, ok := scrapeText(text, name, `feed="default"`); !ok {
				t.Errorf("shred mode did not export %s; a silent feed must report zeros, not disappear", name)
			}
		}
		// This asserts the zero VALUE, not that a window was published: no
		// window is published pre-traffic at all. DrainWindow errors on an idle
		// tracker, so publishWindows (main.go) hits `continue` and leaves the
		// zero-value Window that Collect reads -- which is why grace reads 0
		// here too rather than the configured 400. Nothing at this level can
		// tell a published window from a merely-registered family, and nothing
		// here needs to: receiver.TestReceiverMetricsExposePacketCountersAndExactWindow
		// pins that directly, publishing GraceMS=400 and asserting it scrapes back.
		if value, ok := scrapeText(text, "bcast_shred_gw_erasure_fraction", `feed="default"`); !ok || value != 0 {
			t.Errorf("shred mode erasure_fraction = %v, ok = %v; want 0 pre-traffic", value, ok)
		}
	})
}

// TestGenericModeRejectsErasureGraceFlag pins the AC3 half: a flag that cannot
// take effect fails at startup rather than reading as configured.
//
// --report-interval is deliberately absent from the reject list and is asserted
// ACCEPTED here, because it is not inert in generic mode: the reporter
// goroutine it drives also runs billDestinations and the broker
// delivery-target reconcile.
func TestGenericModeRejectsErasureGraceFlag(t *testing.T) {
	generic := []string{
		"--mode", "generic",
		"--source-label", "synthetic",
		"--rights-basis", "synthetic-generated-no-third-party-content",
		"--http-addr", "",
	}

	t.Run("explicit grace is rejected", func(t *testing.T) {
		// --feed bad is a later, unrelated validation error. It is here so that
		// removing the grace guard makes this subtest FAIL on the message rather
		// than hang in listenAndScore -- a mutation that hangs is not a caught one.
		err := run(append([]string{"--erasure-grace-ms", "400", "--feed", "bad"}, generic...))
		if err == nil || !strings.Contains(err.Error(), "--erasure-grace-ms requires --mode shred") {
			t.Fatalf("run() error = %v, want the generic-mode grace rejection", err)
		}
	})

	t.Run("explicit grace is accepted in shred mode", func(t *testing.T) {
		// Control: the rejection is keyed on the mode, not on the flag.
		err := run([]string{"--erasure-grace-ms", "400", "--http-addr", "", "--feed", "bad"})
		if err == nil || strings.Contains(err.Error(), "--erasure-grace-ms") {
			t.Fatalf("run() error = %v, want a later validation error, not the grace rejection", err)
		}
	})

	t.Run("report-interval is accepted in generic mode", func(t *testing.T) {
		err := run(append([]string{"--report-interval", "5s", "--feed", "bad"}, generic...))
		if err == nil || strings.Contains(err.Error(), "--report-interval") {
			t.Fatalf("run() error = %v, want a later validation error; --report-interval is not inert in generic mode", err)
		}
	})
}
