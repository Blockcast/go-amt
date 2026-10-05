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

// windowSeriesNames is every window-derived series OUTSIDE the erasure prefix:
// the three BLO-40163 ruled omitted in generic mode. They are listed separately
// from erasureSeriesNames because scrapeErasureLines cannot see them -- they
// carry no erasure prefix -- so the generic-mode half below has to name them.
//
// All three are read off the same erasure.Window as the erasure family, and no
// window is ever published in generic mode: publishWindows iterates trackers,
// and listenAndScore builds none there. Their zeros are not measurements.
var windowSeriesNames = []string{
	"bcast_shred_gw_shreds_per_second",
	"bcast_shred_gw_gap_events",
	"bcast_shred_gw_report_schema",
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
//
// It deliberately returns the pre-publication state: it breaks on the first
// body the endpoint serves, which normally beats the first report tick, so
// every window-derived series (grace, schema, any published value) reads as
// its zero value here regardless of configuration. Use this helper to assert
// which series are PRESENT, never what they hold. To assert a published value,
// poll until that value is non-zero, as TestDefaultGraceReachesMetrics
// (erasure_test.go) does -- otherwise the answer flips at ~40ms.
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

// scrapeSeriesLines returns every exposition line, comment or sample, whose
// metric name is exactly name or name with a label set appended.
//
// It exists alongside scrapeErasureLines because that one matches a prefix and
// these three share none. The match is anchored on the name boundary rather
// than a bare prefix so that bcast_shred_gw_shreds_per_second cannot be
// satisfied by a longer unrelated name that happens to start the same way.
//
// HELP and TYPE lines are included for the same reason as scrapeErasureLines: a
// registered-but-unpublished collector still emits them, so a sample-only
// assertion would pass on a family that is half present.
func scrapeSeriesLines(text, name string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		candidate := line
		if after, ok := strings.CutPrefix(line, "# HELP "); ok {
			candidate = after
		} else if after, ok := strings.CutPrefix(line, "# TYPE "); ok {
			candidate = after
		} else if strings.HasPrefix(line, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(candidate, name)
		if !ok {
			continue
		}
		// Anchor: what follows the name must start a label set, a value, or a
		// TYPE/HELP word -- never another name character.
		if rest == "" || strings.HasPrefix(rest, "{") || strings.HasPrefix(rest, " ") {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestGenericModeExportsNoWindowSeries pins the BLO-40163 ruling: the three
// window-derived series outside the erasure prefix are ABSENT under
// --mode generic, and unchanged under --mode shred.
//
// All three read off the same never-published erasure.Window as the erasure
// family BLO-28910 removed, so all three carry the same defect in a different
// disguise:
//
//   - _report_schema=0 advertises a schema version that was never published; 0
//     is outside the vocabulary, the shred-mode value being 1.
//   - _gap_events all-zero reads as "no inter-arrival gaps observed" -- the
//     same false-healthy shape as erasure_fraction=0.
//   - _shreds_per_second=0 is the one argued honest in the ticket, and is not.
//     Its zero comes from the unpublished window, not from measuring a generic
//     feed and finding no shreds, so a generic feed carrying 30k packets/s
//     reports a zero shred rate while ingress_packets_total climbs. That is
//     false-UNhealthy: a rate alert fires on a feed that is working. Liveness
//     cannot resolve it, because liveness is exactly what contradicts it.
//
// Each series gets its own subtest so a mutation reverting one guard names that
// series. Both scrapes are taken once and shared: runAndScrape starts a real
// binary, and the assertions are independent reads of one body.
func TestGenericModeExportsNoWindowSeries(t *testing.T) {
	genericText := runAndScrape(t, scoring{
		mode:        "generic",
		sourceLabel: "synthetic",
		rightsBasis: "synthetic-generated-no-third-party-content",
	})
	// Control: the scrape is a real one, not an empty body that would make
	// every absence assertion below vacuous.
	if _, ok := scrapeText(genericText, "bcast_shred_gw_ingress_packets_total", `feed="default"`); !ok {
		t.Fatal("generic mode exported no ingress_packets_total; the scrape proves nothing")
	}
	shredText := runAndScrape(t, scoring{mode: "shred"})

	for _, name := range windowSeriesNames {
		t.Run(name, func(t *testing.T) {
			if lines := scrapeSeriesLines(genericText, name); len(lines) != 0 {
				t.Errorf("generic mode exported %d %s lines, want 0:\n%s",
					len(lines), name, strings.Join(lines, "\n"))
			}
			// The shred half is the control, and it is the load-bearing one: an
			// assertion that a series is missing in generic mode passes just as
			// well if it is missing everywhere. It asserts the PRE-TRAFFIC state
			// -- no packet is ever sent here -- because a shred feed that has
			// received nothing must still report zeros rather than disappear.
			if lines := scrapeSeriesLines(shredText, name); len(lines) == 0 {
				t.Errorf("shred mode did not export %s; a silent feed must report zeros, not disappear", name)
			}
		})
	}
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
		// This asserts the zero VALUE, not that a window was published. Nothing
		// at this level can tell a published window from a merely-registered
		// family, and nothing here needs to: TestDefaultGraceReachesMetrics
		// (erasure_test.go) pins publication directly, in this mode, by
		// asserting the configured 400ms grace scrapes back. Grace reads 0 here
		// only because runAndScrape's scrape wins the race against the first
		// report tick; nothing here asserts it.
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
