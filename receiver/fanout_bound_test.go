package receiver

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TestRevisitThresholdLeavesHeadroomBelowTheCrossover pins the ONE relationship
// between the two constants that makes the guard worth having.
//
// A warning that fires at the crossover announces a decision whose window has
// already closed: re-architecting a delivery path is weeks, so the threshold
// has to sit far enough below to leave room to act. Collapsing the two to one
// number is the plausible "cleanup" — they look redundant — and it would turn
// an early warning into a post-mortem while every other test here still passed.
func TestRevisitThresholdLeavesHeadroomBelowTheCrossover(t *testing.T) {
	if RevisitThresholdDestinations >= MulticastCrossoverDestinations {
		t.Fatalf("RevisitThresholdDestinations (%d) must sit below MulticastCrossoverDestinations (%d), "+
			"or the warning fires only once the crossover it is meant to pre-announce has already passed",
			RevisitThresholdDestinations, MulticastCrossoverDestinations)
	}
	// Not an arbitrary floor: the guard exists so an operator can escalate the
	// revisit BEFORE the economics inverts. A one- or two-destination gap is not
	// an actionable margin at the rate destinations get added by hand.
	if headroom := MulticastCrossoverDestinations - RevisitThresholdDestinations; headroom < 5 {
		t.Fatalf("only %d destinations of headroom between the threshold (%d) and the crossover (%d), "+
			"which is not enough notice to act on", headroom, RevisitThresholdDestinations,
			MulticastCrossoverDestinations)
	}
}

// TestFanoutDestinationsGaugeReportsTheConfiguredCount asserts the gauge equals
// N, which is the whole point: the N-bound revisit trigger was written down in
// the design record and bounded by nothing observable, so it could only be
// enforced by a human remembering it.
func TestFanoutDestinationsGaugeReportsTheConfiguredCount(t *testing.T) {
	for _, count := range []int{0, 1, 3, RevisitThresholdDestinations, RevisitThresholdDestinations + 1} {
		registry := prometheus.NewRegistry()
		if _, err := NewDestinationMetrics(registry, &stubLedger{stats: ledgerOfSize(count)}); err != nil {
			t.Fatal(err)
		}
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		// Asserted with no labels on purpose. An operator alerts on this as one
		// series; any label would split it into a set that has to be summed
		// first, and a forgotten sum() is a silent false negative.
		assertMetric(t, families, "bcast_shred_gw_fanout_destinations", map[string]string{}, float64(count))
	}
}

// TestFanoutDestinationsGaugeFollowsTheLiveTable pins that the gauge is
// computed per scrape rather than captured at registration.
//
// The table is reconcilable — a revoked grant removes a destination — so a
// count cached at construction would freeze at the startup value and read as
// "still 56 destinations" forever after the operator removed one. That is worse
// than no gauge: it would keep an alert latched with nothing left to fix.
func TestFanoutDestinationsGaugeFollowsTheLiveTable(t *testing.T) {
	ledger := &stubLedger{stats: ledgerOfSize(4)}
	registry := prometheus.NewRegistry()
	if _, err := NewDestinationMetrics(registry, ledger); err != nil {
		t.Fatal(err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertMetric(t, families, "bcast_shred_gw_fanout_destinations", map[string]string{}, 4)

	// Stand in for a reconcile that revoked two grants.
	ledger.stats = ledgerOfSize(2)
	families, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertMetric(t, families, "bcast_shred_gw_fanout_destinations", map[string]string{}, 2)
}

// TestMetricsEndpointStillServesWithTheGaugeRegistered is the negative control
// for the new series: adding it must not break the endpoint it shares.
//
// This is not hypothetical caution. The gauge is emitted from the same Collect
// as the four per-destination series, and an unlabelled metric emitted twice in
// one Collect is a duplicate label set, which fails Gather for the WHOLE
// registry — returning 500 for /metrics and taking the pre-existing feed series
// down with it, exactly the blast radius that decided the ledger's label set.
// So this drives the real promhttp handler on a registry carrying both
// collectors, and pins the gauge appearing exactly once in the output.
func TestMetricsEndpointStillServesWithTheGaugeRegistered(t *testing.T) {
	registry := prometheus.NewRegistry()
	if _, err := NewReceiverMetrics(registry, []string{"feed-a"}); err != nil {
		t.Fatal(err)
	}
	// Two destinations sharing one address: the duplicate-address case that
	// makes label choice load-bearing, so the control covers it too.
	ledger := &stubLedger{stats: []DestinationStat{
		{TargetID: "0", Destination: "10.0.0.1:7000", Packets: 4},
		{TargetID: "1", Destination: "10.0.0.1:7000", Packets: 9},
	}}
	if _, err := NewDestinationMetrics(registry, ledger); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	defer server.Close()

	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/metrics returned %d, want 200; a Gather failure here takes every "+
			"other series down with it: %s", response.StatusCode, body)
	}
	// One sample line, not one mention: the HELP and TYPE headers name the
	// series too, so count the line that carries a value.
	var samples int
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "bcast_shred_gw_fanout_destinations ") {
			samples++
		}
	}
	if samples != 1 {
		t.Fatalf("fanout_destinations appears %d times in /metrics, want exactly 1:\n%s", samples, body)
	}
	// The series it summarises must survive alongside it.
	if !strings.Contains(string(body), "bcast_shred_gw_fanout_destination_packets_total") {
		t.Errorf("per-destination ledger series missing from /metrics:\n%s", body)
	}
}

// ledgerOfSize builds a ledger of n destinations with distinct target IDs, so
// the per-destination series stay scrapeable while the gauge is under test.
func ledgerOfSize(n int) []DestinationStat {
	stats := make([]DestinationStat, n)
	for i := range stats {
		stats[i] = DestinationStat{
			TargetID:    strconv.Itoa(i),
			Destination: fmt.Sprintf("10.0.0.%d:7000", i+1),
		}
	}
	return stats
}
