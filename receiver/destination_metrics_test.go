package receiver

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// stubLedger is a fixed ledger snapshot, so a scrape can be asserted without
// driving a live worker.
type stubLedger struct {
	stats []DestinationStat
}

func (l *stubLedger) DestinationStats() []DestinationStat { return l.stats }

// TestDestinationMetricsExportEveryLedgerColumn pins that all four ledger
// columns reach Prometheus. Before this collector existed DestinationStats had
// no caller outside tests, so the per-subscriber accounting was built, correct,
// and unobservable in production.
func TestDestinationMetricsExportEveryLedgerColumn(t *testing.T) {
	ledger := &stubLedger{stats: []DestinationStat{
		{TargetID: "0", Destination: "10.0.0.1:7000", Packets: 12, Bytes: 480, Drops: 3, WriteErrors: 1},
		{TargetID: "1", Destination: "10.0.0.2:7000", Packets: 15, Bytes: 600, Drops: 0, WriteErrors: 0},
	}}
	registry := prometheus.NewRegistry()
	if _, err := NewDestinationMetrics(registry, ledger); err != nil {
		t.Fatal(err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	first := map[string]string{"dest": "10.0.0.1:7000", "target": "0"}
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_packets_total", first, 12)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_bytes_total", first, 480)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_drops_total", first, 3)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_write_errors_total", first, 1)

	second := map[string]string{"dest": "10.0.0.2:7000", "target": "1"}
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_packets_total", second, 15)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_bytes_total", second, 600)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_drops_total", second, 0)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_write_errors_total", second, 0)
}

// TestDestinationMetricsKeepDuplicateDestinationsScrapeable guards the hazard
// that decided the label set. NewUDPFanout resolves each destination
// independently and does not dedupe, so two entries can share an address — a
// hostname and its literal IP resolve to the same string. Labelling by address
// alone would emit two metrics with identical label sets, which makes Gather
// fail; because the collector shares a registry with the feed metrics, that
// would return 500 for the whole /metrics endpoint rather than degrade this
// one series. The target label makes the pair distinguishable by construction.
func TestDestinationMetricsKeepDuplicateDestinationsScrapeable(t *testing.T) {
	ledger := &stubLedger{stats: []DestinationStat{
		{TargetID: "0", Destination: "10.0.0.1:7000", Packets: 4},
		{TargetID: "1", Destination: "10.0.0.1:7000", Packets: 9},
	}}
	registry := prometheus.NewRegistry()
	if _, err := NewDestinationMetrics(registry, ledger); err != nil {
		t.Fatal(err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("duplicate destinations broke the scrape: %v", err)
	}

	assertMetric(t, families, "bcast_shred_gw_fanout_destination_packets_total",
		map[string]string{"dest": "10.0.0.1:7000", "target": "0"}, 4)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_packets_total",
		map[string]string{"dest": "10.0.0.1:7000", "target": "1"}, 9)

	// Both series must survive as separate samples, not collapse into one.
	if got := countSamples(t, families, "bcast_shred_gw_fanout_destination_packets_total"); got != 2 {
		t.Errorf("packets series has %d samples, want 2", got)
	}
}

// TestDestinationMetricsTrackARealFanoutLedger closes the loop the stub cannot:
// that *Fanout satisfies DestinationLedger and the exported numbers are the
// worker's own, including a fault localised to the destination that caused it.
func TestDestinationMetricsTrackARealFanoutLedger(t *testing.T) {
	const packets = 5
	good := &recordingWriter{}
	bad := &errorWriter{err: errors.New("destination unavailable")}
	fanout, err := NewFanout([]io.WriteCloser{good, bad}, packets, nil)
	if err != nil {
		t.Fatal(err)
	}

	packet := []byte("shred-payload")
	for i := 0; i < packets; i++ {
		if fanout.Enqueue("feed", packet) != EnqueueAccepted {
			t.Fatalf("packet %d dropped with a sized ring", i)
		}
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	registry := prometheus.NewRegistry()
	if _, err := NewDestinationMetrics(registry, fanout); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	healthy := map[string]string{"dest": "writer[0]", "target": "0"}
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_packets_total", healthy, packets)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_bytes_total", healthy, float64(packets*len(packet)))
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_drops_total", healthy, 0)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_write_errors_total", healthy, 0)

	broken := map[string]string{"dest": "writer[1]", "target": "1"}
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_packets_total", broken, 0)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_drops_total", broken, packets)
	assertMetric(t, families, "bcast_shred_gw_fanout_destination_write_errors_total", broken, packets)
}

func TestNewDestinationMetricsRejectsMissingDependencies(t *testing.T) {
	if _, err := NewDestinationMetrics(nil, &stubLedger{}); err == nil {
		t.Error("nil registerer accepted")
	}
	if _, err := NewDestinationMetrics(prometheus.NewRegistry(), nil); err == nil {
		t.Error("nil ledger accepted")
	}
}

// TestNewDestinationMetricsRejectsATypedNilLedger covers the nil that an
// interface hides. A (*Fanout)(nil) satisfies DestinationLedger, so the
// interface is non-nil and a plain ledger == nil check lets it through; the
// nil receiver is not dereferenced until DestinationStats runs inside Collect.
//
// That is why this is rejected at construction rather than tolerated at scrape
// time: Gather runs collectors on goroutines it spawns, so the panic does not
// surface in the handler and promhttp's recover cannot catch it. A typed nil
// reaching the registry crashes the process on first scrape instead of
// degrading one endpoint — the same blast radius the duplicate-label case is
// guarded against, arrived at from the other direction.
func TestNewDestinationMetricsRejectsATypedNilLedger(t *testing.T) {
	var fanout *Fanout // non-nil interface, nil pointer inside

	registry := prometheus.NewRegistry()
	if _, err := NewDestinationMetrics(registry, fanout); err == nil {
		t.Fatal("typed-nil ledger accepted; it would panic in Collect on a Gather goroutine")
	}

	// Nothing was registered, so the endpoint stays scrapeable. Without the
	// guard this Gather is what panics.
	if _, err := registry.Gather(); err != nil {
		t.Fatalf("gather after rejected registration: %v", err)
	}

	// Negative control: the guard must reject only nil pointers, not every
	// pointer, so a live *Fanout still registers.
	live, err := NewFanout([]io.WriteCloser{&recordingWriter{}}, 4, nil)
	if err != nil {
		t.Fatalf("new fanout: %v", err)
	}
	defer live.Close()
	if _, err := NewDestinationMetrics(prometheus.NewRegistry(), live); err != nil {
		t.Fatalf("live *Fanout ledger rejected: %v", err)
	}
}

// TestDestinationMetricsHelpWarnsAgainstAlertingOnTheCrossDestinationInvariant
// keeps the caveat attached to the series an operator actually reads. The
// Packets+Drops equality tears across destinations on a live snapshot, and a
// scrape is exactly that, so a monitor written against the invariant would
// false-positive on a healthy process.
func TestDestinationMetricsHelpWarnsAgainstAlertingOnTheCrossDestinationInvariant(t *testing.T) {
	registry := prometheus.NewRegistry()
	if _, err := NewDestinationMetrics(registry, &stubLedger{stats: []DestinationStat{{Destination: "d"}}}); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "bcast_shred_gw_fanout_destination_drops_total" {
			continue
		}
		if help := family.GetHelp(); !strings.Contains(help, "do not alert") {
			t.Errorf("drops help does not warn against alerting on the cross-destination invariant: %q", help)
		}
		return
	}
	t.Fatal("drops series not registered")
}

func countSamples(t *testing.T, families []*dto.MetricFamily, name string) int {
	t.Helper()
	for _, family := range families {
		if family.GetName() == name {
			return len(family.Metric)
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}
