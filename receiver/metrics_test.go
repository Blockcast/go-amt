package receiver

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestReceiverMetricsExposePacketCountersAndExactWindow(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewReceiverMetrics(registry, []string{"feed-a", "feed-b"}, ReportsWindows)
	if err != nil {
		t.Fatal(err)
	}

	if err := metrics.ObserveIngress("feed-a", 1200, time.Unix(1750000000, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if err := metrics.AddEgress("feed-a", 2); err != nil {
		t.Fatal(err)
	}
	if err := metrics.IncFanoutDrop("feed-a"); err != nil {
		t.Fatal(err)
	}
	if err := metrics.AddWriteErrors("feed-a", 3); err != nil {
		t.Fatal(err)
	}
	if err := metrics.IncUnparsed("feed-a"); err != nil {
		t.Fatal(err)
	}
	window := erasure.Window{
		SetsTotal:       5,
		SetsErased:      2,
		ErasureFraction: 0.4,
		RMean:           12.5,
		RPeak100MS:      70,
		GapMSHist: erasure.GapHistogram{
			LT1: 1, From1To2_4: 2, From2_4To7: 3, From7To32: 4, GTE32: 5,
		},
		GraceMS: 400,
		Schema:  1,
	}
	if err := metrics.PublishWindow("feed-a", window); err != nil {
		t.Fatal(err)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertMetric(t, families, "bcast_shred_gw_ingress_packets_total", labels("feed", "feed-a"), 1)
	assertMetric(t, families, "bcast_shred_gw_egress_packets_total", labels("feed", "feed-a"), 2)
	assertMetric(t, families, "bcast_shred_gw_fanout_dropped_packets_total", labels("feed", "feed-a"), 1)
	assertMetric(t, families, "bcast_shred_gw_fanout_write_errors_total", labels("feed", "feed-a"), 3)
	assertMetric(t, families, "bcast_shred_gw_shreds_unparsed_total", labels("feed", "feed-a"), 1)
	assertMetric(t, families, "bcast_shred_gw_erasure_sets", labels("feed", "feed-a", "result", "total"), 5)
	assertMetric(t, families, "bcast_shred_gw_erasure_sets", labels("feed", "feed-a", "result", "erased"), 2)
	assertMetric(t, families, "bcast_shred_gw_erasure_fraction", labels("feed", "feed-a"), 0.4)
	assertMetric(t, families, "bcast_shred_gw_shreds_per_second", labels("feed", "feed-a", "measure", "mean"), 12.5)
	assertMetric(t, families, "bcast_shred_gw_shreds_per_second", labels("feed", "feed-a", "measure", "peak_100ms"), 70)
	assertMetric(t, families, "bcast_shred_gw_gap_events", labels("feed", "feed-a", "bucket", "<1"), 1)
	assertMetric(t, families, "bcast_shred_gw_gap_events", labels("feed", "feed-a", "bucket", "1-2.4"), 2)
	assertMetric(t, families, "bcast_shred_gw_gap_events", labels("feed", "feed-a", "bucket", "2.4-7"), 3)
	assertMetric(t, families, "bcast_shred_gw_gap_events", labels("feed", "feed-a", "bucket", "7-32"), 4)
	assertMetric(t, families, "bcast_shred_gw_gap_events", labels("feed", "feed-a", "bucket", ">=32"), 5)
	assertMetric(t, families, "bcast_shred_gw_erasure_grace_milliseconds", labels("feed", "feed-a"), 400)
	assertMetric(t, families, "bcast_shred_gw_report_schema", labels("feed", "feed-a"), 1)

	assertMetric(t, families, "bcast_shred_gw_ingress_packets_total", labels("feed", "feed-b"), 0)
	assertMetric(t, families, "bcast_shred_gw_fanout_write_errors_total", labels("feed", "feed-b"), 0)
	assertMetric(t, families, "bcast_shred_gw_gap_events", labels("feed", "feed-b", "bucket", ">=32"), 0)
}

func TestReceiverMetricsRejectUnknownFeedWithoutCreatingSeries(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewReceiverMetrics(registry, []string{"configured"}, ReportsWindows)
	if err != nil {
		t.Fatal(err)
	}

	if err := metrics.ObserveIngress("attacker-controlled", 1, time.Unix(1750000000, 0).UTC()); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("ObserveIngress() error = %v, want %v", err, ErrUnknownFeed)
	}
	if err := metrics.AddEgress("attacker-controlled", 1); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("AddEgress() error = %v, want %v", err, ErrUnknownFeed)
	}
	if err := metrics.IncFanoutDrop("attacker-controlled"); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("IncFanoutDrop() error = %v, want %v", err, ErrUnknownFeed)
	}
	if err := metrics.AddWriteErrors("attacker-controlled", 1); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("AddWriteErrors() error = %v, want %v", err, ErrUnknownFeed)
	}
	if err := metrics.IncUnparsed("attacker-controlled"); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("IncUnparsed() error = %v, want %v", err, ErrUnknownFeed)
	}
	if err := metrics.PublishWindow("attacker-controlled", erasure.Window{}); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("PublishWindow() error = %v, want %v", err, ErrUnknownFeed)
	}

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			if metricLabels(metric)["feed"] != "configured" {
				t.Fatalf("metric %s materialized unknown feed: %v", family.GetName(), metricLabels(metric))
			}
		}
	}
}

func TestReceiverMetricsGatherNeverMixesPublishedWindows(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewReceiverMetrics(registry, []string{"feed"}, ReportsWindows)
	if err != nil {
		t.Fatal(err)
	}
	first := erasure.Window{SetsTotal: 11, SetsErased: 1, ErasureFraction: 1.0 / 11.0, RMean: 111, Schema: 1}
	second := erasure.Window{SetsTotal: 22, SetsErased: 2, ErasureFraction: 2.0 / 22.0, RMean: 222, Schema: 2}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if err := metrics.PublishWindow("feed", first); err != nil {
				t.Errorf("PublishWindow(first): %v", err)
				return
			}
			if err := metrics.PublishWindow("feed", second); err != nil {
				t.Errorf("PublishWindow(second): %v", err)
				return
			}
		}
	}()

	for i := 0; i < 1000; i++ {
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		total := metricValue(t, families, "bcast_shred_gw_erasure_sets", labels("feed", "feed", "result", "total"))
		rate := metricValue(t, families, "bcast_shred_gw_shreds_per_second", labels("feed", "feed", "measure", "mean"))
		schema := metricValue(t, families, "bcast_shred_gw_report_schema", labels("feed", "feed"))
		if total == 0 && rate == 0 && schema == 0 {
			continue
		}
		if !((total == 11 && rate == 111 && schema == 1) || (total == 22 && rate == 222 && schema == 2)) {
			t.Fatalf("gather mixed windows: total=%v rate=%v schema=%v", total, rate, schema)
		}
	}
	wg.Wait()
}

func TestNewReceiverMetricsRegistrationFailureLeavesNoPartialSeries(t *testing.T) {
	registry := prometheus.NewRegistry()
	conflict := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "report_schema",
		Help:      "Conflicting descriptor.",
	})
	registry.MustRegister(conflict)

	if _, err := NewReceiverMetrics(registry, []string{"feed"}, ReportsWindows); err == nil {
		t.Fatal("NewReceiverMetrics() succeeded with a conflicting descriptor")
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "bcast_shred_gw_ingress_packets_total" {
			t.Fatal("failed registration left ingress collector in registry")
		}
	}
}

func TestNewReceiverMetricsValidatesConfiguredFeeds(t *testing.T) {
	tests := []struct {
		name    string
		feeds   []string
		wantErr string
	}{
		{name: "empty list", wantErr: "at least one feed"},
		{name: "empty ID", feeds: []string{""}, wantErr: "feed ID is empty"},
		{name: "duplicate", feeds: []string{"same", "same"}, wantErr: "configured more than once"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewReceiverMetrics(prometheus.NewRegistry(), test.feeds, ReportsWindows)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("NewReceiverMetrics() error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func assertMetric(t *testing.T, families []*dto.MetricFamily, name string, wantLabels map[string]string, want float64) {
	t.Helper()
	got := metricValue(t, families, name, wantLabels)
	if got != want {
		t.Fatalf("metric %s%v = %v, want %v", name, wantLabels, got, want)
	}
}

func metricValue(t *testing.T, families []*dto.MetricFamily, name string, wantLabels map[string]string) float64 {
	t.Helper()
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if equalLabels(metricLabels(metric), wantLabels) {
				var got float64
				switch family.GetType() {
				case dto.MetricType_COUNTER:
					got = metric.GetCounter().GetValue()
				case dto.MetricType_GAUGE:
					got = metric.GetGauge().GetValue()
				default:
					t.Fatalf("metric %s has unsupported type %s", name, family.GetType())
				}
				return got
			}
		}
	}
	t.Fatalf("metric %s%v not found", name, wantLabels)
	return 0
}

func metricLabels(metric *dto.Metric) map[string]string {
	got := make(map[string]string, len(metric.Label))
	for _, pair := range metric.Label {
		got[pair.GetName()] = pair.GetValue()
	}
	return got
}

func labels(values ...string) map[string]string {
	result := make(map[string]string, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		result[values[i]] = values[i+1]
	}
	return result
}

func equalLabels(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

// TestReceiverMetricsExposeSlotGuardCounters proves the slot guard is visible.
//
// The guard's failure mode is silence: an operator whose feed is being refused
// sees a perfect erasure score and no reason for it. Tracker.Stats() carried
// these counters but had no caller anywhere in the receiver, so the guard could
// reject every datagram on the wire and publish nothing at all.
func TestReceiverMetricsExposeSlotGuardCounters(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewReceiverMetrics(registry, []string{"feed-a", "feed-b"}, ReportsWindows)
	if err != nil {
		t.Fatal(err)
	}

	// Zero-valued series must exist before anything is published, so an alert
	// on the guard has a baseline rather than a missing series.
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertMetric(t, families, "bcast_shred_gw_erasure_slot_rejections_total", labels("feed", "feed-a", "direction", "ahead"), 0)
	assertMetric(t, families, "bcast_shred_gw_erasure_slot_rejections_total", labels("feed", "feed-a", "direction", "behind"), 0)
	assertMetric(t, families, "bcast_shred_gw_erasure_frontier_resyncs_total", labels("feed", "feed-a"), 0)

	if err := metrics.PublishGuard("feed-a", erasure.Stats{
		RejectedSlotJumps: 17,
		StaleRejections:   9,
		FrontierResyncs:   2,
	}); err != nil {
		t.Fatal(err)
	}

	families, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertMetric(t, families, "bcast_shred_gw_erasure_slot_rejections_total", labels("feed", "feed-a", "direction", "ahead"), 17)
	assertMetric(t, families, "bcast_shred_gw_erasure_slot_rejections_total", labels("feed", "feed-a", "direction", "behind"), 9)
	assertMetric(t, families, "bcast_shred_gw_erasure_frontier_resyncs_total", labels("feed", "feed-a"), 2)

	// Publishing one feed must not disturb another.
	assertMetric(t, families, "bcast_shred_gw_erasure_slot_rejections_total", labels("feed", "feed-b", "direction", "ahead"), 0)
	assertMetric(t, families, "bcast_shred_gw_erasure_frontier_resyncs_total", labels("feed", "feed-b"), 0)

	// Guard totals are cumulative and must survive a window drain, which is the
	// whole reason they are not carried on Window.
	if err := metrics.PublishWindow("feed-a", erasure.Window{Schema: 1}); err != nil {
		t.Fatal(err)
	}
	families, err = registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	assertMetric(t, families, "bcast_shred_gw_erasure_frontier_resyncs_total", labels("feed", "feed-a"), 2)
}

func TestReceiverMetricsRejectGuardPublishForUnknownFeed(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewReceiverMetrics(registry, []string{"feed"}, ReportsWindows)
	if err != nil {
		t.Fatal(err)
	}
	if err := metrics.PublishGuard("attacker-controlled", erasure.Stats{}); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("PublishGuard() error = %v, want %v", err, ErrUnknownFeed)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if strings.Contains(label.GetValue(), "attacker-controlled") {
					t.Fatalf("unknown feed created series in %s", family.GetName())
				}
			}
		}
	}
}

// TestNoWindowReportingOmitsTheFamilyFromDescribe covers the half of the
// NoWindowReporting contract that a /metrics scrape cannot see.
//
// The text exposition writes HELP and TYPE only for families that produced a
// sample, so suppressing Collect alone makes a family vanish from a scrape
// whether or not Describe still advertises it. Describe is therefore asserted
// directly: a collector that describes a descriptor it never emits still
// reserves that fully-qualified name against the registry, so a second
// collector legitimately exporting one of these names would be refused as a
// duplicate by a receiver that drains no window at all.
//
// All eight window-derived descriptors are asserted, not just the erasure five:
// the name-reservation argument is identical for _shreds_per_second,
// _gap_events and _report_schema, which BLO-40163 added to this gate.
//
// Both arms assert the COMPLETE described set rather than scanning for the
// forbidden names, because enumerating only what must be absent fails in the
// wrong direction: a window-derived descriptor added above the Describe gate
// (metrics.go) is simply not in any list, so a forbidden-set scan passes and
// reintroduces this PR's defect silently. Equality makes that case fail loudly,
// and makes a new packet-path counter fail too -- which is the right prompt,
// since it forces the author to classify the new descriptor as one or the other.
// descFQName extracts the name Desc.String() publishes. Desc has no accessor for
// it, and exact names rather than substrings are what let an assertion state a
// complement -- a substring match cannot.
var descFQName = regexp.MustCompile(`fqName:\s*"([^"]+)"`)

func fqNameOf(t *testing.T, descString string) string {
	t.Helper()
	match := descFQName.FindStringSubmatch(descString)
	if match == nil {
		t.Fatalf("no fqName in Desc.String() = %q; the matcher has rotted", descString)
	}
	return match[1]
}

func TestNoWindowReportingOmitsTheFamilyFromDescribe(t *testing.T) {
	// Described unconditionally: driven by the packet path, honest in every mode.
	packetPathDescNames := []string{
		"bcast_shred_gw_ingress_packets_total",
		"bcast_shred_gw_egress_packets_total",
		"bcast_shred_gw_fanout_dropped_packets_total",
		"bcast_shred_gw_fanout_write_errors_total",
		"bcast_shred_gw_shreds_unparsed_total",
	}
	// Described only under ReportsWindows: every value is read off a drained Window.
	windowDescNames := []string{
		"bcast_shred_gw_erasure_sets",
		"bcast_shred_gw_erasure_fraction",
		"bcast_shred_gw_erasure_grace_milliseconds",
		"bcast_shred_gw_erasure_slot_rejections_total",
		"bcast_shred_gw_erasure_frontier_resyncs_total",
		"bcast_shred_gw_shreds_per_second",
		"bcast_shred_gw_gap_events",
		"bcast_shred_gw_report_schema",
	}
	describedNames := func(reporting WindowReporting) []string {
		t.Helper()
		metrics, err := NewReceiverMetrics(prometheus.NewRegistry(), []string{"feed"}, reporting)
		if err != nil {
			t.Fatalf("NewReceiverMetrics() error = %v", err)
		}
		descs := make(chan *prometheus.Desc, 64)
		go func() {
			metrics.Describe(descs)
			close(descs)
		}()
		var names []string
		for desc := range descs {
			names = append(names, fqNameOf(t, desc.String()))
		}
		slices.Sort(names)
		return names
	}

	wantQuiet := slices.Sorted(slices.Values(packetPathDescNames))
	if got := describedNames(NoWindowReporting); !slices.Equal(got, wantQuiet) {
		t.Errorf("NoWindowReporting described:\n%s\nwant exactly the packet path:\n%s",
			strings.Join(got, "\n"), strings.Join(wantQuiet, "\n"))
	}
	// Control: the matcher really does find the window descriptors when reporting
	// is on, so the assertion above is not vacuously passing on a broken parse.
	wantAll := slices.Sorted(slices.Values(append(slices.Clone(packetPathDescNames), windowDescNames...)))
	if got := describedNames(ReportsWindows); !slices.Equal(got, wantAll) {
		t.Errorf("ReportsWindows described:\n%s\nwant packet path + all %d window descriptors:\n%s",
			strings.Join(got, "\n"), len(windowDescNames), strings.Join(wantAll, "\n"))
	}
}

// TestDescribeAndCollectAgreePerMode pins the two gates to each other, which
// nothing else does. The registry will not: Registry.Gather only rejects a
// metric whose descriptor was never described when pedantic checks are on --
// registry.go:442-445 populates registeredDescIDs only if
// pedanticChecksEnabled, and the "collected metric ... with unregistered
// descriptor" error at registry.go:711 is gated on that map being non-nil.
// cmd/blockcast-shreds builds a plain prometheus.NewRegistry() (main.go:700),
// which is not pedantic, so a series collected ABOVE the Collect gate while
// correctly described BELOW the Describe gate is exported with no error at all:
// a window-derived permanent zero in generic mode, which is the exact defect
// BLO-40163 removed.
//
// The sibling test above cannot catch that, because in that shape the
// descriptor is placed correctly and only Collect is wrong. Set equality
// catches it from either side, and does so without re-listing the taxonomy in
// a further place -- the two gates are asserted against each other, not against
// a hand-maintained list.
func TestDescribeAndCollectAgreePerMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reporting WindowReporting
	}{
		{"NoWindowReporting", NoWindowReporting},
		{"ReportsWindows", ReportsWindows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metrics, err := NewReceiverMetrics(prometheus.NewRegistry(), []string{"feed"}, tc.reporting)
			if err != nil {
				t.Fatalf("NewReceiverMetrics() error = %v", err)
			}

			descs := make(chan *prometheus.Desc, 64)
			go func() {
				metrics.Describe(descs)
				close(descs)
			}()
			var described []string
			for desc := range descs {
				described = append(described, fqNameOf(t, desc.String()))
			}

			metricCh := make(chan prometheus.Metric, 64)
			go func() {
				metrics.Collect(metricCh)
				close(metricCh)
			}()
			var collected []string
			for metric := range metricCh {
				collected = append(collected, fqNameOf(t, metric.Desc().String()))
			}

			// Collect emits several series per descriptor -- two rate measures,
			// five gap buckets, two set kinds -- so compare distinct names.
			slices.Sort(described)
			slices.Sort(collected)
			described, collected = slices.Compact(described), slices.Compact(collected)
			if !slices.Equal(collected, described) {
				t.Errorf("the two gates disagree.\ncollected:\n%s\ndescribed:\n%s",
					strings.Join(collected, "\n"), strings.Join(described, "\n"))
			}
			// Vacuity control: equality also holds when both sets are empty, which
			// a broken extraction would produce. The packet path is described and
			// collected unconditionally, so neither set can legitimately be empty.
			if len(collected) == 0 {
				t.Error("no series at all; the extraction is broken, not the gates")
			}
		})
	}
}

// TestPublishGuardRefusedWithoutWindowReporting pins the refusal rather than a
// silent accept: with NoWindowReporting there is no surface to read guard stats
// back from, so storing them would discard a caller's counters unobserved.
func TestPublishGuardRefusedWithoutWindowReporting(t *testing.T) {
	metrics, err := NewReceiverMetrics(prometheus.NewRegistry(), []string{"feed"}, NoWindowReporting)
	if err != nil {
		t.Fatalf("NewReceiverMetrics() error = %v", err)
	}
	if err := metrics.PublishGuard("feed", erasure.Stats{FrontierResyncs: 1}); err == nil {
		t.Fatal("PublishGuard() succeeded with window reporting disabled; the stats would vanish")
	}
	// An unknown feed must still report the unknown feed, not the mode.
	if err := metrics.PublishGuard("nope", erasure.Stats{}); !errors.Is(err, ErrUnknownFeed) {
		t.Fatalf("PublishGuard(unknown) error = %v, want ErrUnknownFeed", err)
	}
}

// TestPublishWindowAcceptedWithoutWindowReporting pins the deliberate asymmetry
// with PublishGuard above: Snapshot returns m.windows without consulting
// reportsWindows, so a Window stored under NoWindowReporting still reaches every
// Snapshot consumer and PublishWindow must accept rather than refuse.
//
// Named for the acceptance rather than folded into the refusal test so that a
// future "make these two consistent" edit finds this by name and has to argue
// with it. The argument to beat is the package boundary -- receiver has no
// concept of the caller's modes -- not any current consumer: do not retire this
// on the grounds that broker/gwclient happens to be shred-only today.
func TestPublishWindowAcceptedWithoutWindowReporting(t *testing.T) {
	metrics, err := NewReceiverMetrics(prometheus.NewRegistry(), []string{"feed"}, NoWindowReporting)
	if err != nil {
		t.Fatalf("NewReceiverMetrics() error = %v", err)
	}
	if err := metrics.PublishWindow("feed", erasure.Window{Schema: 1}); err != nil {
		t.Fatalf("PublishWindow() error = %v; Snapshot still reads this window", err)
	}
	if got := metrics.Snapshot()[0].Window.Schema; got != 1 {
		t.Fatalf("Snapshot() window schema = %d, want 1; the Snapshot path lost the window", got)
	}
}
