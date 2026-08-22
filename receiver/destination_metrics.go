package receiver

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/prometheus/client_golang/prometheus"
)

// DestinationLedger is the scrape-time source of the per-destination delivery
// ledger. *Fanout implements it.
//
// This is an interface rather than a *Fanout so the collector can be tested
// against a fixed ledger, and so registration does not have to happen at the
// same point in startup as fan-out construction.
type DestinationLedger interface {
	DestinationStats() []DestinationStat
}

var _ DestinationLedger = (*Fanout)(nil)

// DestinationMetrics exports the per-destination delivery ledger to Prometheus.
//
// Until this existed the ledger was reachable only from Go code calling
// DestinationStats, so the per-subscriber accounting that makes delivery
// auditable was invisible to an operator: the registered fan-out series
// (egress_packets_total, fanout_write_errors_total) are feed-labelled
// aggregates, and their own help text tells the reader to divide by the
// destination count — which is precisely the process-wide average a
// per-destination shortfall can hide inside.
//
// Series are labelled by destination address and by stable target ID. The
// target ID is not redundant with the address: destinations are not guaranteed
// unique, because targets are resolved independently and two distinct entries
// can resolve to the same address (a hostname and its literal IP, most
// obviously). Two metrics with identical label sets make Gather fail, which
// would return 500 for the whole /metrics endpoint and take the pre-existing
// feed series down with it. Target ID is unique within a table by
// construction, because resolveTargets rejects a duplicate.
//
// The label carries the TARGET ID and not the slice position, even though
// under a static --dest-ip-ports list the two have the same value (the target
// ID assigned to the Nth entry is "N"). They diverge the moment the table is
// reconciled: revoking one grant renumbers every later destination, so a
// positional label would move a subscriber's whole history onto its
// neighbour's series and read as a counter reset on both. The target ID
// survives the reconcile, so the series does too.
type DestinationMetrics struct {
	ledger DestinationLedger

	packetsDesc     *prometheus.Desc
	bytesDesc       *prometheus.Desc
	dropsDesc       *prometheus.Desc
	writeErrorsDesc *prometheus.Desc
}

// NewDestinationMetrics registers the per-destination ledger collector.
//
// Label cardinality is bounded by the destination list, which is fixed when
// the fan-out is constructed and never grows at packet time. That is the same
// guarantee NewReceiverMetrics gets from rejecting unconfigured feeds.
func NewDestinationMetrics(registerer prometheus.Registerer, ledger DestinationLedger) (*DestinationMetrics, error) {
	if registerer == nil {
		return nil, errors.New("destination metrics registerer is nil")
	}
	if ledgerIsNil(ledger) {
		return nil, errors.New("destination metrics ledger is nil")
	}

	labels := []string{"dest", "target"}
	metrics := &DestinationMetrics{
		ledger: ledger,
		packetsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(receiverMetricsNamespace, "", "fanout_destination_packets_total"),
			"Datagrams written successfully to this one destination. Unlike egress_packets_total this is not summed over destinations, so a single subscriber falling behind is visible instead of averaged away.",
			labels, nil,
		),
		bytesDesc: prometheus.NewDesc(
			prometheus.BuildFQName(receiverMetricsNamespace, "", "fanout_destination_bytes_total"),
			"Payload bytes written successfully to this one destination.",
			labels, nil,
		),
		dropsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(receiverMetricsNamespace, "", "fanout_destination_drops_total"),
			"Packets this destination did not receive, for any reason. Packets+Drops is exact per destination at any instant, but across destinations only once the worker is quiesced: do not alert on a transient cross-destination mismatch, because a scrape can catch a batch mid-flight with some destinations charged and others not.",
			labels, nil,
		),
		writeErrorsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(receiverMetricsNamespace, "", "fanout_destination_write_errors_total"),
			"Writes for this destination that actively failed. A subset of drops: a partial sendmmsg abandons the rest of the batch, so those destinations are dropped without being attempted and are deliberately not blamed here. This is the column that localises a fault to one subscriber.",
			labels, nil,
		),
	}
	if err := registerer.Register(metrics); err != nil {
		return nil, fmt.Errorf("register destination metrics: %w", err)
	}
	return metrics, nil
}

// ledgerIsNil reports whether ledger is unusable: either an untyped nil, or a
// non-nil interface value holding a nil pointer.
//
// The second case is the one a plain ledger == nil misses. A (*Fanout)(nil)
// satisfies DestinationLedger, so the interface itself is non-nil and
// construction would succeed; the nil receiver is then not dereferenced until
// DestinationStats runs inside Collect. That is not a recoverable 500. Gather
// runs each collector on a goroutine it spawns itself, so the panic surfaces
// there rather than in the handler, where neither promhttp's recover nor the
// scraping caller can catch it — the first scrape takes the whole process
// down. Rejecting at construction keeps that failure at wiring time, where the
// stack still names the caller that passed the nil.
func ledgerIsNil(ledger DestinationLedger) bool {
	if ledger == nil {
		return true
	}
	// IsNil panics on kinds that cannot be nil, so it must be guarded.
	switch value := reflect.ValueOf(ledger); value.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

// Describe implements prometheus.Collector.
func (m *DestinationMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.packetsDesc
	ch <- m.bytesDesc
	ch <- m.dropsDesc
	ch <- m.writeErrorsDesc
}

// Collect implements prometheus.Collector. All four series for a destination
// come from one DestinationStats snapshot, so a scrape cannot mix reads taken
// either side of a counter update for the same destination.
func (m *DestinationMetrics) Collect(ch chan<- prometheus.Metric) {
	for _, stat := range m.ledger.DestinationStats() {
		ch <- prometheus.MustNewConstMetric(m.packetsDesc, prometheus.CounterValue, float64(stat.Packets), stat.Destination, stat.TargetID)
		ch <- prometheus.MustNewConstMetric(m.bytesDesc, prometheus.CounterValue, float64(stat.Bytes), stat.Destination, stat.TargetID)
		ch <- prometheus.MustNewConstMetric(m.dropsDesc, prometheus.CounterValue, float64(stat.Drops), stat.Destination, stat.TargetID)
		ch <- prometheus.MustNewConstMetric(m.writeErrorsDesc, prometheus.CounterValue, float64(stat.WriteErrors), stat.Destination, stat.TargetID)
	}
}
