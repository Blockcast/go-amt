package receiver

import (
	"errors"
	"fmt"
	"sync"

	"github.com/blockcast/go-amt/erasure"
	"github.com/prometheus/client_golang/prometheus"
)

const receiverMetricsNamespace = "bcast_shred_gw"

var ErrUnknownFeed = errors.New("receiver metrics feed is not configured")

var gapBuckets = []string{"<1", "1-2.4", "2.4-7", "7-32", ">=32"}

// ReceiverMetrics is the fan-out worker's egress observer.
var _ EgressObserver = (*ReceiverMetrics)(nil)

// ReceiverMetrics exposes packet-path counters and the latest delivery report
// for a fixed set of configured feeds. Unknown feeds are rejected so packet
// data cannot create unbounded Prometheus label cardinality.
type ReceiverMetrics struct {
	mu      sync.RWMutex
	feedIDs []string
	feeds   map[string]feedMetrics
	windows map[string]erasure.Window

	ingress     *prometheus.CounterVec
	egress      *prometheus.CounterVec
	dropped     *prometheus.CounterVec
	writeErrors *prometheus.CounterVec
	unparsed    *prometheus.CounterVec

	setsDesc     *prometheus.Desc
	fractionDesc *prometheus.Desc
	rateDesc     *prometheus.Desc
	gapsDesc     *prometheus.Desc
	graceDesc    *prometheus.Desc
	schemaDesc   *prometheus.Desc
}

type feedMetrics struct {
	ingress     prometheus.Counter
	egress      prometheus.Counter
	dropped     prometheus.Counter
	writeErrors prometheus.Counter
	unparsed    prometheus.Counter
}

// NewReceiverMetrics registers receiver metrics and materializes zero-valued
// series for every configured feed.
func NewReceiverMetrics(registerer prometheus.Registerer, feedIDs []string) (*ReceiverMetrics, error) {
	if registerer == nil {
		return nil, errors.New("receiver metrics registerer is nil")
	}
	if len(feedIDs) == 0 {
		return nil, errors.New("receiver metrics require at least one feed")
	}
	configured := make(map[string]struct{}, len(feedIDs))
	for _, feedID := range feedIDs {
		if feedID == "" {
			return nil, errors.New("receiver metrics feed ID is empty")
		}
		if _, exists := configured[feedID]; exists {
			return nil, fmt.Errorf("receiver metrics feed %q is configured more than once", feedID)
		}
		configured[feedID] = struct{}{}
	}

	metrics := &ReceiverMetrics{
		feedIDs: append([]string(nil), feedIDs...),
		feeds:   make(map[string]feedMetrics, len(feedIDs)),
		windows: make(map[string]erasure.Window, len(feedIDs)),
	}
	metrics.ingress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "ingress_packets_total",
		Help:      "Packets received from the broker-selected unicast feed endpoint.",
	}, []string{"feed"})
	metrics.egress = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "egress_packets_total",
		Help:      "Datagrams written successfully to validator destinations. Counted per destination write, so one received packet increments this once for every configured --dest-ip-ports target; divide by the destination count to recover packets forwarded.",
	}, []string{"feed"})
	metrics.dropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "fanout_dropped_packets_total",
		Help:      "Packets rejected because the bounded fan-out ring was full.",
	}, []string{"feed"})
	metrics.writeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "fanout_write_errors_total",
		Help:      "Datagram writes to validator destinations that failed or were short. Counted per destination write; each one is a packet that did not reach that destination.",
	}, []string{"feed"})
	metrics.unparsed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "shreds_unparsed_total",
		Help:      "Delivered packets whose Solana shred header could not be parsed.",
	}, []string{"feed"})
	metrics.setsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "erasure_sets"),
		"Receiver-observed FEC sets in the latest reporting window.", []string{"feed", "result"}, nil,
	)
	metrics.fractionDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "erasure_fraction"),
		"Erased sets divided by total sets in the latest reporting window.", []string{"feed"}, nil,
	)
	metrics.rateDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "shreds_per_second"),
		"Receiver-observed shred rate in the latest reporting window.", []string{"feed", "measure"}, nil,
	)
	metrics.gapsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "gap_events"),
		"Consecutive shred-arrival gaps in the latest reporting window.", []string{"feed", "bucket"}, nil,
	)
	metrics.graceDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "erasure_grace_milliseconds"),
		"Configured delay after a slot boundary before FEC sets are scored.", []string{"feed"}, nil,
	)
	metrics.schemaDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "report_schema"),
		"Schema version of the receiver delivery report.", []string{"feed"}, nil,
	)

	for _, feedID := range feedIDs {
		metrics.feeds[feedID] = feedMetrics{
			ingress:     metrics.ingress.WithLabelValues(feedID),
			egress:      metrics.egress.WithLabelValues(feedID),
			dropped:     metrics.dropped.WithLabelValues(feedID),
			writeErrors: metrics.writeErrors.WithLabelValues(feedID),
			unparsed:    metrics.unparsed.WithLabelValues(feedID),
		}
		metrics.windows[feedID] = erasure.Window{}
	}
	if err := registerer.Register(metrics); err != nil {
		return nil, fmt.Errorf("register receiver metrics: %w", err)
	}
	return metrics, nil
}

// Describe implements prometheus.Collector.
func (m *ReceiverMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.ingress.Describe(ch)
	m.egress.Describe(ch)
	m.dropped.Describe(ch)
	m.writeErrors.Describe(ch)
	m.unparsed.Describe(ch)
	ch <- m.setsDesc
	ch <- m.fractionDesc
	ch <- m.rateDesc
	ch <- m.gapsDesc
	ch <- m.graceDesc
	ch <- m.schemaDesc
}

// Collect implements prometheus.Collector. Every report series for a feed is
// emitted from one locked Window snapshot, preventing mixed-window scrapes.
func (m *ReceiverMetrics) Collect(ch chan<- prometheus.Metric) {
	m.ingress.Collect(ch)
	m.egress.Collect(ch)
	m.dropped.Collect(ch)
	m.writeErrors.Collect(ch)
	m.unparsed.Collect(ch)

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, feedID := range m.feedIDs {
		window := m.windows[feedID]
		ch <- prometheus.MustNewConstMetric(m.setsDesc, prometheus.GaugeValue, float64(window.SetsTotal), feedID, "total")
		ch <- prometheus.MustNewConstMetric(m.setsDesc, prometheus.GaugeValue, float64(window.SetsErased), feedID, "erased")
		ch <- prometheus.MustNewConstMetric(m.fractionDesc, prometheus.GaugeValue, window.ErasureFraction, feedID)
		ch <- prometheus.MustNewConstMetric(m.rateDesc, prometheus.GaugeValue, window.RMean, feedID, "mean")
		ch <- prometheus.MustNewConstMetric(m.rateDesc, prometheus.GaugeValue, window.RPeak100MS, feedID, "peak_100ms")
		gapValues := []uint64{
			window.GapMSHist.LT1,
			window.GapMSHist.From1To2_4,
			window.GapMSHist.From2_4To7,
			window.GapMSHist.From7To32,
			window.GapMSHist.GTE32,
		}
		for i, bucket := range gapBuckets {
			ch <- prometheus.MustNewConstMetric(m.gapsDesc, prometheus.GaugeValue, float64(gapValues[i]), feedID, bucket)
		}
		ch <- prometheus.MustNewConstMetric(m.graceDesc, prometheus.GaugeValue, float64(window.GraceMS), feedID)
		ch <- prometheus.MustNewConstMetric(m.schemaDesc, prometheus.GaugeValue, float64(window.Schema), feedID)
	}
}

// IncIngress records a successfully received unicast packet.
func (m *ReceiverMetrics) IncIngress(feedID string) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	feed.ingress.Inc()
	return nil
}

// AddEgress records successful destination writes. count is per destination,
// so one packet fanned out to N destinations adds N.
func (m *ReceiverMetrics) AddEgress(feedID string, count uint64) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	feed.egress.Add(float64(count))
	return nil
}

// AddWriteErrors records failed or short destination writes. count is per
// destination, matching AddEgress.
func (m *ReceiverMetrics) AddWriteErrors(feedID string, count uint64) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	feed.writeErrors.Add(float64(count))
	return nil
}

// IncFanoutDrop records one packet rejected by the bounded ring.
func (m *ReceiverMetrics) IncFanoutDrop(feedID string) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	feed.dropped.Inc()
	return nil
}

// IncUnparsed records one delivered packet with a malformed shred header.
func (m *ReceiverMetrics) IncUnparsed(feedID string) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	feed.unparsed.Inc()
	return nil
}

// PublishWindow exposes the exact delivery report used by the broker heartbeat.
func (m *ReceiverMetrics) PublishWindow(feedID string, window erasure.Window) error {
	if _, err := m.feed(feedID); err != nil {
		return err
	}
	m.mu.Lock()
	m.windows[feedID] = window
	m.mu.Unlock()
	return nil
}

func (m *ReceiverMetrics) feed(feedID string) (feedMetrics, error) {
	feed, ok := m.feeds[feedID]
	if !ok {
		return feedMetrics{}, fmt.Errorf("%w: %q", ErrUnknownFeed, feedID)
	}
	return feed, nil
}
