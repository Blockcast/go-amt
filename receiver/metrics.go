package receiver

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/prometheus/client_golang/prometheus"
)

const receiverMetricsNamespace = "bcast_shred_gw"

var ErrUnknownFeed = errors.New("receiver metrics feed is not configured")

// WindowReporting says whether this receiver drains delivery-report windows at
// all. It gates every window-derived series on /metrics, not only the erasure
// family: _shreds_per_second, _gap_events and _report_schema are read off the
// same erasure.Window and are just as unpublished without a tracker.
//
// It is a required constructor argument rather than an option defaulting to on,
// because the wrong answer is silent: a receiver that registers these series and
// never drives them publishes zeros for the life of the process, which is
// indistinguishable from a genuinely perfect feed. That is the same false
// attestation heartbeatOptions in cmd/blockcast-shreds already refuses to emit
// for generic mode, and publishWindows refuses to emit on a failed drain.
// Forcing every call site to state the answer keeps a future mode from
// inheriting the wrong one.
//
// It is a named type so a call site reads NoWindowReporting rather than false.
type WindowReporting bool

const (
	// ReportsWindows registers every window-derived series: the
	// bcast_shred_gw_erasure_* family, _shreds_per_second, _gap_events and
	// _report_schema. The caller must drive them via PublishWindow and
	// PublishGuard.
	ReportsWindows WindowReporting = true
	// NoWindowReporting omits all of them entirely. Absent is the point: a
	// consumer can then tell "this mode drains no delivery window" from
	// "window drained, nothing observed" (BLO-28910, BLO-40163).
	NoWindowReporting WindowReporting = false
)

var gapBuckets = []string{"<1", "1-2.4", "2.4-7", "7-32", ">=32"}

// ReceiverMetrics is the fan-out worker's egress observer.
var _ EgressObserver = (*ReceiverMetrics)(nil)

// ReceiverMetrics exposes packet-path counters and the latest delivery report
// for a fixed set of configured feeds. Unknown feeds are rejected so packet
// data cannot create unbounded Prometheus label cardinality.
type ReceiverMetrics struct {
	mu      sync.RWMutex
	feedIDs []string
	// reportsWindows gates every window-derived descriptor in Describe and
	// Collect. The descs are built either way; only publication is conditional.
	// Immutable after construction: set once in NewReceiverMetrics and never
	// mutated, which is why Describe, Collect and PublishGuard read it without
	// holding mu. Adding a setter would make those reads a data race.
	reportsWindows bool
	feeds          map[string]feedMetrics
	windows        map[string]erasure.Window
	// liveness holds the per-feed ingress activity the broker heartbeat
	// reports. It is kept here, beside the prometheus counters and written on
	// the same call, because the heartbeat's packet count and
	// ingress_packets_total state the same fact: a second entry point that
	// moved one without the other would let /metrics and the heartbeat
	// disagree about a feed, which is the divergence PublishWindow's comment
	// already argues against for the delivery report.
	liveness map[string]FeedLiveness
	// guards holds cumulative slot-guard state, kept separate from windows
	// because it is process-lifetime totals rather than a per-window snapshot.
	guards map[string]erasure.Stats

	ingress       *prometheus.CounterVec
	egress        *prometheus.CounterVec
	dropped       *prometheus.CounterVec
	writeErrors   *prometheus.CounterVec
	unparsed      *prometheus.CounterVec
	undeliverable *prometheus.CounterVec

	setsDesc      *prometheus.Desc
	fractionDesc  *prometheus.Desc
	rateDesc      *prometheus.Desc
	gapsDesc      *prometheus.Desc
	graceDesc     *prometheus.Desc
	slotGuardDesc *prometheus.Desc
	resyncsDesc   *prometheus.Desc
	schemaDesc    *prometheus.Desc
}

type feedMetrics struct {
	ingress       prometheus.Counter
	egress        prometheus.Counter
	dropped       prometheus.Counter
	writeErrors   prometheus.Counter
	unparsed      prometheus.Counter
	undeliverable prometheus.Counter
}

// NewReceiverMetrics registers receiver metrics and materializes zero-valued
// series for every configured feed.
//
// With NoWindowReporting no window-derived series is exported at all -- not the
// bcast_shred_gw_erasure_* family, and not _shreds_per_second, _gap_events or
// _report_schema. See WindowReporting for why that is absent rather than zero.
// The packet-path counters are unaffected: they are driven by ObserveIngress and
// the fan-out, not by a drain, so they stay honest in every mode and remain the
// liveness signal a consumer pairs against.
func NewReceiverMetrics(registerer prometheus.Registerer, feedIDs []string, reporting WindowReporting) (*ReceiverMetrics, error) {
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
		reportsWindows: bool(reporting),

		feedIDs:  append([]string(nil), feedIDs...),
		feeds:    make(map[string]feedMetrics, len(feedIDs)),
		windows:  make(map[string]erasure.Window, len(feedIDs)),
		liveness: make(map[string]FeedLiveness, len(feedIDs)),
		guards:   make(map[string]erasure.Stats, len(feedIDs)),
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
	metrics.undeliverable = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: receiverMetricsNamespace,
		Name:      "shreds_undeliverable_total",
		Help:      "Forwarder frames withheld from validator destinations because they carry no shred a TVU accepts: a version-3 frame (an erasure shard without signature or Merkle proof; run the shred-forwarder with --wire-version v4) or a malformed version-4 frame with no body.",
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
	metrics.slotGuardDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "erasure_slot_rejections_total"),
		"Observations refused by the slot-plausibility guard, by direction. "+
			"'ahead' is beyond the forward jump bound; 'behind' is too far behind the frontier. "+
			"A sustained 'behind' rate means the frontier itself is suspect.",
		[]string{"feed", "direction"}, nil,
	)
	metrics.resyncsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "erasure_frontier_resyncs_total"),
		"Times the slot frontier was abandoned and re-adopted. Each one is a "+
			"discontinuity in the erasure series: sets in flight were dropped unscored.",
		[]string{"feed"}, nil,
	)
	metrics.schemaDesc = prometheus.NewDesc(
		prometheus.BuildFQName(receiverMetricsNamespace, "", "report_schema"),
		"Schema version of the receiver delivery report.", []string{"feed"}, nil,
	)

	for _, feedID := range feedIDs {
		metrics.feeds[feedID] = feedMetrics{
			ingress:       metrics.ingress.WithLabelValues(feedID),
			egress:        metrics.egress.WithLabelValues(feedID),
			dropped:       metrics.dropped.WithLabelValues(feedID),
			writeErrors:   metrics.writeErrors.WithLabelValues(feedID),
			unparsed:      metrics.unparsed.WithLabelValues(feedID),
			undeliverable: metrics.undeliverable.WithLabelValues(feedID),
		}
		metrics.windows[feedID] = erasure.Window{}
		metrics.guards[feedID] = erasure.Stats{}
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
	m.undeliverable.Describe(ch)
	if !m.reportsWindows {
		return
	}
	ch <- m.rateDesc
	ch <- m.gapsDesc
	ch <- m.schemaDesc
	ch <- m.setsDesc
	ch <- m.fractionDesc
	ch <- m.graceDesc
	ch <- m.slotGuardDesc
	ch <- m.resyncsDesc
}

// Collect implements prometheus.Collector. Every report series for a feed is
// emitted from one locked Window snapshot, preventing mixed-window scrapes.
func (m *ReceiverMetrics) Collect(ch chan<- prometheus.Metric) {
	m.ingress.Collect(ch)
	m.egress.Collect(ch)
	m.dropped.Collect(ch)
	m.writeErrors.Collect(ch)
	m.unparsed.Collect(ch)
	m.undeliverable.Collect(ch)

	// Nothing below this line is reachable without a drain: every value is read
	// off m.windows, which only PublishWindow writes. A receiver that drains no
	// window would publish the zero Window forever, so the whole loop is skipped
	// rather than emitting zeros -- see WindowReporting.
	if !m.reportsWindows {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, feedID := range m.feedIDs {
		window := m.windows[feedID]
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
		ch <- prometheus.MustNewConstMetric(m.schemaDesc, prometheus.GaugeValue, float64(window.Schema), feedID)
		ch <- prometheus.MustNewConstMetric(m.setsDesc, prometheus.GaugeValue, float64(window.SetsTotal), feedID, "total")
		ch <- prometheus.MustNewConstMetric(m.setsDesc, prometheus.GaugeValue, float64(window.SetsErased), feedID, "erased")
		ch <- prometheus.MustNewConstMetric(m.fractionDesc, prometheus.GaugeValue, window.ErasureFraction, feedID)
		ch <- prometheus.MustNewConstMetric(m.graceDesc, prometheus.GaugeValue, float64(window.GraceMS), feedID)
		guard := m.guards[feedID]
		ch <- prometheus.MustNewConstMetric(m.slotGuardDesc, prometheus.CounterValue, float64(guard.RejectedSlotJumps), feedID, "ahead")
		ch <- prometheus.MustNewConstMetric(m.slotGuardDesc, prometheus.CounterValue, float64(guard.StaleRejections), feedID, "behind")
		ch <- prometheus.MustNewConstMetric(m.resyncsDesc, prometheus.CounterValue, float64(guard.FrontierResyncs), feedID)
	}
}

// ObserveIngress records a successfully received unicast packet of size bytes
// that arrived at at.
//
// This is the single ingress entry point on purpose. It moves
// ingress_packets_total and the heartbeat's per-feed liveness together, so the
// two surfaces cannot report different packet counts for the same feed. An
// IncIngress that touched only the counter used to exist; it was removed rather
// than kept alongside this, because a caller reaching for the shorter name
// would silently under-report every heartbeat while /metrics looked correct.
//
// bytes is the datagram's payload length and may legally be 0 — a zero-length
// UDP datagram is a packet that carried no bytes, which is why the heartbeat
// contract requires Bytes == 0 when Packets == 0 but never the converse.
//
// at is the arrival timestamp captured before any per-packet work, so first/last
// bound observed traffic rather than lock-acquisition order. A zero at is
// rejected: it would produce a feed claiming packets with no first-packet time,
// which broker.ValidateHeartbeat rejects at the far end, and failing here names
// the feed instead.
func (m *ReceiverMetrics) ObserveIngress(feedID string, bytes int, at time.Time) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	if bytes < 0 {
		return fmt.Errorf("receiver metrics feed %q: ingress bytes is negative (%d)", feedID, bytes)
	}
	if at.IsZero() {
		return fmt.Errorf("receiver metrics feed %q: ingress timestamp is zero", feedID)
	}

	feed.ingress.Inc()

	m.mu.Lock()
	defer m.mu.Unlock()
	live := m.liveness[feedID]
	live.Packets++
	live.Bytes += uint64(bytes)
	// Guard against a non-monotonic clock rather than assuming arrival order:
	// time.Now() is not guaranteed monotonic across a wall-clock step, and the
	// heartbeat contract rejects last_packet_at preceding first_packet_at.
	if live.FirstAt.IsZero() || at.Before(live.FirstAt) {
		live.FirstAt = at
	}
	if at.After(live.LastAt) {
		live.LastAt = at
	}
	m.liveness[feedID] = live
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

// IncUndeliverable records one packet withheld from destinations because it
// carries no shred a TVU can accept (a version-3 forwarder frame).
func (m *ReceiverMetrics) IncUndeliverable(feedID string) error {
	feed, err := m.feed(feedID)
	if err != nil {
		return err
	}
	feed.undeliverable.Inc()
	return nil
}

// PublishWindow exposes the exact delivery report used by the broker heartbeat.
//
// It stores the Window unconditionally, including under NoWindowReporting where
// Collect exports none of it: Snapshot reads the same map for the heartbeat, and
// that path does not depend on the /metrics gate. See PublishGuard for why the
// two methods answer differently.
func (m *ReceiverMetrics) PublishWindow(feedID string, window erasure.Window) error {
	if _, err := m.feed(feedID); err != nil {
		return err
	}
	m.mu.Lock()
	m.windows[feedID] = window
	m.mu.Unlock()
	return nil
}

// PublishGuard records the tracker's cumulative slot-guard state for a feed.
//
// Kept separate from PublishWindow because these are process-lifetime totals,
// not per-window figures: a frontier resync is a discontinuity in the erasure
// series, and an operator needs to see it as one rather than have it reset to
// zero with the next window.
func (m *ReceiverMetrics) PublishGuard(feedID string, stats erasure.Stats) error {
	if _, err := m.feed(feedID); err != nil {
		return err
	}
	// Refused rather than stored: with NoWindowReporting guards reach no
	// surface at all -- m.guards is read only by Collect -- so accepting would
	// drop a caller's counters silently. Failing names the mismatch.
	//
	// PublishWindow deliberately does NOT error under the same condition. The
	// distinction is no longer "partial vs whole no-op" on /metrics -- since
	// BLO-40163 Collect skips every window series, so neither reaches /metrics
	// here. It is that m.windows has a SECOND reader: Snapshot returns the
	// stored Window without consulting reportsWindows. WindowReporting is a
	// receiver-package gate, not a mode -- this package has no concept of the
	// caller's modes -- so a Window stored under NoWindowReporting still
	// reaches every Snapshot consumer, and there is no honest error for
	// PublishWindow to return.
	//
	// Do not re-derive this from the cmd layer. Today's only Snapshot consumer
	// (broker/gwclient) happens to be reachable only under --mode shred, so it
	// is tempting to read the asymmetry as dead and collapse it. That couples a
	// receiver invariant to one caller's current flag validation, which is
	// exactly what this package must not assume.
	//
	// The only caller discards this (publishWindows, main.go), so today the
	// error names the mismatch to nobody; it is here for the next caller that
	// checks, and to make the no-op fail loudly under test.
	if !m.reportsWindows {
		return fmt.Errorf("receiver metrics feed %q: window reporting is disabled", feedID)
	}
	m.mu.Lock()
	m.guards[feedID] = stats
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

// FeedLiveness is one feed's observed ingress activity: the counters and the
// arrival bounds a gateway heartbeat reports per feed.
//
// FirstAt and LastAt are arrival timestamps, not window boundaries — they bound
// traffic actually seen, and are both zero for a feed that has received
// nothing. Packets and Bytes are process-lifetime cumulative totals, which is
// deliberate and is NOT the same shape as the erasure window beside them: that
// window is a per-drain counter delta the broker deduplicates on
// (feed_id, window_start). Do not read the two as though they covered the same
// interval.
type FeedLiveness struct {
	Packets uint64
	Bytes   uint64
	FirstAt time.Time
	LastAt  time.Time
}

// FeedSnapshot is everything the heartbeat producer reports for one feed, read
// under a single lock acquisition.
//
// Liveness and Window are captured together so a heartbeat cannot pair one
// feed's counters with another drain's delivery report. Window is the last
// window PublishWindow recorded, republished on every heartbeat until the next
// drain replaces it — see the FeedReport doc in package broker for why that
// repetition is safe and why the broker deduplicates rather than sums.
type FeedSnapshot struct {
	FeedID   string
	Liveness FeedLiveness
	Window   erasure.Window
}

// Snapshot returns one entry per configured feed, in configured order.
//
// Feeds that have received nothing are included with a zero FeedLiveness rather
// than omitted: a silent feed is the case an SLA dispute is about, and omitting
// it would make "received nothing" indistinguishable from "not configured" at
// the broker.
func (m *ReceiverMetrics) Snapshot() []FeedSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := make([]FeedSnapshot, 0, len(m.feedIDs))
	for _, feedID := range m.feedIDs {
		snapshot = append(snapshot, FeedSnapshot{
			FeedID:   feedID,
			Liveness: m.liveness[feedID],
			Window:   m.windows[feedID],
		})
	}
	return snapshot
}
