//go:build linux

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// counters holds the stats-line counters that /metrics and the stats line
// share. The stats line stays the rollback path and reads exactly these
// fields, so there is one source of truth and no shadow copy to drift: the
// exporter reads the live values at scrape time rather than a snapshot
// published on the stats tick, which would otherwise tie an alert's freshness
// to -stats-interval.
//
// Every field is written by a reader or the processor goroutine and read by
// the scrape goroutine, hence atomic. The per-output sent/err/drop counters
// already are and stay on output.
//
// The counters NOT here (dup_prod, emitted_v3, skipped, ...) stay plain
// uint64s local to the processor loop: they are stats-line only. Moving one
// here is what exporting it costs.
//
// ponytail: rx and emitted are incremented inside main's processor loop, which
// no test can drive without extracting that loop — a change to the emit path
// this row is scoped not to make. Both increments survived mutation testing
// (BLO-43479); every other guard here failed under one. The gap is bounded by
// this struct being the single source of truth: the stats line reads the same
// fields, so a dropped increment prints rx_prod=0 in the journal rather than
// disagreeing with /metrics. Close it by extracting the loop body when that
// path needs changing for its own reasons.
type counters struct {
	// Indexed by frame.src: 0 is ingest A, the production SSM channel; 1 is
	// ingest B, the second listener. foreign[1] can never move, because reader
	// counts a foreign datagram only when it was given a source to admit and
	// ingest B is given none. It is exported anyway, so "ingest B rejected
	// nothing" is a published 0 rather than an absent series.
	rx      [2]atomic.Uint64
	foreign [2]atomic.Uint64

	emitted atomic.Uint64
	qdrop   atomic.Uint64
}

// ingestLabels names each frame.src on /metrics.
var ingestLabels = [2]string{"a", "b"}

// counterFunc returns a monotonic counter reading f at scrape time. Const
// labels, rather than a CounterVec, because every series is known at
// registration: the cardinality is fixed at 2 and nothing may create a third.
func counterFunc(name, help string, labels prometheus.Labels, f func() uint64) prometheus.Collector {
	return prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace:   "shred_merger",
		Name:        name,
		Help:        help,
		ConstLabels: labels,
	}, func() float64 { return float64(f()) })
}

// registerMerger registers the stats-line counters with r. outs may be empty.
func registerMerger(r prometheus.Registerer, c *counters, outs []*output) error {
	cs := []prometheus.Collector{
		counterFunc("emitted_total", "Shreds the union has emitted (stats-line emitted).", nil, c.emitted.Load),
		counterFunc("queue_drops_total", "Frames dropped with the processor queue full (stats-line qdrop).", nil, c.qdrop.Load),
		counterFunc("emit_errors_total", "Output writes that failed, summed over every output (stats-line emit_err).", nil, func() uint64 {
			var n uint64
			for _, o := range outs {
				n += o.err.Load()
			}
			return n
		}),
		counterFunc("output_drops_total", "Frames dropped with an output queue full, summed over every output (stats-line out_drop).", nil, func() uint64 {
			var n uint64
			for _, o := range outs {
				n += o.drop.Load()
			}
			return n
		}),
	}
	for i, name := range ingestLabels {
		l := prometheus.Labels{"ingest": name}
		cs = append(cs,
			// Method values, so each closes over &c.rx[i] rather than i.
			counterFunc("received_total", "Datagrams taken from an ingest (stats-line rx_prod and rx_listener2).", l, c.rx[i].Load),
			counterFunc("foreign_datagrams_total", "Datagrams dropped unread because their source is not the one the ingest admits (stats-line foreign).", l, c.foreign[i].Load),
		)
	}
	for _, m := range cs {
		if err := r.Register(m); err != nil {
			return err
		}
	}
	return nil
}

// serveMetrics serves c on addr at /metrics, in its own registry rather than
// the global default (metrics/sockbuf.go gives the reason). An empty addr
// opens no listener and returns a nil address, which is the default: this
// merger's whole subject is a UDP port more reachable than it should be, so it
// adds a second listener only when asked, and asked for loopback.
func serveMetrics(addr string, c *counters, outs []*output) (net.Addr, error) {
	if strings.TrimSpace(addr) == "" {
		return nil, nil
	}
	r := prometheus.NewRegistry()
	if err := registerMerger(r, c, outs); err != nil {
		return nil, fmt.Errorf("register metrics: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %q for /metrics: %w", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	go func() {
		if err := http.Serve(ln, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("/metrics server: %v", err)
		}
	}()
	log.Printf("metrics: http://%s/metrics", ln.Addr())
	return ln.Addr(), nil
}
