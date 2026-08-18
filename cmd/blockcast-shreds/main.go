// Command blockcast-shreds is the zero-account demo receiver and verifier.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/receiver/config"
	"github.com/blockcast/go-amt/shred"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// defaultReportInterval matches the broker heartbeat cadence. /metrics and the
// heartbeat must publish the same window or the two SLA surfaces disagree, so
// the scrape shows the last drained window rather than a live partial count.
const defaultReportInterval = 30 * time.Second

const help = `blockcast-shreds demo mode

Usage:
  blockcast-shreds [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...] [--http-addr IP:PORT] [--health-max-age DURATION] [--json]
  blockcast-shreds selftest --fixture [--json]

Demo mode has no broker, certificates, accounts, or heartbeats. --feed is
repeatable for first-arrival-wins scoring across multiple unicast UDP feeds.
With two or more feeds the receipt reports the measured worth of a second
feed: each feed's own erasure fraction, the union's, and the FEC sets the
extra feeds rescued. It measures this run only — it cannot tell whether the
inputs are independently operated or share one tap.

/healthz is readiness-shaped: it reports unhealthy until the first packet
arrives, so it is not a safe liveness probe. --health-max-age sets the
ingress freshness window.`

type feeds []string

type feed struct {
	name    string
	address string
}

func (f *feeds) String() string { return strings.Join(*f, ",") }
func (f *feeds) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "blockcast-shreds:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 0 && args[0] == "selftest" {
		return selftest(args[1:])
	}
	flags := flag.NewFlagSet("blockcast-shreds", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { fmt.Fprintln(flags.Output(), help) }
	var configuredFeeds feeds
	var listen, destinations, httpAddress string
	var healthMaxAge time.Duration
	flags.Var(&configuredFeeds, "feed", "repeatable NAME=IP:PORT unicast feed")
	flags.StringVar(&listen, "listen", "0.0.0.0:20000", "unicast UDP listen address")
	flags.StringVar(&destinations, "dest-ip-ports", "", "comma-separated UDP forward destinations")
	asJSON := flags.Bool("json", false, "emit the receipt as JSON instead of the human table")
	flags.StringVar(&httpAddress, "http-addr", "127.0.0.1:8080", "metrics and health HTTP address; empty disables HTTP")
	flags.DurationVar(&healthMaxAge, "health-max-age", 30*time.Second, "/healthz ingress freshness window; readiness-shaped, see README")
	graceMS := flags.Int("erasure-grace-ms", int(config.DefaultErasureGrace/time.Millisecond),
		"receiver-observed FEC-set scoring grace in milliseconds; a set still below 32 of 64 shreds at slot_boundary plus this grace scores erased")
	reportInterval := flags.Duration("report-interval", defaultReportInterval,
		"how often the delivery window is drained into /metrics; matches the broker heartbeat cadence")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *graceMS <= 0 {
		return errors.New("--erasure-grace-ms must be positive")
	}
	if *reportInterval <= 0 {
		return errors.New("--report-interval must be positive")
	}
	configured := []feed{{name: "default", address: listen}}
	if len(configuredFeeds) != 0 {
		configured = configured[:0]
		seen := make(map[string]struct{}, len(configuredFeeds))
		for _, value := range configuredFeeds {
			name, address, ok := strings.Cut(value, "=")
			if !ok || name == "" || address == "" {
				return fmt.Errorf("--feed %q must be NAME=IP:PORT", value)
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate --feed name %q", name)
			}
			seen[name] = struct{}{}
			configured = append(configured, feed{name: name, address: address})
		}
	}
	if healthMaxAge <= 0 {
		return fmt.Errorf("--health-max-age must be positive, got %s", healthMaxAge)
	}
	return listenAndScore(configured, splitNonempty(destinations), httpAddress, healthMaxAge, *asJSON,
		time.Duration(*graceMS)*time.Millisecond, *reportInterval, nil)
}

func selftest(args []string) error {
	flags := flag.NewFlagSet("selftest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	fixture := flags.Bool("fixture", false, "replay the bundled deterministic pcap")
	asJSON := flags.Bool("json", false, "emit the receipt as JSON instead of the human table")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*fixture || flags.NArg() != 0 {
		return errors.New("usage: blockcast-shreds selftest --fixture [--json]")
	}
	scorer := shred.NewScorer()
	if err := shred.ReplayFixture(scorer); err != nil {
		return err
	}
	return printReceipt(scorer.Receipt(), *asJSON)
}

// printReceipt writes either the human table (the receipt's String form) or an
// indented JSON document for machine consumption.
func printReceipt(receipt fmt.Stringer, asJSON bool) error {
	if !asJSON {
		fmt.Println(receipt)
		return nil
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

// listenAndScore serves every configured feed until stop is closed or a socket
// fails. stop may be nil, in which case only a signal or a socket error ends it.
func listenAndScore(feeds []feed, destinations []string, httpAddress string, healthMaxAge time.Duration, asJSON bool, grace, reportInterval time.Duration, stop <-chan struct{}) error {
	names := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		names = append(names, feed.name)
	}
	scorer := shred.NewFeedScorer(names)
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, names)
	if err != nil {
		return err
	}

	// One tracker per feed. The delivery SLA is per feed, and a shared tracker
	// would let a healthy feed mask an erased one behind a pooled fraction.
	windowStart := time.Now()
	trackers := make(map[string]*erasure.Tracker, len(names))
	for _, name := range names {
		tracker, err := erasure.NewTracker(grace, windowStart)
		if err != nil {
			return fmt.Errorf("erasure tracker for feed %q: %w", name, err)
		}
		trackers[name] = tracker
	}

	// The fan-out is constructed after the metrics so the worker can attribute
	// each delivered datagram back to the feed that received it.
	var fanout *receiver.Fanout
	if len(destinations) != 0 {
		fanout, err = receiver.NewUDPFanout(destinations, 4096, metrics)
		if err != nil {
			return err
		}
		defer fanout.Close()
	}

	health, err := receiver.NewHealth(healthMaxAge)
	if err != nil {
		return err
	}
	httpServer, err := startHTTP(httpAddress, registry, health)
	if err != nil {
		return err
	}
	if httpServer != nil {
		defer func() { _ = httpServer.Close() }()
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	// Drain each feed's window into /metrics on the heartbeat cadence. The
	// tracker carries its own mutex, so this runs off the read path and cannot
	// hold up ingress or delivery.
	reporter := time.NewTicker(reportInterval)
	defer reporter.Stop()
	reporterStop := make(chan struct{})
	reportDone := make(chan struct{})
	go func() {
		defer close(reportDone)
		for {
			select {
			case now := <-reporter.C:
				publishWindows(trackers, metrics, now)
			case <-reporterStop:
				return
			}
		}
	}()
	// stopReporter is idempotent so the error path can unwind through the defer
	// while the clean path stops the ticker explicitly, before the final drain.
	stopReporter := sync.OnceFunc(func() {
		close(reporterStop)
		<-reportDone
	})
	defer stopReporter()

	errCh := make(chan error, len(feeds))
	var sockets []*net.UDPConn
	var mu sync.Mutex
	for _, feed := range feeds {
		udpAddress, err := net.ResolveUDPAddr("udp", feed.address)
		if err != nil {
			return fmt.Errorf("resolve feed %q: %w", feed.name, err)
		}
		conn, err := net.ListenUDP("udp", udpAddress)
		if err != nil {
			return fmt.Errorf("listen feed %q at %q: %w", feed.name, feed.address, err)
		}
		sockets = append(sockets, conn)
		go func(feedName string, conn *net.UDPConn) {
			packet := make([]byte, 2048)
			for {
				n, _, err := conn.ReadFromUDP(packet)
				if err != nil {
					errCh <- err
					return
				}
				// receivedAt is captured here, before any per-packet work, so it
				// is a true arrival timestamp rather than a lock-ordered one.
				// Every consumer below synchronizes itself.
				receivedAt := time.Now()
				// mu guards the tracker set against the periodic reporter and
				// the final drain; receivedAt is taken before it so the
				// timestamp stays a true arrival time rather than a
				// lock-ordered one.
				mu.Lock()
				health.MarkReceived(receivedAt)
				_ = metrics.IncIngress(feedName)
				processPacket(feedName, packet[:n], receivedAt, scorer, fanout, metrics, trackers[feedName])
				mu.Unlock()
			}
		}(feed.name, conn)
	}

	select {
	case <-signals:
	case <-stop:
	case err := <-errCh:
		for _, conn := range sockets {
			_ = conn.Close()
		}
		return err
	}
	for _, conn := range sockets {
		_ = conn.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	// Stop the periodic reporter before the last drain so the two cannot split
	// the final window between them.
	stopReporter()
	// Drain once more on the way out. Without this a run shorter than one report
	// interval exits having scraped nothing but zeros, which is the same wrong
	// answer -- a clean feed -- that this reporting path exists to prevent.
	publishWindows(trackers, metrics, time.Now())
	// Sockets are closed, but a reader goroutine can still be mid-packet: it may
	// be blocked in Enqueue or between the read and Observe. FeedScorer.Receipt
	// takes the scorer's own lock, so the receipt is a consistent snapshot even
	// if a late Observe lands after it.
	return printReceipt(scorer.Receipt(), asJSON)
}

// publishWindows scores every tracker through now and publishes the drained
// window for each feed. Advance is called first so sets whose deadline has
// passed are scored even when a feed has gone silent and Observe is no longer
// running.
//
// A drain that fails leaves the previously published window in place rather
// than substituting a zero. Publishing a zero window on error would report a
// perfect feed, which is indistinguishable from a genuinely clean one.
func publishWindows(trackers map[string]*erasure.Tracker, metrics *receiver.ReceiverMetrics, now time.Time) {
	for feedID, tracker := range trackers {
		tracker.Advance(now)
		window, err := tracker.DrainWindow(now)
		if err != nil {
			continue
		}
		_ = metrics.PublishWindow(feedID, window)
	}
}

// processPacket delivers one packet and then scores it.
//
// Delivery runs FIRST and unconditionally. Scoring is accounting: it may not
// sit in front of a validator's packet, and it may not decide whether a packet
// is forwarded. Malformed and duplicate packets reach every destination
// unchanged; what to do with them is the validator's decision.
//
// Every value used here is internally synchronized -- Fanout copies the packet
// under its own lock, FeedScorer serializes its own state, and Health and
// ReceiverMetrics each carry their own.
//
// receivedAt is captured at the socket read, so concurrent feeds can present it
// out of order. That is the scorer's problem to absorb, and it does: see
// Scorer.Observe on why the gap frontier and per-set extent advance
// monotonically rather than assuming call order matches timestamp order.
//
// Only EnqueueOverflow counts as a drop. A closed fan-out also refuses the
// packet, but that is a shutdown artifact rather than receiver overload, and
// charging it to the ring-overflow counter would let shutdown inflate a metric
// the README defines as ring-full only.
//
// tracker may be nil, which disables receiver-observed erasure scoring for the
// feed without affecting delivery.
func processPacket(feedName string, packet []byte, receivedAt time.Time, scorer *shred.FeedScorer, fanout *receiver.Fanout, metrics *receiver.ReceiverMetrics, tracker *erasure.Tracker) {
	if fanout != nil && fanout.Enqueue(feedName, packet) == receiver.EnqueueOverflow {
		_ = metrics.IncFanoutDrop(feedName)
	}

	_, parseErr := scorer.Observe(feedName, packet, receivedAt)
	if parseErr != nil {
		_ = metrics.IncUnparsed(feedName)
		return
	}
	if tracker == nil {
		return
	}
	// The header is parsed a second time here rather than threaded out of
	// FeedScorer.Observe: shred/score.go is under concurrent change by other
	// in-flight receiver PRs, and widening its signature would conflict with
	// them for a header parse that is a handful of little-endian field reads on
	// a path that no longer precedes delivery. Reunify the two once those land.
	header, err := shred.Parse(packet, shred.FormatForwarder)
	if err != nil {
		return
	}
	tracker.Observe(header, receivedAt)
}

func startHTTP(address string, registry *prometheus.Registry, health http.Handler) (*http.Server, error) {
	if strings.TrimSpace(address) == "" {
		return nil, nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.Handle("/healthz", health)
	server := &http.Server{Addr: address, Handler: mux}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen HTTP endpoint %q: %w", address, err)
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "blockcast-shreds HTTP:", err)
		}
	}()
	return server, nil
}

func splitNonempty(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
