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
	"syscall"
	"time"

	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/shred"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const help = `blockcast-shreds demo mode

Usage:
  blockcast-shreds [--mode shred|generic] [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...] [--http-addr IP:PORT] [--health-max-age DURATION] [--retain DURATION] [--json]
  blockcast-shreds selftest --fixture [--json]
  blockcast-shreds selftest --generic [--json]
  blockcast-shreds gensend --to IP:PORT [--iface IP]

Demo mode has no broker, certificates, accounts, or heartbeats. --feed is
repeatable for first-arrival-wins scoring across multiple unicast UDP feeds.
With two or more feeds the receipt reports the measured worth of a second
feed: each feed's own erasure fraction, the union's, and the FEC sets the
extra feeds rescued. It measures this run only — it cannot tell whether the
inputs are independently operated or share one tap.

--mode generic scores generic framed records instead of shreds: the same
delivery receipt, on a payload that isn't shreds. It reports no FEC erasure,
because this mode does no erasure coding, and no cross-feed union, because
nothing in this mode establishes that two feeds carry the same stream.
gensend emits the synthetic framed feed so the receipt can be driven
end-to-end through the demo tap.

/healthz is readiness-shaped: it reports unhealthy until the first packet
arrives, so it is not a safe liveness probe. --health-max-age sets the
ingress freshness window.

--retain bounds the scorer's memory: per-shred state is kept for that long
past each arrival, so the receiver reaches a steady state instead of growing
for as long as it runs. The receipt still covers the whole run; the window is
how long a second copy of a shred can still be recognised as a duplicate.
Widening it past the completion histogram's ceiling makes completion
percentiles at or above that ceiling understate with no bound, and warns at
startup; every other figure stays exact at any window. See the README.`

// sessionScorer is the seam that keeps shred mode and generic mode one client.
// Both modes are selected once at construction; the packet loop below has no
// mode switch in it.
//
// SessionReceipt returns fmt.Stringer so both modes render through the same
// printReceipt, which is what makes --json compose with --mode rather than being
// a shred-only flag. Each scorer supplies it in the shred package, so call sites
// pass the concrete scorer with no wrapper.
type sessionScorer interface {
	Observe(feed string, packet []byte, receivedAt time.Time) (bool, error)
	SessionReceipt() fmt.Stringer
}

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
	if len(args) != 0 && args[0] == "gensend" {
		return gensend(args[1:])
	}
	flags := flag.NewFlagSet("blockcast-shreds", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() { fmt.Fprintln(flags.Output(), help) }
	var configuredFeeds feeds
	var listen, destinations, httpAddress, mode, sourceLabel, rightsBasis string
	var healthMaxAge time.Duration
	flags.Var(&configuredFeeds, "feed", "repeatable NAME=IP:PORT unicast feed")
	flags.StringVar(&listen, "listen", "0.0.0.0:20000", "unicast UDP listen address")
	flags.StringVar(&destinations, "dest-ip-ports", "", "comma-separated UDP forward destinations")
	asJSON := flags.Bool("json", false, "emit the receipt as JSON instead of the human table")
	flags.StringVar(&httpAddress, "http-addr", "127.0.0.1:8080", "metrics and health HTTP address; empty disables HTTP")
	flags.StringVar(&mode, "mode", "shred", "scoring mode: shred or generic")
	flags.StringVar(&sourceLabel, "source-label", "", "generic mode: provenance of the input, e.g. synthetic")
	flags.StringVar(&rightsBasis, "rights-basis", "", "generic mode: recorded rights basis for the input")
	flags.DurationVar(&healthMaxAge, "health-max-age", 30*time.Second, "/healthz ingress freshness window; readiness-shaped, see README")
	retention := flags.Duration("retain", shred.DefaultRetention, "how far behind the newest arrival to keep per-shred scoring state; see README")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	switch mode {
	case "shred":
		if sourceLabel != "" || rightsBasis != "" {
			return errors.New("--source-label and --rights-basis apply to --mode generic only")
		}
	case "generic":
		// Both labels are mandatory rather than defaulted. A generic receipt
		// whose input provenance is unstated is the artifact the rights
		// guardrail exists to prevent, and defaulting to "synthetic" would let
		// a real capture be scored under a synthetic label by omission.
		if sourceLabel == "" || rightsBasis == "" {
			return errors.New("--mode generic requires --source-label and --rights-basis")
		}
	default:
		return fmt.Errorf("--mode %q must be shred or generic", mode)
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
	// A non-positive window would evict each shred as it was written, so every
	// arrival would read as new and duplicate suppression would stop working.
	if *retention <= 0 {
		return fmt.Errorf("--retain must be positive, got %s", *retention)
	}
	// Warn rather than reject above the histogram's ceiling. Widening the window
	// past it degrades exactly one number — completion percentiles, which stop
	// being bounded above and report the overflow floor instead, understating
	// with no bound. Everything else the receipt carries (dedup, erasure, gaps,
	// means) stays exact at any window, and recognising cross-feed duplicates is
	// what --retain is primarily for, so refusing to run would trade a
	// percentile caveat for a service that will not start. The operator who
	// followed "widen --retain if your inputs can be seconds apart" learns the
	// cost here, at the point of use, rather than from shred/retention.go.
	if warning := retentionWarning(*retention); warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}
	return listenAndScore(configured, splitNonempty(destinations), httpAddress, healthMaxAge, *asJSON, *retention, mode, sourceLabel, rightsBasis)
}

// retentionWarning returns the operator warning for a retention window that
// outreaches the completion histogram's ladder, or "" when the window is inside
// it.
//
// Split out from run so it can be tested without starting a receiver. run's
// only above-ceiling path is a VALID configuration, so a test that drove this
// through run would parse successfully, fall through to listenAndScore, bind
// sockets and block until the package test timeout — the same failure shape
// TestUndefinedFlagIsRejected hit when --retain became real. A pure function
// makes the warning assertable without ever reaching that path.
func retentionWarning(window time.Duration) string {
	if window < shred.CompletionCeiling {
		return ""
	}
	return fmt.Sprintf(
		"blockcast-shreds: warning: --retain %s is at or above the completion "+
			"histogram's ceiling (%s), so a completion at or above that ceiling is "+
			"reported AS the ceiling and understates, with no bound. The receipt's "+
			"stated %.2f%% error applies below the ceiling only; every other figure "+
			"is exact at any window.",
		window, shred.CompletionCeiling, shred.CompletionRelativeError*100)
}

func selftest(args []string) error {
	flags := flag.NewFlagSet("selftest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	fixture := flags.Bool("fixture", false, "replay the bundled deterministic pcap")
	generic := flags.Bool("generic", false, "replay the deterministic synthetic generic feed")
	asJSON := flags.Bool("json", false, "emit the receipt as JSON instead of the human table")
	if err := flags.Parse(args); err != nil {
		return err
	}
	// Exactly one mode: *fixture == *generic rejects both "neither" and "both",
	// so the selftest can never silently pick a mode the caller did not name.
	if flags.NArg() != 0 || *fixture == *generic {
		return errors.New("usage: blockcast-shreds selftest --fixture | --generic [--json]")
	}
	if *generic {
		scorer := shred.NewGenericScorer(shred.GenericSyntheticSource, shred.GenericSyntheticRightsBasis)
		if err := shred.ReplayGenericFixture(scorer); err != nil {
			return err
		}
		return printReceipt(scorer.Receipt(), *asJSON)
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

// gensend emits the synthetic generic feed as real datagrams so the receipt can
// be driven end-to-end through the demo tap rather than only in-process. It
// sends the same records the selftest scores, so the two paths cannot disagree
// about what the fixture is.
func gensend(args []string) error {
	flags := flag.NewFlagSet("gensend", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	to := flags.String("to", "", "destination IP:PORT, typically the tap's SSM group")
	iface := flags.String("iface", "", "local interface IP to send from; required for same-host multicast")
	pace := flags.Bool("pace", true, "sleep between records to match the fixture's arrival spacing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *to == "" || flags.NArg() != 0 {
		return errors.New("usage: blockcast-shreds gensend --to IP:PORT [--iface IP] [--pace=false]")
	}
	destination, err := net.ResolveUDPAddr("udp4", *to)
	if err != nil {
		return fmt.Errorf("resolve --to %q: %w", *to, err)
	}
	// Binding the source address is what makes same-host SSM work: the tap
	// filters on source, so a datagram leaving an unexpected interface is
	// dropped by the join with no error anywhere.
	var local *net.UDPAddr
	if *iface != "" {
		local = &net.UDPAddr{IP: net.ParseIP(*iface)}
		if local.IP == nil {
			return fmt.Errorf("--iface %q is not an IP address", *iface)
		}
	}
	conn, err := net.DialUDP("udp4", local, destination)
	if err != nil {
		return fmt.Errorf("dial %q: %w", *to, err)
	}
	defer func() { _ = conn.Close() }()

	spec := shred.DefaultGenericFixtureSpec()
	records := spec.Build()
	for _, record := range records {
		if _, err := conn.Write(record.Payload); err != nil {
			return fmt.Errorf("send record: %w", err)
		}
		if *pace {
			time.Sleep(spec.Interval)
		}
	}
	fmt.Printf("gensend source=%s rights=%s records=%d to=%s\n",
		shred.GenericSyntheticSource, shred.GenericSyntheticRightsBasis, len(records), *to)
	return nil
}

func listenAndScore(feeds []feed, destinations []string, httpAddress string, healthMaxAge time.Duration, asJSON bool, retention time.Duration, mode, sourceLabel, rightsBasis string) error {
	names := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		names = append(names, feed.name)
	}
	var scorer sessionScorer
	if mode == "generic" {
		scorer = shred.NewGenericFeedScorer(names, sourceLabel, rightsBasis)
		// The provenance is announced at start, not only in the closing
		// receipt, so a run that is interrupted still has its input labelled.
		// It goes to stderr so --json keeps stdout a single JSON document.
		fmt.Fprintf(os.Stderr, "mode=generic source=%s rights=%s\n", sourceLabel, rightsBasis)
	} else {
		scorer = shred.NewFeedScorerWithRetention(shred.FormatForwarder, names, retention)
	}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, names)
	if err != nil {
		return err
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
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	errCh := make(chan error, len(feeds))
	var sockets []*net.UDPConn
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
				health.MarkReceived(receivedAt)
				_ = metrics.IncIngress(feedName)
				processPacket(feedName, packet[:n], receivedAt, scorer, fanout, metrics)
			}
		}(feed.name, conn)
	}

	select {
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
	// Sockets are closed, but a reader goroutine can still be mid-packet: it may
	// be blocked in Enqueue or between the read and Observe. Both scorers behind
	// sessionScorer take their own lock in Receipt, so the receipt is a
	// consistent snapshot even if a late Observe lands after it.
	return printReceipt(scorer.SessionReceipt(), asJSON)
}

// processPacket delivers a packet and then scores it.
//
// Delivery runs first and is never held up by scoring: malformed and duplicate
// packets must still reach every configured validator destination unchanged.
// Every value used here is internally synchronized — Fanout copies the packet
// under its own lock, both sessionScorer implementations serialize their own
// state, and Health and ReceiverMetrics each carry their own — so feed
// goroutines do not serialize behind a caller-held lock on the ingress hot path.
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
func processPacket(feedName string, packet []byte, receivedAt time.Time, scorer sessionScorer, fanout *receiver.Fanout, metrics *receiver.ReceiverMetrics) {
	if fanout != nil && fanout.Enqueue(feedName, packet) == receiver.EnqueueOverflow {
		_ = metrics.IncFanoutDrop(feedName)
	}
	if _, parseErr := scorer.Observe(feedName, packet, receivedAt); parseErr != nil {
		_ = metrics.IncUnparsed(feedName)
	}
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
