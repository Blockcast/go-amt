// Command blockcast-shreds is the zero-account demo receiver and verifier.
package main

import (
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

	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/shred"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const help = `blockcast-shreds demo mode

Usage:
  blockcast-shreds [--mode shred|generic] [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...] [--http-addr IP:PORT]
  blockcast-shreds selftest --fixture
  blockcast-shreds selftest --generic
  blockcast-shreds gensend --to IP:PORT [--iface IP]

Demo mode has no broker, certificates, accounts, or heartbeats. --feed is
repeatable for first-arrival-wins scoring across multiple unicast UDP feeds.

--mode generic scores generic framed records instead of shreds: the same
delivery receipt, on a payload that isn't shreds. It reports no FEC erasure,
because this mode does no erasure coding. gensend emits the synthetic framed
feed so the receipt can be driven end-to-end through the demo tap.`

// sessionScorer is the seam that keeps shred mode and generic mode one client.
// Both modes are selected once at construction; the packet loop below has no
// mode switch in it.
type sessionScorer interface {
	Observe(feed string, packet []byte, receivedAt time.Time) (bool, error)
	ReceiptString() string
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
	flags.Var(&configuredFeeds, "feed", "repeatable NAME=IP:PORT unicast feed")
	flags.StringVar(&listen, "listen", "0.0.0.0:20000", "unicast UDP listen address")
	flags.StringVar(&destinations, "dest-ip-ports", "", "comma-separated UDP forward destinations")
	flags.StringVar(&httpAddress, "http-addr", "127.0.0.1:8080", "metrics and health HTTP address; empty disables HTTP")
	flags.StringVar(&mode, "mode", "shred", "scoring mode: shred or generic")
	flags.StringVar(&sourceLabel, "source-label", "", "generic mode: provenance of the input, e.g. synthetic")
	flags.StringVar(&rightsBasis, "rights-basis", "", "generic mode: recorded rights basis for the input")
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
	return listenAndScore(configured, splitNonempty(destinations), httpAddress, mode, sourceLabel, rightsBasis)
}

func selftest(args []string) error {
	flags := flag.NewFlagSet("selftest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	fixture := flags.Bool("fixture", false, "replay the bundled deterministic pcap")
	generic := flags.Bool("generic", false, "replay the deterministic synthetic generic feed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *fixture == *generic {
		return errors.New("usage: blockcast-shreds selftest --fixture | --generic")
	}
	if *generic {
		scorer := shred.NewGenericScorer(shred.GenericSyntheticSource, shred.GenericSyntheticRightsBasis)
		if err := shred.ReplayGenericFixture(scorer); err != nil {
			return err
		}
		fmt.Println(scorer.Receipt())
		return nil
	}
	scorer := shred.NewScorer()
	if err := shred.ReplayFixture(scorer); err != nil {
		return err
	}
	fmt.Println(scorer.Receipt())
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

func listenAndScore(feeds []feed, destinations []string, httpAddress, mode, sourceLabel, rightsBasis string) error {
	names := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		names = append(names, feed.name)
	}
	var scorer sessionScorer
	if mode == "generic" {
		scorer = shred.NewGenericFeedScorer(names, sourceLabel, rightsBasis)
		// The provenance is announced at start, not only in the closing
		// receipt, so a run that is interrupted still has its input labelled.
		fmt.Printf("mode=generic source=%s rights=%s\n", sourceLabel, rightsBasis)
	} else {
		scorer = shred.NewFeedScorer(names)
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

	health, err := receiver.NewHealth(30 * time.Second)
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
				mu.Lock()
				receivedAt := time.Now()
				health.MarkReceived(receivedAt)
				_ = metrics.IncIngress(feedName)
				processPacket(feedName, packet[:n], receivedAt, scorer, fanout, metrics)
				mu.Unlock()
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
	mu.Lock()
	fmt.Println(scorer.ReceiptString())
	mu.Unlock()
	return nil
}

func processPacket(feedName string, packet []byte, receivedAt time.Time, scorer sessionScorer, fanout *receiver.Fanout, metrics *receiver.ReceiverMetrics) {
	_, parseErr := scorer.Observe(feedName, packet, receivedAt)
	// Delivery is independent of scoring: malformed and duplicate packets must
	// still reach every configured validator destination unchanged.
	if fanout != nil && !fanout.Enqueue(feedName, packet) {
		_ = metrics.IncFanoutDrop(feedName)
	}
	if parseErr != nil {
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
