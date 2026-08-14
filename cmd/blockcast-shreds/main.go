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
  blockcast-shreds [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...] [--http-addr IP:PORT]
  blockcast-shreds selftest --fixture

Demo mode has no broker, certificates, accounts, or heartbeats. --feed is
repeatable for first-arrival-wins scoring across multiple unicast UDP feeds.`

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
	flags.Var(&configuredFeeds, "feed", "repeatable NAME=IP:PORT unicast feed")
	flags.StringVar(&listen, "listen", "0.0.0.0:20000", "unicast UDP listen address")
	flags.StringVar(&destinations, "dest-ip-ports", "", "comma-separated UDP forward destinations")
	flags.StringVar(&httpAddress, "http-addr", "127.0.0.1:8080", "metrics and health HTTP address; empty disables HTTP")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
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
	return listenAndScore(configured, splitNonempty(destinations), httpAddress)
}

func selftest(args []string) error {
	flags := flag.NewFlagSet("selftest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	fixture := flags.Bool("fixture", false, "replay the bundled deterministic pcap")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*fixture || flags.NArg() != 0 {
		return errors.New("usage: blockcast-shreds selftest --fixture")
	}
	scorer := shred.NewScorer()
	if err := shred.ReplayFixture(scorer); err != nil {
		return err
	}
	fmt.Println(scorer.Receipt())
	return nil
}

func listenAndScore(feeds []feed, destinations []string, httpAddress string) error {
	var fanout *receiver.Fanout
	var err error
	if len(destinations) != 0 {
		fanout, err = receiver.NewUDPFanout(destinations, 4096)
		if err != nil {
			return err
		}
		defer fanout.Close()
	}

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
				accepted, parseErr := scorer.Observe(feedName, packet[:n], receivedAt)
				mu.Unlock()
				if parseErr != nil {
					_ = metrics.IncUnparsed(feedName)
					continue
				}
				if accepted && fanout != nil {
					if !fanout.Enqueue(packet[:n]) {
						_ = metrics.IncFanoutDrop(feedName)
					}
				}
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
	fmt.Println(scorer.Receipt())
	mu.Unlock()
	return nil
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
