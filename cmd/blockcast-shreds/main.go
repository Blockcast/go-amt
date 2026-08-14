// Command blockcast-shreds is the zero-account demo receiver and verifier.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/shred"
)

const help = `blockcast-shreds demo mode

Usage:
  blockcast-shreds [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...] [--json]
  blockcast-shreds selftest --fixture [--json]

Demo mode has no broker, certificates, accounts, or heartbeats. --feed is
repeatable for first-arrival-wins scoring across multiple unicast UDP feeds.
With two or more feeds the receipt reports the measured worth of a second
feed: each feed's own erasure fraction, the union's, and the FEC sets the
extra feeds rescued. It measures this run only — it cannot tell whether the
inputs are independently operated or share one tap.`

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
	var listen, destinations string
	flags.Var(&configuredFeeds, "feed", "repeatable NAME=IP:PORT unicast feed")
	flags.StringVar(&listen, "listen", "0.0.0.0:20000", "unicast UDP listen address")
	flags.StringVar(&destinations, "dest-ip-ports", "", "comma-separated UDP forward destinations")
	asJSON := flags.Bool("json", false, "emit the receipt as JSON instead of the human table")
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
	return listenAndScore(configured, splitNonempty(destinations), *asJSON)
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

func listenAndScore(feeds []feed, destinations []string, asJSON bool) error {
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
				accepted, parseErr := scorer.Observe(feedName, packet[:n], time.Now())
				mu.Unlock()
				if parseErr != nil {
					continue
				}
				if accepted && fanout != nil {
					fanout.Enqueue(packet[:n])
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
	defer mu.Unlock()
	return printReceipt(scorer.Receipt(), asJSON)
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
