// Command blockcast-shreds is the zero-account demo receiver and verifier.
package main

import (
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
  blockcast-shreds [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...]
  blockcast-shreds selftest --fixture

Demo mode has no broker, certificates, accounts, or heartbeats. --feed is
repeatable for first-arrival-wins scoring across multiple unicast UDP feeds.`

type feeds []string

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
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	addresses := []string{listen}
	if len(configuredFeeds) != 0 {
		addresses = addresses[:0]
		for _, feed := range configuredFeeds {
			_, address, ok := strings.Cut(feed, "=")
			if !ok || address == "" {
				return fmt.Errorf("--feed %q must be NAME=IP:PORT", feed)
			}
			addresses = append(addresses, address)
		}
	}
	return listenAndScore(addresses, splitNonempty(destinations))
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

func listenAndScore(addresses, destinations []string) error {
	var fanout *receiver.Fanout
	var err error
	if len(destinations) != 0 {
		fanout, err = receiver.NewUDPFanout(destinations, 4096)
		if err != nil {
			return err
		}
		defer fanout.Close()
	}

	scorer := shred.NewScorer()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	errCh := make(chan error, len(addresses))
	var sockets []*net.UDPConn
	var mu sync.Mutex
	for _, address := range addresses {
		udpAddress, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return fmt.Errorf("resolve --listen %q: %w", address, err)
		}
		conn, err := net.ListenUDP("udp", udpAddress)
		if err != nil {
			return fmt.Errorf("listen %q: %w", address, err)
		}
		sockets = append(sockets, conn)
		go func(conn *net.UDPConn) {
			packet := make([]byte, 2048)
			for {
				n, _, err := conn.ReadFromUDP(packet)
				if err != nil {
					errCh <- err
					return
				}
				mu.Lock()
				accepted, parseErr := scorer.Observe(packet[:n], time.Now())
				mu.Unlock()
				if parseErr != nil {
					continue
				}
				if accepted && fanout != nil {
					fanout.Enqueue(packet[:n])
				}
			}
		}(conn)
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
