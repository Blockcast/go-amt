// Package config parses and validates bcast-shred-gw configuration.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultBindAddress  = "0.0.0.0:0"
	DefaultRcvBufBytes  = 16 << 20
	DefaultErasureGrace = 400 * time.Millisecond
)

// Config contains the transport-independent v1 receiver configuration. The
// broker session supplies each feed's remote UDP endpoint at runtime.
type Config struct {
	FeedIDs      []string
	BindAddress  netip.AddrPort
	Interface    string
	RcvBufBytes  int
	Destinations []netip.AddrPort
	Certificate  string
	PrivateKey   string
	BrokerURL    *url.URL
	ErasureGrace time.Duration
}

// Parse parses bcast-shred-gw command-line arguments and rejects ambiguous or
// unsafe configuration before any broker or socket work starts.
func Parse(args []string) (Config, error) {
	var raw struct {
		feedIDs       string
		bindAddress   string
		interfaceName string
		rcvBufBytes   int
		destinations  string
		certificate   string
		privateKey    string
		brokerURL     string
		graceMS       int
	}

	flags := flag.NewFlagSet("bcast-shred-gw", flag.ContinueOnError)
	flags.SetOutput(new(strings.Builder))
	flags.StringVar(&raw.feedIDs, "feed-ids", "", "comma-separated broker feed IDs")
	flags.StringVar(&raw.bindAddress, "bind-address", DefaultBindAddress, "local UDP IP:port used for outbound feed flows")
	flags.StringVar(&raw.interfaceName, "interface", "", "optional local interface name")
	flags.IntVar(&raw.rcvBufBytes, "rcvbuf-bytes", DefaultRcvBufBytes, "requested UDP receive buffer size")
	flags.StringVar(&raw.destinations, "dest-ip-ports", "", "comma-separated validator destination IP:ports")
	flags.StringVar(&raw.certificate, "cert", "", "mTLS client certificate path")
	flags.StringVar(&raw.privateKey, "key", "", "mTLS client private-key path")
	flags.StringVar(&raw.brokerURL, "broker-url", "", "HTTPS session broker URL")
	flags.IntVar(&raw.graceMS, "erasure-grace-ms", int(DefaultErasureGrace/time.Millisecond), "receiver-observed FEC-set scoring grace in milliseconds")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}

	feedIDs, err := parseUniqueStrings("feed ID", raw.feedIDs)
	if err != nil {
		return Config{}, err
	}
	bindAddress, err := netip.ParseAddrPort(raw.bindAddress)
	if err != nil {
		return Config{}, fmt.Errorf("parse --bind-address: %w", err)
	}
	destinations, err := parseDestinations(raw.destinations)
	if err != nil {
		return Config{}, err
	}
	if raw.rcvBufBytes <= 0 {
		return Config{}, errors.New("--rcvbuf-bytes must be positive")
	}
	if raw.graceMS <= 0 {
		return Config{}, errors.New("--erasure-grace-ms must be positive")
	}
	if strings.TrimSpace(raw.certificate) == "" {
		return Config{}, errors.New("--cert is required")
	}
	if strings.TrimSpace(raw.privateKey) == "" {
		return Config{}, errors.New("--key is required")
	}
	brokerURL, err := url.Parse(raw.brokerURL)
	if err != nil {
		return Config{}, fmt.Errorf("parse --broker-url: %w", err)
	}
	if brokerURL.Scheme != "https" || brokerURL.Host == "" || brokerURL.User != nil {
		return Config{}, errors.New("--broker-url must be an HTTPS URL without user information")
	}

	return Config{
		FeedIDs:      feedIDs,
		BindAddress:  bindAddress,
		Interface:    strings.TrimSpace(raw.interfaceName),
		RcvBufBytes:  raw.rcvBufBytes,
		Destinations: destinations,
		Certificate:  strings.TrimSpace(raw.certificate),
		PrivateKey:   strings.TrimSpace(raw.privateKey),
		BrokerURL:    brokerURL,
		ErasureGrace: time.Duration(raw.graceMS) * time.Millisecond,
	}, nil
}

func parseDestinations(value string) ([]netip.AddrPort, error) {
	items, err := parseUniqueStrings("destination", value)
	if err != nil {
		return nil, err
	}
	destinations := make([]netip.AddrPort, 0, len(items))
	for _, item := range items {
		destination, err := netip.ParseAddrPort(item)
		if err != nil {
			return nil, fmt.Errorf("parse destination %q: %w", item, err)
		}
		if destination.Addr().IsUnspecified() || destination.Addr().IsMulticast() || destination.Port() == 0 {
			return nil, fmt.Errorf("destination %q must be a unicast IP with a non-zero port", item)
		}
		destinations = append(destinations, destination)
	}
	return destinations, nil
}

func parseUniqueStrings(name, value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("at least one %s is required", name)
	}
	seen := make(map[string]struct{})
	items := strings.Split(value, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("%s is empty", name)
		}
		if _, exists := seen[item]; exists {
			return nil, fmt.Errorf("%s %q is configured more than once", name, item)
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result, nil
}
