// Package config parses and validates bcast-shred-gw configuration.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBindAddress  = "0.0.0.0:0"
	DefaultRcvBufBytes  = 16 << 20
	DefaultErasureGrace = 400 * time.Millisecond
	maxDurationMillis   = (1<<63 - 1) / int64(time.Millisecond)
)

// Config contains the transport-independent v1 receiver configuration. The
// broker session supplies each feed's remote UDP endpoint at runtime.
//
// There are deliberately no Certificate/PrivateKey fields. They existed here,
// populated from required --cert/--key flags, while nothing in this repository
// imported crypto/tls, crypto/x509, or a gRPC client — so the flags obliged an
// operator to supply mTLS material and then ignored it. A required flag that is
// ignored is worse than a missing feature: it reads as evidence the transport
// is authenticated. They are removed rather than stubbed, so that whoever adds
// the broker client has to add the flags back alongside a real *tls.Config and
// cannot inherit the appearance of one. See BLO-29728.
type Config struct {
	FeedIDs      []string
	BindAddress  netip.AddrPort
	Interface    string
	RcvBufBytes  int
	Destinations []netip.AddrPort
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
	bindAddress = netip.AddrPortFrom(bindAddress.Addr().Unmap(), bindAddress.Port())
	if bindAddress.Addr().IsMulticast() {
		return Config{}, errors.New("--bind-address must not be multicast")
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
	if int64(raw.graceMS) > maxDurationMillis {
		return Config{}, errors.New("--erasure-grace-ms exceeds the maximum supported duration")
	}
	brokerURL, err := url.Parse(raw.brokerURL)
	if err != nil {
		return Config{}, fmt.Errorf("parse --broker-url: %w", err)
	}
	if !strings.EqualFold(brokerURL.Scheme, "https") || brokerURL.Hostname() == "" || brokerURL.User != nil {
		return Config{}, errors.New("--broker-url must be an HTTPS URL without user information")
	}
	if port := brokerURL.Port(); port != "" {
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil || portNumber == 0 {
			return Config{}, errors.New("--broker-url port must be between 1 and 65535")
		}
	}

	return Config{
		FeedIDs:      feedIDs,
		BindAddress:  bindAddress,
		Interface:    strings.TrimSpace(raw.interfaceName),
		RcvBufBytes:  raw.rcvBufBytes,
		Destinations: destinations,
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
	seen := make(map[netip.AddrPort]struct{}, len(items))
	for _, item := range items {
		destination, err := netip.ParseAddrPort(item)
		if err != nil {
			return nil, fmt.Errorf("parse destination %q: %w", item, err)
		}
		destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
		if (!destination.Addr().IsGlobalUnicast() && !destination.Addr().IsLoopback()) || destination.Port() == 0 {
			return nil, fmt.Errorf("destination %q must be a unicast IP with a non-zero port", item)
		}
		if _, exists := seen[destination]; exists {
			return nil, fmt.Errorf("destination %q resolves to a duplicate address", item)
		}
		seen[destination] = struct{}{}
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
