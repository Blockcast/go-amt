// Command blockcast-shreds is the zero-account demo receiver and verifier.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/blockcast/go-amt/broker"
	"github.com/blockcast/go-amt/broker/gwclient"
	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/receiver/config"
	"github.com/blockcast/go-amt/receiver/delivery"
	"github.com/blockcast/go-amt/shred"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// defaultReportInterval matches the broker heartbeat cadence. /metrics and the
// heartbeat must publish the same window or the two SLA surfaces disagree, so
// the scrape shows the last drained window rather than a live partial count.
const defaultReportInterval = 30 * time.Second

// maxReportInterval bounds --report-interval from above.
//
// The original bound was justified by arrival retention: the tracker kept one
// 24-byte timestamp per accepted shred until the window drained, which made
// --report-interval 1h ask for ~2.5 GiB at 30k shred/s -- an OOM reachable
// through a plausible operator setting. BLO-28451 replaced that slice with a
// fixed-size streaming fold, so that justification no longer holds and the
// figure is not merely smaller, it is gone: delivery retention is now O(1) in
// the shred count.
//
// The bound is kept, for two weaker but real reasons. First, one 32-byte score
// event still accumulates per COMPLETED FEC SET until the window drains, so
// retention still grows linearly with the interval -- just per set rather than
// per shred, a 64x smaller slope. Measured: 0.4 MiB at the 30s default and
// 51.5 MiB at 1h, both at 30k shred/s. That is worth capping and is no longer
// worth calling an OOM. Second, and now the primary reason, erasure_fraction is
// a windowed gauge: at hour-long windows it stops being an SLA signal an
// operator can alert on, because a single bad minute is averaged into 59 good
// ones and the discontinuity a frontier resync introduces is invisible. 5
// minutes is well past any broker heartbeat cadence and caps the same feed near
// 4.3 MiB.
const maxReportInterval = 5 * time.Minute

const help = `blockcast-shreds demo mode

Usage:
  blockcast-shreds [--mode shred|generic] [--feed NAME=IP:PORT]... [--listen IP:PORT] [--dest-ip-ports IP:PORT,...] [--http-addr IP:PORT] [--health-max-age DURATION] [--retain DURATION] [--json]
   blockcast-shreds [--broker-url URL --gw-uuid UUID --broker-client-cert FILE --broker-client-key FILE]
  blockcast-shreds selftest --fixture [--json]
  blockcast-shreds selftest --generic [--json]
  blockcast-shreds gensend --to IP:PORT [--iface IP] [--pace=false]
  blockcast-shreds --version

Demo mode has no broker, certificates or accounts, and sends no heartbeats.
--feed is repeatable for first-arrival-wins scoring across multiple unicast
UDP feeds. With two or more feeds the receipt reports the measured worth of a
second feed: each feed's own erasure fraction, the union's, and the FEC sets
the extra feeds rescued. It measures this run only — it cannot tell whether
the inputs are independently operated or share one tap.

--broker-url and --gw-uuid opt into the gateway heartbeat and must be given
together: a broker URL without an identity produces heartbeats the broker
rejects, and an identity without a URL is inert but looks configured. When
enabled, the receiver POSTs a per-feed liveness and delivery report every 30s.
--broker-client-cert and --broker-client-key are required together with the
heartbeat flags; --broker-ca may add the broker's issuing CA to system roots.
Omitting both — the default — keeps demo mode heartbeat-free. They require
--mode shred: the report carries a per-feed erasure window, and generic mode
does no erasure scoring, so the pair is rejected at startup there rather than
emitting a beat the broker discards.

--version prints the build-stamped version reported in every heartbeat and
exits, without requiring a valid receiver configuration.

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
It does not bound completion percentiles: a set that keeps receiving is never
evicted, so its span can exceed the histogram's ceiling at any window. The
receipt reports completions_above_ceiling when that happened; a nonzero value
means time_to_32nd_shred understates. See the README.`

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
	// Handled before flag parsing, alongside the subcommands, rather than as a
	// flag: every other invocation requires at least one --feed, so a
	// --version registered on the FlagSet would still fall through to config
	// validation and exit non-zero with "no feeds configured". A release
	// pipeline asking a binary what it is must not need a valid receiver
	// configuration to get an answer.
	//
	// This prints broker.Version() — the Go build-stamped symbol the heartbeat
	// reports — and is what the packaging workflow asserts is not
	// "dev-unstamped". It is deliberately NOT amt.Version(), which is the Rust
	// library's version behind CGO and does not exist in this CGO_ENABLED=0
	// binary at all.
	if len(args) != 0 && (args[0] == "--version" || args[0] == "-version" || args[0] == "version") {
		fmt.Println(broker.Version())
		return nil
	}
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
	var listen, destinations, httpAddress string
	var healthMaxAge time.Duration
	flags.Var(&configuredFeeds, "feed", "repeatable NAME=IP:PORT unicast feed")
	flags.StringVar(&listen, "listen", "0.0.0.0:20000", "unicast UDP listen address")
	flags.StringVar(&destinations, "dest-ip-ports", "", "comma-separated UDP forward destinations")
	asJSON := flags.Bool("json", false, "emit the receipt as JSON instead of the human table")
	flags.StringVar(&httpAddress, "http-addr", "127.0.0.1:8080", "metrics and health HTTP address; empty disables HTTP")
	score := scoringFlags(flags)
	flags.DurationVar(&healthMaxAge, "health-max-age", 30*time.Second, "/healthz ingress freshness window; readiness-shaped, see README")
	graceMS := flags.Int("erasure-grace-ms", int(config.DefaultErasureGrace/time.Millisecond),
		"receiver-observed FEC-set scoring grace in milliseconds; a set still below 32 of 64 shreds at slot_boundary plus this grace scores erased")
	reportInterval := flags.Duration("report-interval", defaultReportInterval,
		"how often the delivery window is drained into /metrics; matches the broker heartbeat cadence")
	retention := flags.Duration("retain", shred.DefaultRetention, "how far behind the newest arrival to keep per-shred scoring state; see README")
	deliveryWAL := flags.String("delivery-wal", "",
		"path to the delivery-session sequence WAL; enables per-destination billing records, requires --delivery-records")
	deliveryRecords := flags.String("delivery-records", "",
		"path to the delivery-session record file (JSON lines); requires --delivery-wal")
	brokerURL := flags.String("broker-url", "",
		"session broker base URL; enables the gateway heartbeat, requires --gw-uuid")
	gwUUID := flags.String("gw-uuid", "",
		"this gateway's canonical lowercase UUID, reported in every heartbeat; requires --broker-url")
	brokerClientCert := flags.String("broker-client-cert", "", "PEM client certificate for the HTTPS session broker")
	brokerClientKey := flags.String("broker-client-key", "", "PEM private key for --broker-client-cert")
	brokerCA := flags.String("broker-ca", "", "PEM CA bundle for the HTTPS session broker")
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
	if *reportInterval > maxReportInterval {
		return fmt.Errorf("--report-interval must not exceed %s: erasure_fraction is a windowed gauge, so a longer window stops being a signal an operator can alert on, and one score event per completed FEC set is retained until the window drains", maxReportInterval)
	}
	if err := score.validate(); err != nil {
		return err
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
	// An early hint only, and deliberately not the guarantee's enforcement. A
	// window at or above the ladder's ceiling is an egregious case worth naming at
	// startup, but its ABSENCE proves nothing: --retain does not bound a set's
	// completion span (a set is aged on its newest arrival, so one that keeps
	// receiving is never evicted), so completions above the ceiling occur at the
	// default window too. The authoritative signal is the receipt's
	// completions_above_ceiling, which counts the condition where it happens
	// instead of predicting it from a quantity that cannot see it.
	if warning := retentionWarning(*retention); warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}
	forwardTo := splitNonempty(destinations)
	// Warns and continues, by design: N crossing the revisit threshold is a
	// capacity-planning signal, and refusing to start would convert it into an
	// outage for a configuration that still delivers correctly.
	if warning := destinationCountWarning(len(forwardTo)); warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}
	bill, err := billingOptions(*deliveryWAL, *deliveryRecords, forwardTo)
	if err != nil {
		return err
	}
	beat, err := heartbeatOptions(*brokerURL, *gwUUID, *brokerClientCert, *brokerClientKey, *brokerCA, *score)
	if err != nil {
		return err
	}
	return listenAndScore(configured, forwardTo, httpAddress, healthMaxAge, *asJSON,
		time.Duration(*graceMS)*time.Millisecond, *reportInterval, *retention, nil, *score, bill, beat)
}

// billing holds the delivery-session record configuration. A zero value
// disables billing, which is what every existing invocation gets.
type billing struct {
	walPath    string
	recordPath string
}

func (b billing) enabled() bool { return b.walPath != "" }

// heartbeatConfig holds the gateway heartbeat producer's configuration. A zero
// value disables the heartbeat, which is what every existing invocation gets:
// the demo receiver and the smoke test have no broker to report to, and a
// receiver that failed to start because it could not reach one would be a
// regression for them.
type heartbeatConfig struct {
	brokerURL  string
	gwUUID     string
	clientCert string
	clientKey  string
	caBundle   string
}

func (h heartbeatConfig) enabled() bool { return h.brokerURL != "" }

// heartbeatOptions validates the heartbeat flags as a set, against the scoring
// mode they will run under.
//
// Both or neither: a broker URL with no gateway identity produces heartbeats
// the broker rejects for an invalid gw_uuid, and a gateway identity with no
// broker URL is a silently inert configuration that looks configured. Failing
// at startup is the point — the alternative surfaces 30 seconds later as a
// rejected heartbeat with no obvious cause.
//
// Generic mode is rejected outright for the same reason, one layer deeper. The
// heartbeat's FeedReport carries a mandatory erasure window, and erasure
// scoring is shred-only: listenAndScore deliberately builds NO trackers in
// generic mode, so nothing ever publishes a window, every feed keeps the zero
// erasure.Window whose Schema is 0, and ValidateHeartbeat — whose floor is 1 —
// rejects the whole beat. Producer.Run only logs that rejection, so the
// gateway would send nothing at all while every flag read as configured. That
// is the silent-inert shape this function already exists to prevent.
//
// The alternative — synthesizing a window to satisfy the schema — is refused
// deliberately, and not only here: the pre-flight drain in listenAndScore
// performs a REAL drain precisely so the producer never reports a delivery
// figure it did not measure, and a zero erasure window reads as a PERFECT
// feed. Fabricating one would turn an unmeasured feed into a clean SLA record,
// which is the confusion the erasure contract exists to prevent.
//
// TestGenericModeHeartbeatIsUnsendable pins the underlying failure, so if
// generic mode ever gains a real window this rejection can be revisited
// against evidence rather than removed on assumption.
func heartbeatOptions(brokerURL, gwUUID, clientCert, clientKey, caBundle string, mode scoring) (heartbeatConfig, error) {
	switch {
	case brokerURL == "" && gwUUID == "":
		if clientCert != "" || clientKey != "" || caBundle != "" {
			return heartbeatConfig{}, errors.New("broker TLS flags require --broker-url and --gw-uuid")
		}
		return heartbeatConfig{}, nil
	case brokerURL == "":
		return heartbeatConfig{}, errors.New("--gw-uuid requires --broker-url")
	case gwUUID == "":
		return heartbeatConfig{}, errors.New("--broker-url requires --gw-uuid")
	case clientCert == "" || clientKey == "":
		return heartbeatConfig{}, errors.New("--broker-client-cert and --broker-client-key are required for broker mTLS")
	case mode.generic():
		return heartbeatConfig{}, errors.New(
			"--broker-url and --gw-uuid require --mode shred: the heartbeat reports a " +
				"per-feed erasure window, generic mode does no erasure scoring, and a " +
				"synthesized zero window would report an unmeasured feed as a perfect one")
	}
	return heartbeatConfig{brokerURL: brokerURL, gwUUID: gwUUID, clientCert: clientCert, clientKey: clientKey, caBundle: caBundle}, nil
}

func heartbeatHTTPClient(beat heartbeatConfig) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(beat.clientCert, beat.clientKey)
	if err != nil {
		return nil, fmt.Errorf("load broker client certificate: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate pool: %w", err)
	}
	if beat.caBundle != "" {
		pem, err := os.ReadFile(beat.caBundle)
		if err != nil {
			return nil, fmt.Errorf("read broker CA bundle: %w", err)
		}
		if ok := roots.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("broker CA bundle %q contains no certificates", beat.caBundle)
		}
	}
	return &http.Client{
		Timeout: broker.HeartbeatInterval - 5*time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		}},
	}, nil
}

// billingOptions validates the delivery-session flags as a set.
//
// The two paths are all-or-nothing, and both are refused without a fan-out
// destination: sessions are opened per destination, so billing with nothing to
// forward to would open a WAL, emit no records, and look configured while
// producing nothing — the exact silent-no-op this issue exists to remove.
func billingOptions(walPath, recordPath string, destinations []string) (billing, error) {
	walPath = strings.TrimSpace(walPath)
	recordPath = strings.TrimSpace(recordPath)
	switch {
	case walPath == "" && recordPath == "":
		return billing{}, nil
	case walPath == "":
		return billing{}, errors.New("--delivery-records requires --delivery-wal")
	case recordPath == "":
		return billing{}, errors.New("--delivery-wal requires --delivery-records")
	case len(destinations) == 0:
		return billing{}, errors.New("--delivery-wal requires at least one --dest-ip-ports destination to bill")
	}
	return billing{walPath: walPath, recordPath: recordPath}, nil
}

// retentionWarning returns an early-hint warning for a retention window at or
// above the completion histogram's ceiling, or "" otherwise.
//
// Read the contract carefully, because the first version of this function got it
// wrong in a way that was worse than saying nothing. A window >= the ceiling is
// sufficient to expect understated percentiles, but it is NOT necessary: the
// window bounds the inter-arrival gap, not the completion span, so 32 shreds
// 200ms apart span 6.2s at the 2s default and understate with this function
// silent. Treating that silence as "safe" is the error — the receipt's
// CompletionsAboveCeiling is the real signal, observed rather than predicted.
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
			"histogram's ceiling (%s), so completions at or above that ceiling are "+
			"reported AS the ceiling and understate. This is a hint, not a bound: a "+
			"narrower window understates too, because --retain does not limit how "+
			"long a set takes to complete. Check completions_above_ceiling on the "+
			"receipt — nonzero means the stated %.2f%% error does not apply.",
		window, shred.CompletionCeiling, shred.CompletionRelativeError*100)
}

// destinationCountWarning returns a startup warning when the configured
// destination count crosses receiver.RevisitThresholdDestinations, or "".
//
// The fan-out was designed to a BOUNDED N with an explicit revisit trigger
// (BLO-25708, document n65-revisit-trigger §6), and until this existed that
// trigger lived only in the document — nothing in the binary bounded N, which
// is exactly how a deliberate "unicast first" becomes an accidental "unicast
// forever". Nobody fires a trigger they have to remember.
//
// It warns and continues. Above the threshold the configuration is still
// correct and still delivers; what has changed is that the economics are
// approaching a re-architecture, which is a planning input, not a fault. A
// startup refusal here would take a working feed down over a capacity forecast.
//
// A pure function for the same reason retentionWarning is one: a large
// destination list is a VALID configuration, so driving this through run would
// parse, fall through to listenAndScore, bind sockets and block until the
// package test timeout. Here it is assertable without opening a socket.
func destinationCountWarning(count int) string {
	if count <= receiver.RevisitThresholdDestinations {
		return ""
	}
	return fmt.Sprintf(
		"blockcast-shreds: warning: %d configured --dest-ip-ports destinations is "+
			"above the N=%d revisit threshold for unicast fan-out. The measured "+
			"crossover where one multicast tree beats N unicast streams is N~%d "+
			"(BLO-25708, document n65-revisit-trigger). Starting anyway: this is a "+
			"capacity-planning signal, not an error, and the feed still delivers "+
			"correctly. Escalate the revisit before N reaches %d, and note the "+
			"crossover itself is modelled on a dummy netdev and wants a real-NIC "+
			"measurement before it is trusted as an absolute.",
		count, receiver.RevisitThresholdDestinations,
		receiver.MulticastCrossoverDestinations, receiver.MulticastCrossoverDestinations)
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

// scoring names the scoring mode and its generic-mode provenance.
//
// These three travelled as adjacent positional strings at the tail of an
// already-long signature. Reordering them -- or adding a fourth label --
// would still compile at every call site while scoring the wrong thing and
// stamping the wrong provenance, and the tests would go on passing. Naming
// the fields makes that a compile error instead.
type scoring struct {
	// _ forces every literal a call site would plausibly write to be keyed.
	// Without it an unkeyed literal is writable, and the distinct types
	// below do NOT save it: untyped string CONSTANTS convert to any ~string
	// type, so scoring{"", "", "shred"} -- mode and rightsBasis transposed
	// -- compiled clean and passed `go vet` (which only flags unkeyed
	// literals for imported structs, never same-package ones). The blank
	// field makes the arity wrong, so that bare-constant form no longer
	// builds.
	//
	// KNOWN RESIDUAL, accepted: the guard breaks the arity of the natural
	// 3-value form, not the unkeyed class as a whole. A blank field is
	// fillable, so the 4-value form scoring{struct{}{}, "", "", "shred"}
	// carries the same transposition and still compiles clean under `go
	// vet`. Nothing rejects it -- not the arity, not the types. It survives
	// only because nobody writes struct{}{} by accident; every real
	// construction site here is keyed. Closing it properly would mean
	// moving scoring to its own package so vet's composites check sees an
	// imported struct, which trades a compile error for a lint and is a
	// far wider change than the hazard warrants.
	_ struct{}

	mode        scoringMode
	sourceLabel scoringSource
	rightsBasis scoringRights
}

// The three fields carry DISTINCT defined types rather than three plain
// strings, which closes the case the blank field above cannot see: a KEYED
// literal built from typed values, scoring{sourceLabel: s.rightsBasis, ...},
// is correctly-keyed and correctly-shaped yet still transposed. Only the types
// reject it.
//
// The two guards are complementary, not redundant -- each catches a swap the
// other admits. Neither alone satisfies BLO-28993; both together do. One class
// escapes both, and is documented as an accepted residual on the guard field
// above: an unkeyed literal that fills the blank field explicitly.
type (
	scoringMode   string
	scoringSource string
	scoringRights string
)

// Distinct types are still not enough on their own. An explicit conversion
// accepts ANY string, so building the struct from three plain string locals --
// scoring{sourceLabel: scoringSource(rightsBasis), ...} -- launders the swap
// back through the type system and compiles cleanly. The conversion has to
// happen somewhere, so it happens exactly once per field, here, keyed by flag
// name, and never again at a construction site.
type stringFlag[T ~string] struct{ target *T }

func (f stringFlag[T]) String() string {
	if f.target == nil {
		return ""
	}
	return string(*f.target)
}

func (f stringFlag[T]) Set(value string) error {
	*f.target = T(value)
	return nil
}

// scoringFlags registers the three scoring flags, each bound straight to its
// own typed field. Because no caller ever writes a conversion, no caller can
// write the wrong one.
func scoringFlags(flags *flag.FlagSet) *scoring {
	score := &scoring{mode: "shred"}
	flags.Var(stringFlag[scoringMode]{&score.mode}, "mode", "scoring mode: shred or generic")
	flags.Var(stringFlag[scoringSource]{&score.sourceLabel}, "source-label", "generic mode: provenance of the input, e.g. synthetic")
	flags.Var(stringFlag[scoringRights]{&score.rightsBasis}, "rights-basis", "generic mode: recorded rights basis for the input")
	return score
}

// validate rejects mode/label combinations that would produce a receipt whose
// provenance is unstated or misattributed.
func (s scoring) validate() error {
	switch s.mode {
	case "shred":
		if s.sourceLabel != "" || s.rightsBasis != "" {
			return errors.New("--source-label and --rights-basis apply to --mode generic only")
		}
	case "generic":
		// Both labels are mandatory rather than defaulted. A generic receipt
		// whose input provenance is unstated is the artifact the rights
		// guardrail exists to prevent, and defaulting to "synthetic" would let
		// a real capture be scored under a synthetic label by omission.
		if s.sourceLabel == "" || s.rightsBasis == "" {
			return errors.New("--mode generic requires --source-label and --rights-basis")
		}
	default:
		return fmt.Errorf("--mode %q must be shred or generic", s.mode)
	}
	return nil
}

func (s scoring) generic() bool { return s.mode == "generic" }

// listenAndScore serves every configured feed until stop is closed or a socket
// fails. stop may be nil, in which case only a signal or a socket error ends it.
func listenAndScore(feeds []feed, destinations []string, httpAddress string, healthMaxAge time.Duration, asJSON bool, grace, reportInterval, retention time.Duration, stop <-chan struct{}, mode scoring, bill billing, beat heartbeatConfig) error {
	names := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		names = append(names, feed.name)
	}
	var scorer sessionScorer
	if mode.generic() {
		scorer = shred.NewGenericFeedScorerWithRetention(names, string(mode.sourceLabel), string(mode.rightsBasis), retention)
		// The provenance is announced at start, not only in the closing
		// receipt, so a run that is interrupted still has its input labelled.
		// It goes to stderr so --json keeps stdout a single JSON document.
		fmt.Fprintf(os.Stderr, "mode=generic source=%s rights=%s\n", mode.sourceLabel, mode.rightsBasis)
	} else {
		scorer = shred.NewFeedScorerWithRetention(shred.FormatForwarder, names, retention)
	}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, names)
	if err != nil {
		return err
	}

	// One tracker per feed. The delivery SLA is per feed, and a shared tracker
	// would let a healthy feed mask an erased one behind a pooled fraction.
	windowStart := time.Now()
	// Erasure scoring is shred-only. Generic mode does no erasure coding, so a
	// tracker there would never be fed -- shred.Parse rejects a generic record
	// -- and publishWindows would then drain an empty window every interval and
	// publish zeros. A zero erasure window reads as a perfect feed, which is the
	// exact confusion the drain-failure path below refuses to create. Leaving
	// the map empty makes trackers[feed] nil, which processPacket treats as
	// "erasure scoring disabled" without touching delivery.
	trackers := make(map[string]*erasure.Tracker, len(names))
	if !mode.generic() {
		for _, name := range names {
			tracker, err := erasure.NewTracker(grace, windowStart)
			if err != nil {
				return fmt.Errorf("erasure tracker for feed %q: %w", name, err)
			}
			trackers[name] = tracker
		}
	}
	var brokerClient *http.Client
	var targetReader *gwclient.DeliveryTargetReader
	var brokerTargets []receiver.Target
	if beat.enabled() {
		brokerClient, err = heartbeatHTTPClient(beat)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			return errors.New("broker delivery targets require at least one feed")
		}
		if len(names) > 1 {
			return errors.New("broker delivery targets support exactly one feed")
		}
		targetReader, err = gwclient.NewDeliveryTargetReader(beat.brokerURL, names[0], brokerClient)
		if err != nil {
			return err
		}
		initial, readErr := targetReader.Read(context.Background())
		if readErr != nil {
			return fmt.Errorf("read initial broker delivery targets: %w", readErr)
		}
		brokerTargets = gwclient.ReceiverTargets(initial)
	}

	// The fan-out is constructed after the metrics so the worker can attribute
	// each delivered datagram back to the feed that received it.
	var fanout *receiver.Fanout
	if beat.enabled() || len(destinations) != 0 {
		if beat.enabled() {
			fanout, err = receiver.NewUDPFanoutTargetsAllowEmpty(brokerTargets, 4096, metrics)
		} else {
			fanout, err = receiver.NewUDPFanout(destinations, 4096, metrics)
		}
		if err != nil {
			return err
		}
		defer fanout.Close()
		// The per-destination ledger is registered separately from the feed
		// metrics because it can only be built once the fan-out exists, and it
		// answers a different question: the feed series are summed over
		// destinations, so they cannot show one subscriber falling behind.
		if _, err := receiver.NewDestinationMetrics(registry, fanout); err != nil {
			return err
		}
	}

	// Delivery-session billing. The Reporter converts the fan-out's cumulative
	// per-destination ledger into the delta-shaped records the W3 wire contract
	// wants; see receiver/delivery/reporter.go for why that conversion is not
	// optional. It is driven only from the reporter goroutine below and from the
	// shutdown path after that goroutine has been joined, so it needs no lock of
	// its own.
	var biller *delivery.Reporter
	if bill.enabled() {
		wal, err := delivery.OpenWAL(bill.walPath)
		if err != nil {
			return err
		}
		defer wal.Close()
		recordFile, err := delivery.OpenRecordFile(bill.recordPath)
		if err != nil {
			return err
		}
		defer recordFile.Close()
		sink, err := delivery.NewWriterSink(recordFile)
		if err != nil {
			return err
		}
		tracker, err := delivery.NewTracker(wal)
		if err != nil {
			return err
		}
		if biller, err = delivery.NewReporter(tracker, sink); err != nil {
			return err
		}
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
				// Billing rides the same cadence as the window drain so a
				// record interval and a metrics window describe the same span,
				// which is what lets the /metrics ledger cross-check the
				// records at all.
				billDestinations(biller, fanout)
				if targetReader != nil {
					if err := reconcileBrokerDeliveryTargets(context.Background(), targetReader, fanout, biller); err != nil {
						// Keep the last-known-good target table on a failed poll.
						fmt.Fprintln(os.Stderr, "delivery-target reconcile:", err)
					}
				}
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

	if beat.enabled() {
		// Drain every feed once BEFORE the first heartbeat can be built.
		//
		// A feed whose window has never been drained holds the zero
		// erasure.Window, whose Schema is 0, and broker.ValidateHeartbeat
		// rejects any schema outside [1,2]. That rejection is whole-heartbeat,
		// so a single never-drained feed discards the liveness of every other
		// feed in the beat. The reporter above is a plain ticker whose first
		// tick is one --report-interval away, and that interval is legal up to
		// five minutes, so without this drain a gateway would emit nothing
		// valid for up to ten consecutive heartbeats at startup -- exactly the
		// silent-feed window an SLA dispute is about.
		//
		// This is the same argument the final drain below already makes, at the
		// other end of the process: a run shorter than one report interval must
		// not report nothing but zeros. Draining here costs one extra window
		// whose span is microseconds (window_ms floors at 1ms) and whose counts
		// are zero, which the contract explicitly admits -- and it is a REAL
		// drain rather than a synthesized report, so the producer never has to
		// fabricate a delivery figure it did not measure.
		//
		// TestBuildRejectsANeverDrainedFeed in broker/gwclient states the
		// consequence if this is ever removed.
		publishWindows(trackers, metrics, time.Now())

		producer, err := gwclient.NewProducer(beat.gwUUID, beat.brokerURL, metrics, gwclient.WithHTTPClient(brokerClient))
		if err != nil {
			return err
		}
		// Cancelled by the deferred stop below, which runs on every exit path,
		// so the producer cannot outlive the receiver whose feeds it reports.
		heartbeatCtx, stopHeartbeat := context.WithCancel(context.Background())
		defer stopHeartbeat()
		heartbeatDone := make(chan struct{})
		go func() {
			defer close(heartbeatDone)
			_ = producer.Run(heartbeatCtx)
		}()
		defer func() {
			stopHeartbeat()
			<-heartbeatDone
		}()
	}

	// closeSessions emits the final record per destination. It runs after
	// stopReporter has joined the reporter goroutine, so the Reporter is only
	// ever touched from one goroutine at a time and needs no lock.
	//
	// It is deferred as well as called on the clean path: an error return that
	// unwinds from here still owes every open session a terminating record, and
	// a session with no final record is an invoice with no end.
	closeSessions := sync.OnceFunc(func() {
		stopReporter()
		if biller == nil {
			return
		}
		// Drain the fan-out BEFORE reading the ledger for the last time.
		//
		// Enqueue accepting a packet is not the same event as the worker
		// delivering it: accepted packets sit in a 4096-deep queue and only
		// reach the per-destination ledger when the worker writes them.
		// Fanout.Close closes that queue and waits for the worker, which
		// delivers everything still queued -- so sampling before Close bills a
		// ledger that is about to grow, and those bytes are delivered but never
		// appear in any record. The deferred fanout.Close below is a closeOnce,
		// so calling it here is safe and simply makes the ordering explicit
		// rather than dependent on defer unwinding order.
		if fanout != nil {
			if err := fanout.Close(); err != nil {
				fmt.Fprintln(os.Stderr, "fan-out close:", err)
			}
		}
		if err := biller.CloseAll(ledgerSamples(fanout), delivery.CloseShutdown); err != nil {
			fmt.Fprintln(os.Stderr, "delivery-session close:", err)
		}
		if pending := biller.Pending(); pending != 0 {
			// Bytes were accounted for but never accepted by the sink, so they
			// will not be billed. Say so rather than exiting 0 in silence.
			fmt.Fprintf(os.Stderr, "delivery-session records unshipped: %d\n", pending)
		}
	})
	defer closeSessions()

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
				_ = metrics.ObserveIngress(feedName, n, receivedAt)
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
	// Same argument for billing: a run shorter than one report interval has
	// delivered bytes and emitted no record, so the final close is where its
	// entire traffic gets billed.
	closeSessions()
	// Sockets are closed, but a reader goroutine can still be mid-packet: it may
	// be blocked in Enqueue or between the read and Observe. Both scorers behind
	// sessionScorer take their own lock in Receipt, so the receipt is a
	// consistent snapshot even if a late Observe lands after it.
	return printReceipt(scorer.SessionReceipt(), asJSON)
}

// ledgerSamples reads the fan-out's per-destination ledger as delivery samples.
// A nil fan-out yields none, which is the no-destinations case.
func ledgerSamples(fanout *receiver.Fanout) []delivery.LedgerSample {
	if fanout == nil {
		return nil
	}
	stats := fanout.DestinationStats()
	samples := make([]delivery.LedgerSample, 0, len(stats))
	for _, stat := range stats {
		samples = append(samples, delivery.LedgerSample{
			// The stable target ID is the billing identity, and carrying it
			// here is what keeps a re-granted subscriber on one session and
			// keeps two subscribers sharing an address on two. The address
			// rides along as endpoint metadata only.
			TargetID:    stat.TargetID,
			Destination: stat.Destination,
			// These are cumulative process-lifetime totals. The Reporter is
			// what turns them into the per-interval deltas the record carries;
			// passing them anywhere that expects an increment double-bills.
			Bytes:   stat.Bytes,
			Packets: stat.Packets,
		})
	}
	return samples
}

// billDestinations folds one ledger reading into the delivery sessions and
// emits a record per destination. Billing errors are reported and not fatal: a
// record that cannot ship is retained for retransmission by the Reporter, and
// dropping the feed because an invoice was late would be the wrong trade.
func billDestinations(biller *delivery.Reporter, fanout *receiver.Fanout) {
	if biller == nil {
		return
	}
	if err := biller.Tick(ledgerSamples(fanout)); err != nil {
		fmt.Fprintln(os.Stderr, "delivery-session emit:", err)
	}
}

// reconcileBrokerDeliveryTargets applies one broker target snapshot to the
// running fan-out. A failed read is deliberately a no-op: the last-known-good
// table must continue serving until a valid snapshot replaces it. An
// authoritative empty snapshot removes every target and closes their sessions
// before returning, so their final ledger delta is billed as TICKET_EXPIRED
// rather than being deferred to sender shutdown.
func reconcileBrokerDeliveryTargets(ctx context.Context, reader *gwclient.DeliveryTargetReader, fanout *receiver.Fanout, biller *delivery.Reporter) error {
	if reader == nil {
		return errors.New("broker delivery target reader is nil")
	}
	if fanout == nil {
		return errors.New("broker delivery fan-out is nil")
	}
	read, err := reader.Read(ctx)
	if err != nil {
		return err
	}
	removed, err := fanout.ReconcileDestinations(gwclient.ReceiverTargets(read))
	if err != nil {
		return err
	}
	if biller == nil || len(removed) == 0 {
		return nil
	}
	samples := make([]delivery.LedgerSample, 0, len(removed))
	for _, stat := range removed {
		samples = append(samples, delivery.LedgerSample{
			TargetID: stat.TargetID, Destination: stat.Destination,
			Bytes: stat.Bytes, Packets: stat.Packets,
		})
	}
	return biller.CloseRemoved(samples)
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
		_ = metrics.PublishGuard(feedID, tracker.Stats())
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
// under its own lock, both sessionScorer implementations serialize their own
// state, and Health and ReceiverMetrics each carry their own -- so feed
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
//
// tracker may be nil, which disables receiver-observed erasure scoring for the
// feed without affecting delivery.
func processPacket(feedName string, packet []byte, receivedAt time.Time, scorer sessionScorer, fanout *receiver.Fanout, metrics *receiver.ReceiverMetrics, tracker *erasure.Tracker) {
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
