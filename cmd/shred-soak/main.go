// Command shred-soak drives blockcast-shreds with a sustained feed of UNIQUE
// shred identities, so the receiver process can be observed reaching a steady
// state rather than growing for as long as it runs.
//
// # Why this exists rather than replaying the fixture
//
// shred.ReplayFixture replays a fixed 54 KB capture. Looping it re-presents the
// SAME (slot, fec_set_index, index_within_set) identities, and that is exactly
// the case Scorer's retention map does not grow on: every arrival after the
// first is a dedup hit that overwrites one map entry. A soak built that way
// shows a flat RSS and passes while testing nothing — a false negative, and the
// most likely way to "prove" a plateau that is not there.
//
// The bound under test is per-identity state (shred/retention.go), so the load
// has to present identities the receiver has never seen. Every datagram this
// command emits carries a distinct identity, for the whole run, and
// TestIdentitiesAreUniqueAcrossTheRun pins that structurally.
//
// # Why the framing is the forwarder header and not a canonical Agave shred
//
// The receiver hardcodes shred.FormatForwarder (cmd/blockcast-shreds/main.go,
// listenAndScore), so a canonical Agave shred sent to its socket is rejected by
// ParseHeader and counted into shreds_unparsed_total — the run would report a
// flat RSS because nothing was ever scored. The in-tree unique-shred generator
// that reads most like the thing to reuse, feedRound (shred/retention_test.go),
// builds Agave packets and is a *testing.T helper besides. So this command
// encodes the 28-byte forwarder header directly, against the layout documented
// on shred.ParseWireHeader, and the test asserts every emitted datagram parses
// through the same exported parser the receiver uses.
//
// # Rate
//
// --rate is a target. Achieved rate is measured and reported, because the
// acceptance criterion is about the rate that actually happened: a driver that
// silently fell to 300/s would take 55 minutes to reach a million shreds and
// would invite reading a short run as a plateau.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

// Forwarder wire-header layout. Mirrors the table on shred.ParseWireHeader;
// see that doc comment for the authoritative description.
const (
	wireHeaderSize = 28
	// wireVersionErasureShard is version 3, "erasure-shard body" — what
	// production emits on every one of the 1,044,775 datagrams the wire.go
	// comment reports verifying against.
	wireVersionErasureShard = 3
	// dataShredsPerFECSet is the geometry ParseWireHeader enforces: a data
	// shred's local index must be below this, and a complete set is this many
	// data shreds.
	dataShredsPerFECSet = 32
)

// setsPerSlot is how many FEC sets each synthetic slot carries before the slot
// number advances. Real Solana slots carry a variable number; a fixed count is
// enough here because the property under test keys on identity churn, not on
// slot geometry. It is >1 so that both components of the identity vary during
// the run rather than the slot alone.
const setsPerSlot = 8

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shred-soak:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("shred-soak", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	to := flags.String("to", "", "destination IP:PORT of the receiver's --listen address")
	rate := flags.Int("rate", 2500, "target unique shreds per second")
	count := flags.Uint64("count", 1_000_000, "total unique shreds to emit, then exit")
	payload := flags.Int("payload", 1200, "datagram size in bytes, including the 28-byte forwarder header")
	progress := flags.Duration("progress", 15*time.Second, "how often to report achieved rate on stdout")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *to == "" || flags.NArg() != 0 {
		return errors.New("usage: shred-soak --to IP:PORT [--rate N] [--count N] [--payload N] [--progress D]")
	}
	if *rate <= 0 {
		return fmt.Errorf("--rate must be positive, got %d", *rate)
	}
	if *count == 0 {
		return errors.New("--count must be positive")
	}
	// Below the header there is no identity to carry; above the receiver's 2048-byte
	// read buffer (cmd/blockcast-shreds/main.go, listenAndScore) the datagram is
	// truncated on read, which would corrupt the feed in a way that looks like
	// packet loss rather than a misconfiguration.
	if *payload < wireHeaderSize || *payload > 2048 {
		return fmt.Errorf("--payload must be between %d and 2048 bytes, got %d", wireHeaderSize, *payload)
	}

	destination, err := net.ResolveUDPAddr("udp", *to)
	if err != nil {
		return fmt.Errorf("resolve --to %q: %w", *to, err)
	}
	conn, err := net.DialUDP("udp", nil, destination)
	if err != nil {
		return fmt.Errorf("dial %q: %w", *to, err)
	}
	defer func() { _ = conn.Close() }()

	return emit(conn, *rate, *count, *payload, *progress, os.Stdout)
}

// writer is the subset of net.UDPConn emit needs, so the pacing and reporting
// can be tested without a socket.
type writer interface{ Write(b []byte) (int, error) }

func emit(conn writer, rate int, count uint64, payload int, progress time.Duration, out *os.File) error {
	packet := make([]byte, payload)
	started := time.Now()
	lastReport := started
	var lastReported uint64

	for n := uint64(0); n < count; n++ {
		encodeDataShred(packet, n, time.Now())
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("send shred %d: %w", n, err)
		}

		// Pace against an ideal schedule computed from the start, not against the
		// previous packet. Sleeping a fixed interval per packet accumulates the
		// scheduler's overshoot and lands well under the target rate over a
		// ten-minute run; anchoring on `started` lets a late packet be followed by
		// an immediate one so the run converges on the target instead of drifting
		// below it.
		due := started.Add(time.Duration(float64(n+1) / float64(rate) * float64(time.Second)))
		if delay := time.Until(due); delay > 0 {
			time.Sleep(delay)
		}

		if progress > 0 && time.Since(lastReport) >= progress {
			now := time.Now()
			sent := n + 1
			fmt.Fprintf(out, "shred-soak progress sent=%d elapsed=%s achieved_rate=%.1f/s interval_rate=%.1f/s\n",
				sent, now.Sub(started).Round(time.Millisecond),
				float64(sent)/now.Sub(started).Seconds(),
				float64(sent-lastReported)/now.Sub(lastReport).Seconds())
			lastReport, lastReported = now, sent
		}
	}

	elapsed := time.Since(started)
	// The achieved rate, not the target. See the package comment.
	fmt.Fprintf(out, "shred-soak done sent=%d elapsed=%s target_rate=%d/s achieved_rate=%.1f/s payload=%dB\n",
		count, elapsed.Round(time.Millisecond), rate, float64(count)/elapsed.Seconds(), payload)
	return nil
}

// encodeDataShred writes the n-th shred of the run into packet, which must be at
// least wireHeaderSize long. Bytes past the header are left as they are: the
// receiver does not inspect the body (see shred.ParseWireHeader), so filling it
// every packet would cost the run throughput to no end.
//
// n maps onto the identity space bijectively, which is the whole point — see
// TestIdentitiesAreUniqueAcrossTheRun:
//
//	set        = n / 32          local index = n % 32
//	slot       = set / setsPerSlot
//	fecSetIndex = (set % setsPerSlot) * 32
//
// Laying consecutive sets 32 apart matches how a data shred's position in its
// set is derived from Index-FECSetIndex on the Agave side, so the synthetic feed
// has the same set geometry a real one does.
func encodeDataShred(packet []byte, n uint64, sendTime time.Time) {
	set := n / dataShredsPerFECSet
	localIndex := uint32(n % dataShredsPerFECSet)
	slot := set / setsPerSlot
	fecSetIndex := uint32(set%setsPerSlot) * dataShredsPerFECSet

	packet[0] = wireVersionErasureShard
	binary.LittleEndian.PutUint64(packet[1:9], slot)
	binary.LittleEndian.PutUint32(packet[9:13], fecSetIndex)
	binary.LittleEndian.PutUint32(packet[13:17], localIndex)
	// Data shreds must advertise no geometry and must not set the coding flag;
	// ParseWireHeader rejects the packet otherwise. DATA_COMPLETE marks the last
	// shred of each set.
	flags := byte(0)
	if localIndex == dataShredsPerFECSet-1 {
		flags |= 0x01
	}
	packet[17] = flags
	packet[18] = 0
	packet[19] = 0
	binary.LittleEndian.PutUint64(packet[20:28], uint64(sendTime.UnixMicro()))
}
