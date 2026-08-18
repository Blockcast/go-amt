package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/shred"
	"github.com/prometheus/client_golang/prometheus"
)

// captureStdout runs work with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, work func() error) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	// Restore os.Stdout and release both pipe ends on every exit path, including
	// the abnormal ones: work may panic, and t.Fatal below unwinds via
	// runtime.Goexit. Leaving the process-global os.Stdout pointed at a
	// reader-less pipe would strand output from unrelated tests in this package,
	// far from the cause. Both closes are idempotent, so the happy path can still
	// close the write end early.
	defer func() {
		os.Stdout = original
		_ = write.Close()
		_ = read.Close()
	}()
	// work writes into the pipe with nothing draining it concurrently, so its
	// output must stay under the pipe buffer (64 KiB on Linux) or this blocks
	// forever rather than failing. Today's receipts are three lines and a small
	// JSON object; drain from a goroutine before reusing this for bulk output.
	workErr := work()
	// Close the write end before draining so ReadFrom sees EOF.
	_ = write.Close()
	os.Stdout = original
	if workErr != nil {
		t.Fatal(workErr)
	}
	var output bytes.Buffer
	if _, err := output.ReadFrom(read); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

type captureWriter struct {
	packets chan []byte
}

func (w *captureWriter) Write(packet []byte) (int, error) {
	w.packets <- append([]byte(nil), packet...)
	return len(packet), nil
}

func (w *captureWriter) Close() error { return nil }

func TestSelftestFixturePrintsOrderedReceipt(t *testing.T) {
	output := captureStdout(t, func() error { return selftest([]string{"--fixture"}) })
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "time_to_32nd_shred") || !strings.HasPrefix(lines[1], "erasure") || !strings.HasPrefix(lines[2], "gap_ms") {
		t.Fatalf("receipt output = %q", output)
	}
}

func TestSelftestFixtureJSONIsMachineReadable(t *testing.T) {
	output := captureStdout(t, func() error { return selftest([]string{"--fixture", "--json"}) })
	var receipt struct {
		SetsTotal        int      `json:"sets_total"`
		ErasureFraction  *float64 `json:"erasure_fraction"`
		MeanShredsPerSet *float64 `json:"mean_shreds_per_set"`
	}
	if err := json.Unmarshal([]byte(output), &receipt); err != nil {
		t.Fatalf("selftest --json output is not JSON: %v\n%s", err, output)
	}
	if receipt.SetsTotal == 0 || receipt.ErasureFraction == nil || receipt.MeanShredsPerSet == nil {
		t.Fatalf("JSON receipt is missing fields: %s", output)
	}
}

func TestSelftestRequiresFixture(t *testing.T) {
	if err := selftest(nil); err == nil {
		t.Fatal("selftest without --fixture succeeded")
	}
}

func TestRunRejectsDuplicateFeedNames(t *testing.T) {
	err := run([]string{"--feed", "same=127.0.0.1:20001", "--feed", "same=127.0.0.1:20002"})
	if err == nil || !strings.Contains(err.Error(), "duplicate --feed name") {
		t.Fatalf("run() error = %v", err)
	}
}

func TestPacketDeliveryDoesNotDependOnScoring(t *testing.T) {
	writer := &captureWriter{packets: make(chan []byte, 2)}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{writer}, 2, metrics)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()
	scorer := shred.NewFeedScorer([]string{"feed"})
	packet := []byte{0x01, 0x02, 0x03}

	for range 2 {
		processPacket("feed", packet, time.Now(), scorer, fanout, metrics)
	}

	for range 2 {
		select {
		case got := <-writer.packets:
			if !bytes.Equal(got, packet) {
				t.Fatalf("forwarded packet = %x, want %x", got, packet)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for forwarded packet")
		}
	}
}

// TestFanoutPublishesEgressToTheScrapedRegistry guards the wiring between the
// fan-out worker and /metrics. Byte-identical forwarding can keep passing while
// egress_packets_total stays pinned at zero, which reads as a healthy receiver
// delivering nothing. Assert the scraped value, not just the delivered bytes.
func TestFanoutPublishesEgressToTheScrapedRegistry(t *testing.T) {
	writer := &captureWriter{packets: make(chan []byte, 2)}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{writer}, 2, metrics)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer([]string{"feed"})

	for range 2 {
		processPacket("feed", []byte{0x01, 0x02, 0x03}, time.Now(), scorer, fanout, metrics)
	}
	for range 2 {
		select {
		case <-writer.packets:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for forwarded packet")
		}
	}
	// Close drains the ring and joins the worker, so every observer callback has
	// landed before the registry is scraped.
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	if got := gaugeValue(t, registry, "bcast_shred_gw_egress_packets_total", "feed"); got != 2 {
		t.Fatalf("scraped egress_packets_total = %v, want 2 (worker egress is not wired to the registry)", got)
	}
	if got := gaugeValue(t, registry, "bcast_shred_gw_ingress_packets_total", "feed"); got != 0 {
		t.Fatalf("scraped ingress_packets_total = %v, want 0; processPacket must not count ingress", got)
	}
	if got := gaugeValue(t, registry, "bcast_shred_gw_fanout_write_errors_total", "feed"); got != 0 {
		t.Fatalf("scraped fanout_write_errors_total = %v, want 0", got)
	}
}

// TestFanoutPublishesWriteErrorsToTheScrapedRegistry covers the second silent
// drop site: a failed or short destination write loses the packet, so it must
// surface as a counter rather than only in FanoutStats.
func TestFanoutPublishesWriteErrorsToTheScrapedRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{&failingWriter{}}, 2, metrics)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer([]string{"feed"})

	processPacket("feed", []byte{0x09}, time.Now(), scorer, fanout, metrics)
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	if got := gaugeValue(t, registry, "bcast_shred_gw_fanout_write_errors_total", "feed"); got != 1 {
		t.Fatalf("scraped fanout_write_errors_total = %v, want 1", got)
	}
	if got := gaugeValue(t, registry, "bcast_shred_gw_egress_packets_total", "feed"); got != 0 {
		t.Fatalf("scraped egress_packets_total = %v, want 0; a failed write is not egress", got)
	}
}

// fixtureShred returns the first datagram of the bundled deterministic capture,
// having confirmed the production parser accepts it. Hand-rolled bytes would
// only prove that processPacket forwards whatever this file's own builder
// produced, and would encode the forwarder framing a second time; the pcap is
// the same real capture selftest --fixture replays, so a framing change shows up
// here instead of being satisfied by a stale local copy of the layout.
func fixtureShred(t *testing.T) []byte {
	t.Helper()
	var first []byte
	err := shred.ReplayFixtureFunc(func(payload []byte, _ time.Time) error {
		if first == nil {
			first = append([]byte(nil), payload...)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("bundled fixture carries no UDP payloads")
	}
	// NewFeedScorer scores FormatForwarder, so that is the frame the caller is
	// about to feed processPacket. Assert it here rather than inferring it from a
	// zero unparsed counter, which would also read as zero if the metric wiring
	// under test were the thing that broke.
	if _, err := shred.Parse(first, shred.FormatForwarder); err != nil {
		t.Fatalf("fixture packet does not parse as a shred: %v", err)
	}
	return first
}

// TestUnparsablePacketPublishesUnparsedToTheScrapedRegistry binds
// processPacket's parse-failure branch to the counter /metrics actually serves.
// receiver/metrics_test.go exercises IncUnparsed directly, which proves the
// counter increments when something calls it -- not that the ingest path ever
// does. Delete the call in processPacket and that unit test stays green while
// shreds_unparsed_total sits at zero through a feed of pure garbage, which reads
// as a clean feed rather than a broken one.
//
// A valid shred goes through the same path so the assertion pins the branch and
// not merely the call: a counter raised unconditionally would also satisfy
// "malformed input increments unparsed".
func TestUnparsablePacketPublishesUnparsedToTheScrapedRegistry(t *testing.T) {
	writer := &captureWriter{packets: make(chan []byte, 2)}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{writer}, 2, metrics)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer([]string{"feed"})

	processPacket("feed", []byte{0x01, 0x02, 0x03}, time.Now(), scorer, fanout, metrics)
	processPacket("feed", fixtureShred(t), time.Now(), scorer, fanout, metrics)
	for range 2 {
		select {
		case <-writer.packets:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for forwarded packet")
		}
	}
	// Close drains the ring and joins the worker, so every observer callback has
	// landed before the registry is scraped.
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	if got := gaugeValue(t, registry, "bcast_shred_gw_shreds_unparsed_total", "feed"); got != 1 {
		t.Fatalf("scraped shreds_unparsed_total = %v, want 1 (processPacket's parse failure is not wired to the registry)", got)
	}
	if got := gaugeValue(t, registry, "bcast_shred_gw_egress_packets_total", "feed"); got != 2 {
		t.Fatalf("scraped egress_packets_total = %v, want 2; an unparsable packet must still be delivered", got)
	}
}

// TestValidShredDuplicateIsForwardedByteIdentically covers what
// TestPacketDeliveryDoesNotDependOnScoring cannot. That test's 3-byte packet
// fails to parse, so both copies are rejected for the same reason and it never
// reaches the duplicate path its name claims -- nor does it show that a
// well-formed shred survives the path unchanged. Here the first copy parses and
// is accepted, first-arrival-wins dedup rejects the second (Scorer.Observe
// returns accepted=false), and both must still reach every destination byte for
// byte: what to do with a duplicate is the validator's decision, not this
// process's.
func TestValidShredDuplicateIsForwardedByteIdentically(t *testing.T) {
	packet := fixtureShred(t)
	// Compare against an independent copy: if processPacket mutated the caller's
	// slice in place, comparing the delivered bytes back to packet would compare
	// the corruption with itself and pass.
	want := append([]byte(nil), packet...)
	writer := &captureWriter{packets: make(chan []byte, 2)}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{writer}, 2, metrics)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer([]string{"feed"})

	for range 2 {
		processPacket("feed", packet, time.Now(), scorer, fanout, metrics)
	}
	for range 2 {
		select {
		case got := <-writer.packets:
			if !bytes.Equal(got, want) {
				t.Fatalf("forwarded packet = %x, want %x", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for forwarded packet")
		}
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	if got := gaugeValue(t, registry, "bcast_shred_gw_shreds_unparsed_total", "feed"); got != 0 {
		t.Fatalf("scraped shreds_unparsed_total = %v, want 0; a duplicate of a valid shred is not a parse failure", got)
	}
	if got := gaugeValue(t, registry, "bcast_shred_gw_egress_packets_total", "feed"); got != 2 {
		t.Fatalf("scraped egress_packets_total = %v, want 2; the duplicate must still be delivered", got)
	}
}

type failingWriter struct{}

func (w *failingWriter) Write([]byte) (int, error) { return 0, errors.New("destination unavailable") }
func (w *failingWriter) Close() error              { return nil }

// gaugeValue scrapes registry and returns the value carried by name for feed.
// A missing series is a failure: these counters are materialized at startup, so
// absence means the collector was never registered.
func gaugeValue(t *testing.T, registry *prometheus.Registry, name, feedID string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "feed" && label.GetValue() == feedID {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s{feed=%q} is absent from the registry", name, feedID)
	return 0
}

// blockingWriter parks the fan-out worker inside a write so the bounded ring
// can be filled deterministically.
type blockingWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func (w *blockingWriter) Close() error { return nil }

// TestShutdownDoesNotInflateTheFanoutDropCounter pins the call-site half of the
// drop-counter contract. The README defines fanout_dropped_packets_total as
// ring-full only, but Enqueue also refuses packets once the fan-out is closed.
// Reader goroutines are not joined before Close, so an in-flight packet can hit
// a closed fan-out during shutdown; charging that to the overflow counter makes
// the scraped metric disagree with Fanout.Stats().DroppedPackets.
func TestShutdownDoesNotInflateTheFanoutDropCounter(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{&captureWriter{packets: make(chan []byte, 4)}}, 4, metrics)
	if err != nil {
		t.Fatal(err)
	}
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer([]string{"feed"})

	processPacket("feed", []byte{0x01}, time.Now(), scorer, fanout, metrics)

	if got := gaugeValue(t, registry, "bcast_shred_gw_fanout_dropped_packets_total", "feed"); got != 0 {
		t.Fatalf("scraped fanout_dropped_packets_total = %v, want 0; a post-close reject is shutdown, not ring overflow", got)
	}
	if got := fanout.Stats().DroppedPackets; got != 0 {
		t.Fatalf("Stats().DroppedPackets = %d, want 0; the metric and the counter must agree", got)
	}
}

// TestRingOverflowIncrementsTheFanoutDropCounter is the positive half: a
// genuinely full ring must still be counted, so the fix above cannot be
// satisfied by never counting drops at all.
func TestRingOverflowIncrementsTheFanoutDropCounter(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
	writer := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	fanout, err := receiver.NewFanout([]io.WriteCloser{writer}, 1, metrics)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer([]string{"feed"})

	processPacket("feed", []byte{0x01}, time.Now(), scorer, fanout, metrics)
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("fan-out worker did not enter the writer")
	}
	processPacket("feed", []byte{0x02}, time.Now(), scorer, fanout, metrics) // fills the ring
	processPacket("feed", []byte{0x03}, time.Now(), scorer, fanout, metrics) // overflows

	if got := gaugeValue(t, registry, "bcast_shred_gw_fanout_dropped_packets_total", "feed"); got != 1 {
		t.Fatalf("scraped fanout_dropped_packets_total = %v, want 1", got)
	}
	close(writer.release)
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}
	if got := fanout.Stats().DroppedPackets; got != 1 {
		t.Fatalf("Stats().DroppedPackets = %d, want 1; the metric and the counter must agree", got)
	}
}

func TestRunRejectsNonPositiveHealthMaxAge(t *testing.T) {
	for _, value := range []string{"0", "-5s"} {
		err := run([]string{"--health-max-age", value})
		if err == nil || !strings.Contains(err.Error(), "--health-max-age must be positive") {
			t.Fatalf("run(--health-max-age %s) error = %v", value, err)
		}
	}
}

// forwarderDataShred builds a valid 28-byte-framed forwarder data shred so this
// package can drive the real scoring path. Package shred's own builder is a
// test helper and is not importable from here.
func forwarderDataShred(slot uint64, fecSet uint32, localIndex uint32) []byte {
	packet := make([]byte, 28+64)
	packet[0] = 3 // wire version
	binary.LittleEndian.PutUint64(packet[1:9], slot)
	binary.LittleEndian.PutUint32(packet[9:13], fecSet)
	binary.LittleEndian.PutUint32(packet[13:17], localIndex)
	// flags 0 (data), and data shreds must advertise no geometry.
	return packet
}

// TestConcurrentProcessPacketIsRaceFreeAndOrderTolerant pins the concurrency
// claim processPacket's doc comment makes. Every prior test here was
// single-goroutine, so nothing exercised the shared FeedScorer, Fanout and
// ReceiverMetrics under the access pattern the receiver actually uses: one
// goroutine per feed, all calling processPacket against the same values.
//
// Two halves:
//
//   - Data races. Covered by CI's race job (go test -race -tags purego), not by
//     assertions here. This test is what gives that job something to detect.
//   - Ordering. receivedAt is captured at the socket read, so concurrent feeds
//     present it out of order. Each feed hands out DEscending timestamps, so
//     within a feed goroutine the regression is program order and therefore
//     deterministic no matter how the goroutines interleave — which is what
//     makes the per-feed assertions below stable assertions rather than a race
//     for the scheduler to win. A scorer that assumed nondecreasing receivedAt
//     reports completed = 1ms - 32ms = -31ms and charges all 31 steps to the
//     sub-millisecond bucket.
func TestConcurrentProcessPacketIsRaceFreeAndOrderTolerant(t *testing.T) {
	const feedCount, shredsPerSet = 4, 32

	names := make([]string, feedCount)
	for i := range names {
		names[i] = fmt.Sprintf("feed-%d", i)
	}
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, names)
	if err != nil {
		t.Fatal(err)
	}
	fanout, err := receiver.NewFanout([]io.WriteCloser{&discardWriter{}}, feedCount*shredsPerSet, metrics)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorer(names)
	base := time.Unix(100, 0)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for f := 0; f < feedCount; f++ {
		wg.Add(1)
		go func(feedIndex int) {
			defer wg.Done()
			<-start
			// Each feed completes its own FEC set, so per-feed accounting is
			// independent of the interleaving.
			slot := uint64(500 + feedIndex)
			for i := 0; i < shredsPerSet; i++ {
				at := base.Add(time.Duration(shredsPerSet-i) * time.Millisecond)
				processPacket(names[feedIndex], forwarderDataShred(slot, 0, uint32(i)), at, scorer, fanout, metrics)
			}
		}(f)
	}
	close(start)
	wg.Wait()
	if err := fanout.Close(); err != nil {
		t.Fatal(err)
	}

	receipt := scorer.Receipt()
	if got := receipt.Union.CompletionP50; got < 0 {
		t.Fatalf("Union.CompletionP50 = %s is negative under concurrent out-of-order arrival", got)
	}
	for _, feed := range receipt.Feeds {
		// Each feed is scored against the union's set universe, so it "erases"
		// the other feeds' sets by construction. Its own is the complete one.
		if feed.Receipt.SetsTotal != feedCount || feed.Receipt.SetsErased != feedCount-1 {
			t.Fatalf("feed %s scored %d sets with %d erased, want %d/%d", feed.Name, feed.Receipt.SetsTotal, feed.Receipt.SetsErased, feedCount, feedCount-1)
		}
		// Extent is 1ms..32ms regardless of the order the shreds were presented.
		// Completion percentiles come from a bounded histogram, so the reported
		// value is the extent rounded up to its bucket's upper edge — never
		// below the truth, and over by at most shred.CompletionRelativeError.
		want := 31 * time.Millisecond
		ceiling := want + time.Duration(float64(want)*shred.CompletionRelativeError) + time.Microsecond
		if got := feed.Receipt.CompletionP50; got < want || got > ceiling {
			t.Fatalf("feed %s CompletionP50 = %s, want within [%s, %s]; completion must measure the set's arrival extent", feed.Name, got, want, ceiling)
		}
		if got := feed.Receipt.Gaps.LT1; got != 0 {
			t.Fatalf("feed %s Gaps.LT1 = %d, want 0; regressing arrivals must not be charged to the sub-millisecond bucket", feed.Name, got)
		}
		if got := feed.Receipt.Gaps.Reordered; got != shredsPerSet-1 {
			t.Fatalf("feed %s Gaps.Reordered = %d, want %d", feed.Name, got, shredsPerSet-1)
		}
	}
	// The ring was sized for every packet, so nothing may be charged as a drop.
	for _, name := range names {
		if got := gaugeValue(t, registry, "bcast_shred_gw_fanout_dropped_packets_total", name); got != 0 {
			t.Fatalf("scraped fanout_dropped_packets_total{feed=%q} = %v, want 0", name, got)
		}
	}
}

type discardWriter struct{}

func (w *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardWriter) Close() error                { return nil }
