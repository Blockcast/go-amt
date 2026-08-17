package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
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
