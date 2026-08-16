package main

import (
	"bytes"
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

type captureWriter struct {
	packets chan []byte
}

func (w *captureWriter) Write(packet []byte) (int, error) {
	w.packets <- append([]byte(nil), packet...)
	return len(packet), nil
}

func (w *captureWriter) Close() error { return nil }

func TestSelftestFixturePrintsOrderedReceipt(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	err = selftest([]string{"--fixture"})
	_ = write.Close()
	os.Stdout = original
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := output.ReadFrom(read); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "time_to_32nd_shred") || !strings.HasPrefix(lines[1], "erasure") || !strings.HasPrefix(lines[2], "gap_ms") {
		t.Fatalf("receipt output = %q", output.String())
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
