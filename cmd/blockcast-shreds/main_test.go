package main

import (
	"bytes"
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
	fanout, err := receiver.NewFanout([]io.WriteCloser{writer}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer fanout.Close()
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewReceiverMetrics(registry, []string{"feed"})
	if err != nil {
		t.Fatal(err)
	}
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
