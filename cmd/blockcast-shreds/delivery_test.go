package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/receiver/delivery"
	"github.com/blockcast/go-amt/shred"
)

// These tests exist because receiver/delivery was complete, tested, and
// imported by nothing (BLO-29728). Every clause of the W3 wire contract was
// implemented and every one of them was unreachable from the binary, so the
// package's own tests passed while production emitted no delivery-session
// records at all. Component tests cannot catch that class of bug by
// construction: they instantiate the very wiring whose absence is the defect.
//
// So these drive listenAndScore -- the function main actually calls -- over
// real UDP sockets and assert against the record file it writes. Deleting the
// Reporter construction, the Tick on the report cadence, or the CloseAll on
// shutdown fails them.

// readRecords parses the JSON-lines record file.
func readRecords(t *testing.T, path string) []delivery.Record {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open record file: %v", err)
	}
	defer file.Close()

	var records []delivery.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var record delivery.Record
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("parse record %q: %v", line, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan record file: %v", err)
	}
	return records
}

// runBilledReceiver drives listenAndScore with billing enabled against a real
// fan-out destination, sends packetCount shreds, and shuts down cleanly.
// It returns the record file path and the destination's address.
func runBilledReceiver(t *testing.T, walPath, recordPath string, packetCount int) string {
	t.Helper()
	silenceStdout(t)

	destination, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = destination.Close() }()
	destinationAddress := destination.LocalAddr().String()

	// Drain the destination so a full socket buffer cannot turn a billing
	// assertion into a buffering artefact.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buffer := make([]byte, 2048)
		for {
			if _, err := destination.Read(buffer); err != nil {
				return
			}
		}
	}()

	feedAddress := freeLocalAddr(t, "udp")
	httpAddress := freeLocalAddr(t, "tcp")

	stop := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- listenAndScore(
			[]feed{{name: "default", address: feedAddress}},
			[]string{destinationAddress},
			httpAddress, 30*time.Second, true,
			30*time.Millisecond, 60*time.Millisecond, shred.DefaultRetention, stop,
			scoring{mode: "shred"},
			billing{walPath: walPath, recordPath: recordPath},
		)
	}()

	waitReady(t, httpAddress)

	sender, err := net.Dial("udp", feedAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()

	slot := uint64(2_000_000)
	for i := 0; i < packetCount; i++ {
		// A write error is not end of stream on a UDP socket here.
		_, _ = sender.Write(dataShred(slot, 0, uint8(i%32)))
		slot += 7
	}

	// Wait only until the receiver has ACCEPTED every packet -- ingress, not
	// egress. There is deliberately no settle sleep here: packets accepted by
	// Enqueue but not yet written by the fan-out worker are exactly the case
	// that must still be billed, and a sleep would let the queue drain and
	// quietly stop testing the shutdown ordering. Shutdown has to drain the
	// fan-out before it samples the ledger for the final record.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ingress, ok := scrape(t, httpAddress, "bcast_shred_gw_ingress_packets_total", `feed="default"`); ok && int(ingress) >= packetCount {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(stop)
	if err := <-finished; err != nil {
		t.Fatalf("listenAndScore: %v", err)
	}
	_ = destination.Close()
	<-drained
	return destinationAddress
}

// TestDeliveryRecordsBillLedgerTotalExactlyOnce is assertion (a) of the issue's
// verifying signal, and the one that fails on the cumulative-versus-delta
// hazard: Fanout.DestinationStats is cumulative while Tracker.Observe takes an
// increment, so wiring them together naively bills a multiple of real traffic.
// Summed bytes_out must equal the destination's ledger byte total exactly --
// not approximately, and not a multiple of it.
func TestDeliveryRecordsBillLedgerTotalExactlyOnce(t *testing.T) {
	directory := t.TempDir()
	walPath := filepath.Join(directory, "delivery.wal")
	recordPath := filepath.Join(directory, "records.jsonl")

	destinationAddress := runBilledReceiver(t, walPath, recordPath, 96)

	records := readRecords(t, recordPath)
	if len(records) == 0 {
		t.Fatal("no delivery-session records were written; receiver/delivery is not wired into the binary")
	}

	var billedBytes, billedPackets uint64
	for _, record := range records {
		if record.SubscriberID != destinationAddress {
			t.Errorf("record subscriber_id = %q, want the fan-out destination %q", record.SubscriberID, destinationAddress)
		}
		billedBytes += record.BytesOut
		billedPackets += record.PacketsOut
	}

	// The ledger total is the fan-out's own count of what it delivered. It is
	// read from the last record's cumulative position: the final record closes
	// the session after folding the tail delta, so the sum IS the ledger total
	// when the delta plumbing is right.
	if billedPackets == 0 {
		t.Fatal("records billed zero packets despite delivered traffic")
	}
	// One shred is WireHeaderSize+16 bytes; every delivered packet is billed
	// exactly once, so bytes must be an exact multiple of the packet size.
	packetSize := uint64(shred.WireHeaderSize + 16)
	if billedBytes != billedPackets*packetSize {
		t.Errorf("billed %d bytes for %d packets, want exactly %d (%d-byte packets); a mismatch means bytes and packets disagree about the delta",
			billedBytes, billedPackets, billedPackets*packetSize, packetSize)
	}
	// Exactly the traffic sent -- an equality, not a bound, in both directions.
	//
	// Over-counting is the cumulative-versus-delta hazard. UNDER-counting is the
	// shutdown-ordering hazard: packets accepted by Enqueue but still queued
	// when the session closes are delivered by Fanout.Close afterwards, so
	// sampling the ledger before draining the fan-out bills fewer packets than
	// were actually delivered. The helper deliberately does not settle the
	// queue before shutdown, so this assertion sees that case.
	if billedPackets != 96 {
		t.Errorf("billed %d packets, want exactly 96: over-counting means traffic is billed twice, "+
			"under-counting means queued packets were delivered by fan-out shutdown after the final record was taken",
			billedPackets)
	}
}

// TestDeliveryFinalRecordCarriesShutdownReason is assertion (c): a session must
// terminate with a final record naming why it ended, or an invoice has no end
// and a delivery gap is indistinguishable from a billing bug.
func TestDeliveryFinalRecordCarriesShutdownReason(t *testing.T) {
	directory := t.TempDir()
	walPath := filepath.Join(directory, "delivery.wal")
	recordPath := filepath.Join(directory, "records.jsonl")

	runBilledReceiver(t, walPath, recordPath, 32)

	records := readRecords(t, recordPath)
	if len(records) == 0 {
		t.Fatal("no delivery-session records were written")
	}

	final := records[len(records)-1]
	if !final.Final {
		t.Error("last record is not marked final; shutdown did not close the session")
	}
	if final.CloseReason != delivery.CloseShutdown {
		t.Errorf("close_reason = %q, want %q", final.CloseReason, delivery.CloseShutdown)
	}
	if final.SessionID == "" {
		t.Error("final record has no session ID")
	}
	if final.OpenedAt.IsZero() || final.EmittedAt.Before(final.OpenedAt) {
		t.Errorf("final record timestamps are inconsistent: opened %s emitted %s", final.OpenedAt, final.EmittedAt)
	}
	// Exactly one final record: a second one would mean a session was closed
	// twice and the destination billed two terminating intervals.
	var finals int
	for _, record := range records {
		if record.Final {
			finals++
		}
	}
	if finals != 1 {
		t.Errorf("final records = %d, want exactly 1", finals)
	}

	// duration_ms is cumulative, so it must never decrease across the session.
	for i := 1; i < len(records); i++ {
		if records[i].DurationMS < records[i-1].DurationMS {
			t.Errorf("duration_ms decreased at record %d (%d -> %d); it must be cumulative",
				i, records[i-1].DurationMS, records[i].DurationMS)
		}
	}
}

// TestDeliverySeqMonotonicAcrossRestart is assertion (b): seq must be durable
// across a process restart, against a real on-disk WAL.
//
// The restart is deliberately a CRASH, not a clean shutdown. WAL.Close
// compacts away retired sessions, so a cleanly closed session is -- correctly
// -- gone from the file, and its sequence numbers can never collide with
// anything again. The seq that has to survive is the one belonging to a session
// still open when the process died, which is exactly the case a restart has to
// get right: the same session ID must not reuse a sequence number a previous
// process already emitted.
func TestDeliverySeqMonotonicAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	walPath := filepath.Join(directory, "delivery.wal")

	const sessionID = "11111111-2222-4333-8444-555555555555"

	// First process: emit some sequence numbers and die without closing the
	// session (no Retire), leaving the high-water mark on disk.
	first, err := delivery.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	var lastBefore uint64
	for i := 0; i < 4; i++ {
		if lastBefore, err = first.NextSeq(sessionID); err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if lastBefore == 0 {
		t.Fatal("no sequence numbers were issued before the restart")
	}

	// Second process against the same path: the sequence must continue, never
	// restart at 1, or a replayed record would collide with a different record
	// under first-write-wins dedup by (SessionID, Seq).
	second, err := delivery.OpenWAL(walPath)
	if err != nil {
		t.Fatalf("reopen WAL: %v", err)
	}
	defer second.Close()

	firstAfter, err := second.NextSeq(sessionID)
	if err != nil {
		t.Fatalf("NextSeq after restart: %v", err)
	}
	if firstAfter <= lastBefore {
		t.Fatalf("seq after restart = %d, want > %d; the WAL did not survive the restart", firstAfter, lastBefore)
	}

	// And strictly increasing from there.
	previous := firstAfter
	for i := 0; i < 3; i++ {
		next, err := second.NextSeq(sessionID)
		if err != nil {
			t.Fatalf("NextSeq: %v", err)
		}
		if next <= previous {
			t.Fatalf("seq not strictly increasing: %d then %d", previous, next)
		}
		previous = next
	}
}

// TestDeliveryUsesDurableWALNotMemoryStore pins that the binary actually writes
// a WAL to the configured path. A Tracker backed by MemorySeqStore would
// satisfy every in-process assertion above and lose every sequence number on
// restart, so the file's existence is the only thing that distinguishes them.
func TestDeliveryUsesDurableWALNotMemoryStore(t *testing.T) {
	directory := t.TempDir()
	walPath := filepath.Join(directory, "nested", "delivery.wal")
	recordPath := filepath.Join(directory, "nested", "records.jsonl")

	runBilledReceiver(t, walPath, recordPath, 32)

	// The WAL is compacted on clean shutdown, so it may legitimately be empty;
	// what must be true is that the binary created it at the configured path
	// rather than keeping sequences in memory.
	if _, err := os.Stat(walPath); err != nil {
		t.Fatalf("stat WAL at the configured path: %v; the binary is not using delivery.OpenWAL", err)
	}
	info, err := os.Stat(recordPath)
	if err != nil {
		t.Fatalf("stat record file: %v", err)
	}
	if info.Size() == 0 {
		t.Error("record file is empty; no delivery-session records were shipped")
	}
	// Billing records name subscribers and their traffic volumes.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("record file mode = %#o, want 0600", mode)
	}
}

// TestBillingOptionsValidation pins the flag contract. The all-or-nothing rule
// and the destination requirement exist so billing cannot be half-configured
// and silently emit nothing, which is the failure this whole issue is about.
func TestBillingOptionsValidation(t *testing.T) {
	destinations := []string{"127.0.0.1:8001"}

	tests := []struct {
		name    string
		wal     string
		records string
		dests   []string
		wantErr string
		wantOn  bool
	}{
		{name: "both empty disables billing", dests: destinations},
		{name: "records without wal", records: "/tmp/r.jsonl", dests: destinations, wantErr: "--delivery-records requires --delivery-wal"},
		{name: "wal without records", wal: "/tmp/d.wal", dests: destinations, wantErr: "--delivery-wal requires --delivery-records"},
		{name: "no destination to bill", wal: "/tmp/d.wal", records: "/tmp/r.jsonl", wantErr: "requires at least one --dest-ip-ports"},
		{name: "fully configured", wal: "/tmp/d.wal", records: "/tmp/r.jsonl", dests: destinations, wantOn: true},
		{name: "whitespace is not configuration", wal: "   ", records: "  ", dests: destinations},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := billingOptions(test.wal, test.records, test.dests)
			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("billingOptions() error = nil, want substring %q", test.wantErr)
				}
				if !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("billingOptions() error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("billingOptions() error = %v", err)
			}
			if got.enabled() != test.wantOn {
				t.Errorf("enabled() = %v, want %v", got.enabled(), test.wantOn)
			}
		})
	}
}
