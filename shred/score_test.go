package shred

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestScorerCountsCompleteErasedAndPaddedSets(t *testing.T) {
	tests := []struct {
		name        string
		observe     func(*testing.T, *Scorer, time.Time)
		total       int
		erased      int
		erasureRate float64
	}{
		{
			name: "erased below 32 of 64",
			observe: func(t *testing.T, scorer *Scorer, started time.Time) {
				for i := uint32(0); i < 31; i++ {
					observeTestPacket(t, scorer, dataPacket(10, 0, i), started.Add(time.Duration(i)*time.Millisecond))
				}
			},
			total: 1, erased: 1, erasureRate: 1,
		},
		{
			name: "padded final set remains consensus 32 plus 32",
			observe: func(t *testing.T, scorer *Scorer, started time.Time) {
				for i := uint32(0); i < 32; i++ {
					observeTestPacket(t, scorer, codingPacket(11, 0, i), started.Add(time.Duration(i)*time.Millisecond))
				}
			},
			total: 1, erased: 0, erasureRate: 0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scorer := NewScorer()
			test.observe(t, scorer, time.Unix(1, 0))
			receipt := scorer.Receipt()
			if receipt.SetsTotal != test.total || receipt.SetsErased != test.erased || receipt.ErasureFraction != test.erasureRate {
				t.Fatalf("receipt = %+v", receipt)
			}
		})
	}
}

func TestCompletionPercentilesKnownFixture(t *testing.T) {
	tests := []struct {
		name      string
		latencies []time.Duration
		p50, p95  time.Duration
		p99       time.Duration
	}{
		{name: "single set", latencies: []time.Duration{31 * time.Millisecond}, p50: 31 * time.Millisecond, p95: 31 * time.Millisecond, p99: 31 * time.Millisecond},
		{name: "nearest rank", latencies: []time.Duration{40 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}, p50: 20 * time.Millisecond, p95: 40 * time.Millisecond, p99: 40 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := append([]time.Duration(nil), test.latencies...)
			sortDurations(values)
			if got := percentile(values, 50); got != test.p50 {
				t.Fatalf("p50 = %s, want %s", got, test.p50)
			}
			if got := percentile(values, 95); got != test.p95 {
				t.Fatalf("p95 = %s, want %s", got, test.p95)
			}
			if got := percentile(values, 99); got != test.p99 {
				t.Fatalf("p99 = %s, want %s", got, test.p99)
			}
		})
	}
}

func TestScorerDeduplicatesFirstArrivalAcrossTwoFeeds(t *testing.T) {
	scorer := NewScorer()
	started := time.Unix(2, 0)
	for i := uint32(0); i < 32; i++ {
		packet := dataPacket(20, 0, i)
		// Feed A reaches the shared scorer first.
		if accepted, err := scorer.Observe(packet, started.Add(time.Duration(i)*time.Millisecond)); err != nil || !accepted {
			t.Fatalf("feed A shred %d = %v, %v", i, accepted, err)
		}
		// Feed B carries the same UDP payload later and must not change metrics.
		if accepted, err := scorer.Observe(packet, started.Add(time.Second+time.Duration(i)*time.Millisecond)); err != nil || accepted {
			t.Fatalf("feed B duplicate %d = %v, %v", i, accepted, err)
		}
	}
	got := scorer.Receipt()
	if got.SetsTotal != 1 || got.CompletionP50 != 31*time.Millisecond || got.Gaps.From1To2_4 != 31 {
		t.Fatalf("duplicates changed first-arrival receipt: %+v", got)
	}
	if !strings.HasPrefix(got.String(), "time_to_32nd_shred") {
		t.Fatalf("receipt does not lead with latency: %q", got.String())
	}
}

func TestFeedScorerReportsPerFeedAndUnionBenefit(t *testing.T) {
	scorer := NewFeedScorer([]string{"blockcast", "external"})
	started := time.Unix(3, 0)
	for i := uint32(0); i < 31; i++ {
		if _, err := scorer.Observe("blockcast", dataPacket(30, 0, i), started.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scorer.Observe("external", dataPacket(30, 0, 31), started.Add(31*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < 31; i++ {
		if _, err := scorer.Observe("external", codingPacket(30, 0, i), started.Add(time.Duration(32+i)*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}

	got := scorer.Receipt()
	if len(got.Feeds) != 2 || got.Feeds[0].Receipt.ErasureFraction != 1 || got.Feeds[1].Receipt.ErasureFraction != 0 || got.Union.ErasureFraction != 0 || got.GapClosed != 1 {
		t.Fatalf("dual-feed receipt = %+v", got)
	}
	want := "time_to_32nd_shred union p50=31ms p95=31ms p99=31ms\nunion erasure sets=1 erased=0 fraction=0.000000\ngap_ms union <1=0 1-2.4=62 2.4-7=0 7-32=0 >=32=0\nfeed name=blockcast erasure sets=1 erased=1 fraction=1.000000\nfeed name=external erasure sets=1 erased=0 fraction=0.000000\nsecond_feed_gap_closed baseline=blockcast fraction=1.000000"
	if got.String() != want {
		t.Fatalf("receipt = %q, want %q", got.String(), want)
	}
}

func TestFeedScorerDeduplicatesUnionFirstArrival(t *testing.T) {
	scorer := NewFeedScorer([]string{"first", "second"})
	packet := dataPacket(31, 0, 0)
	if accepted, err := scorer.Observe("second", packet, time.Unix(4, 0)); err != nil || !accepted {
		t.Fatalf("first union arrival = %v, %v", accepted, err)
	}
	if accepted, err := scorer.Observe("first", packet, time.Unix(5, 0)); err != nil || accepted {
		t.Fatalf("later union duplicate = %v, %v", accepted, err)
	}
	if got := scorer.Receipt(); got.Feeds[0].Receipt.SetsTotal != 1 || got.Feeds[1].Receipt.SetsTotal != 1 || got.Union.SetsTotal != 1 {
		t.Fatalf("feed universe mismatch: %+v", got)
	}
}

func TestParseHeaderRejectsNonConsensusCodingShape(t *testing.T) {
	packet := codingPacket(1, 0, 0)
	binary.LittleEndian.PutUint16(packet[83:85], 31)
	if _, err := ParseHeader(packet); err == nil {
		t.Fatal("31+32 coding header accepted")
	}
}

func sortDurations(values []time.Duration) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func observeTestPacket(t *testing.T, scorer *Scorer, packet []byte, at time.Time) {
	t.Helper()
	if accepted, err := scorer.Observe(packet, at); err != nil || !accepted {
		t.Fatalf("Observe() = %v, %v", accepted, err)
	}
}

func dataPacket(slot uint64, fec, index uint32) []byte {
	packet := make([]byte, commonHeaderSize)
	packet[64] = 0x96
	binary.LittleEndian.PutUint64(packet[65:73], slot)
	binary.LittleEndian.PutUint32(packet[73:77], index)
	binary.LittleEndian.PutUint32(packet[79:83], fec)
	return packet
}

func codingPacket(slot uint64, fec, position uint32) []byte {
	packet := make([]byte, commonHeaderSize+codingHeaderSize)
	packet[64] = 0x66
	binary.LittleEndian.PutUint64(packet[65:73], slot)
	binary.LittleEndian.PutUint32(packet[73:77], fec+32+position)
	binary.LittleEndian.PutUint32(packet[79:83], fec)
	binary.LittleEndian.PutUint16(packet[83:85], 32)
	binary.LittleEndian.PutUint16(packet[85:87], 32)
	binary.LittleEndian.PutUint16(packet[87:89], uint16(position))
	return packet
}
