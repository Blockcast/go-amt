package shred

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestScorerCountsCompleteErasedAndPaddedSets(t *testing.T) {
	scorer := NewScorer()
	started := time.Unix(1, 0)
	for i := uint32(0); i < 32; i++ {
		observeTestPacket(t, scorer, dataPacket(10, 0, i), started.Add(time.Duration(i)*time.Millisecond))
	}
	for i := uint32(0); i < 31; i++ {
		observeTestPacket(t, scorer, dataPacket(10, 32, 32+i), started.Add(40*time.Millisecond+time.Duration(i)*time.Millisecond))
	}
	for i := uint32(0); i < 32; i++ {
		observeTestPacket(t, scorer, codingPacket(11, 0, i), started.Add(80*time.Millisecond+time.Duration(i)*time.Millisecond))
	}

	receipt := scorer.Receipt()
	if receipt.SetsTotal != 3 || receipt.SetsErased != 1 || receipt.ErasureFraction != 1.0/3.0 {
		t.Fatalf("receipt = %+v", receipt)
	}
	if receipt.CompletionP50 != 31*time.Millisecond || receipt.CompletionP99 != 31*time.Millisecond {
		t.Fatalf("completion latency = p50 %s p99 %s", receipt.CompletionP50, receipt.CompletionP99)
	}
	if !strings.HasPrefix(receipt.String(), "time_to_32nd_shred") {
		t.Fatalf("receipt does not lead with latency: %q", receipt.String())
	}
}

func TestScorerDeduplicatesAcrossFeeds(t *testing.T) {
	scorer := NewScorer()
	packet := dataPacket(20, 0, 0)
	if accepted, err := scorer.Observe(packet, time.Unix(2, 0)); err != nil || !accepted {
		t.Fatalf("first arrival = %v, %v", accepted, err)
	}
	if accepted, err := scorer.Observe(packet, time.Unix(2, 1)); err != nil || accepted {
		t.Fatalf("duplicate arrival = %v, %v", accepted, err)
	}
	if got := scorer.Receipt(); got.SetsTotal != 1 || got.Gaps != (GapHistogram{}) {
		t.Fatalf("duplicate affected receipt: %+v", got)
	}
}

func TestParseHeaderRejectsNonConsensusCodingShape(t *testing.T) {
	packet := codingPacket(1, 0, 0)
	binary.LittleEndian.PutUint16(packet[83:85], 31)
	if _, err := ParseHeader(packet); err == nil {
		t.Fatal("31+32 coding header accepted")
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
