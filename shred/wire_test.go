package shred

import (
	"encoding/binary"
	"testing"
	"time"
)

// forwarderPacket builds a 28-byte forwarder-framed datagram.
func forwarderPacket(version uint8, slot uint64, fecSet uint32, localIndex uint32, coding bool, sendTS uint64) []byte {
	p := make([]byte, WireHeaderSize+64) // header + a token body
	p[0] = version
	binary.LittleEndian.PutUint64(p[1:9], slot)
	binary.LittleEndian.PutUint32(p[9:13], fecSet)
	binary.LittleEndian.PutUint32(p[13:17], localIndex)
	if coding {
		p[17] = wireFlagCoding
		p[18] = 32
		p[19] = 32
	}
	binary.LittleEndian.PutUint64(p[20:28], sendTS)
	return p
}

func TestParseWireHeaderReadsForwarderFraming(t *testing.T) {
	p := forwarderPacket(3, 439000406, 544, 57, true, 1785000000000000)
	h, err := ParseWireHeader(p)
	if err != nil {
		t.Fatalf("ParseWireHeader: %v", err)
	}
	if h.Slot != 439000406 || h.FECSetIndex != 544 || h.IndexWithinSet != 57 {
		t.Fatalf("unexpected header %+v", h)
	}
	if h.Kind != KindCoding {
		t.Fatalf("expected coding shred, got kind %d", h.Kind)
	}
	if h.SendTimeMicros != 1785000000000000 {
		t.Fatalf("send timestamp not carried: %d", h.SendTimeMicros)
	}
}

// The parser must not be pointed at Agave bytes: an Agave shred starts with a
// signature, so its leading byte is arbitrary and the fields would be garbage.
func TestParseWireHeaderRejectsNonForwarderVersions(t *testing.T) {
	p := forwarderPacket(3, 1, 0, 0, false, 0)
	for _, v := range []uint8{0, 1, 2, 5, 0x90, 0xff} {
		p[0] = v
		if _, err := ParseWireHeader(p); err == nil {
			t.Fatalf("version %d should be rejected", v)
		}
	}
}

func TestParseWireHeaderRejectsShortAndOutOfRange(t *testing.T) {
	if _, err := ParseWireHeader(make([]byte, WireHeaderSize-1)); err == nil {
		t.Fatal("short datagram should be rejected")
	}
	p := forwarderPacket(4, 1, 0, 64, false, 0) // 64 is outside a 32+32 set
	if _, err := ParseWireHeader(p); err == nil {
		t.Fatal("local index 64 should be rejected")
	}
}

// Regression: the old dedup key was (Slot, Index), but Index is an absolute
// index derived as FECSetIndex+localIndex for data shreds. Two shreds in
// different FEC sets of one slot therefore share an Index — set 0 index 5 and
// set 5 index 0 both yield Index 5 — so the second was silently dropped as a
// duplicate, which reads downstream as packet loss and inflates erasure.
func TestScorerDoesNotCollideAcrossFECSetsWithEqualAbsoluteIndex(t *testing.T) {
	s := NewScorer()
	now := time.Now()
	a := forwarderPacket(3, 10, 0, 5, false, 0) // absolute Index 5
	b := forwarderPacket(3, 10, 5, 0, false, 0) // absolute Index 5, different set
	if ha, err := ParseWireHeader(a); err != nil || ha.Index != 5 {
		t.Fatalf("precondition: a.Index = %v (%v)", ha.Index, err)
	}
	if hb, err := ParseWireHeader(b); err != nil || hb.Index != 5 {
		t.Fatalf("precondition: b.Index = %v (%v)", hb.Index, err)
	}
	if ok, err := s.Observe(a, now); err != nil || !ok {
		t.Fatalf("first shred not accepted: %v %v", ok, err)
	}
	ok, err := s.Observe(b, now.Add(time.Millisecond))
	if err != nil {
		t.Fatalf("second shred errored: %v", err)
	}
	if !ok {
		t.Fatal("shred in a different FEC set was dropped as a duplicate")
	}
	if got := s.Receipt().SetsTotal; got != 2 {
		t.Fatalf("expected 2 distinct FEC sets, got %d", got)
	}
}

// A set completing in the same clock tick as its first arrival is complete, not
// erased: zero is a legitimate completion duration and must not be a sentinel.
func TestScorerCountsZeroDurationCompletionAsComplete(t *testing.T) {
	s := NewScorer()
	now := time.Now()
	for i := uint32(0); i < 32; i++ {
		if ok, err := s.Observe(forwarderPacket(3, 12, 0, i, false, 0), now); err != nil || !ok {
			t.Fatalf("index %d: %v %v", i, ok, err)
		}
	}
	r := s.Receipt()
	if r.SetsErased != 0 {
		t.Fatalf("set reached 32 distinct shreds in one tick; expected 0 erased, got %d", r.SetsErased)
	}
}

func TestScorerDedupsRepeatsWithinASet(t *testing.T) {
	s := NewScorer()
	now := time.Now()
	p := forwarderPacket(3, 10, 0, 7, false, 0)
	if ok, _ := s.Observe(p, now); !ok {
		t.Fatal("first copy should be accepted")
	}
	for i := 0; i < 4; i++ {
		if ok, _ := s.Observe(p, now); ok {
			t.Fatal("repeat should be deduplicated")
		}
	}
}

// Two FEC sets in one slot reuse the same in-set index space; they must stay
// distinct sets.
func TestScorerKeepsFECSetsInASlotDistinct(t *testing.T) {
	s := NewScorer()
	now := time.Now()
	for i := uint32(0); i < 32; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		if ok, err := s.Observe(forwarderPacket(3, 9, 0, i, false, 0), at); err != nil || !ok {
			t.Fatalf("set 0 index %d: %v %v", i, ok, err)
		}
		if ok, err := s.Observe(forwarderPacket(3, 9, 1, i, false, 0), at); err != nil || !ok {
			t.Fatalf("set 1 index %d: %v %v", i, ok, err)
		}
	}
	r := s.Receipt()
	if r.SetsTotal != 2 {
		t.Fatalf("expected 2 distinct FEC sets, got %d", r.SetsTotal)
	}
	if r.SetsErased != 0 {
		t.Fatalf("both sets reached 32 distinct shreds, expected 0 erased, got %d", r.SetsErased)
	}
}

func TestScorerWithAgaveFormatStillParsesAgaveShreds(t *testing.T) {
	s := NewScorerWithFormat(FormatAgave)
	if _, err := s.Observe(forwarderPacket(3, 1, 0, 0, false, 0), time.Now()); err == nil {
		t.Fatal("forwarder framing should not parse as an Agave shred")
	}
}
