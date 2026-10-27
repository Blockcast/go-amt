package txfeed

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestFooterTimes replays the 2026-10-22 capture of TestAlpenglowLiveSets,
// each frame arriving at its own send_ts_us: a receiver on the clock of the
// listener that forwarded it, with no path delay. A footer's latency is then
// its leader to forwarder delay, which a sampler deleted on 10-23 measured as
// 93.9 and 96.8 ms. The capture holds no shred of the set before a footer's,
// so the footer's batch decodes only once that set's DATA_COMPLETE shred is
// primed.
func TestFooterTimes(t *testing.T) {
	frames := fixtureFrames(t, "alpenglow-sets-2026-10-22.bin.gz", 327)
	type block struct {
		slot     uint64
		footer   uint32 // the footer's FEC set
		hash     string // its bank hash
		agent    string // its client prefix, "" from Firedancer
		producer uint64
	}
	blocks := []block{
		{460191482, 480, "2BLWnrUPqLvMHp3oqq9Y8xBpobR4tFqTwR41rb8DLzh4", "agave/4.3.2", 1792705262401095514},
		{460191528, 576, "BphWnFDaMML883x7NhQcVHwL4FNd36FBGVwogJ9J7Qh9", "", 1792705271897184280},
	}
	for _, tc := range []struct {
		name        string
		lose, prime bool // lose each footer's own data shred; prime the DATA_COMPLETE shred before its set
		latency     [2]time.Duration
	}{
		// The footer's own data shred, the first of its set.
		{"received", false, false, [2]time.Duration{93_885_486, 96_819_720}},
		// The 32nd shard of its set, a data shred at 23 and a coding shard at 34.
		{"recovered", true, false, [2]time.Duration{107_333_486, 180_231_720}},
		// That shard also decodes the footer's batch, which releases its shreds.
		{"recovered, batch", true, true, [2]time.Duration{107_333_486, 180_231_720}},
	} {
		ft := NewFooterTimes()
		var got []FooterTime
		for _, b := range blocks {
			if tc.prime { // the capture misses it, so the footer's batch could never start
				ft.Add(testFrame(b.slot, b.footer-numData, numData-1, testDataShard(b.slot, b.footer-1, flagDataComplete, nil), false), time.Time{})
			}
		}
		for _, fr := range frames {
			slot, fec := binary.LittleEndian.Uint64(fr[1:9]), binary.LittleEndian.Uint32(fr[9:13])
			if tc.lose && binary.LittleEndian.Uint32(fr[13:17]) == 0 &&
				slices.ContainsFunc(blocks, func(b block) bool { return b.slot == slot && b.footer == fec }) {
				continue
			}
			got = append(got, ft.Add(fr, time.UnixMicro(int64(binary.LittleEndian.Uint64(fr[20:28]))))...)
		}
		if len(got) != len(blocks) {
			t.Fatalf("%s: %d footers, want %d: %+v", tc.name, len(got), len(blocks), got)
		}
		for i, b := range blocks {
			g := got[i]
			if g.Slot != b.slot || Base58Encode(g.BankHash[:]) != b.hash || !strings.HasPrefix(g.UserAgent, b.agent) || (b.agent == "") != (g.UserAgent == "") ||
				g.ProducerTimeNanos != b.producer || g.Latency() != tc.latency[i] || g.Recovered != tc.lose || g.ShredTs != uint64(g.At.UnixMicro()) {
				t.Errorf("%s: footer %d = %+v, latency %v; want slot %d, bank hash %s, client %q, latency %v, recovered %v",
					tc.name, i, g, g.Latency(), b.slot, b.hash, b.agent, tc.latency[i], tc.lose)
			}
			// Primed, the batch decoded and released the footer's shreds, so only
			// the batch could report it.
			ss := ft.asm.slots[b.slot]
			if ss == nil {
				t.Fatalf("%s: slot %d not held after the replay", tc.name, b.slot)
			}
			if _, held := ss.payload[b.footer]; held == tc.prime {
				t.Errorf("%s: slot %d: footer shred held %v after the replay", tc.name, b.slot, held)
			}
		}
	}
}

// footerMarker is a footer from an Agave 4.3.2 leader stamped at producer, its
// bank hash all 7s, with certs bytes of certificates.
func footerMarker(producer time.Time, certs int) []byte {
	body := append([]byte{1}, bytes.Repeat([]byte{7}, 32)...) // version 1, bank hash
	body = binary.LittleEndian.AppendUint64(body, uint64(producer.UnixNano()))
	body = append(append(body, byte(len("agave/4.3.2"))), "agave/4.3.2"...)
	return marker(MarkerFooter, append(body, make([]byte, certs)...))
}

// A footer with more certificates than one shred carries is timed at the
// arrival of the last of its shreds, not before: shreds held past a missing
// one never stand in for its bytes, even where they make up the length.
func TestFooterTimesLongFooter(t *testing.T) {
	producer := time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)
	m := footerMarker(producer, 2000) // three shreds
	// Each shred zero-filled to full size, as a Firedancer leader sends them,
	// and shred 3 padding: without shred 1, shreds 0, 2 and 3 hold more bytes
	// than the footer states.
	m = append(m, make([]byte, 4*testPayload-len(m))...)
	frame := func(i uint32) []byte {
		return testFrame(9, 32, i, testDataShard(9, 32+i, 0, m[i*testPayload:(i+1)*testPayload]), false)
	}
	ft := NewFooterTimes()
	for _, i := range []uint32{0, 2, 3} {
		if got := ft.Add(frame(i), producer.Add(90*time.Millisecond)); len(got) != 0 {
			t.Fatalf("shred %d, without shred 1: %+v; want no footer yet", i, got)
		}
	}
	at, last := producer.Add(95*time.Millisecond), frame(1)
	got := ft.Add(last, at)
	if len(got) != 1 || got[0].Slot != 9 || got[0].BankHash != [32]byte(bytes.Repeat([]byte{7}, 32)) || got[0].UserAgent != "agave/4.3.2" ||
		!got[0].At.Equal(at) || got[0].Latency() != 95*time.Millisecond || got[0].Recovered || got[0].ShredTs != binary.LittleEndian.Uint64(last[20:28]) {
		t.Errorf("shred 1: %+v; want the footer, 95ms after its producer time", got)
	}
}

// Bytes that frame a footer are one only where a component can start: not in
// a set that continues an entry batch, nor in a frame the Assembler refused.
func TestFooterTimesWhereNoComponentStarts(t *testing.T) {
	m := footerMarker(time.Unix(0, 1), 0)
	// An entry batch running on into the second set, whose bytes at that set's
	// first data shred frame a footer.
	batch := append(binary.LittleEndian.AppendUint64(nil, 1), make([]byte, numData*testPayload-8)...) // one entry
	batch = append(batch, m...)
	next := testFrame(9, numData, 0, testDataShard(9, numData, 0, batch[numData*testPayload:]), false)
	for _, tc := range []struct {
		name    string
		frames  [][]byte // added in order
		footers int
	}{
		// Nothing held says the set continues a batch.
		{"its set's first shred alone", [][]byte{next}, 1},
		{"after the end of a batch", [][]byte{
			testFrame(9, 0, numData-1, testDataShard(9, numData-1, flagDataComplete, nil), false), next}, 1},
		{"after the batch's shred before it", [][]byte{
			testFrame(9, 0, numData-1, testDataShard(9, numData-1, 0, batch[(numData-1)*testPayload:numData*testPayload]), false), next}, 0},
		// The footer's bytes in data shred 33, then a frame stating a set
		// starting there, which the Assembler refuses.
		{"a refused frame", [][]byte{
			testFrame(9, numData, 1, testDataShard(9, numData+1, 0, m), false),
			testFrame(9, numData+1, 0, testDataShard(9, numData+1, 0, nil), false)}, 0},
	} {
		ft := NewFooterTimes()
		var got []FooterTime
		for _, fr := range tc.frames {
			got = append(got, ft.Add(fr, time.Unix(1, 0))...)
		}
		if len(got) != tc.footers {
			t.Errorf("%s: %+v; want %d footers", tc.name, got, tc.footers)
		}
	}
}

// A footer is read once its set's shreds held hold its stated length, and not
// before: one stating more than its set holds is never read and costs no
// allocation, whatever arrives of the set or the sets after it, and one
// stating no body is one parse error a frame.
func TestFooterTimesBoundedWork(t *testing.T) {
	for _, tc := range []struct {
		body   uint16
		allocs float64
	}{
		{0, 8}, // a parse error a frame, not one a shred
		{0xffff, 0},
	} {
		m := footerMarker(time.Unix(0, 1), 0)
		binary.LittleEndian.PutUint16(m[len(footerFraming):], tc.body)
		var set [][]byte
		for i := range uint32(numData) {
			p := make([]byte, testPayload)
			if i == 0 {
				p = m
			}
			set = append(set, testFrame(9, numData, i, testDataShard(9, numData+i, 0, p), false))
		}
		ft := NewFooterTimes()
		// The data shreds of the two sets after the footer's, which with its own
		// hold more than a body of 0xffff bytes.
		for i := 2 * uint32(numData); i < 4*numData; i++ {
			ft.Add(testFrame(9, i/numData*numData, i%numData, testDataShard(9, i, 0, make([]byte, testPayload)), false), time.Unix(1, 0))
		}
		for _, fr := range set {
			if got := ft.Add(fr, time.Unix(1, 0)); len(got) != 0 {
				t.Fatalf("body length %d: %+v; want no footer", tc.body, got)
			}
		}
		// Each frame of the set looks again: a copy of the last.
		if a := testing.AllocsPerRun(100, func() { ft.Add(set[numData-1], time.Unix(1, 0)) }); a > tc.allocs {
			t.Errorf("body length %d: %v allocations a frame, want at most %v", tc.body, a, tc.allocs)
		}
	}
}
