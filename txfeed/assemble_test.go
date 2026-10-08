package txfeed

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/klauspost/reedsolomon"
)

const (
	testShardSize = 987 // a 32:32 chained Merkle erasure shard: proof 6, not resigned
	testPayload   = testShardSize - dataHeaderSize
)

// testSlot is one slot's entry batches, shredded the way Agave does: each
// batch's payload split over data shreds of testPayload bytes,
// DATA_COMPLETE on its last shred, the final FEC set padded with empty
// shreds, and LAST_SHRED_IN_SLOT on the slot's last shred.
type testSlot struct {
	slot    uint64
	batches [][]byte // payloads
	starts  []uint32 // each batch's first data shred
	data    [][]byte // data shards by index
}

func newTestSlot(rng *rand.Rand, slot uint64, sizes ...int) *testSlot {
	ts := &testSlot{slot: slot}
	for bi, n := range sizes {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(rng.Uint32())
		}
		ts.batches = append(ts.batches, p)
		ts.starts = append(ts.starts, uint32(len(ts.data)))
		var chunks [][]byte
		for off := 0; off < n || len(chunks) == 0; off += testPayload {
			chunks = append(chunks, p[off:min(off+testPayload, n)])
		}
		last := bi == len(sizes)-1
		for last && (len(ts.data)+len(chunks))%32 != 0 {
			chunks = append(chunks, nil)
		}
		for j, c := range chunks {
			var flags byte
			if j == len(chunks)-1 {
				flags = flagDataComplete
				if last {
					flags = 0xc0 // LAST_SHRED_IN_SLOT
				}
			}
			ts.data = append(ts.data, testDataShard(slot, uint32(len(ts.data)), flags, c))
		}
	}
	return ts
}

func testDataShard(slot uint64, index uint32, flags byte, payload []byte) []byte {
	s := make([]byte, testShardSize)
	s[0] = 0x96 // chained Merkle data, proof 6
	binary.LittleEndian.PutUint64(s[1:9], slot)
	binary.LittleEndian.PutUint32(s[9:13], index)
	binary.LittleEndian.PutUint32(s[15:19], index/32*32)
	binary.LittleEndian.PutUint16(s[19:21], 1) // parent_offset
	s[21] = flags
	binary.LittleEndian.PutUint16(s[22:24], uint16(64+dataHeaderSize+len(payload)))
	copy(s[dataHeaderSize:], payload)
	return s
}

// sets frames the slot, by FEC set: 32 data frames, then the 32 coding frames
// klauspost encodes. v4 frames carry full shreds: 0x96 data, 1203 bytes, and
// 0x66 coding, 1228 bytes. Every frame's send_ts_us is distinct.
func (ts *testSlot) sets(t *testing.T, v4 bool) [][][]byte {
	enc, err := reedsolomon.New(32, 32)
	if err != nil {
		t.Fatal(err)
	}
	var sets [][][]byte
	for fec := 0; fec < len(ts.data); fec += 32 {
		shards := slices.Clone(ts.data[fec : fec+32])
		for range 32 {
			shards = append(shards, make([]byte, testShardSize))
		}
		if err := enc.Encode(shards); err != nil {
			t.Fatal(err)
		}
		var set [][]byte
		for local, s := range shards {
			set = append(set, testFrame(ts.slot, uint32(fec), uint32(local), s, v4))
		}
		sets = append(sets, set)
	}
	return sets
}

func testFrame(slot uint64, fec, local uint32, shard []byte, v4 bool) []byte {
	h := make([]byte, 28)
	h[0] = 3
	binary.LittleEndian.PutUint64(h[1:9], slot)
	binary.LittleEndian.PutUint32(h[9:13], fec)
	binary.LittleEndian.PutUint32(h[13:17], local)
	coding := local >= 32
	if coding {
		h[17], h[18], h[19] = 0x02, 32, 32
	}
	binary.LittleEndian.PutUint64(h[20:28], slot<<20|uint64(fec)<<6|uint64(local))
	if !v4 {
		return append(h, shard...)
	}
	h[0] = 4
	signature, trailer := make([]byte, 64), make([]byte, 32+6*20)
	if !coding {
		return slices.Concat(h, signature, shard, trailer)
	}
	headers := make([]byte, 19+6) // the rest of the common header, then the coding header
	headers[0] = 0x66             // chained Merkle code, proof 6
	binary.LittleEndian.PutUint64(headers[1:9], slot)
	binary.LittleEndian.PutUint32(headers[9:13], fec+local-32)
	binary.LittleEndian.PutUint32(headers[15:19], fec)
	binary.LittleEndian.PutUint16(headers[19:21], 32)
	binary.LittleEndian.PutUint16(headers[21:23], 32)
	binary.LittleEndian.PutUint16(headers[23:25], uint16(local-32))
	return slices.Concat(h, signature, headers, shard, trailer)
}

// feed adds frames in order. Each batch must carry the send time of the frame
// that completed it.
func feed(t *testing.T, a *Assembler, frames [][]byte) []Batch {
	t.Helper()
	var out []Batch
	for _, f := range frames {
		bs := a.Add(f)
		for _, b := range bs {
			if want := binary.LittleEndian.Uint64(f[20:28]); b.ShredTs != want {
				t.Errorf("batch at %d: ShredTs %d, want %d from the frame that completed it", b.StartIndex, b.ShredTs, want)
			}
		}
		out = append(out, bs...)
	}
	return out
}

// check asserts got is exactly the slot's batches whose data shreds are all
// available, each once and byte-exact. A batch also needs the shred before
// it, which says where it starts.
func (ts *testSlot) check(t *testing.T, got []Batch, available func(i uint32) bool) {
	t.Helper()
	byStart := map[uint32]Batch{}
	for _, b := range got {
		if _, dup := byStart[b.StartIndex]; dup || b.Slot != ts.slot {
			t.Errorf("batch at slot %d index %d: emitted twice, or in the wrong slot", b.Slot, b.StartIndex)
		}
		byStart[b.StartIndex] = b
	}
	want := 0
	for i, s := range ts.starts {
		e := uint32(len(ts.data))
		if i+1 < len(ts.starts) {
			e = ts.starts[i+1]
		}
		decodable := s == 0 || available(s-1)
		for j := s; j < e; j++ {
			decodable = decodable && available(j)
		}
		b, ok := byStart[s]
		switch {
		case decodable && !ok:
			t.Errorf("batch %d at %d..%d was not emitted", i, s, e-1)
		case !decodable && ok:
			t.Errorf("batch %d at %d..%d was emitted, but it was not complete", i, s, e-1)
		case ok && !bytes.Equal(b.Payload, ts.batches[i]):
			t.Errorf("batch %d at %d: %d bytes, not the %d it was shredded from", i, s, len(b.Payload), len(ts.batches[i]))
		}
		if decodable {
			want++
		}
	}
	if len(got) != want {
		t.Errorf("%d batches emitted, want %d", len(got), want)
	}
}

// lossy returns the frames of sets, dropping drop(set) frames of each set at
// random, duplicating one in ten and shuffling the lot. It also returns the
// dropped frames and the number of duplicates.
func lossy(rng *rand.Rand, sets [][][]byte, drop func(set int) int) (frames [][]byte, dropped map[*byte]bool, dups int) {
	dropped = map[*byte]bool{}
	for k, set := range sets {
		n := drop(k)
		for i, j := range rng.Perm(len(set)) {
			if i < n {
				dropped[&set[j][0]] = true
			} else {
				frames = append(frames, set[j])
			}
		}
	}
	for n := len(frames); dups < n/10; dups++ {
		frames = append(frames, frames[rng.IntN(n)])
	}
	rng.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })
	return frames, dropped, dups
}

func TestAssemblerRecoversEveryBatch(t *testing.T) {
	sizes := []int{1, 500, testPayload, testPayload + 1, 0, 2000, 32 * testPayload, 40000, 3}
	for _, v4 := range []bool{false, true} {
		var total Stats
		for seed := range uint64(20) {
			rng := rand.New(rand.NewPCG(seed, 7))
			ts := newTestSlot(rng, 300000000+seed, sizes...)
			sets := ts.sets(t, v4)
			// Any 32 of a set's 64 shards recover it.
			frames, _, dups := lossy(rng, sets, func(int) int { return rng.IntN(33) })
			a := NewAssembler(64)
			ts.check(t, feed(t, a, frames), func(uint32) bool { return true })

			s := a.Stats()
			if s.Frames != uint64(len(frames)) || s.Dups != uint64(dups) || s.Bad != 0 || s.RecoveredBad != 0 || s.ParityMismatch != 0 {
				t.Errorf("v4=%t seed %d: %+v; want %d frames, %d dups, nothing bad", v4, seed, s, len(frames), dups)
			}
			total.SetsRecovered += s.SetsRecovered
			total.ShardsRecovered += s.ShardsRecovered
			total.ParityChecked += s.ParityChecked
		}
		if total.SetsRecovered == 0 || total.ShardsRecovered == 0 || total.ParityChecked == 0 {
			t.Errorf("v4=%t: %+v; the runs never recovered a shard or checked parity, so they tested neither", v4, total)
		}
	}
}

func TestAssemblerDecodesPastAnUnrecoverableGap(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	var sizes []int
	for range 60 {
		sizes = append(sizes, rng.IntN(3*testPayload))
	}
	ts := newTestSlot(rng, 5, sizes...)
	sets := ts.sets(t, false)
	if len(sets) < 3 {
		t.Fatalf("%d FEC sets; the test needs one on each side of the broken one", len(sets))
	}
	// Set 1 keeps 31 shards, one short of recovery; the others lose up to 32.
	frames, dropped, _ := lossy(rng, sets, func(set int) int {
		if set == 1 {
			return 33
		}
		return rng.IntN(33)
	})
	a := NewAssembler(64)
	got := feed(t, a, frames)
	available := func(i uint32) bool { return i/32 != 1 || !dropped[&sets[1][i%32][0]] }
	ts.check(t, got, available)
	if !slices.ContainsFunc(got, func(b Batch) bool { return b.StartIndex >= 64 }) {
		t.Error("no batch after the broken set decoded")
	}
}

func TestAssemblerRejectsARecoveredShardWithTheWrongHeader(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	ts := newTestSlot(rng, 9, 3000, 2000, 30000)
	// Corrupt data shred 5's index before encoding, so parity agrees with
	// the bad header and recovery reproduces it.
	binary.LittleEndian.PutUint32(ts.data[5][9:13], 6)
	sets := ts.sets(t, false)
	frames := slices.Concat(sets...)
	frames = slices.Delete(frames, 5, 6)

	a := NewAssembler(64)
	ts.check(t, feed(t, a, frames), func(i uint32) bool { return i != 5 })
	if s := a.Stats(); s.RecoveredBad != 1 || s.ShardsRecovered != 0 || s.Bad != 0 {
		t.Errorf("%+v; want the one recovered shard rejected, nothing else", s)
	}
}

func TestAssemblerChecksParity(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	ts := newTestSlot(rng, 9, 3000)
	set := ts.sets(t, false)[0]
	set[40][28+100] ^= 0x01 // a coding shard's byte

	a := NewAssembler(64)
	ts.check(t, feed(t, a, set), func(uint32) bool { return true }) // data first: nothing to recover
	if s := a.Stats(); s.ParityChecked != 1 || s.ParityMismatch != 1 {
		t.Errorf("%+v; want 1 set checked, 1 mismatch", s)
	}
}

func TestAssemblerEvictsOldSlots(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 10))
	old := newTestSlot(rng, 100, 2*testPayload) // one batch, two shreds
	set := old.sets(t, false)[0]

	a := NewAssembler(4)
	feed(t, a, [][]byte{set[0]})
	feed(t, a, [][]byte{newTestSlot(rng, 104, 1).sets(t, false)[0][0]}) // 4 slots on: kept
	if s := a.Stats(); s.Evicted != 0 || s.Slots != 2 {
		t.Fatalf("%+v; slot 100 is still inside the window", s)
	}
	feed(t, a, [][]byte{newTestSlot(rng, 105, 1).sets(t, false)[0][0]})
	if s := a.Stats(); s.Evicted != 1 || s.Slots != 2 || s.MaxSlot != 105 {
		t.Fatalf("%+v; want slot 100 evicted", s)
	}
	if got := feed(t, a, [][]byte{set[1]}); len(got) != 0 || a.Stats().Slots != 2 {
		t.Errorf("a late frame for the evicted slot completed %d batches or revived it", len(got))
	}
}

func TestAssemblerCountsBadFrames(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 12))
	ts := newTestSlot(rng, 50, 1000)
	v3, v4 := ts.sets(t, false)[0], ts.sets(t, true)[0]
	with := func(f []byte, at int, v byte) []byte {
		f = bytes.Clone(f)
		f[at] = v
		return f
	}
	size := func(f []byte, n uint16) []byte {
		f = bytes.Clone(f)
		binary.LittleEndian.PutUint16(f[28+22:], n)
		return f
	}
	a := NewAssembler(64)
	bad := [][]byte{
		v3[0][:27],                      // shorter than the header
		with(v3[0], 0, 5),               // unknown version
		v4[0][:len(v4[0])-1],            // FrameV3 refuses it
		with(v3[1], 28+9, 0xee),         // the shard's index is not its position
		with(v3[1], 28+15, 1),           // the shard's fec_set_index is not the frame's
		size(v3[1], 87),                 // size below the headers
		size(v3[1], 64+testShardSize+1), // payload past the shard
		with(v3[40], 18, 0),             // coding without a geometry
		with(v3[40], 13, 31),            // coding local index inside the data range
		v3[2][:len(v3[2])-1],            // not the set's shard size
	}
	feed(t, a, [][]byte{v3[0]}) // fixes the set's shard size
	feed(t, a, bad)
	if s := a.Stats(); s.Bad != uint64(len(bad)) || s.Slots != 1 {
		t.Errorf("%+v; want %d bad frames", s, len(bad))
	}
}
