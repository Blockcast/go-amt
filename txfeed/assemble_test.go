package txfeed

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
	"time"

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
			a := NewAssembler(testKeep)
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
	a := NewAssembler(testKeep)
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

	a := NewAssembler(testKeep)
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

	a := NewAssembler(testKeep)
	ts.check(t, feed(t, a, set), func(uint32) bool { return true }) // data first: nothing to recover
	if s := a.Stats(); s.ParityChecked != 1 || s.ParityMismatch != 1 {
		t.Errorf("%+v; want 1 set checked, 1 mismatch", s)
	}
}

const testKeep = 10 * time.Second

func TestAssemblerForgetsIdleSlots(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 10))
	old := newTestSlot(rng, 100, 2*testPayload) // one batch, two shreds
	set := old.sets(t, false)[0]

	a := NewAssembler(testKeep)
	clock := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return clock }
	feed(t, a, [][]byte{set[0]})
	clock = clock.Add(9 * time.Second) // slot 100 idle 9s, inside keep
	feed(t, a, [][]byte{newTestSlot(rng, 104, 1).sets(t, false)[0][0]})
	if s := a.Stats(); s.Evicted != 0 || s.Slots != 2 {
		t.Fatalf("%+v; slot 100 is still inside keep", s)
	}
	clock = clock.Add(7 * time.Second) // idle 16s; sweeps run every keep/2
	feed(t, a, [][]byte{newTestSlot(rng, 105, 1).sets(t, false)[0][0]})
	if s := a.Stats(); s.Evicted != 1 || s.Slots != 2 || s.MaxSlot != 105 {
		t.Fatalf("%+v; want slot 100 forgotten", s)
	}
	// A late frame starts the slot afresh, without the shred before it that
	// says where its batch starts.
	if got := feed(t, a, [][]byte{set[1]}); len(got) != 0 {
		t.Errorf("a late frame for a forgotten slot completed %d batches", len(got))
	}
}

// A forged far-future slot used to move a slot window past every real slot,
// and nothing decoded again. Arrival-time state has no window to move.
func TestAssemblerDecodesPastAForgedSlot(t *testing.T) {
	rng := rand.New(rand.NewPCG(13, 14))
	ts := newTestSlot(rng, 100, 3*testPayload, 40*testPayload)
	var frames [][]byte
	for _, set := range ts.sets(t, false) {
		frames = append(frames, set...)
	}
	a := NewAssembler(testKeep)
	got := feed(t, a, frames[:5])
	for _, forged := range []uint64{1 << 62, 1<<64 - 1, 1} {
		got = append(got, feed(t, a, [][]byte{testFrame(forged, 0, 0, testDataShard(forged, 0, 0, []byte{1}), false)})...)
	}
	got = append(got, feed(t, a, frames[5:])...)
	ts.check(t, got, func(uint32) bool { return true })
}

func TestAssemblerBoundsSlotsUnderAFlood(t *testing.T) {
	rng := rand.New(rand.NewPCG(15, 16))
	ts := newTestSlot(rng, 100, 3*testPayload, 40*testPayload)
	var frames [][]byte
	for _, set := range ts.sets(t, false) {
		frames = append(frames, set...)
	}
	a := NewAssembler(testKeep)
	clock := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	a.now = func() time.Time { clock = clock.Add(time.Microsecond); return clock }
	var got []Batch
	forged := uint64(1 << 40)
	for _, f := range frames {
		got = append(got, feed(t, a, [][]byte{f})...)
		for range 3 * maxSlots / len(frames) {
			a.Add(testFrame(forged, 0, 0, testDataShard(forged, 0, 0, []byte{1}), false))
			forged++
		}
	}
	if s := a.Stats(); s.Slots > maxSlots {
		t.Errorf("holding %d slots, want at most %d", s.Slots, maxSlots)
	}
	ts.check(t, got, func(uint32) bool { return true }) // the slot being received survived the flood
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
	a := NewAssembler(testKeep)
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

// Data frames carry no geometry, so a forged one could claim a coding
// position in the bitmap of received local indexes. Sixty-four of them once
// "completed" a set with no coding shards, and the parity check panicked.
func TestAssemblerKeepsDataFramesOffCodingPositions(t *testing.T) {
	data := func(slot uint64, local uint32) []byte {
		s := testDataShard(slot, local, 0, []byte{1})
		binary.LittleEndian.PutUint32(s[15:19], 0) // every frame in FEC set 0
		f := testFrame(slot, 0, local, s, false)
		f[17], f[18], f[19] = 0, 0, 0 // a data frame, whatever its local index
		return f
	}
	a := NewAssembler(testKeep)
	for local := range uint32(64) {
		a.Add(data(1, local))
	}
	if s := a.Stats(); s.Bad != 32 {
		t.Errorf("%+v; want the 32 data frames past num_data rejected", s)
	}

	// Nor can a coding frame move the boundary by stating another geometry.
	for local := range uint32(21) {
		a.Add(data(2, local))
	}
	f := testFrame(2, 0, 25, make([]byte, testShardSize), false)
	f[17], f[18], f[19] = 0x02, 16, 16 // 16:16 would make local 25 coding position 9
	before := a.Stats().Bad
	a.Add(f)
	if s := a.Stats(); s.Bad != before+1 {
		t.Errorf("%+v; want the 16:16 coding frame refused", s)
	}

	// And a rejected frame does not fix the set's shard size.
	before = a.Stats().Bad
	a.Add(data(4, 40)[:28+32]) // past num_data, and short
	a.Add(data(4, 0))
	if s := a.Stats(); s.Bad != before+1 {
		t.Errorf("%+v; want only the rejected frame bad", s)
	}
}

// The geometry comes off the wire, and Reed-Solomon work grows with it: a
// stream rotating large geometries made every set rebuild an encoder (Ally,
// go-amt#145, the supplementary pass on bb7e505). Only 32:32 is accepted, as
// shred/header.go requires.
func TestAssemblerRefusesGeometriesButThirtyTwoThirtyTwo(t *testing.T) {
	a := NewAssembler(testKeep)
	for i, g := range [][2]byte{{1, 1}, {16, 16}, {32, 33}, {33, 32}, {64, 64}, {128, 128}, {32, 32}} {
		f := testFrame(3, uint32(32*i), 40, make([]byte, testShardSize), false)
		f[18], f[19] = g[0], g[1]
		a.Add(f)
	}
	if s := a.Stats(); s.Bad != 6 || s.Held != 1 {
		t.Errorf("%+v; want the six geometries other than 32:32 refused, the 32:32 frame held", s)
	}
}

// A slot's data shreds are indexed in fixed bitmaps, not in a slice sized by
// the highest index seen, which let one forged frame at 32767 pin a megabyte
// (Ally, go-amt#145 review 5464388445).
func TestAssemblerMemoryDoesNotFollowTheIndex(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	a := NewAssembler(testKeep)
	for slot := range uint64(maxSlots) {
		s := testDataShard(slot+1, 32767, 0, []byte{1})
		a.Add(testFrame(slot+1, 32767/32*32, 31, s, false))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if s := a.Stats(); s.Held != maxSlots || s.Bad != 0 {
		t.Fatalf("%+v; want one frame held in each of %d slots", s, maxSlots)
	}
	// 12 KiB of index and one frame per slot is 1.7 MiB; an index-sized slice
	// was 128 MiB.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 16<<20 {
		t.Errorf("%d frames at index 32767 hold %d MiB", maxSlots, grew>>20)
	}
	runtime.KeepAlive(a)
}

// Finding a batch's ends along a run with no DATA_COMPLETE used to walk the
// run shred by shred, so a run sent in reverse cost quadratic time: 1.6 s for
// 32768 shreds, against 0.07 s in order. The bitmaps keep the reverse order
// within a small factor of the forward one.
func TestAssemblerReverseRunCostsAboutWhatForwardDoes(t *testing.T) {
	frames := make([][]byte, maxSlotIndexes)
	for i := range uint32(maxSlotIndexes) {
		frames[i] = testFrame(7, i/32*32, i%32, testDataShard(7, i, 0, []byte{1}), false)
	}
	run := func(order func(int) int) time.Duration {
		a := NewAssembler(testKeep)
		start := time.Now()
		for k := range frames {
			a.Add(frames[order(k)])
		}
		return time.Since(start)
	}
	fwd := run(func(k int) int { return k })
	rev := run(func(k int) int { return len(frames) - 1 - k })
	if rev > 4*fwd+50*time.Millisecond {
		t.Errorf("reverse order took %v, forward %v: the search for a batch's ends is no longer cheap", rev, fwd)
	}
}

// FuzzAssembler feeds frames built from the input. Their headers agree with
// their framing, so they get past validation into the set logic, which must
// never panic or outgrow its bounds. Each 8-byte op is a run of frames:
// slot (and, with its top two bits set, a set not starting at a multiple of
// 32), FEC set, first local index, run length, kind (and whether a coding
// frame states another geometry), its num_data or the data flags, payload,
// and how far the clock then moves.
func FuzzAssembler(f *testing.F) {
	f.Add([]byte{1, 0, 0, 31, 0, 0x40, 9, 0, 1, 0, 32, 31, 65, 32, 7, 1})
	f.Add([]byte{0xd5, 3, 0, 31, 0, 0x40, 9, 0, 0xd5, 3, 32, 31, 1, 0, 7, 1}) // a set starting at 405
	f.Fuzz(func(t *testing.T, ops []byte) {
		a := NewAssembler(testKeep)
		clock := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
		a.now = func() time.Time { return clock }
		for ; len(ops) >= 8; ops = ops[8:] {
			slot, fec := uint64(ops[0]%4), uint32(ops[1])<<7 // up to 32640, near the last index
			if ops[0]&0xc0 == 0xc0 {
				fec += uint32(ops[0]>>2) & 31 // a set not starting at a multiple of 32, to be refused
			}
			for local := uint32(ops[2]); local <= uint32(ops[2])+uint32(ops[3]%64); local++ {
				var fr []byte
				if ops[4]&1 == 0 {
					s := testDataShard(slot, fec+local, ops[5]&0xc0, bytes.Repeat([]byte{ops[6]}, int(ops[6])))
					binary.LittleEndian.PutUint32(s[15:19], fec)
					fr = testFrame(slot, fec, local, s, false)
					fr[17], fr[18], fr[19] = 0, 0, 0
				} else {
					fr = testFrame(slot, fec, local, bytes.Repeat([]byte{ops[6]}, testShardSize), false)
					fr[17], fr[18], fr[19] = 0x02, 32, 32
					if ops[4]&2 != 0 {
						fr[18], fr[19] = ops[5], ops[4]>>2 // another geometry, to be refused
					}
				}
				bad := a.stats.Bad
				a.Add(fr)
				if fec%numData != 0 && a.stats.Bad != bad+1 {
					t.Fatalf("a frame of a set starting at %d was not refused", fec)
				}
			}
			clock = clock.Add(time.Duration(ops[7]) * time.Second / 16)
		}
		if s := a.Stats(); s.Slots > maxSlots {
			t.Errorf("%+v: past the slot bound", s)
		}
	})
}

// A set starts at a multiple of 32, so a flood of distinct set indexes on one
// slot number holds at most 1024 sets. Taking any index let one 52-byte frame
// per index pin 1.9 KiB of set: 59 MiB a slot, 36 times what was sent.
func TestAssemblerBoundsWhatOneSlotHolds(t *testing.T) {
	a := NewAssembler(testKeep)
	shard := make([]byte, testShardSize)
	for fec := range uint32(maxSlotIndexes) {
		a.Add(testFrame(5, fec, 32, shard, false)) // one coding frame a set
	}
	sets := uint64(maxSlotIndexes / numData)
	if s := a.Stats(); s.Held != sets || s.Bad != maxSlotIndexes-sets {
		t.Errorf("%+v; want the %d sets starting at a multiple of %d held, the rest refused", s, sets, numData)
	}
}
