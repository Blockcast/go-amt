// Package txfeed turns the shred union into a feed of decoded Solana
// transactions, partitioned onto multicast groups by vote/non-vote and by
// program (BLO-41705).
//
// The pipeline: reduce each union frame to its erasure shard, assemble FEC
// sets (recovering missing data shards with Reed-Solomon), deshred complete
// entry batches, parse each transaction (legacy, v0 or SIMD-0385 v1),
// classify it, and frame it one per datagram for every partition group it
// belongs to.
//
// Nothing here authenticates shreds: a wire version 3 frame carries no
// signature to check. A transaction's own signatures prove who signed it,
// not that a leader put it in a block.
package txfeed

import (
	"bytes"
	"encoding/binary"
	"slices"
	"time"

	"github.com/klauspost/reedsolomon"

	"github.com/blockcast/go-amt/shred"
)

// A data shard is the data shred after its 64-byte signature, so each offset
// here is the Agave shred offset minus 64:
//
//	[0]       variant
//	[1:9]     slot           u64 LE
//	[9:13]    index          u32 LE
//	[13:15]   version        u16 LE
//	[15:19]   fec_set_index  u32 LE
//	[19:21]   parent_offset  u16 LE
//	[21]      flags          u8  0x40 DATA_COMPLETE_SHRED, 0xc0 LAST_SHRED_IN_SLOT
//	                             (which includes 0x40); low 6 bits: reference tick
//	[22:24]   size           u16 LE  shred bytes through the payload: 88 + payload length
//	[24:size-64]  payload
const (
	dataHeaderSize   = 24
	flagDataComplete = 0x40

	// Bounds on what a hostile stream can make the assembler hold.
	maxSetShards   = 256   // data + coding shards per FEC set
	maxSlotIndexes = 32768 // data shred indexes per slot

	// maxSlots bounds the slots held under a flood of distinct forged slots.
	// Real traffic holds keep times the slot rate, about 40 at a keep of 10s.
	// Past it, the slot idle longest goes first, and a slot still being
	// received is never the idlest.
	maxSlots = 128

	// maxSlotFrames bounds what one slot holds. A flood of distinct sets and
	// local indexes on one slot number keeps that slot fresh, so neither keep
	// nor maxSlots ever forgets it. A real slot carries at most 32768 data
	// shreds and as many coding. Past it, the slot starts over.
	maxSlotFrames = 1 << 16

	// maxEncoders bounds the Reed-Solomon encoders cached by geometry, which
	// comes off the wire. Production uses one.
	maxEncoders = 8

	// Production is 32:32 on every set. Data frames carry no geometry, so a
	// set assumes this until a coding frame states its own.
	defaultNumData   = 32
	defaultNumCoding = 32

	// The parity check samples sets that arrive complete: the first
	// parityWarmup, then every parityEvery-th.
	parityWarmup = 200
	parityEvery  = 1000
)

// Batch is one deshredded entry batch.
type Batch struct {
	Slot       uint64
	StartIndex uint32 // absolute data-shred index of the batch's first shred
	Payload    []byte // bincode Vec<Entry>
	ShredTs    uint64 // send_ts_us of the frame whose arrival completed the batch
}

// Stats counts what an Assembler has seen.
type Stats struct {
	Frames          uint64 // frames added
	Dups            uint64 // frames whose (slot, fec_set_index, local_index) was already received
	Bad             uint64 // malformed frames, dropped
	SetsRecovered   uint64 // FEC sets that recovered at least one data shard
	ShardsRecovered uint64 // data shards recovered
	RecoveredBad    uint64 // recovered data shards whose own header contradicts their position, discarded
	ParityChecked   uint64 // complete sets whose coding shards were re-encoded from their data
	ParityMismatch  uint64 // checked sets whose re-encoded parity differs from what was received
	Batches         uint64 // entry batches emitted
	Evicted         uint64 // slots forgotten: idle past keep, the idlest at maxSlots, or full at maxSlotFrames

	Slots   uint64 // slots held
	Held    uint64 // frames accepted into the slots held
	MaxSlot uint64 // highest slot seen
}

// Assembler reassembles entry batches from union frames. It is not safe for
// concurrent use.
//
// It forgets a slot once keep passes with no frame of it. State is bounded by
// arrival time, not by distance from the highest slot seen, because the slot
// is whatever the frame's sender wrote (see the package doc). With a slot
// window, one forged far-future slot pushed every real slot out of the window,
// and nothing decoded again.
type Assembler struct {
	keep     time.Duration
	now      func() time.Time // the arrival clock; tests replace it
	sweep    time.Time        // when the next eviction pass runs
	maxSlot  uint64           // for Stats only
	slots    map[uint64]*slotState
	encoders map[[2]int]reedsolomon.Encoder // by (num_data, num_coding)
	complete uint64                         // sets that arrived complete
	stats    Stats
}

type slotState struct {
	last   time.Time          // arrival of its latest frame
	frames int                // frames accepted, toward maxSlotFrames
	sets   map[uint32]*fecSet // by fec_set_index
	shreds []dataShred        // by absolute index
}

// dataShred is a data shred available to deshred, received or recovered.
type dataShred struct {
	payload []byte // released once its batch is decoded
	flags   byte
	have    bool
	decoded bool // the batch starting here was emitted
}

type fecSet struct {
	numData, numCoding int
	geometry           bool                      // a coding frame fixed numData and numCoding
	size               int                       // shard length, the same for every shard of the set
	data, coding       [][]byte                  // by position, nil when missing; data includes recovered shards
	received           [maxSetShards / 64]uint64 // bitmap of received local indexes
	tried              bool                      // reconstruction has run
	done               bool                      // every shard was received; data and coding are released
}

func (s *fecSet) has(local uint32) bool { return s.received[local/64]&(1<<(local%64)) != 0 }
func (s *fecSet) mark(local uint32)     { s.received[local/64] |= 1 << (local % 64) }

// NewAssembler returns an Assembler that forgets a slot once keep passes with
// no frame of it. A frame for a slot already forgotten starts the slot afresh.
func NewAssembler(keep time.Duration) *Assembler {
	return &Assembler{
		keep:     keep,
		now:      time.Now,
		slots:    map[uint64]*slotState{},
		encoders: map[[2]int]reedsolomon.Encoder{},
	}
}

// Stats returns the counters.
func (a *Assembler) Stats() Stats {
	s := a.stats
	s.Slots, s.MaxSlot = uint64(len(a.slots)), a.maxSlot
	for _, ss := range a.slots {
		s.Held += uint64(ss.frames)
	}
	return s
}

// Add takes one union frame, forwarder wire version 3 or 4, and returns the
// batches it completed, in order. The assembler keeps references into frame,
// so the caller must not reuse it.
func (a *Assembler) Add(frame []byte) []Batch {
	a.stats.Frames++
	if len(frame) > 0 && frame[0] == 4 {
		v3, ok := shred.FrameV3(frame)
		if !ok {
			a.stats.Bad++
			return nil
		}
		frame = v3
	}
	if len(frame) < shred.WireHeaderSize+dataHeaderSize || frame[0] != 3 {
		a.stats.Bad++
		return nil
	}
	slot := binary.LittleEndian.Uint64(frame[1:9])
	fec := binary.LittleEndian.Uint32(frame[9:13])
	local := binary.LittleEndian.Uint32(frame[13:17])
	coding := frame[17]&0x02 != 0 // flags bit1: IS_CODING_SHRED
	nd, nc := int(frame[18]), int(frame[19])
	ts := binary.LittleEndian.Uint64(frame[20:28])
	shard := frame[shred.WireHeaderSize:]

	// Validate before the frame can create state. A coding frame's local
	// index is num_data + its position; a data frame's is its position, and
	// its shard's own header must agree.
	var payload []byte
	var flags byte
	ok := fec < maxSlotIndexes && local < maxSetShards
	if ok && coding {
		ok = nd > 0 && nc > 0 && nd+nc <= maxSetShards && int(local) >= nd && int(local) < nd+nc
	} else if ok {
		payload, flags, ok = dataShard(shard, slot, fec, fec+local)
		ok = ok && fec+local < maxSlotIndexes
	}
	if !ok {
		a.stats.Bad++
		return nil
	}

	now := a.now()
	a.maxSlot = max(a.maxSlot, slot)
	if !now.Before(a.sweep) {
		// One pass per keep/2, so a slot can outlive keep by up to half of it.
		for s, ss := range a.slots {
			if now.Sub(ss.last) > a.keep {
				delete(a.slots, s)
				a.stats.Evicted++
			}
		}
		a.sweep = now.Add(a.keep / 2)
	}
	ss := a.slots[slot]
	if ss != nil && ss.frames >= maxSlotFrames {
		delete(a.slots, slot) // more frames than a real slot has: start it over
		a.stats.Evicted++
		ss = nil
	}
	if ss == nil {
		if len(a.slots) >= maxSlots {
			a.evictIdlest()
		}
		ss = &slotState{sets: map[uint32]*fecSet{}}
		a.slots[slot] = ss
	}
	ss.last = now
	set := ss.sets[fec]
	if set == nil {
		set = &fecSet{numData: defaultNumData, numCoding: defaultNumCoding}
		ss.sets[fec] = set
	}

	if set.has(local) {
		a.stats.Dups++
		return nil
	}
	// The bitmap of received local indexes says nothing of which kind of frame
	// took each one, so keep the kinds apart: data below num_data, coding from
	// it on (checked above), and the set's first coding frame cannot set a
	// num_data that a data frame already received reaches.
	if set.size != 0 && len(shard) != set.size ||
		!coding && int(local) >= set.numData ||
		coding && set.geometry && (nd != set.numData || nc != set.numCoding) ||
		coding && !set.geometry && len(set.data) > nd {
		a.stats.Bad++
		return nil
	}
	set.size = len(shard)
	set.mark(local)
	ss.frames++

	var fresh []uint32 // absolute indexes of data shreds this frame made available
	if coding {
		set.numData, set.numCoding, set.geometry = nd, nc, true
		set.coding = put(set.coding, int(local)-nd, shard)
	} else {
		// A received shard replaces a recovered one, so a complete set's
		// parity is checked against received data only.
		set.data = put(set.data, int(local), shard)
		if ss.add(fec+local, payload, flags) {
			fresh = append(fresh, fec+local)
		}
	}
	fresh = append(fresh, a.recover(slot, fec, set, ss)...)
	a.checkComplete(set)
	return a.deshred(slot, ss, fresh, ts)
}

// evictIdlest forgets the slot whose latest frame arrived longest ago.
func (a *Assembler) evictIdlest() {
	var idlest uint64
	var at time.Time
	for s, ss := range a.slots {
		if at.IsZero() || ss.last.Before(at) {
			idlest, at = s, ss.last
		}
	}
	delete(a.slots, idlest)
	a.stats.Evicted++
}

// recover reconstructs the set's missing data shards once at least numData
// shards are present, and returns the absolute indexes that became
// available. It runs once per set.
func (a *Assembler) recover(slot uint64, fec uint32, set *fecSet, ss *slotState) []uint32 {
	nd, nc := set.numData, set.numCoding
	if set.tried || !set.geometry {
		return nil
	}
	present, missing := 0, false
	for i := range nd {
		if i < len(set.data) && set.data[i] != nil {
			present++
		} else {
			missing = true
		}
	}
	for i := range min(nc, len(set.coding)) {
		if set.coding[i] != nil {
			present++
		}
	}
	if !missing || present < nd {
		return nil
	}
	set.tried = true
	enc := a.encoder(nd, nc)
	shards := make([][]byte, nd+nc)
	copy(shards[:nd], set.data)
	copy(shards[nd:], set.coding)
	if enc == nil || enc.ReconstructData(shards) != nil {
		return nil
	}
	var fresh []uint32
	recovered := false
	for i := range nd {
		if i < len(set.data) && set.data[i] != nil {
			continue
		}
		// A recovered shard carries its own header. If it contradicts the
		// shard's position, recovery produced garbage: never feed it on.
		idx := fec + uint32(i)
		payload, flags, ok := dataShard(shards[i], slot, fec, idx)
		if !ok || idx >= maxSlotIndexes {
			a.stats.RecoveredBad++
			continue
		}
		set.data = put(set.data, i, shards[i])
		a.stats.ShardsRecovered++
		recovered = true
		if ss.add(idx, payload, flags) {
			fresh = append(fresh, idx)
		}
	}
	if recovered {
		a.stats.SetsRecovered++
	}
	return fresh
}

// checkComplete marks the set done once every shard was received, samples it
// for the parity check, and releases its shards.
//
// The parity check is empirical: Agave encodes with reed-solomon-erasure,
// which is Backblaze-compatible, as klauspost/reedsolomon should be. Any
// mismatch means recovered shards cannot be trusted.
func (a *Assembler) checkComplete(set *fecSet) {
	if set.done {
		return
	}
	for i := range set.numData + set.numCoding {
		if !set.has(uint32(i)) {
			return
		}
	}
	set.done = true
	a.complete++
	if enc := a.encoder(set.numData, set.numCoding); enc != nil && (a.complete <= parityWarmup || a.complete%parityEvery == 0) {
		shards := make([][]byte, set.numData+set.numCoding)
		copy(shards, set.data[:set.numData])
		for i := set.numData; i < len(shards); i++ {
			shards[i] = make([]byte, set.size)
		}
		if enc.Encode(shards) == nil {
			a.stats.ParityChecked++
			for i, c := range set.coding[:set.numCoding] {
				if !bytes.Equal(shards[set.numData+i], c) {
					a.stats.ParityMismatch++
					break
				}
			}
		}
	}
	set.data, set.coding = nil, nil
}

// encoder returns the cached encoder for a geometry, nil if there is none.
func (a *Assembler) encoder(nd, nc int) reedsolomon.Encoder {
	k := [2]int{nd, nc}
	enc, ok := a.encoders[k]
	if !ok {
		if len(a.encoders) >= maxEncoders {
			clear(a.encoders)
		}
		// No inversion cache: it keeps a matrix per pattern of missing shards,
		// and live sets miss a different pattern nearly every time.
		enc, _ = reedsolomon.New(nd, nc, reedsolomon.WithInversionCache(false))
		a.encoders[k] = enc
	}
	return enc
}

// add makes data shred i available and reports whether it was new.
func (ss *slotState) add(i uint32, payload []byte, flags byte) bool {
	if int(i) >= len(ss.shreds) {
		ss.shreds = append(ss.shreds, make([]dataShred, int(i)+1-len(ss.shreds))...)
	}
	if ss.shreds[i].have {
		return false
	}
	ss.shreds[i] = dataShred{payload: payload, flags: flags, have: true}
	return true
}

// deshred decodes, once each, the complete batches around the fresh data
// shreds. Batches decode out of order, and past a gap that never fills.
func (a *Assembler) deshred(slot uint64, ss *slotState, fresh []uint32, ts uint64) []Batch {
	var at []uint32
	for _, i := range fresh {
		at = append(at, i)
		// A DATA_COMPLETE shred also says where the next batch starts.
		if ss.shreds[i].flags&flagDataComplete != 0 && int(i)+1 < len(ss.shreds) && ss.shreds[i+1].have {
			at = append(at, i+1)
		}
	}
	slices.Sort(at)
	var out []Batch
	for _, i := range at {
		s, e, ok := ss.batchAround(i)
		if !ok || ss.shreds[s].decoded {
			continue
		}
		ss.shreds[s].decoded = true
		n := 0
		for _, d := range ss.shreds[s : e+1] {
			n += len(d.payload)
		}
		payload := make([]byte, 0, n)
		for j := s; j <= e; j++ {
			payload = append(payload, ss.shreds[j].payload...)
			ss.shreds[j].payload = nil
		}
		a.stats.Batches++
		out = append(out, Batch{Slot: slot, StartIndex: s, Payload: payload, ShredTs: ts})
	}
	return out
}

// batchAround returns the batch [s..e] holding the present data shred i, if
// it is complete: s is 0 or follows a DATA_COMPLETE shred, e is the first
// DATA_COMPLETE shred from i on, and every shred from s-1 to e is present.
func (ss *slotState) batchAround(i uint32) (s, e uint32, ok bool) {
	sh := ss.shreds
	for e = i; sh[e].flags&flagDataComplete == 0; {
		e++
		if int(e) == len(sh) || !sh[e].have {
			return 0, 0, false
		}
	}
	for s = i; s > 0; s-- {
		if !sh[s-1].have {
			return 0, 0, false
		}
		if sh[s-1].flags&flagDataComplete != 0 {
			break
		}
	}
	return s, e, true
}

// dataShard checks a data shard's own header against where it was framed and
// returns its payload and flags.
func dataShard(shard []byte, slot uint64, fec, index uint32) (payload []byte, flags byte, ok bool) {
	if len(shard) < dataHeaderSize ||
		binary.LittleEndian.Uint64(shard[1:9]) != slot ||
		binary.LittleEndian.Uint32(shard[9:13]) != index ||
		binary.LittleEndian.Uint32(shard[15:19]) != fec {
		return nil, 0, false
	}
	size := int(binary.LittleEndian.Uint16(shard[22:24]))
	if size < 64+dataHeaderSize || size-64 > len(shard) {
		return nil, 0, false
	}
	return shard[dataHeaderSize : size-64], shard[21], true
}

// put stores b at s[i], growing s as needed.
func put(s [][]byte, i int, b []byte) [][]byte {
	if i >= len(s) {
		s = append(s, make([][]byte, i+1-len(s))...)
	}
	s[i] = b
	return s
}
