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
	"math/bits"
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

	// Every FEC set is 32 data shreds and 32 coding, as shred/header.go
	// requires, so a set starts at a multiple of 32, as every set on the live
	// union does. A data frame's local index is its position, below numData; a
	// coding frame's is numData plus its position. A frame stating any other
	// geometry or start is refused, so the wire cannot choose the Reed-Solomon
	// work, and one slot holds at most 1024 sets of 64 frames.
	numData   = 32
	numCoding = 32

	maxSlotIndexes = 32768 // data shred indexes per slot

	// maxSlots bounds the slots held under a flood of distinct forged slots.
	// Real traffic holds keep times the slot rate, about 40 at a keep of 10s.
	// Past it, the slot idle longest goes first, and a slot still being
	// received is never the idlest. One 52-byte frame per set index across
	// every slot holds about 237 MiB, nearly all of it the 1.5 KiB shards
	// array of each set (measured by Ally, go-amt#145 review 5465850517).
	maxSlots = 128

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
	Bad             uint64 // malformed frames, coding frames stating a geometry but 32:32, and frames of a set not starting at a multiple of 32, dropped
	SetsRecovered   uint64 // FEC sets that recovered at least one data shard
	ShardsRecovered uint64 // data shards recovered
	RecoveredBad    uint64 // recovered data shards whose own header contradicts their position, discarded
	ParityChecked   uint64 // complete sets whose coding shards were re-encoded from their data
	ParityMismatch  uint64 // checked sets whose re-encoded parity differs from what was received
	Batches         uint64 // entry batches emitted
	Evicted         uint64 // slots forgotten: idle past keep, or the idlest at maxSlots

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
	enc      reedsolomon.Encoder // 32:32
	complete uint64              // sets that arrived complete
	stats    Stats
}

type slotState struct {
	last    time.Time          // arrival of its latest frame
	frames  int                // frames accepted, for Stats.Held
	sets    map[uint32]*fecSet // by fec_set_index
	data    *slotIndex         // the data shreds available to deshred; nil until the first
	payload map[uint32][]byte  // their payloads by absolute index, until their batch decodes
}

// slotIndex records, by absolute data shred index, which data shreds are
// available (received or recovered), which carry DATA_COMPLETE, and which
// start a batch already decoded. It is 12 KiB whatever index a frame names:
// a slice sized by index let one forged frame at 32767 pin a megabyte. Read a
// word at a time, it also keeps the search for a batch's ends cheap along a
// long run with no DATA_COMPLETE, which a hostile stream sent in reverse once
// made quadratic.
type slotIndex struct {
	have, complete, decoded [maxSlotIndexes / 64]uint64
}

type fecSet struct {
	size     int        // shard length, the same for every shard of the set
	shards   [64][]byte // by local index, nil when missing; data includes recovered shards
	received uint64     // bitmap of received local indexes
	tried    bool       // reconstruction has run
	done     bool       // every shard was received; shards are released
}

// NewAssembler returns an Assembler that forgets a slot once keep passes with
// no frame of it. A frame for a slot already forgotten starts the slot afresh.
func NewAssembler(keep time.Duration) *Assembler {
	// No inversion cache: it keeps a matrix per pattern of missing shards, and
	// live sets miss a different pattern nearly every time.
	enc, err := reedsolomon.New(numData, numCoding, reedsolomon.WithInversionCache(false))
	if err != nil {
		panic(err) // fixed, valid arguments
	}
	return &Assembler{
		keep:  keep,
		now:   time.Now,
		slots: map[uint64]*slotState{},
		enc:   enc,
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

	// Validate before the frame can create state. The local index alone says
	// which kind of shard a position takes, so data and coding never claim
	// the same one.
	var payload []byte
	var flags byte
	ok := fec < maxSlotIndexes && fec%numData == 0
	if coding {
		ok = ok && nd == numData && nc == numCoding && local >= numData && local < numData+numCoding
	} else {
		ok = ok && local < numData
		if ok {
			payload, flags, ok = dataShard(shard, slot, fec, fec+local)
		}
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
		set = &fecSet{}
		ss.sets[fec] = set
	}

	if set.received&(1<<local) != 0 {
		a.stats.Dups++
		return nil
	}
	if set.size != 0 && len(shard) != set.size {
		a.stats.Bad++
		return nil
	}
	set.size = len(shard)
	set.received |= 1 << local
	ss.frames++
	// A received data shard replaces a recovered one, so a complete set's
	// parity is checked against received data only.
	set.shards[local] = shard

	var fresh []uint32 // absolute indexes of data shreds this frame made available
	if !coding && ss.add(fec+local, payload, flags) {
		fresh = append(fresh, fec+local)
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
	const allData = 1<<numData - 1
	if set.tried || set.received&allData == allData || bits.OnesCount64(set.received) < numData {
		return nil
	}
	set.tried = true
	shards := set.shards
	if a.enc.ReconstructData(shards[:]) != nil {
		return nil
	}
	var fresh []uint32
	recovered := false
	for i := range uint32(numData) {
		if set.shards[i] != nil {
			continue
		}
		// A recovered shard carries its own header. If it contradicts the
		// shard's position, recovery produced garbage: never feed it on.
		idx := fec + i
		payload, flags, ok := dataShard(shards[i], slot, fec, idx)
		if !ok {
			a.stats.RecoveredBad++
			continue
		}
		set.shards[i] = shards[i]
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
	if set.done || set.received != 1<<(numData+numCoding)-1 {
		return
	}
	set.done = true
	a.complete++
	if a.complete <= parityWarmup || a.complete%parityEvery == 0 {
		shards := set.shards
		for i := numData; i < numData+numCoding; i++ {
			shards[i] = make([]byte, set.size)
		}
		if a.enc.Encode(shards[:]) == nil {
			a.stats.ParityChecked++
			for i := numData; i < numData+numCoding; i++ {
				if !bytes.Equal(shards[i], set.shards[i]) {
					a.stats.ParityMismatch++
					break
				}
			}
		}
	}
	set.shards = [64][]byte{}
}

// add makes data shred i available and reports whether it was new.
func (ss *slotState) add(i uint32, payload []byte, flags byte) bool {
	if ss.data == nil {
		ss.data, ss.payload = &slotIndex{}, map[uint32][]byte{}
	}
	w, m := i/64, uint64(1)<<(i%64)
	if ss.data.have[w]&m != 0 {
		return false
	}
	ss.data.have[w] |= m
	if flags&flagDataComplete != 0 {
		ss.data.complete[w] |= m
	}
	if len(payload) > 0 {
		ss.payload[i] = payload
	}
	return true
}

// deshred decodes, once each, the complete batches around the fresh data
// shreds. Batches decode out of order, and past a gap that never fills.
func (a *Assembler) deshred(slot uint64, ss *slotState, fresh []uint32, ts uint64) []Batch {
	x := ss.data
	var at []uint32
	for _, i := range fresh {
		at = append(at, i)
		// A DATA_COMPLETE shred also says where the next batch starts.
		if x.complete[i/64]&(1<<(i%64)) != 0 && i+1 < maxSlotIndexes && x.has(i+1) {
			at = append(at, i+1)
		}
	}
	slices.Sort(at)
	var out []Batch
	for _, i := range at {
		s, e, ok := x.batchAround(i)
		if !ok || x.decoded[s/64]&(1<<(s%64)) != 0 {
			continue
		}
		x.decoded[s/64] |= 1 << (s % 64)
		n := 0
		for j := s; j <= e; j++ {
			n += len(ss.payload[j])
		}
		payload := make([]byte, 0, n)
		for j := s; j <= e; j++ {
			payload = append(payload, ss.payload[j]...)
			delete(ss.payload, j)
		}
		a.stats.Batches++
		out = append(out, Batch{Slot: slot, StartIndex: s, Payload: payload, ShredTs: ts})
	}
	return out
}

func (x *slotIndex) has(i uint32) bool { return x.have[i/64]&(1<<(i%64)) != 0 }

// stops returns word w of the stops: shreds not available, or carrying
// DATA_COMPLETE. A batch runs from just past one stop to the next.
func (x *slotIndex) stops(w uint32) uint64 { return ^x.have[w] | x.complete[w] }

// batchAround returns the batch [s..e] holding the available data shred i, if
// it is complete: s is 0 or follows a DATA_COMPLETE shred, e is the first
// DATA_COMPLETE shred from i on, and every shred from s-1 to e is available.
func (x *slotIndex) batchAround(i uint32) (s, e uint32, ok bool) {
	// e is the first stop from i on, and must be available, so DATA_COMPLETE.
	w := i / 64
	m := x.stops(w) & (^uint64(0) << (i % 64))
	for m == 0 {
		if w++; w == uint32(len(x.have)) {
			return 0, 0, false // no DATA_COMPLETE before the slot's last index
		}
		m = x.stops(w)
	}
	e = w*64 + uint32(bits.TrailingZeros64(m))
	if !x.has(e) {
		return 0, 0, false
	}
	// s is just past the last stop before i, which must be available, so
	// DATA_COMPLETE; or 0 when every shred before i is available.
	if i == 0 {
		return 0, e, true
	}
	w = (i - 1) / 64
	m = x.stops(w) & (^uint64(0) >> (63 - (i-1)%64))
	for m == 0 {
		if w == 0 {
			return 0, e, true
		}
		w--
		m = x.stops(w)
	}
	p := w*64 + 63 - uint32(bits.LeadingZeros64(m))
	if !x.has(p) {
		return 0, 0, false
	}
	return p + 1, e, true
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
