package txfeed

import (
	"bytes"
	"encoding/binary"
	"time"

	"github.com/blockcast/go-amt/shred"
)

// FooterTime is one Alpenglow block footer and when it reached this receiver
// (BLO-49345). A leader stamps its footer as it builds it, at the end of the
// block (Agave 4.3.2's block_creation_loop), so Latency is the leader to
// receiver delay at the end of the block, plus how far this receiver's clock is
// ahead of the leader's. Agave clamps the stamp to at least its parent's plus
// 1ns and at most its parent's plus twice the slot time since the parent
// (skew_block_producer_time_nanos): after a parent stamped by a fast clock, the
// stamp can be that floor, later than the leader's clock, and Latency reads
// short.
type FooterTime struct {
	Slot              uint64
	BankHash          [32]byte // with Slot, names the block: a footer carries no block id
	UserAgent         string   // "" from a Firedancer leader
	ProducerTimeNanos uint64   // the leader's clock, Unix nanoseconds, clamped as above
	// At is the arrival of the frame after which this receiver held every byte
	// of the footer: a data shred of it, or the shard that let Reed-Solomon
	// rebuild it. ShredTs is that frame's send_ts_us, on the clock of the
	// listener that forwarded it.
	At      time.Time
	ShredTs uint64
	// Recovered: Reed-Solomon rebuilt the footer's first data shred, which had
	// not arrived when the footer was read. It says nothing of the other shreds
	// of a longer footer.
	Recovered bool
}

// Latency is At minus the producer time.
func (f FooterTime) Latency() time.Duration {
	return f.At.Sub(time.Unix(0, int64(f.ProducerTimeNanos)))
}

// FooterTimes times the block footers on the shred union. It is not safe for
// concurrent use.
//
// A footer opens an FEC set of its own, padded to 32 data shreds, so it is read
// from that set as soon as its shreds are held, not only from the batch an
// Assembler emits: the batch also waits for the padding and for the previous
// set's DATA_COMPLETE shred. A set's first data shred is taken to start a
// component unless the shred before it is held without DATA_COMPLETE.
type FooterTimes struct {
	asm *Assembler
	// ponytail: one entry a block, never evicted, about 17,000 an hour. Drop a
	// slot's with the Assembler's if runs outgrow hours.
	seen map[footerKey]bool
}

type footerKey struct {
	slot uint64
	hash [32]byte
}

// footerFraming opens every footer: a zero entry count, version 1 and the
// footer variant. Its u16 body length follows (ParseMarker).
var footerFraming = []byte{0, 0, 0, 0, 0, 0, 0, 0, 1, 0, MarkerFooter}

// NewFooterTimes returns a FooterTimes that holds a slot for 10s past its
// latest frame, shred-txfeed's default -keep.
func NewFooterTimes() *FooterTimes {
	return &FooterTimes{asm: NewAssembler(10 * time.Second), seen: map[footerKey]bool{}}
}

// Stats returns the counters of the Assembler under it.
func (f *FooterTimes) Stats() Stats { return f.asm.Stats() }

// Add takes one union frame, forwarder wire version 3 or 4, that arrived at
// at, and returns the footers it completed, once each per slot and bank hash.
// Like Assembler.Add, it keeps references into frame.
func (f *FooterTimes) Add(frame []byte, at time.Time) []FooterTime {
	batches := f.asm.Add(frame)
	if len(frame) < shred.WireHeaderSize {
		return nil
	}
	// The same offsets in wire versions 3 and 4.
	slot := binary.LittleEndian.Uint64(frame[1:9])
	fec := binary.LittleEndian.Uint32(frame[9:13])
	ss := f.asm.slots[slot]
	if ss == nil || ss.sets[fec] == nil {
		return nil // the Assembler refused the frame
	}
	var out []FooterTime
	found := func(start uint32, m Marker, ok bool, err error) {
		k := footerKey{slot, m.Hash}
		if err != nil || !ok || m.Variant != MarkerFooter || f.seen[k] {
			return
		}
		f.seen[k] = true
		out = append(out, FooterTime{Slot: slot, BankHash: m.Hash, UserAgent: m.UserAgent, ProducerTimeNanos: m.ProducerTimeNanos,
			At: at, ShredTs: binary.LittleEndian.Uint64(frame[20:28]),
			Recovered: ss.sets[start/numData*numData].received&(1<<(start%numData)) == 0})
	}
	// Decoding the footer's batch released its shreds: read it there.
	for _, b := range batches {
		m, ok, err := ParseMarker(b.Payload)
		found(b.StartIndex, m, ok, err)
	}
	// Before then, read it from the first data shred of the frame's set, unless
	// the shred before it is held and ends no batch, which this one continues.
	// ponytail: with the shred before it not yet held, a set continuing an
	// entry batch whose bytes there frame a footer reads as one. Wait for that
	// shred to be DATA_COMPLETE if such footers turn up; the 10-22 capture
	// lacks it.
	p, held := ss.payload[fec]
	if i := fec - 1; held && fec > 0 && ss.data.has(i) && ss.data.complete[i/64]&(1<<(i%64)) == 0 {
		held = false
	}
	if held && len(p) >= len(footerFraming)+2 && bytes.HasPrefix(p, footerFraming) {
		// The body length says how many of the shreds after p hold the rest:
		// count them, then join them once, into a copy, as p is a view of a frame.
		need := len(footerFraming) + 2 + int(binary.LittleEndian.Uint16(p[len(footerFraming):]))
		n, end := len(p), fec+1
		for ; n < need && end < fec+numData && ss.data.has(end); end++ {
			n += len(ss.payload[end])
		}
		if n >= need {
			b := p
			if end > fec+1 {
				b = append(make([]byte, 0, n), p...)
				for i := fec + 1; i < end; i++ {
					b = append(b, ss.payload[i]...)
				}
			}
			m, ok, err := ParseMarker(b)
			found(fec, m, ok, err)
		}
	}
	return out
}
