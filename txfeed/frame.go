package txfeed

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// A txframe carries one transaction, or one chunk of one, per datagram.
//
// Version 1, a whole transaction:
//
//	[0]      version      u8       1
//	[1]      flags        u8       bit0 vote
//	[2:10]   slot         u64 LE
//	[10:14]  batch start  u32 LE   absolute data-shred index of the batch
//	[14:16]  tx index     u16 LE   within the batch
//	[16:24]  shred_ts_us  u64 LE   send_ts_us of the frame that completed the batch
//	[24:]    the exact VersionedTransaction bytes
//
// Version 2, one chunk of a transaction too large for a version-1 frame of
// at most MaxDatagram bytes:
//
//	[0]      version      u8       2
//	[1:24]   as version 1
//	[24]     chunk index  u8       0..chunk count-1
//	[25]     chunk count  u8       at least 1
//	[26:]    the chunk, a slice of the transaction. shred-txfeed cuts at
//	         MaxDatagram-26 = 1376 bytes, the last chunk shorter.
//
// (slot, batch start, tx index) names the transaction, so it is the
// reassembly key. Every chunk carries the same header, and concatenating the
// chunks in index order gives the exact transaction. A transaction that fits
// is always sent as version 1, byte for byte as before version 2 existed, so a
// decoder that knows only version 1 still gets every transaction that fits.
// It rejects version 2 by its version byte and loses the rest. Behind a
// userspace AMT gateway it lost those already: they arrived as IP fragments,
// which the gateways drop. A native subscriber whose kernel reassembled them
// needs version 2 to keep them.
//
// JS and other decoders (such as pim's solana-txframe.js): accept version 2,
// hold chunks by (slot, batch start, tx index) until all chunk count of them
// arrive, then concatenate them in index order, assuming no chunk size, and
// parse the result as the transaction of a version-1 frame with the same
// header: bytes 1..23 mean what they mean in version 1. A subscriber joined
// to several groups receives each chunk once per group, so ignore a chunk
// index already held. Drop the transaction when its chunks disagree on the
// vote flag, shred_ts_us or chunk count, when the whole would exceed MaxTxSize,
// or when it is still incomplete after a second (Reassembler does all of
// this).
const (
	frameHeaderSize = 24
	chunkHeaderSize = frameHeaderSize + 2
)

// MaxDatagram is the largest txframe shred-txfeed sends, so that no datagram
// is IP-fragmented on a 1500-byte path, natively or through an AMT relay, in
// either address family: 1500 minus the AMT encapsulation, outer IPv6 40 +
// UDP 8 + AMT Multicast Data header 2, minus the inner IPv6 40 + UDP 8. Native
// multicast is then at most 1430 bytes over IPv4 and 1450 over IPv6; AMT
// packets are 1460 bytes with IPv4 inside and out, 1480 with one IPv6 header,
// 1500 with two.
const MaxDatagram = 1500 - (40 + 8 + 2) - (40 + 8) // 1402

// maxChunk is the transaction bytes a version-2 frame carries, all but the
// last chunk of a transaction.
const maxChunk = MaxDatagram - chunkHeaderSize // 1376

// MaxTxSize is the largest transaction: SIMD-0296 lets a version-1
// transaction be 4096 bytes. shred-txfeed drops anything larger.
const MaxTxSize = 4096

// MaxFrameSize is the largest version-1 frame a shred-txfeed from before
// version 2 sent, and so a receive buffer that takes any txframe.
const MaxFrameSize = frameHeaderSize + MaxTxSize

// Frame is one txframe.
type Frame struct {
	Vote       bool
	Slot       uint64
	BatchStart uint32
	Index      uint16
	ShredTs    uint64
	// Chunks is 0 for a version-1 frame, whose Tx is the whole transaction.
	// Otherwise the frame is version 2 and Tx is chunk Chunk of Chunks.
	Chunk, Chunks uint8
	Tx            []byte
}

// AppendFrame appends f, framed, to dst: version 1 when f.Chunks is 0, else
// version 2.
func AppendFrame(dst []byte, f Frame) []byte {
	var flags byte
	if f.Vote {
		flags = 1
	}
	version := byte(1)
	if f.Chunks != 0 {
		version = 2
	}
	dst = append(dst, version, flags)
	dst = binary.LittleEndian.AppendUint64(dst, f.Slot)
	dst = binary.LittleEndian.AppendUint32(dst, f.BatchStart)
	dst = binary.LittleEndian.AppendUint16(dst, f.Index)
	dst = binary.LittleEndian.AppendUint64(dst, f.ShredTs)
	if f.Chunks != 0 {
		dst = append(dst, f.Chunk, f.Chunks)
	}
	return append(dst, f.Tx...)
}

// Datagrams returns the datagrams carrying f, whose Tx is a whole transaction
// of at most MaxTxSize bytes: one version-1 frame when it fits in
// MaxDatagram, else version-2 chunks, none longer than MaxDatagram.
func Datagrams(f Frame) [][]byte {
	if frameHeaderSize+len(f.Tx) <= MaxDatagram {
		return [][]byte{AppendFrame(nil, f)}
	}
	tx, n := f.Tx, (len(f.Tx)+maxChunk-1)/maxChunk
	dgs := make([][]byte, n)
	f.Chunks = uint8(n)
	for i := range dgs {
		f.Chunk, f.Tx = uint8(i), tx[i*maxChunk:min((i+1)*maxChunk, len(tx))]
		dgs[i] = AppendFrame(nil, f)
	}
	return dgs
}

// ParseFrame parses a txframe, version 1 or 2. Tx aliases b.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < frameHeaderSize {
		return Frame{}, fmt.Errorf("txframe: %d bytes, shorter than the header", len(b))
	}
	f := Frame{
		Vote:       b[1]&1 != 0,
		Slot:       binary.LittleEndian.Uint64(b[2:10]),
		BatchStart: binary.LittleEndian.Uint32(b[10:14]),
		Index:      binary.LittleEndian.Uint16(b[14:16]),
		ShredTs:    binary.LittleEndian.Uint64(b[16:24]),
		Tx:         b[frameHeaderSize:],
	}
	switch b[0] {
	case 1:
		return f, nil
	case 2:
		if len(b) < chunkHeaderSize {
			return Frame{}, fmt.Errorf("txframe: version 2, %d bytes, shorter than the header", len(b))
		}
		if f.Chunk, f.Chunks, f.Tx = b[24], b[25], b[chunkHeaderSize:]; f.Chunk >= f.Chunks {
			return Frame{}, fmt.Errorf("txframe: chunk %d of %d", f.Chunk, f.Chunks)
		}
		return f, nil
	}
	return Frame{}, fmt.Errorf("txframe: unsupported version %d", b[0])
}

// ReassemblyStats counts what a Reassembler has seen.
type ReassemblyStats struct {
	Chunks       uint64 // version-2 frames added
	Txs          uint64 // transactions reassembled
	Dups         uint64 // chunks already held, or of a transaction already reassembled or dropped
	Inconsistent uint64 // transactions dropped: chunks disagreeing on the header or on a repeated chunk's bytes, or a whole over MaxTxSize
	Timeouts     uint64 // transactions dropped incomplete after the timeout
	Overflow     uint64 // chunks dropped because maxPending transactions were held
}

type txKey struct {
	slot  uint64
	batch uint32
	index uint16
}

type partial struct {
	first   time.Time
	vote    bool
	shredTs uint64
	chunks  [][]byte // by chunk index; nil once reassembled or dropped
	have    int      // chunks held
	size    int      // their bytes
}

// Reassembler rebuilds transactions from version-2 chunks. It holds at most
// maxPending transactions, and forgets each one once timeout passes from its
// first chunk; one reassembled or dropped is remembered until then, so its
// chunks from another group count as Dups instead of starting it over. It is
// not safe for concurrent use.
type Reassembler struct {
	timeout time.Duration
	max     int
	pending map[txKey]*partial
	sweep   time.Time // when the next expiry pass runs
	stats   ReassemblyStats
}

// NewReassembler returns a Reassembler holding at most maxPending
// transactions, each for at most timeout from its first chunk.
func NewReassembler(timeout time.Duration, maxPending int) *Reassembler {
	return &Reassembler{timeout: timeout, max: maxPending, pending: map[txKey]*partial{}}
}

// Stats returns the counters.
func (r *Reassembler) Stats() ReassemblyStats { return r.stats }

// Add takes a parsed frame that arrived at now. It returns a version-1 frame
// as it is, and a version-2 chunk's whole transaction, as a version-1 frame,
// once the chunk completes it. Add copies what it keeps of f.Tx.
func (r *Reassembler) Add(f Frame, now time.Time) (Frame, bool) {
	if f.Chunks == 0 {
		return f, true
	}
	r.stats.Chunks++
	if !now.Before(r.sweep) {
		for k, p := range r.pending {
			if now.Sub(p.first) > r.timeout {
				if p.chunks != nil {
					r.stats.Timeouts++
				}
				delete(r.pending, k)
			}
		}
		r.sweep = now.Add(r.timeout / 2)
	}
	k := txKey{f.Slot, f.BatchStart, f.Index}
	p := r.pending[k]
	if p == nil {
		if len(r.pending) >= r.max {
			r.stats.Overflow++
			return Frame{}, false
		}
		p = &partial{first: now, vote: f.Vote, shredTs: f.ShredTs, chunks: make([][]byte, f.Chunks)}
		r.pending[k] = p
	}
	held := p.chunks
	if held == nil {
		r.stats.Dups++ // of a transaction already reassembled or dropped
		return Frame{}, false
	}
	if int(f.Chunks) == len(held) && f.Chunk < f.Chunks && f.Vote == p.vote && f.ShredTs == p.shredTs {
		switch c := held[f.Chunk]; {
		case c != nil && bytes.Equal(c, f.Tx):
			r.stats.Dups++
			return Frame{}, false
		case c == nil && p.size+len(f.Tx) <= MaxTxSize:
			held[f.Chunk] = append([]byte{}, f.Tx...) // never nil, even when empty
			p.have++
			p.size += len(f.Tx)
			if p.have < len(held) {
				return Frame{}, false
			}
			p.chunks = nil
			r.stats.Txs++
			f.Chunk, f.Chunks, f.Tx = 0, 0, bytes.Join(held, nil)
			return f, true
		}
	}
	p.chunks = nil // the chunks disagree: drop the transaction
	r.stats.Inconsistent++
	return Frame{}, false
}
