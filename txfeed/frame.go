package txfeed

import (
	"encoding/binary"
	"fmt"
)

// txframe version 1 carries one transaction per datagram:
//
//	[0]      version      u8       1
//	[1]      flags        u8       bit0 vote
//	[2:10]   slot         u64 LE
//	[10:14]  batch start  u32 LE   absolute data-shred index of the batch
//	[14:16]  tx index     u16 LE   within the batch
//	[16:24]  shred_ts_us  u64 LE   send_ts_us of the frame that completed the batch
//	[24:]    the exact VersionedTransaction bytes
const frameHeaderSize = 24

// MaxTxSize is the largest transaction: SIMD-0296 lets a version-1
// transaction be 4096 bytes. shred-txfeed drops anything larger, so no frame
// exceeds MaxFrameSize, the receive buffer a subscriber needs.
const MaxTxSize = 4096

const MaxFrameSize = frameHeaderSize + MaxTxSize

// Frame is one txframe.
type Frame struct {
	Vote       bool
	Slot       uint64
	BatchStart uint32
	Index      uint16
	ShredTs    uint64
	Tx         []byte
}

// AppendFrame appends f, framed, to dst.
func AppendFrame(dst []byte, f Frame) []byte {
	var flags byte
	if f.Vote {
		flags = 1
	}
	dst = append(dst, 1, flags)
	dst = binary.LittleEndian.AppendUint64(dst, f.Slot)
	dst = binary.LittleEndian.AppendUint32(dst, f.BatchStart)
	dst = binary.LittleEndian.AppendUint16(dst, f.Index)
	dst = binary.LittleEndian.AppendUint64(dst, f.ShredTs)
	return append(dst, f.Tx...)
}

// ParseFrame parses a txframe. Tx aliases b.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < frameHeaderSize {
		return Frame{}, fmt.Errorf("txframe: %d bytes, shorter than the header", len(b))
	}
	if b[0] != 1 {
		return Frame{}, fmt.Errorf("txframe: unsupported version %d", b[0])
	}
	return Frame{
		Vote:       b[1]&1 != 0,
		Slot:       binary.LittleEndian.Uint64(b[2:10]),
		BatchStart: binary.LittleEndian.Uint32(b[10:14]),
		Index:      binary.LittleEndian.Uint16(b[14:16]),
		ShredTs:    binary.LittleEndian.Uint64(b[16:24]),
		Tx:         b[frameHeaderSize:],
	}, nil
}
