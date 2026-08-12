package shred

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The shred-forwarder emits each shred to the SSM group framed with its own
// 28-byte header, followed by a body. This is NOT a canonical Agave shred, so
// ParseHeader (which reads Agave offsets) cannot parse it:
//
//	[0]      version       u8   3 = erasure-shard body, 4 = full shred body
//	[1:9]    slot          u64 LE
//	[9:13]   fec_set_index u32 LE
//	[13:17]  local_index   u32 LE   data: 0..num_data; coding: num_data+position
//	[17]     flags         u8       bit0 DATA_COMPLETE, bit1 IS_CODING_SHRED
//	[18]     num_data      u8       set on coding shreds only; 0 on data
//	[19]     num_coding    u8       set on coding shreds only; 0 on data
//	[20:28]  send_ts_us    u64 LE   sender-side send time, microseconds
//	[28:]    body
//
// Everything FEC-set scoring needs is in the header; the body is not inspected.
// Verified against production: 1,044,775 consecutive datagrams, 100% version 3,
// (num_data, num_coding) == (32, 32) on every coding shred.
const (
	WireHeaderSize = 28

	wireFlagDataComplete = 0x01
	wireFlagCoding       = 0x02
)

var (
	// ErrWireTooShort means the datagram cannot hold a forwarder header.
	ErrWireTooShort = errors.New("forwarder wire header too short")
	// ErrWireVersion means the version byte is not a version we can frame.
	ErrWireVersion = errors.New("unsupported forwarder wire version")
)

// Format selects how a datagram is framed.
type Format int

const (
	// FormatForwarder is the 28-byte shred-forwarder wire header. This is what
	// the SSM group and the demo tap actually carry, so it is the default.
	FormatForwarder Format = iota
	// FormatAgave is a canonical Agave shred, as received directly on a TVU
	// socket.
	FormatAgave
)

// ParseWireHeader parses the shred-forwarder framing.
//
// Deliberately not auto-detected from the payload: an Agave shred begins with a
// 64-byte signature whose first byte is effectively random, so it lands on 3 or
// 4 about once in 128 packets. Silently mis-framing that fraction would corrupt
// scoring in a way that looks like packet loss, so the caller states the format.
func ParseWireHeader(packet []byte) (Header, error) {
	if len(packet) < WireHeaderSize {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrWireTooShort, len(packet))
	}
	version := packet[0]
	if version != 3 && version != 4 {
		return Header{}, fmt.Errorf("%w: %d", ErrWireVersion, version)
	}

	localIndex := binary.LittleEndian.Uint32(packet[13:17])
	if localIndex >= shredsPerFECSet {
		return Header{}, fmt.Errorf("%w: local index %d outside FEC set", ErrInvalidIndex, localIndex)
	}

	flags := packet[17]
	kind := KindData
	if flags&wireFlagCoding != 0 {
		kind = KindCoding
	}

	header := Header{
		Slot:           binary.LittleEndian.Uint64(packet[1:9]),
		FECSetIndex:    binary.LittleEndian.Uint32(packet[9:13]),
		Kind:           kind,
		IndexWithinSet: uint8(localIndex),
		SendTimeMicros: binary.LittleEndian.Uint64(packet[20:28]),
	}
	// Index is the absolute shred index, which the framing only carries for data
	// shreds (local_index is relative to the FEC set). Coding shreds occupy a
	// separate index space that cannot be recovered from this header, so Index
	// is left at the in-set value for them. Nothing in scoring keys on Index —
	// see Scorer.Observe, which keys on (Slot, FECSetIndex, IndexWithinSet).
	if kind == KindData {
		header.Index = header.FECSetIndex + localIndex
	} else {
		header.Index = localIndex
	}
	return header, nil
}

// Parse frames a datagram according to format.
func Parse(packet []byte, format Format) (Header, error) {
	switch format {
	case FormatForwarder:
		return ParseWireHeader(packet)
	case FormatAgave:
		return ParseHeader(packet)
	default:
		return Header{}, fmt.Errorf("unknown shred format %d", int(format))
	}
}
