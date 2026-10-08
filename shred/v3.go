package shred

// Agave chained-Merkle shred geometry, as the shred-forwarder's parse_shred and
// erasure_shard (libmmt shred-forwarder/src/main.rs) assume it.
const (
	agaveDataShredSize   = 1203
	agaveCodingShredSize = 1228
	signatureSize        = 64
	merkleRootSize       = 32
	merkleProofEntrySize = 20
	retransmitterSigSize = 64
)

// FrameV3 converts a version-4 forwarder frame to the version-3 frame the
// shred-forwarder would have sent for the same shred.
//
// A version-4 frame is the 28-byte header followed by the full canonical
// Agave shred. A version-3 frame has the same header, with version byte 3,
// followed by the shred's erasure shard, the region the shred-forwarder's
// erasure_shard selects:
//   - start: after the signature for data shreds, after the coding headers
//     for coding shreds;
//   - end: before the Merkle trailer. The trailer is the 32-byte chained
//     root, 20 bytes per proof entry, and a 64-byte retransmitter signature
//     on resigned variants.
//
// ok is false when packet is not a well-formed version-4 frame. That
// includes any variant the forwarder never emits: only chained Merkle shreds
// exist on Agave master.
func FrameV3(packet []byte) (v3 []byte, ok bool) {
	if len(packet) < WireHeaderSize || packet[0] != 4 {
		return nil, false
	}
	body := packet[WireHeaderSize:]
	coding := packet[17]&wireFlagCoding != 0
	size, start := agaveDataShredSize, signatureSize
	if coding {
		size, start = agaveCodingShredSize, commonHeaderSize+codingHeaderSize
	}
	if len(body) != size {
		return nil, false
	}
	variant := body[signatureSize]
	family := variant & 0xf0
	switch {
	case coding && (family == 0x60 || family == 0x70): // chained Merkle code, optionally resigned
	case !coding && (family == 0x90 || family == 0xb0): // chained Merkle data, optionally resigned
	default:
		return nil, false
	}
	trailer := merkleRootSize + int(variant&0x0f)*merkleProofEntrySize
	if family == 0xb0 || family == 0x70 {
		trailer += retransmitterSigSize
	}
	shard := body[start : len(body)-trailer]

	v3 = make([]byte, WireHeaderSize+len(shard))
	copy(v3, packet[:WireHeaderSize])
	v3[0] = 3
	copy(v3[WireHeaderSize:], shard)
	return v3, true
}
