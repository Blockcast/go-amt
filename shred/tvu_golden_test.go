package shred

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

// Two real forwarder frames from one FEC set, captured 2026-10-09T18:57Z from
// the production forwarder channel (S=69.25.95.197, G=232.0.0.1):5001 on a
// receive-only native SSM join. Full datagrams, 28-byte header included.
//
// These exist because TestTVUPayload exercises the v4 arm with a placeholder
// body ("agave!!!"), which proves the slice offset and nothing about the bytes.
// The claim that matters for delivery is stronger and was previously untested:
// stripping WireHeaderSize off a real v4 frame yields a shred a validator will
// accept at sigverify. Sigverify is the gate the TVU actually applies, so it is
// the gate asserted here — a validator's shred_fetch counters move on receipt,
// before sigverify, and so cannot distinguish an accepted shred from a rejected
// one. See BLO-41382.
var (
	//go:embed testdata/v4_data_slot454966338_idx15.hex
	v4DataFrameHex string
	//go:embed testdata/v4_coding_slot454966338_idx12.hex
	v4CodingFrameHex string
)

const (
	// goldenLeader is the slot leader for slot 454966338 on mainnet, per
	// getSlotLeaders. Kept in base58 so it can be checked against an RPC
	// response without decoding anything first.
	goldenLeader = "HEL1USMZKAL2odpNBj2oCjffnFGaYwmbGmyewGv1e2TU"
	// goldenMerkleRoot is what both frames' proofs must rebuild to: one FEC
	// set has one root. Cross-checking the two against each other is what
	// makes a transcription error in either fixture fail loudly.
	goldenMerkleRoot = "1868b5f6cf22579a576a58c47af91e1a7c2661443705e631dedbbd0a75d0f504"
	goldenSlot       = 454966338
)

func TestTVUPayloadYieldsSignatureValidShred(t *testing.T) {
	leader := ed25519.PublicKey(base58Decode(t, goldenLeader))
	if len(leader) != ed25519.PublicKeySize {
		t.Fatalf("leader pubkey decoded to %d bytes, want %d", len(leader), ed25519.PublicKeySize)
	}

	for _, testCase := range []struct {
		name           string
		frameHex       string
		wantFrameLen   int
		wantKind       Kind
		wantIndex      uint32
		wantIndexInSet uint8
	}{
		{"data", v4DataFrameHex, WireHeaderSize + agaveDataShredSize, KindData, 15, 15},
		// A coding shred's Merkle leaf sits at num_data+position (32+12), not
		// at its own index, which is why the two index fields differ here.
		{"coding", v4CodingFrameHex, WireHeaderSize + agaveCodingShredSize, KindCoding, 12, 44},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			frame := decodeFixture(t, testCase.frameHex)
			if len(frame) != testCase.wantFrameLen {
				t.Fatalf("fixture is %d bytes, want %d — transcription error", len(frame), testCase.wantFrameLen)
			}

			// The frame as it arrives is NOT a shred. This is the negative
			// control: without it the test would still pass if TVUPayload
			// became the identity function.
			if _, err := ParseHeader(frame); err == nil {
				t.Fatal("unstripped forwarder frame parsed as a canonical Agave shred; the strip is not load-bearing")
			}

			body, ok := TVUPayload(frame)
			if !ok {
				t.Fatal("TVUPayload withheld a version-4 frame")
			}
			if len(body) != len(frame)-WireHeaderSize {
				t.Fatalf("payload is %d bytes, want %d", len(body), len(frame)-WireHeaderSize)
			}

			header, err := ParseHeader(body)
			if err != nil {
				t.Fatalf("stripped body does not parse at Agave offsets: %v", err)
			}
			if header.Slot != goldenSlot || header.FECSetIndex != 0 ||
				header.Kind != testCase.wantKind || header.Index != testCase.wantIndex ||
				header.IndexWithinSet != testCase.wantIndexInSet {
				t.Fatalf("header = %+v; want slot %d, fec 0, kind %d, index %d, in-set %d",
					header, uint64(goldenSlot), testCase.wantKind, testCase.wantIndex, testCase.wantIndexInSet)
			}

			root := merkleRoot(t, body)
			if got := hex.EncodeToString(root); got != goldenMerkleRoot {
				t.Fatalf("rebuilt Merkle root %s, want %s", got, goldenMerkleRoot)
			}
			if !ed25519.Verify(leader, root, body[:signatureSize]) {
				t.Fatal("leader signature over the Merkle root does not verify; a TVU would drop this at sigverify")
			}

			// Mutating one payload byte must break the proof. Without this the
			// test cannot tell a correct root from one computed over the wrong
			// range: a constant-folding bug in merkleRoot would still match.
			tampered := append([]byte(nil), body...)
			tampered[200] ^= 0x01
			if hex.EncodeToString(merkleRoot(t, tampered)) == goldenMerkleRoot {
				t.Fatal("flipping a payload bit left the Merkle root unchanged")
			}
		})
	}
}

// merkleRoot rebuilds the FEC set's Merkle root from a single shred and the
// proof it carries, following Agave ledger/src/shred/merkle.rs. The proof is
// the tail of the payload, so its offset is measured back from the end.
//
// Note this boundary is NOT FrameV3's trailer: that one also excludes the
// 32-byte chained Merkle root, because the root is outside the erasure shard.
// The root IS inside the hashed leaf range, which is why it is not subtracted
// here — the signature check below is what proves that distinction right.
func merkleRoot(t *testing.T, body []byte) []byte {
	t.Helper()
	variant := body[signatureSize]
	proofSize := int(variant & 0x0f)

	var leafIndex int
	switch variant & 0xf0 {
	case 0x90, 0xb0: // chained Merkle data, optionally resigned
		leafIndex = int(binary.LittleEndian.Uint32(body[73:77]) - binary.LittleEndian.Uint32(body[79:83]))
	case 0x60, 0x70: // chained Merkle code, optionally resigned
		numData := int(binary.LittleEndian.Uint16(body[commonHeaderSize : commonHeaderSize+2]))
		leafIndex = numData + int(binary.LittleEndian.Uint16(body[commonHeaderSize+4:commonHeaderSize+6]))
	default:
		t.Fatalf("fixture carries shred variant 0x%02x, which is not a chained-Merkle variant", variant)
	}

	proofAt := len(body) - merkleProofEntrySize*proofSize
	if variant&0xf0 == 0x70 || variant&0xf0 == 0xb0 {
		proofAt -= retransmitterSigSize
	}

	// Leaf and node use different one-byte domain-separation prefixes, and
	// nodes are joined on their first 20 bytes only.
	node := sha256Concat([]byte("\x00SOLANA_MERKLE_SHREDS_LEAF"), body[signatureSize:proofAt])
	for i := 0; i < proofSize; i++ {
		sibling := body[proofAt+merkleProofEntrySize*i : proofAt+merkleProofEntrySize*(i+1)]
		if leafIndex%2 == 0 {
			node = sha256Concat([]byte("\x01SOLANA_MERKLE_SHREDS_NODE"), node[:merkleProofEntrySize], sibling)
		} else {
			node = sha256Concat([]byte("\x01SOLANA_MERKLE_SHREDS_NODE"), sibling, node[:merkleProofEntrySize])
		}
		leafIndex /= 2
	}
	return node
}

func sha256Concat(parts ...[]byte) []byte {
	digest := sha256.New()
	for _, part := range parts {
		digest.Write(part)
	}
	return digest.Sum(nil)
}

func decodeFixture(t *testing.T, fixture string) []byte {
	t.Helper()
	packet, err := hex.DecodeString(strings.Join(strings.Fields(fixture), ""))
	if err != nil {
		t.Fatalf("fixture is not hex: %v", err)
	}
	return packet
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Decode keeps goldenLeader readable as the pubkey an RPC actually
// returns. Twelve lines of math/big beats a dependency for one constant.
func base58Decode(t *testing.T, encoded string) []byte {
	t.Helper()
	value := new(big.Int)
	for _, char := range encoded {
		digit := strings.IndexRune(base58Alphabet, char)
		if digit < 0 {
			t.Fatalf("%q is not base58", encoded)
		}
		value.Mul(value, big.NewInt(58)).Add(value, big.NewInt(int64(digit)))
	}
	decoded := value.Bytes()
	for _, char := range encoded {
		if char != '1' { // leading '1's are leading zero bytes
			break
		}
		decoded = append([]byte{0}, decoded...)
	}
	return decoded
}
