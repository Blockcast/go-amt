package shred

import (
	"bytes"
	"testing"
)

// fullShredFrame is a version-4 frame carrying a canonical-size shred whose
// bytes follow a position pattern, so a test can tell exactly which slice
// FrameV3 kept. FrameV3 reads only the variant byte of the shred itself.
func fullShredFrame(variant byte, coding bool) (frame, body []byte) {
	size, localIndex := agaveDataShredSize, uint32(5)
	if coding {
		size, localIndex = agaveCodingShredSize, 37
	}
	body = make([]byte, size)
	for i := range body {
		body[i] = byte(i * 7)
	}
	body[signatureSize] = variant
	header := forwarderPacket(4, 439000406, 544, localIndex, coding, 1785000000000000)[:WireHeaderSize:WireHeaderSize]
	return append(header, body...), body
}

func withByte(b []byte, i int, v byte) []byte {
	c := bytes.Clone(b)
	c[i] = v
	return c
}

func TestFrameV3KeepsTheErasureShard(t *testing.T) {
	// Bounds are spelled out from the Agave layout, not taken from FrameV3's
	// constants, so a wrong constant fails here.
	for _, tc := range []struct {
		name       string
		variant    byte
		coding     bool
		start, end int
	}{
		{"data, chained, proof 6", 0x96, false, 64, 1203 - 32 - 6*20},
		{"data, chained resigned, proof 6", 0xb6, false, 64, 1203 - 32 - 6*20 - 64},
		{"data, chained, proof 5", 0x95, false, 64, 1203 - 32 - 5*20},
		{"code, chained, proof 6", 0x66, true, 83 + 6, 1228 - 32 - 6*20},
		{"code, chained resigned, proof 6", 0x76, true, 83 + 6, 1228 - 32 - 6*20 - 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, body := fullShredFrame(tc.variant, tc.coding)
			v3, ok := FrameV3(frame)
			if !ok {
				t.Fatal("FrameV3 refused a well-formed version-4 frame")
			}
			if v3[0] != 3 {
				t.Errorf("version byte = %d, want 3", v3[0])
			}
			if !bytes.Equal(v3[1:WireHeaderSize], frame[1:WireHeaderSize]) {
				t.Error("header bytes after the version changed")
			}
			if !bytes.Equal(v3[WireHeaderSize:], body[tc.start:tc.end]) {
				t.Errorf("body is %d bytes, want shred[%d:%d] (%d bytes)",
					len(v3)-WireHeaderSize, tc.start, tc.end, tc.end-tc.start)
			}
		})
	}
}

func TestFrameV3DataAndCodeShardsAreEqualSize(t *testing.T) {
	// Reed-Solomon needs equal shards, so in a 32:32 batch (proof 6) a data and
	// a coding shred reduce to the same 987 bytes: every version-3 frame of
	// such a batch is 1015 bytes.
	data, _ := fullShredFrame(0x96, false)
	code, _ := fullShredFrame(0x66, true)
	dv3, _ := FrameV3(data)
	cv3, _ := FrameV3(code)
	if len(dv3) != 1015 || len(cv3) != 1015 {
		t.Errorf("version-3 frame sizes: data %d, code %d; want 1015 for both", len(dv3), len(cv3))
	}
}

func TestFrameV3RefusesWhatTheForwarderNeverSends(t *testing.T) {
	data, _ := fullShredFrame(0x96, false)
	code, _ := fullShredFrame(0x66, true)
	variantAt := WireHeaderSize + signatureSize
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"version 3", withByte(data, 0, 3)},
		{"shorter than the header", data[:WireHeaderSize-1]},
		{"truncated data shred", data[:len(data)-1]},
		{"coding flag on a data-sized shred", withByte(data, 17, wireFlagCoding)},
		{"data flag, coding variant", withByte(data, variantAt, 0x66)},
		{"coding flag, data variant", withByte(code, variantAt, 0x96)},
		{"unchained Merkle data", withByte(data, variantAt, 0x86)},
		{"unchained Merkle code", withByte(code, variantAt, 0x46)},
		{"legacy data", withByte(data, variantAt, 0xa5)},
		{"legacy code", withByte(code, variantAt, 0x5a)},
	} {
		if v3, ok := FrameV3(tc.frame); ok {
			t.Errorf("%s: FrameV3 returned %d bytes; want a refusal", tc.name, len(v3))
		}
	}
}
