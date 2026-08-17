package shred

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		want    Header
		wantErr error
	}{
		{
			name:   "merkle data",
			packet: testPacket(0x96, 101, 43, 32, 0, 0, 0),
			want: Header{
				Slot: 101, FECSetIndex: 32, Kind: KindData, Index: 43, IndexWithinSet: 11,
			},
		},
		{
			name:   "resigned merkle data",
			packet: testPacket(0xb6, 102, 63, 32, 0, 0, 0),
			want: Header{
				Slot: 102, FECSetIndex: 32, Kind: KindData, Index: 63, IndexWithinSet: 31,
			},
		},
		{
			name:   "merkle coding",
			packet: testPacket(0x66, 103, 90, 64, 32, 32, 5),
			want: Header{
				Slot: 103, FECSetIndex: 64, Kind: KindCoding, Index: 90, IndexWithinSet: 37,
			},
		},
		{
			name:   "resigned merkle coding",
			packet: testPacket(0x76, 104, 91, 64, 32, 32, 31),
			want: Header{
				Slot: 104, FECSetIndex: 64, Kind: KindCoding, Index: 91, IndexWithinSet: 63,
			},
		},
		{name: "short common header", packet: make([]byte, 82), wantErr: ErrHeaderTooShort},
		{name: "short coding header", packet: testPacket(0x66, 1, 1, 0, 0, 0, 0)[:88], wantErr: ErrHeaderTooShort},
		{name: "legacy data is rejected", packet: testPacket(0xa5, 1, 1, 0, 0, 0, 0), wantErr: ErrInvalidVariant},
		{name: "unknown variant", packet: testPacket(0x10, 1, 1, 0, 0, 0, 0), wantErr: ErrInvalidVariant},
		{name: "data before FEC set", packet: testPacket(0x96, 1, 31, 32, 0, 0, 0), wantErr: ErrInvalidIndex},
		{name: "data at coding boundary", packet: testPacket(0x96, 1, 64, 32, 0, 0, 0), wantErr: ErrInvalidIndex},
		{name: "zero data coding set", packet: testPacket(0x66, 1, 1, 0, 0, 32, 0), wantErr: ErrInvalidIndex},
		{name: "zero coding shreds", packet: testPacket(0x66, 1, 1, 0, 32, 0, 0), wantErr: ErrInvalidIndex},
		{name: "coding position outside coding count", packet: testPacket(0x66, 1, 1, 0, 32, 16, 16), wantErr: ErrInvalidIndex},
		{name: "coding set larger than bitmap", packet: testPacket(0x66, 1, 1, 0, 33, 32, 0), wantErr: ErrInvalidIndex},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHeader(tt.packet)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseHeader() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseHeader() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseHeaderDoesNotRetainPacket(t *testing.T) {
	packet := testPacket(0x96, 101, 43, 32, 0, 0, 0)
	header, err := ParseHeader(packet)
	if err != nil {
		t.Fatal(err)
	}

	for i := range packet {
		packet[i] = 0
	}
	if header.Slot != 101 || header.Index != 43 {
		t.Fatalf("header changed after packet reuse: %+v", header)
	}
}

func testPacket(variant byte, slot uint64, index, fecSetIndex uint32, numData, numCoding, position uint16) []byte {
	packet := make([]byte, commonHeaderSize+codingHeaderSize)
	packet[64] = variant
	binary.LittleEndian.PutUint64(packet[65:73], slot)
	binary.LittleEndian.PutUint32(packet[73:77], index)
	binary.LittleEndian.PutUint32(packet[79:83], fecSetIndex)
	binary.LittleEndian.PutUint16(packet[83:85], numData)
	binary.LittleEndian.PutUint16(packet[85:87], numCoding)
	binary.LittleEndian.PutUint16(packet[87:89], position)
	return packet
}
