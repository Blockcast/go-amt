// Package shred parses the Solana shred fields needed for delivery scoring.
package shred

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	commonHeaderSize    = 83
	codingHeaderSize    = 6
	dataShredsPerFECSet = 32
	shredsPerFECSet     = 64
)

var (
	ErrHeaderTooShort = errors.New("shred header too short")
	ErrInvalidVariant = errors.New("invalid shred variant")
	ErrInvalidIndex   = errors.New("invalid shred index")
)

type Kind uint8

const (
	KindData Kind = iota
	KindCoding
)

type Header struct {
	Slot           uint64
	FECSetIndex    uint32
	Kind           Kind
	Index          uint32
	IndexWithinSet uint8
}

// ParseHeader parses only the stable Solana shred wire header. It intentionally
// does not inspect, authenticate, or retain the shred payload.
func ParseHeader(packet []byte) (Header, error) {
	if len(packet) < commonHeaderSize {
		return Header{}, ErrHeaderTooShort
	}

	kind, err := parseKind(packet[64])
	if err != nil {
		return Header{}, err
	}

	header := Header{
		Slot:        binary.LittleEndian.Uint64(packet[65:73]),
		Index:       binary.LittleEndian.Uint32(packet[73:77]),
		FECSetIndex: binary.LittleEndian.Uint32(packet[79:83]),
		Kind:        kind,
	}

	switch kind {
	case KindData:
		if header.Index < header.FECSetIndex {
			return Header{}, fmt.Errorf("%w: data index %d precedes FEC set %d", ErrInvalidIndex, header.Index, header.FECSetIndex)
		}
		index := header.Index - header.FECSetIndex
		if index >= dataShredsPerFECSet {
			return Header{}, fmt.Errorf("%w: data position %d is outside FEC set", ErrInvalidIndex, index)
		}
		header.IndexWithinSet = uint8(index)
	case KindCoding:
		if len(packet) < commonHeaderSize+codingHeaderSize {
			return Header{}, ErrHeaderTooShort
		}
		numData := uint32(binary.LittleEndian.Uint16(packet[83:85]))
		numCoding := uint32(binary.LittleEndian.Uint16(packet[85:87]))
		position := uint32(binary.LittleEndian.Uint16(packet[87:89]))
		index := numData + position
		if numData != dataShredsPerFECSet || numCoding != dataShredsPerFECSet || position >= numCoding {
			return Header{}, fmt.Errorf("%w: coding position %d with %d data and %d coding shreds is outside FEC set", ErrInvalidIndex, position, numData, numCoding)
		}
		header.IndexWithinSet = uint8(index)
	}

	return header, nil
}

func parseKind(variant byte) (Kind, error) {
	switch variant & 0xf0 {
	case 0x60, 0x70:
		return KindCoding, nil
	case 0x90, 0xb0:
		return KindData, nil
	default:
		return 0, fmt.Errorf("%w: 0x%02x", ErrInvalidVariant, variant)
	}
}
