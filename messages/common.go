package messages

import (
	"fmt"
)

// message types
type MessageType uint8

const (
	_ MessageType = iota
	RelayDiscoveryType
	RelayAdvertisementType
	RequestType
	MembershipQueryType
	MembershipUpdateType
	MulticastDataType
	TeardownType
)

// Default port
const DefaultPort = 2268

// Current version
const Version = 0

type Header struct {
	Version  uint8
	Type     MessageType
	Reserved [3]byte
}

// EncodeHeader encodes the Header into a single byte.
func (h *Header) MarshalBinary() (data []byte, err error) {
	// Validate the extracted values if necessary
	if h.Type < RelayDiscoveryType || h.Type > TeardownType {
		return nil, fmt.Errorf("invalid message type: %d", h.Type)
	}
	if h.Version != Version {
		return nil, fmt.Errorf("unsupported version: %d", h.Version)
	}

	var b byte
	b |= (h.Version << 4) // Shift Version to the first nibble
	b |= byte(h.Type)     // Set Type in the next nibble
	return []byte{b, 0, 0, 0}, nil
}

// DecodeHeader decodes a single byte into a Header.
func (header *Header) UnmarshalBinary(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("data too short for Header")
	}
	header.Version = (b[0] >> 4) & 0xF    // Extract the first nibble for Version
	header.Type = MessageType(b[0] & 0xF) // Extract the last niblbe for Type

	if header.Version != Version {
		return fmt.Errorf("unsupported version: %d", header.Version)
	}

	// Validate the extracted values if necessary
	if header.Type < RelayDiscoveryType || header.Type > TeardownType {
		return fmt.Errorf("invalid message type: %d", header.Type)
	}

	return nil
}
