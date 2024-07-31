package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  V=0  |Type=3 |   Reserved  |P|            Reserved           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Request Nonce                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	RFC7450 Figure 13: Request Message Format
*/

// If the P flag in the Request message is 0, the relay MUST return an
// IPv4-encapsulated IGMPv3 General Query in the Membership Query
// message.  If the P flag is 1, the relay MUST return an
// IPv6-encapsulated MLDv2 General Query in the Membership Query
// message.

type RequestMessage struct {
	Protocol MembershipProtocolFlag
	Reserved uint16
	Nonce    [4]byte
}

type MembershipProtocolFlag bool

const (
	IGMPv3 MembershipProtocolFlag = false // IPv4 packet carrying an IGMPv3 General Query
	MLDv2  MembershipProtocolFlag = true  // IPv6 packet carrying an MLDv2 General Query
)

// RequestMessage Encode and Decode
// Note: This example assumes the PFlag affects the Reserved field's first bit.
func (rm *RequestMessage) MarshalBinary() ([]byte, error) {

	var myvar [4]byte

	myvar[0] = 0x03 // version + type
	myvar[1] = 0x00 // rsvd1 + p_flag
	myvar[2] = 0x00 // rsvd2 (high byte)
	myvar[3] = 0x00 // rsvd2 (low byte)

	result := append(myvar[:], rm.Nonce[:]...)

	return result, nil
}

func DecodeRequestMessage(data []byte) (*RequestMessage, error) {
	if len(data) < 8 {
		return nil, errors.New("data too short for RequestMessage")
	}
	buf := bytes.NewReader(data)
	rm := &RequestMessage{}
	// if err := binary.Read(buf, binary.BigEndian, &rm.Header.Version); err != nil {
	// 	return nil, err
	// }
	// if err := binary.Read(buf, binary.BigEndian, &rm.Header.Type); err != nil {
	// 	return nil, err
	// }
	pFlagByte := uint8(0)
	if err := binary.Read(buf, binary.BigEndian, &pFlagByte); err != nil {
		return nil, err
	}
	// rm.PFlag = pFlagByte&0x80 != 0
	if err := binary.Read(buf, binary.BigEndian, &rm.Reserved); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &rm.Nonce); err != nil {
		return nil, err
	}
	return rm, nil
}

type AMTRelayRequest struct {
	Version   uint8   // 4 bits
	Type      uint8   // 4 bits
	Reserved1 uint8   // 7 bits
	PFlag     uint8   // 1 bit
	Reserved2 uint16  // 16 bits
	Nonce     [4]byte // 4 bytes
}

func (r *AMTRelayRequest) ToBytes() []byte {
	buf := make([]byte, 8) // Size is 4 bytes for the header + 4 bytes for nonce

	buf[0] = (r.Version << 4) | r.Type
	buf[1] = (r.Reserved1 << 1) | r.PFlag
	binary.BigEndian.PutUint16(buf[2:4], r.Reserved2)
	copy(buf[4:], r.Nonce[:])

	return buf
}

func FromBytes(data []byte) (*AMTRelayRequest, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short")
	}

	r := &AMTRelayRequest{}
	r.Version = data[0] >> 4
	r.Type = data[0] & 0x0F
	r.Reserved1 = data[1] >> 1
	r.PFlag = data[1] & 0x01
	r.Reserved2 = binary.BigEndian.Uint16(data[2:4])
	copy(r.Nonce[:], data[4:8])

	return r, nil
}
