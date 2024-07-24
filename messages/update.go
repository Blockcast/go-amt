package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
)

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  V=0  |Type=5 |  Reserved     |        Response MAC           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Request Nonce                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|         Encapsulated Group Membership Update Message          |
~           IPv4:IGMP(Membership Report|Leave Group)            ~
|            IPv6:MLD(Listener Report|Listener Done)            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

RFC7450 Figure 15: Membership Update Message Format
*/
type MembershipUpdateMessage struct {
	Header
	ResponseMAC  net.HardwareAddr
	Nonce        [4]byte
	Encapsulated MembershipProtocolFlag // or MLDv2 packets are not directly represented
}

// MembershipUpdateMessage Encode and Decode
func (mum *MembershipUpdateMessage) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, mum.Header.Version); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, mum.Header.Type); err != nil {
		return nil, err
	}
	if _, err := buf.Write(mum.ResponseMAC); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, mum.Nonce); err != nil {
		return nil, err
	}
	// Note: Encapsulated IGMPv3 or MLDv2 packets are not directly represented
	return buf.Bytes(), nil
}

func DecodeMembershipUpdateMessage(data []byte) (*MembershipUpdateMessage, error) {
	if len(data) < 8 {
		return nil, errors.New("data too short for MembershipUpdateMessage")
	}
	buf := bytes.NewReader(data)
	mum := &MembershipUpdateMessage{}
	if err := binary.Read(buf, binary.BigEndian, &mum.Header.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &mum.Header.Type); err != nil {
		return nil, err
	}
	macBytes := make([]byte, 6)
	if _, err := buf.Read(macBytes); err != nil {
		return nil, err
	}
	mum.ResponseMAC = net.HardwareAddr(macBytes)
	if err := binary.Read(buf, binary.BigEndian, &mum.Nonce); err != nil {
		return nil, err
	}
	// Note: Encapsulated IGMPv3 or MLDv2 packets are not directly represented
	return mum, nil
}
