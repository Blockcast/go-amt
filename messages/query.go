package messages

import (
	"net"
)

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  V=0  |Type=4 | Reserved  |L|G|         Response MAC          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Request Nonce                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|               Encapsulated General Query Message              |
~                 IPv4:IGMPv3(Membership Query)                 ~
|                  IPv6:MLDv2(Listener Query)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Gateway Port Number       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                                                               +
|                Gateway IP Address (IPv4 or IPv6)              |
+                                                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	RFC7450 Figure 14: Membership Query Message Format
*/
type MembershipQueryMessage struct {
	Header
	Rsvd1             uint8
	LimitedMembership bool
	HasGatewayAddress bool
	ResponseMAC       net.HardwareAddr
	Nonce             [4]byte
	// Encapsulated IGMPv3 or MLDv2 packets are not directly represented
}

//
//// MembershipQueryMessage Encode and Decode
//func (mqm *MembershipQueryMessage) Encode() ([]byte, error) {
//	buf := new(bytes.Buffer)
//	if err := binary.Write(buf, binary.BigEndian, mqm.Header.Version); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, mqm.Header.Type); err != nil {
//		return nil, err
//	}
//	flags := uint8(0)
//	if mqm.LimitedMembership {
//		flags |= 0x40 // Sets the L bit
//	}
//	if mqm.HasGatewayAddress {
//		flags |= 0x20 // Sets the G bit
//	}
//	if err := buf.WriteByte(flags); err != nil {
//		return nil, err
//	}
//	if _, err := buf.Write(mqm.ResponseMAC); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, mqm.Nonce); err != nil {
//		return nil, err
//	}
//	// Note: Encapsulated IGMPv3 or MLDv2 packets are not directly represented
//	return buf.Bytes(), nil
//}
//
//func DecodeMembershipQueryMessage(data []byte) (*MembershipQueryMessage, error) {
//	if len(data) < 8 {
//		return nil, errors.New("data too short for MembershipQueryMessage")
//	}
//	buf := bytes.NewReader(data)
//	mqm := &MembershipQueryMessage{}
//	if err := binary.Read(buf, binary.BigEndian, &mqm.Header.Version); err != nil {
//		return nil, err
//	}
//	if err := binary.Read(buf, binary.BigEndian, &mqm.Header.Type); err != nil {
//		return nil, err
//	}
//	flags := uint8(0)
//	if err := binary.Read(buf, binary.BigEndian, &flags); err != nil {
//		return nil, err
//	}
//	mqm.LimitedMembership = flags&0x40 != 0
//	mqm.HasGatewayAddress = flags&0x20 != 0
//	macBytes := make([]byte, 6)
//	if _, err := buf.Read(macBytes); err != nil {
//		return nil, err
//	}
//	mqm.ResponseMAC = net.HardwareAddr(macBytes)
//	if err := binary.Read(buf, binary.BigEndian, &mqm.Nonce); err != nil {
//		return nil, err
//	}
//	// Note: Encapsulated IGMPv3 or MLDv2 packets are not directly represented
//	return mqm, nil
//}
