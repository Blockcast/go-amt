package messages

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

// If the relay is not accepting Membership Update messages that create
//    new tunnel endpoints due to resource limitations, it SHOULD set the
//    L flag in the Membership Query message to notify the gateway of this
//    state.  Support for the L flag is OPTIONAL

type MembershipQueryMessage struct {
	Rsvd1             uint8
	LimitedMembership bool
	HasGatewayAddress bool
	ResponseMAC       net.HardwareAddr
	Nonce             [4]byte
	// Encapsulated      []byte //IGMPv3 or MLDv2 packets are not directly represented

	EncapsulatedQuery []byte
	GatewayPortNumber uint16
	GatewayIPAddress  net.IP
}

func (mqm *MembershipQueryMessage) MarshalBinary() (data []byte, err error) {

	var b byte
	b |= (0 << 4) // Shift Version to the first nibble
	b |= byte(4)  // Set Type in the next nibble
	ret := []byte{b, 0, 0, 0}

	flags := uint8(0)
	if mqm.LimitedMembership {
		flags |= 0x40 // Sets the L bit
	}
	if mqm.HasGatewayAddress {
		flags |= 0x20 // Sets the G bit
	}
	ret = append(ret, flags)
	ret = append(ret, mqm.ResponseMAC...)
	// ret = append(ret, binary.BigEndian)

	ret = append(ret, mqm.Nonce[:]...)
	ret = append(ret, mqm.EncapsulatedQuery[:]...)

	switch len(mqm.GatewayIPAddress) {
	case net.IPv4len:
		ret = append(ret, mqm.GatewayIPAddress.To4()...)
	case net.IPv6len:
		ret = append(ret, mqm.GatewayIPAddress.To16()...)

	default:
		err = fmt.Errorf("invalid IP address length for RelayAdvertisementMessage: %d", len(mqm.GatewayIPAddress))
	}

	return ret, nil

}

// MembershipQueryMessage Encode and Decode
func (mqm *MembershipQueryMessage) UnmarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	// if err := binary.Write(buf, binary.BigEndian, mqm.Header.Version); err != nil {
	// 	return nil, err
	// }
	// if err := binary.Write(buf, binary.BigEndian, mqm.Header.Type); err != nil {
	// 	return nil, err
	// }
	flags := uint8(0)
	if mqm.LimitedMembership {
		flags |= 0x40 // Sets the L bit
	}
	if mqm.HasGatewayAddress {
		flags |= 0x20 // Sets the G bit
	}
	if err := buf.WriteByte(flags); err != nil {
		return nil, err
	}
	if _, err := buf.Write(mqm.ResponseMAC); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, mqm.Nonce); err != nil {
		return nil, err
	}
	// Note: Encapsulated IGMPv3 or MLDv2 packets are not directly represented
	return buf.Bytes(), nil
}

func DecodeMembershipQueryMessage(data []byte) (*MembershipQueryMessage, error) {
	if len(data) < 8 {
		return nil, errors.New("data too short for MembershipQueryMessage")
	}
	buf := bytes.NewReader(data)
	mqm := &MembershipQueryMessage{}
	// if err := binary.Read(buf, binary.BigEndian, &mqm.Header.Version); err != nil {
	// 	return nil, err
	// }
	// if err := binary.Read(buf, binary.BigEndian, &mqm.Header.Type); err != nil {
	// 	return nil, err
	// }
	flags := uint16(0)
	if err := binary.Read(buf, binary.BigEndian, &flags); err != nil {
		return nil, err
	}
	mqm.LimitedMembership = flags&0x4 != 0
	mqm.HasGatewayAddress = flags&0x2 != 0

	macBytes := make([]byte, 6)
	if err := binary.Read(buf, binary.LittleEndian, &macBytes); err != nil {
		return nil, err
	}
	mqm.ResponseMAC = net.HardwareAddr(macBytes)

	if err := binary.Read(buf, binary.BigEndian, &mqm.Nonce); err != nil {
		return nil, err
	}

	encapsulatedLength := buf.Len() // - 8 // 8 bytes for Gateway Port and IP
	if encapsulatedLength > 0 {
		mqm.EncapsulatedQuery = make([]byte, encapsulatedLength)
		if _, err := buf.Read(mqm.EncapsulatedQuery); err != nil {
			return nil, err
		}
	}

	// // Read Gateway Port Number
	// if err := binary.Read(buf, binary.BigEndian, &mqm.GatewayPortNumber); err != nil {
	// 	return nil, err
	// }
	// // Read Gateway IP Address
	// mqm.GatewayIPAddress = make([]byte, buf.Len()) // Remaining bytes should be the IP
	// if _, err := buf.Read(mqm.GatewayIPAddress); err != nil {
	// 	return nil, err
	// }

	return mqm, nil
}
