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
|  V=0  |Type=7 |  Reserved     |         Response MAC          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Request Nonce                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Gateway Port Number       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
+                                                               +
|              Gateway IP Address (IPv4 or IPv6)                |
+                                                               +
|                                                               |
+                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	RFC7450 Figure 17: Membership Teardown Message Format
*/
type MembershipTeardownMessage struct {
	ResponseMAC []byte
	Nonce       [4]byte

	GWPortNum uint16
	GWIPAddr  []byte
}

// MembershipTeardownMessage Encode and Decode
func (mtm *MembershipTeardownMessage) MarshalBinary() ([]byte, error) {
	var b byte
	b |= (0 << 4) // Shift Version to the first nibble
	b |= byte(7)  // Set Type in the next nibble
	ret := []byte{b, 0}
	ret = append(ret, mtm.ResponseMAC...)
	ret = append(ret, mtm.Nonce[:]...)

	aux := make([]byte, 2)
	aux[0] = byte(mtm.GWPortNum >> 8)
	aux[1] = byte(mtm.GWPortNum & 0xff)

	ret = append(ret, aux...)

	ret = append(ret, mtm.GWIPAddr...)
	return ret, nil
}

func DecodeMembershipTeardownMessage(data []byte) (*MembershipTeardownMessage, error) {
	if len(data) < 8 {
		return nil, errors.New("data too short for MembershipTeardownMessage")
	}
	buf := bytes.NewReader(data)
	mtm := &MembershipTeardownMessage{}
	if err := binary.Read(buf, binary.BigEndian, 0); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, 7); err != nil {
		return nil, err
	}
	macBytes := make([]byte, 6)
	if _, err := buf.Read(macBytes); err != nil {
		return nil, err
	}
	mtm.ResponseMAC = net.HardwareAddr(macBytes)
	if err := binary.Read(buf, binary.BigEndian, &mtm.Nonce); err != nil {
		return nil, err
	}
	// if err := binary.Read(buf, binary.BigEndian, &mtm.GWPortNum); err != nil {
	// 	return nil, err
	// }
	ipBytes := make([]byte, 16) // Assuming IPv6 length
	if _, err := buf.Read(ipBytes); err != nil {
		return nil, err
	}
	// mtm.GWIPAddr = net.IP(ipBytes)
	return mtm, nil
}
