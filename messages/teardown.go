package messages

import (
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
	Header
	ResponseMAC net.HardwareAddr
	Nonce       [4]byte
	GWPortNum   uint16
	GWIPAddr    net.IP
}

//
//// MembershipTeardownMessage Encode and Decode
//func (mtm *MembershipTeardownMessage) Encode() ([]byte, error) {
//	buf := new(bytes.Buffer)
//	if err := binary.Write(buf, binary.BigEndian, mtm.Header.Version); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, mtm.Header.Type); err != nil {
//		return nil, err
//	}
//	if _, err := buf.Write(mtm.ResponseMAC); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, mtm.Nonce); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, mtm.GWPortNum); err != nil {
//		return nil, err
//	}
//	if _, err := buf.Write(mtm.GWIPAddr.To16()); err != nil {
//		return nil, err
//	}
//	return buf.Bytes(), nil
//}
//
//func DecodeMembershipTeardownMessage(data []byte) (*MembershipTeardownMessage, error) {
//	if len(data) < 8 {
//		return nil, errors.New("data too short for MembershipTeardownMessage")
//	}
//	buf := bytes.NewReader(data)
//	mtm := &MembershipTeardownMessage{}
//	if err := binary.Read(buf, binary.BigEndian, &mtm.Header.Version); err != nil {
//		return nil, err
//	}
//	if err := binary.Read(buf, binary.BigEndian, &mtm.Header.Type); err != nil {
//		return nil, err
//	}
//	macBytes := make([]byte, 6)
//	if _, err := buf.Read(macBytes); err != nil {
//		return nil, err
//	}
//	mtm.ResponseMAC = net.HardwareAddr(macBytes)
//	if err := binary.Read(buf, binary.BigEndian, &mtm.Nonce); err != nil {
//		return nil, err
//	}
//	if err := binary.Read(buf, binary.BigEndian, &mtm.GWPortNum); err != nil {
//		return nil, err
//	}
//	ipBytes := make([]byte, 16) // Assuming IPv6 length
//	if _, err := buf.Read(ipBytes); err != nil {
//		return nil, err
//	}
//	mtm.GWIPAddr = net.IP(ipBytes)
//	return mtm, nil
//}
