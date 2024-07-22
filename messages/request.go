package messages

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
type RequestMessage struct {
	Header
	Protocol MembershipProtocolFlag
	Reserved uint16
	Nonce    [4]byte
}

type MembershipProtocolFlag bool

const (
	IGMPv3 MembershipProtocolFlag = false // IPv4 packet carrying an IGMPv3 General Query
	MLDv2  MembershipProtocolFlag = true  // IPv6 packet carrying an MLDv2 General Query
)

//
//// RequestMessage Encode and Decode
//// Note: This example assumes the PFlag affects the Reserved field's first bit.
//func (rm *RequestMessage) Encode() ([]byte, error) {
//	buf := new(bytes.Buffer)
//	if err := binary.Write(buf, binary.BigEndian, rm.Header.Version); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, rm.Header.Type); err != nil {
//		return nil, err
//	}
//	pFlagByte := uint8(0)
//	if rm.PFlag {
//		pFlagByte = 0x80 // Sets the first bit to 1
//	}
//	if err := buf.WriteByte(pFlagByte); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, rm.Reserved); err != nil {
//		return nil, err
//	}
//	if err := binary.Write(buf, binary.BigEndian, rm.Nonce); err != nil {
//		return nil, err
//	}
//	return buf.Bytes(), nil
//}
//
//func DecodeRequestMessage(data []byte) (*RequestMessage, error) {
//	if len(data) < 8 {
//		return nil, errors.New("data too short for RequestMessage")
//	}
//	buf := bytes.NewReader(data)
//	rm := &RequestMessage{}
//	if err := binary.Read(buf, binary.BigEndian, &rm.Header.Version); err != nil {
//		return nil, err
//	}
//	if err := binary.Read(buf, binary.BigEndian, &rm.Header.Type); err != nil {
//		return nil, err
//	}
//	pFlagByte := uint8(0)
//	if err := binary.Read(buf, binary.BigEndian, &pFlagByte); err != nil {
//		return nil, err
//	}
//	rm.PFlag = pFlagByte&0x80 != 0
//	if err := binary.Read(buf, binary.BigEndian, &rm.Reserved); err != nil {
//		return nil, err
//	}
//	if err := binary.Read(buf, binary.BigEndian, &rm.Nonce); err != nil {
//		return nil, err
//	}
//	return rm, nil
//}
