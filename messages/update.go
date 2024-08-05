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
	ResponseMAC net.HardwareAddr
	Nonce       [4]byte
	// Encapsulated MembershipProtocolFlag // or MLDv2 packets are not directly represented
	Encapsulated []byte // or MLDv2 packets are not directly represented

}

const (
	IGMPv3TypeMembershipReport = 0x22
)

type IGMPv3GroupRecord struct {
	RecordType uint8
	AuxDataLen uint8
	NumSources uint16
	Multicast  [4]byte
	Sources    [][4]byte
}

type IGMPv3MembershipReport struct {
	Type            uint8
	Reserved1       uint8
	Checksum        uint16
	Reserved2       uint16
	NumGroupRecords uint16
	GroupRecords    []IGMPv3GroupRecord
}

func (mum *MembershipUpdateMessage) MarshalBinary() (data []byte, err error) {

	var myvar [2]byte

	// Fill in the bit fields according to their sizes
	myvar[0] = 0x05 // version + type
	myvar[1] = 0x00 // rsvd1
	result := append(myvar[:], mum.ResponseMAC[:]...)
	result = append(result[:], mum.Nonce[:]...)
	result = append(result[:], mum.Encapsulated[:]...)

	return result, nil
}

// MembershipUpdateMessage Encode and Decode
func (mum *MembershipUpdateMessage) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	// if err := binary.Write(buf, binary.BigEndian, mum.Header.Version); err != nil {
	// 	return nil, err
	// }
	// if err := binary.Write(buf, binary.BigEndian, mum.Header.Type); err != nil {
	// 	return nil, err
	// }
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
	// if err := binary.Read(buf, binary.BigEndian, &mum.Header.Version); err != nil {
	// 	return nil, err
	// }
	// if err := binary.Read(buf, binary.BigEndian, &mum.Header.Type); err != nil {
	// 	return nil, err
	// }
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

func (report *IGMPv3MembershipReport) MarshalBinary() ([]byte, error) {
	buffer := make([]byte, 8) // IGMPv3 Membership Report header is 8 bytes
	buffer[0] = report.Type
	buffer[1] = report.Reserved1
	binary.BigEndian.PutUint16(buffer[2:], report.Checksum)
	binary.BigEndian.PutUint16(buffer[4:], report.Reserved2)
	binary.BigEndian.PutUint16(buffer[6:], report.NumGroupRecords)

	for _, groupRecord := range report.GroupRecords {
		recordBuffer, err := groupRecord.MarshalBinary()
		if err != nil {
			return nil, err
		}
		buffer = append(buffer, recordBuffer...)
	}

	// Compute and set checksum
	checksum := calculateChecksum(buffer)
	binary.BigEndian.PutUint16(buffer[2:], checksum)

	return buffer, nil
}

func (record *IGMPv3GroupRecord) MarshalBinary() ([]byte, error) {
	buffer := make([]byte, 8+(len(record.Sources)*4)) // Group Record header is 8 bytes, each source is 4 bytes
	buffer[0] = record.RecordType
	buffer[1] = record.AuxDataLen
	binary.BigEndian.PutUint16(buffer[2:], record.NumSources)
	copy(buffer[4:], record.Multicast[:])

	offset := 8
	for _, source := range record.Sources {
		copy(buffer[offset:], source[:])
		offset += 4
	}

	return buffer, nil
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1])
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
