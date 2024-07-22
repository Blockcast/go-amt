package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  V=0  |Type=2 |                   Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Discovery Nonce                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
~                  Relay Address (IPv4 or IPv6)                 ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	RFC7450 Figure 12: Relay Advertisement Message Format
*/
type RelayAdvertisementMessage struct {
	Header
	Nonce     [4]byte
	RelayAddr net.IP
}

func (ram *RelayAdvertisementMessage) MarshalBinary() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if ram.Type != RelayAdvertisementType {
		return nil, fmt.Errorf("invalid message type for RelayAdvertisementMessage: %d", ram.Type)
	}

	hdr, err := ram.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if _, err = buf.Write(hdr); err != nil {
		return nil, err
	}

	// Skip reserved 3 bytes
	if _, err = buf.Write(advReserved[:]); err != nil {
		return nil, err
	}

	if err = binary.Write(buf, binary.BigEndian, ram.Nonce); err != nil {
		return nil, err
	}

	switch len(ram.RelayAddr) {
	case net.IPv4len:
		_, err = buf.Write(ram.RelayAddr.To4())
	case net.IPv6len:
		_, err = buf.Write(ram.RelayAddr.To16())
	default:
		err = fmt.Errorf("invalid IP address length for RelayAdvertisementMessage: %d", len(ram.RelayAddr))
	}

	return buf.Bytes(), err
}

func (ram *RelayAdvertisementMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 8 { // Header (1 bytes) + Reserved (3 bytes) + Nonce (4 bytes)
		return fmt.Errorf("data too short for RelayAdvertisementMessage: %d", len(data))
	}
	if err := ram.Header.UnmarshalBinary(data); err != nil {
		return err
	}

	if data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return fmt.Errorf("invalid reserved bytes for RelayAdvertisementMessage: %v", data[1:4])
	}

	buf := bytes.NewReader(data[4:])
	if err := binary.Read(buf, binary.BigEndian, &ram.Nonce); err != nil {
		return err
	}

	ipLen := 4           // Assuming IPv4 length
	if len(data) == 24 { // IPv6 length
		ipLen = 16
	}
	ipBytes := make([]byte, ipLen)
	if _, err := buf.Read(ipBytes); err != nil {
		return err
	}
	ram.RelayAddr = ipBytes
	return nil
}

var advReserved = [3]byte{0, 0, 0}
