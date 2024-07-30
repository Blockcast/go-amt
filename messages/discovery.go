package messages

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  V=0  |Type=1 |     Reserved                                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Discovery Nonce                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	RFC7450 Figure 11: Relay Discovery Message Format
*/
type DiscoveryMessage struct {
	Header
	Nonce [4]byte
}

func (d *DiscoveryMessage) MarshalBinary() (data []byte, err error) {

	var b byte
	b |= (0 << 4) // Shift Version to the first nibble
	b |= byte(1)  // Set Type in the next nibble
	ret := []byte{b, 0, 0, 0}

	return append(ret, d.Nonce[:]...), nil
}
