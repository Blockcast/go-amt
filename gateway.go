package amt

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MessageBody interface {
	MarshalBinary() (data []byte, err error)
}

var _ MessageBody = (*m.DiscoveryMessage)(nil)
var _ MessageBody = (*m.RelayAdvertisementMessage)(nil)
var _ MessageBody = (*m.MembershipQueryMessage)(nil)
var _ MessageBody = (*m.MembershipUpdateMessage)(nil)
var _ MessageBody = (*m.RequestMessage)(nil)

type Message struct {
	Version uint8
	Type    m.MessageType
	Body    MessageBody
}

func setupSocket(relay string) (*net.UDPConn, error) {
	relayIP := relay
	relayPort := m.DefaultPort

	relayAddr := &net.UDPAddr{
		IP:   net.ParseIP(relayIP),
		Port: relayPort,
	}

	conn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		fmt.Println("Error connecting to relay:", err)
		return nil, nil
	}
	return conn, nil
}

func sendDiscovery(conn *net.UDPConn, nonce []byte) error {
	fmt.Print("Sending AMT relay discovery")
	fmt.Println()

	m := Message{
		Version: m.Version,
		Type:    m.RelayDiscoveryType,
		Body:    &m.DiscoveryMessage{Nonce: [4]byte(nonce)},
	}

	data, err := m.Body.MarshalBinary()

	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = conn.Write(data)

	return err
}

func sendRequest(conn *net.UDPConn, nonce []byte, relayIP string) error {
	fmt.Print("Sending AMT relay advertisement")
	fmt.Println()

	m := Message{
		Version: m.Version,
		Type:    m.RequestType,
		Body:    &m.RequestMessage{Nonce: [4]byte(nonce), Reserved: uint16(0)},
	}

	data, err := m.Body.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}

	_, err = conn.Write(data)

	return err
}

func sendMembershipQuery(conn *net.UDPConn, nonce []byte, response m.RelayAdvertisementMessage) {

	localAddr := conn.LocalAddr().String()

	m := Message{
		Version: m.Version,
		Type:    m.RelayAdvertisementType,
		Body: &m.MembershipQueryMessage{
			LimitedMembership: true,
			HasGatewayAddress: true,
			ResponseMAC:       net.HardwareAddr("0"),

			Nonce:       response.Nonce,
			GatewayAddr: net.ParseIP(localAddr)},
	}

	data, _ := m.Body.MarshalBinary()
	conn.Write(data)
}

func sendMembershipUpdate(conn *net.UDPConn, nonce []byte, membershipQuery m.MembershipQueryMessage, mult, sou string) {
	// multicast := net.ParseIP(mult).To4()
	// source := net.ParseIP(sou).To4()

	// groupRecord := m.IGMPv3GroupRecord{
	// 	RecordType: 4, // Change this based on the type of record you need (e.g., 1 for Mode Is Include)
	// 	AuxDataLen: 0,
	// 	NumSources: 1,
	// 	Multicast:  [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
	// 	Sources:    [][4]byte{{source[0], source[1], source[2], source[3]}},
	// }

	// membershipReport := m.IGMPv3MembershipReport{
	// 	Type:            m.IGMPv3TypeMembershipReport,
	// 	Reserved1:       0,
	// 	Checksum:        0,
	// 	Reserved2:       0,
	// 	NumGroupRecords: 1,
	// 	GroupRecords:    []m.IGMPv3GroupRecord{groupRecord},
	// }

	// encapsulated, err := membershipReport.MarshalBinary()
	encapsulated := createIPv4MembershipReport(mult, sou)

	igmpv3 := createIGMPv3Packet(mult, sou)
	fmt.Println(igmpv3)

	encapsulated = append(encapsulated, igmpv3...)

	// fmt.Println("membership query:")
	// fmt.Println(membershipQuery)
	m := Message{
		Version: m.Version,
		Type:    m.MembershipUpdateType,
		Body: &m.MembershipUpdateMessage{
			ResponseMAC:  membershipQuery.ResponseMAC,
			Nonce:        [4]byte(nonce),
			Encapsulated: encapsulated,
		},
	}

	// for _, b := range nonce {
	// 	// Convert byte to binary string
	// 	binaryStr := fmt.Sprintf("%08b", b)
	// 	// Print each bit
	// 	for i := 0; i < len(binaryStr); i++ {
	// 		fmt.Print(string(binaryStr[i]), " ")
	// 	}
	// 	fmt.Print(" ") // Space between bytes
	// }

	data, err := m.Body.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println(err.Error())
	}

}

func readRelayAdvertisement(conn *net.UDPConn, nonce []byte, responseChan chan []byte) error {
	buffer := make([]byte, 1500)
	fmt.Println("Local Address:", conn.LocalAddr())
	fmt.Println("Remote Address:", conn.RemoteAddr())

	n, err := conn.Read(buffer)

	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return err
	}

	fmt.Printf("Read %d bytes from connection\n", n)

	responseChan <- buffer[:n]

	return nil
}

func receiveAndForwardData(conn *net.UDPConn, dataChannel chan []byte) {

	buffer := make([]byte, 1024)
	timeout := 30 * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buffer)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Read timeout, no data received")
			break
		} else if err != nil {
			fmt.Println("Error reading from connection:", err)
			break
		}
		// fmt.Println("Received data:", buffer[:n])
		dataChannel <- buffer[:n]
	}

}

func sendTeardown(conn *net.UDPConn, nonce []byte) {
	teardown := m.MembershipTeardownMessage{
		Header: m.Header{Version: m.Version, Type: m.TeardownType},
		Nonce:  [4]byte(nonce), // Example nonce, should match the one used in DiscoveryMessage
	}
	data, _ := teardown.Encode()
	conn.Write(data)
}

func StartGateway(relay, source, multicast string, dataChannel chan []byte) {

	conn, err := setupSocket(relay)
	if err != nil {
		fmt.Println("Error setting up socket:", err)
		return
	}
	defer conn.Close()

	nonce := make([]byte, 4)
	rand.Read(nonce)

	relayResponseChan := make(chan []byte)
	go readRelayAdvertisement(conn, nonce, relayResponseChan)

	err = sendDiscovery(conn, nonce)
	if err != nil {
		fmt.Println("Error sending discovery:", err)
		return
	}

	for response := range relayResponseChan {
		relayAdvertisement := &m.RelayAdvertisementMessage{}
		err = relayAdvertisement.UnmarshalBinary(response)
		err = sendRequest(conn, nonce, relay)
		if err != nil {
			fmt.Println("Error sending advertisement:", err)
			return
		}

		go receiveAndForwardData(conn, dataChannel)

		break

	}

	for response := range dataChannel {
		membershipQuery, err := m.DecodeMembershipQueryMessage(response)
		if err != nil {
			fmt.Print("Error in DecodeMembershipQueryMessage", err)
		}
		sendMembershipUpdate(conn, nonce, *membershipQuery, multicast, source)

		receiveAndForwardData(conn, dataChannel)

		break

	}

}

func createIPv4MembershipReport(multicast, source string) []byte {
	srcIP := net.ParseIP(source)
	dstIP := net.ParseIP(multicast)
	// Create the IPv4 layer
	ipv4 := gopacket.NewSerializeBuffer()
	ipv4Layer := &layers.IPv4{
		Version:    4,
		IHL:        5,
		TOS:        0,
		Length:     20, // Header length only
		Id:         0,
		Flags:      0,
		FragOffset: 0,
		TTL:        64,                                               // Default TTL value
		Protocol:   layers.IPProtocol(layers.IGMPMembershipReportV1), // TODO: see this
		Checksum:   0,                                                // To be calculated
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	// Serialize IPv4 header
	err := gopacket.SerializeLayers(ipv4, gopacket.SerializeOptions{}, ipv4Layer)
	if err != nil {
		fmt.Println("Error serializing IPv4 layer:", err)
		return nil
	}

	// Get the serialized bytes
	packetBytes := ipv4.Bytes()
	return packetBytes
	// // Define the IGMPv3 header
	// multicastBytes := ipToBytes(net.ParseIP(multicast))
	// sourceBytes := ipToBytes(net.ParseIP(source))
	// igmpv3Header := gopacket.Payload([]byte{
	// 	0x11, // Type (Membership Report)
	// 	0x00, // Reserved
	// 	0x00, // Checksum (we'll calculate this later)
	// 	0x01, // Number of Group Records
	// })

	// // Define the IGMPv3 Group Record
	// groupRecord := gopacket.Payload([]byte{
	// 	0x01,              // Record Type (Mode is Include)
	// 	0x00,              // Auxiliary Data Length
	// 	0x01,              // Number of Sources
	// 	multicastBytes[0], // Multicast Address
	// 	multicastBytes[1],
	// 	multicastBytes[2],
	// 	multicastBytes[3],
	// 	sourceBytes[0], // Source Address
	// 	sourceBytes[1],
	// 	sourceBytes[2],
	// 	sourceBytes[3],
	// })

	// // Combine IGMPv3 header and Group Record
	// igmpv3Packet := append(igmpv3Header, groupRecord...)

	// // Calculate checksum
	// checksum := calculateChecksum(igmpv3Packet)
	// igmpv3Packet[2] = byte(checksum >> 8)
	// igmpv3Packet[3] = byte(checksum & 0xFF)
	// return igmpv3Packet
}

func ipToBytes(ip net.IP) []byte {
	if ip.To4() != nil {
		return ip.To4()
	}
	return ip.To16() // For IPv6
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += (sum >> 16)
	return ^uint16(sum)
}

func createIGMPv3Packet(multicast, source string) []byte {
	srcIP := net.ParseIP(source)
	dstIP := net.ParseIP(multicast)
	// igmpv3 := gopacket.NewSerializeBuffer()

	// Create the IGMPv3 layer
	igmpv3Layer := &layers.IGMP{
		Type: layers.IGMPMembershipReportV3,
		GroupRecords: []layers.IGMPv3GroupRecord{
			{
				Type:             layers.IGMPv3GroupRecordType(layers.IGMPMembershipReportV1),
				AuxDataLen:       0,
				MulticastAddress: dstIP,
				SourceAddresses:  []net.IP{srcIP},
			},
		},
	}

	fmt.Println(igmpv3Layer)

	// // Serialize IPv4 header
	// err := gopacket.SerializeLayers(igmpv3, gopacket.SerializeOptions{}, igmpv3Layer)
	// if err != nil {
	// 	fmt.Println("Error serializing IPv4 layer:", err)
	// 	return nil
	// }

	// Get the serialized bytes
	packetBytes := igmpv3Layer.LayerPayload()
	return packetBytes

}
