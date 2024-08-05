package amt

import (
	"crypto/rand"
	"encoding/binary"
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
var _ MessageBody = (*m.MembershipTeardownMessage)(nil)

type Message struct {
	Version uint8
	Type    m.MessageType
	Body    MessageBody
}

type AMTresponse struct {
	AMTmessageType m.MessageType
	Data           []byte
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
	fmt.Println("Sending AMT Relay Discovery")

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
	fmt.Println("Sending AMT Request")

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

			Nonce:            response.Nonce,
			GatewayIPAddress: net.ParseIP(localAddr)},
	}

	data, _ := m.Body.MarshalBinary()
	conn.Write(data)
}

func sendMembershipUpdate(conn *net.UDPConn, nonce []byte, membershipQuery m.MembershipQueryMessage, mult, sou string) {
	fmt.Println("Sending AMT Membership Update")
	multicast := net.ParseIP(mult).To4()
	source := net.ParseIP(sou).To4()

	groupRecord := m.IGMPv3GroupRecord{
		RecordType: 1, // Change this based on the type of record you need (e.g., 1 for Mode Is Include)
		AuxDataLen: 0,
		NumSources: 1,
		Multicast:  [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
		Sources:    [][4]byte{{source[0], source[1], source[2], source[3]}},
	}

	membershipReport := m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport,
		Reserved1:       0,
		Checksum:        0,
		Reserved2:       0,
		NumGroupRecords: 1,
		GroupRecords:    []m.IGMPv3GroupRecord{groupRecord},
	}

	encapsulated := createIPv4MembershipReport(mult, sou)

	membershipReportBinary, err := membershipReport.MarshalBinary()

	encapsulated = append(encapsulated, membershipReportBinary...)

	m := Message{
		Version: m.Version,
		Type:    m.MembershipUpdateType,
		Body: &m.MembershipUpdateMessage{
			ResponseMAC:  membershipQuery.ResponseMAC,
			Nonce:        [4]byte(nonce),
			Encapsulated: encapsulated,
		},
	}

	data, err := m.Body.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println(err.Error())
	}

}

func readRelayAdvertisement(conn *net.UDPConn, amtResponseChan chan AMTresponse) error {

	// defer close(amtResponseChan)
	buffer := make([]byte, 1500)

	for {
		n, err := conn.Read(buffer)

		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return err
		}
		amtMessageType := determineAMTmessageType(buffer[:])
		amtResponse := AMTresponse{amtMessageType, buffer[:n]}
		amtResponseChan <- amtResponse

		// amtResponseChan <- buffer[:n]

	}
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
		fmt.Println("Receiving data..")

		dataChannel <- buffer[:n]
	}

}

func sendTeardown(conn *net.UDPConn, membershipQuery m.MembershipQueryMessage, multicast string) {
	fmt.Println("Sending AMT Teardown")
	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	ip := net.ParseIP(multicast).To4()

	ipv6 := make([]byte, 16) // ip must be IPv6 or IPv4 prefixed with 96 bits set to zero (see [RFC4291])
	copy(ipv6[12:], ip)

	m := Message{
		Version: m.Version,
		Type:    m.TeardownType,
		Body: &m.MembershipTeardownMessage{
			ResponseMAC: membershipQuery.ResponseMAC,
			Nonce:       membershipQuery.Nonce,
			GWPortNum:   uint16(localPort),
			GWIPAddr:    ipv6,
		},
	}

	data, _ := m.Body.MarshalBinary()
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

	amtResponseChan := make(chan AMTresponse)
	go func() {
		err := readRelayAdvertisement(conn, amtResponseChan)
		if err != nil {
			fmt.Println("Error reading advertisement:", err)
		}
	}()

	err = sendDiscovery(conn, nonce)
	if err != nil {
		fmt.Println("Error sending discovery:", err)
		return
	}

	for response := range amtResponseChan {
		switch response.AMTmessageType {
		case m.RelayAdvertisementType:
			fmt.Println("Received AMT Relay Advertisement")
			relayAdvertisement := &m.RelayAdvertisementMessage{}
			err := relayAdvertisement.UnmarshalBinary(response.Data)
			err = sendRequest(conn, nonce, relay)
			if err != nil {
				fmt.Println("Error sending advertisement:", err)
				return
			}
		case m.MembershipQueryType:
			fmt.Println("Received AMT Membership Query")
			membershipQuery, err := m.DecodeMembershipQueryMessage(response.Data)
			if err != nil {
				fmt.Print("Error in DecodeMembershipQueryMessage", err)
				return
			}
			fmt.Println("port", membershipQuery.GatewayPortNumber)
			fmt.Println("ip", membershipQuery.GatewayIPAddress)

			sendMembershipUpdate(conn, nonce, *membershipQuery, multicast, source)

			// Simulate timeout
			go timer(conn, membershipQuery, multicast)

		case m.MulticastDataType:
			fmt.Println("Receiving data..")
		default:
			fmt.Println("Unknown data type") // TODO: see how to handle
			break
		}
	}

}

func createIPv4MembershipReport(multicast, source string) []byte {
	srcIP := net.ParseIP("0.0.0.0")
	dstIP := net.ParseIP("224.0.0.22")
	// Create the IPv4 layer
	ipv4 := gopacket.NewSerializeBuffer()
	ipv4Layer := &layers.IPv4{
		Version:    4,
		IHL:        6,
		TOS:        0xc0,
		Length:     44, // Header length only
		Id:         1,
		Flags:      0,
		FragOffset: 0,
		TTL:        1, // Default TTL value
		Protocol:   2, // TODO: see this
		Checksum:   0, // To be calculated
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Options:    []layers.IPv4Option{},
	}

	// Serialize IPv4 header
	err := gopacket.SerializeLayers(ipv4, gopacket.SerializeOptions{}, ipv4Layer)
	if err != nil {
		fmt.Println("Error serializing IPv4 layer:", err)
		return nil
	}

	// Get the serialized bytes
	packetBytes := ipv4.Bytes()
	var optionsarray byte

	packetBytes = append(packetBytes, optionsarray)
	packetBytes = append(packetBytes, optionsarray)
	packetBytes = append(packetBytes, optionsarray)
	packetBytes = append(packetBytes, optionsarray)

	checksum := calculateChecksum(packetBytes)
	binary.BigEndian.PutUint16(packetBytes[10:], checksum)

	return packetBytes
}

func createIGMPv3Packet(multicast, source string) []byte {
	srcIP := net.ParseIP(source)
	dstIP := net.ParseIP(multicast)
	//igmpv3 := gopacket.NewSerializeBuffer()

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

	// // Serialize IPv4 header
	// err := gopacket.SerializeLayers(igmpv3, gopacket.SerializeOptions{}, igmpv3Layer)
	// if err != nil {
	// 	fmt.Println("Error serializing IPv4 layer:", err)
	// 	return nil
	// }

	// Get the serialized bytes
	packetBytes := igmpv3Layer.LayerContents()
	fmt.Println(packetBytes)
	return packetBytes

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

func determineAMTmessageType(data []byte) m.MessageType {
	return m.MessageType(data[0])
}

func timer(conn *net.UDPConn, membershipQuery *m.MembershipQueryMessage, multicast string) {
	time.Sleep(3 * time.Second)
	sendTeardown(conn, *membershipQuery, multicast)

}
