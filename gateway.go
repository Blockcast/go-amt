package amt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"syscall"
	"time"
)

type Gateway struct {
	conn         *ipv4.PacketConn
	nonce        []byte
	RelayAddr    net.Addr
	cm           *ipv4.ControlMessage
	leave        bool
	SourceAddr   net.IP
	GroupAddr    net.IP
	MTU          int
	intervalTime time.Duration
}

func (g *Gateway) setupSocket() (*ipv4.PacketConn, error) {
	if len(g.SourceAddr) == 0 {
		g.SourceAddr = net.IPv4zero
	}
	// Create socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("could not get socket: %w", err)
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
		return nil, fmt.Errorf("could not set socket timestamp: %w", err)
	}

	// Turn the socket file descriptor into an *os.File
	file := os.NewFile(uintptr(sock), "")

	// Turn it into a net.PacketConn
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}

	// We no longer need the file
	if err = file.Close(); err != nil {
		return nil, err
	}

	return ipv4.NewPacketConn(conn), nil
}

func (g *Gateway) sendDiscovery() error {
	msg := m.Message{
		Version: m.Version,
		Type:    m.RelayDiscoveryType,
		Body:    &m.DiscoveryMessage{Nonce: [4]byte(g.nonce)},
	}

	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

func (g *Gateway) sendRequest() error {
	msg := m.Message{
		Version: m.Version,
		Type:    m.RequestType,
		Body:    &m.RequestMessage{Nonce: [4]byte(g.nonce), Reserved: uint16(0)},
	}

	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

func (g *Gateway) sendMembershipUpdate(membershipQuery m.MembershipQueryMessage) error {
	multicast := g.GroupAddr.To4()
	var encapsulated []byte
	var err error
	//if g.SourceAddr.IsUnspecified() {
	//	membershipReport := m.IGMPv2Message{
	//		Type:        m.IGMPv2TypeMembershipReport,
	//		MaxRespTime: 10,
	//		GroupAddr:   [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
	//	}
	//	encapsulated, err = createIPv4MembershipReport(g.GroupAddr, g.SourceAddr, 32)
	//	if err != nil {
	//		return err
	//	}
	//	membershipReportBinary, err := membershipReport.MarshalBinary()
	//	if err != nil {
	//		return err
	//	}
	//
	//	encapsulated = append(encapsulated, membershipReportBinary...)
	//} else {
	var length uint16 = 40
	srcAddr := g.SourceAddr
	groupRecord := m.IGMPv3GroupRecord{
		RecordType: m.IGMPv3ModeIsExclude, // Change this based on the type of record you need (e.g., 1 for Mode Is Include)
		AuxDataLen: 0,
		Multicast:  [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
	}
	if !g.SourceAddr.IsUnspecified() {
		source := srcAddr.To4()
		groupRecord.Sources = [][4]byte{{source[0], source[1], source[2], source[3]}}
		groupRecord.NumSources = 1
		groupRecord.RecordType = m.IGMPv3ModeIsInclude
		length += 4
	}

	membershipReport := m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport,
		NumGroupRecords: 1,
		GroupRecords:    []m.IGMPv3GroupRecord{groupRecord},
	}

	encapsulated, err = createIPv4MembershipReport(g.GroupAddr, srcAddr, length)
	if err != nil {
		return err
	}
	membershipReportBinary, err := membershipReport.MarshalBinary()
	if err != nil {
		return err
	}

	encapsulated = append(encapsulated, membershipReportBinary...)
	//}

	msg := m.Message{
		Version: m.Version,
		Type:    m.MembershipUpdateType,
		Body: &m.MembershipUpdateMessage{
			ResponseMAC:  membershipQuery.ResponseMAC,
			Nonce:        [4]byte(g.nonce),
			Encapsulated: encapsulated,
		},
	}

	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

func (g *Gateway) sendMembershipLeave(membershipQuery m.MembershipQueryMessage) error {
	var encapsulated []byte
	var err error
	multicast := g.GroupAddr.To4()
	srcAddr := g.SourceAddr

	//	membershipReport := m.IGMPv2Message{
	//		Type:        m.IGMPv2TypeLeaveGroup,
	//		MaxRespTime: 10,
	//		GroupAddr:   [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
	//	}
	//	encapsulated, err = createIPv4MembershipReport(g.GroupAddr, g.SourceAddr, 32)
	//	if err != nil {
	//		return err
	//	}
	//	membershipReportBinary, err := membershipReport.MarshalBinary()
	//	if err != nil {
	//		return err
	//	}
	//
	//	encapsulated = append(encapsulated, membershipReportBinary...)
	//} else {
	groupRecord := m.IGMPv3GroupRecord{
		RecordType: m.IGMPv3ChangeToIncludeMode, // Change this based on the type of record you need (e.g., 1 for Mode Is Include)
		AuxDataLen: 0,
		NumSources: 0,
		Multicast:  [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
		Sources:    [][4]byte{},
	}

	membershipReport := m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport,
		NumGroupRecords: 1,
		GroupRecords:    []m.IGMPv3GroupRecord{groupRecord},
	}

	encapsulated, err = createIPv4MembershipReport(g.GroupAddr, srcAddr, 40)
	if err != nil {
		return err
	}
	membershipReportBinary, err := membershipReport.MarshalBinary()
	if err != nil {
		return err
	}

	encapsulated = append(encapsulated, membershipReportBinary...)
	//}

	msg := m.Message{
		Version: m.Version,
		Type:    m.MembershipUpdateType,
		Body: &m.MembershipUpdateMessage{
			ResponseMAC:  membershipQuery.ResponseMAC,
			Nonce:        [4]byte(g.nonce),
			Encapsulated: encapsulated,
		},
	}

	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

func (g *Gateway) sendTeardown(membershipQuery m.MembershipQueryMessage) error {
	var ipv6 = make([]byte, 16)
	if membershipQuery.HasGatewayAddress {
		copy(ipv6[12:], membershipQuery.GatewayIPAddress)
	}

	msg := m.Message{
		Version: m.Version,
		Type:    m.TeardownType,
		Body: &m.MembershipTeardownMessage{
			ResponseMAC: membershipQuery.ResponseMAC,
			Nonce:       membershipQuery.Nonce,
			GWPortNum:   membershipQuery.GatewayPortNumber,
			GWIPAddr:    ipv6,
		},
	}

	data, _ := msg.Body.MarshalBinary()
	_, err := g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

func (g *Gateway) Open() (err error) {
	g.cm = &ipv4.ControlMessage{}
	g.conn, err = g.setupSocket()
	if err != nil {
		return fmt.Errorf("Error setting up socket: %w", err)
	}
	g.intervalTime = 125 * time.Second
	g.nonce = make([]byte, 4)
	_, err = rand.Read(g.nonce)
	if err != nil {
		return err
	}

	err = g.sendDiscovery()
	if err != nil {
		return fmt.Errorf("Error sending discovery: %w", err)
	}
	buffer := make([]byte, g.MTU)
	n, _, _, err := g.conn.ReadFrom(buffer)
	if err != nil {
		return fmt.Errorf("Error reading from connection: %w", err)
	}
	if amtMessageType := determineAMTmessageType(buffer[:]); amtMessageType != m.RelayAdvertisementType {
		return fmt.Errorf("Expected relay advertisement after discovery")
	}
	data := buffer[:n]

	relayAdvertisement := &m.RelayAdvertisementMessage{}
	err = relayAdvertisement.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("Failed to read advertisemnt: %w", err)
	}

	err = g.sendRequest()
	if err != nil {
		return fmt.Errorf("Error sending advertisement: %w", err)
	}

	n, _, _, err = g.conn.ReadFrom(buffer)
	if err != nil {
		return fmt.Errorf("Error reading from connection: %w", err)
	}
	if amtMessageType := determineAMTmessageType(buffer[:]); amtMessageType != m.MembershipQueryType {
		return fmt.Errorf("Expected membership query after request")
	}
	data = buffer[:n]
	if err = g.handleMembershipQuery(data); err != nil {
		return err
	}
	go func() {
		for {
			if g.leave {
				return
			}
			err = g.sendRequest()
			if err != nil {
				return
			}
			time.Sleep(time.Duration(float64(g.intervalTime) * 0.8))
		}
	}()

	return nil
}

func createIPv4MembershipReport(dstIP, srcIP net.IP, length uint16) ([]byte, error) {
	// Create the IPv4 layer
	packet := gopacket.NewSerializeBuffer()
	ipv4Layer := &layers.IPv4{
		Version:    4,
		IHL:        6,
		TOS:        0xc0,
		Length:     length, // Header length only
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
	err := gopacket.SerializeLayers(packet, gopacket.SerializeOptions{}, ipv4Layer)
	if err != nil {
		return nil, fmt.Errorf("Error serializing IPv4 layer: %w", err)
	}

	// Get the serialized bytes
	packetBytes := packet.Bytes()
	var optionsarray byte

	packetBytes = append(packetBytes, optionsarray)
	packetBytes = append(packetBytes, optionsarray)
	packetBytes = append(packetBytes, optionsarray)
	packetBytes = append(packetBytes, optionsarray)

	checksum := calculateChecksum(packetBytes)
	binary.BigEndian.PutUint16(packetBytes[10:], checksum)

	return packetBytes, err
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

func (g *Gateway) handleMembershipQuery(data []byte) error {
	membershipQuery, err := m.DecodeMembershipQueryMessage(data)
	if err != nil {
		return fmt.Errorf("Error in DecodeMembershipQueryMessage: %w", err)
	}
	if membershipQuery.EncapsulatedQuery[0]>>4 == 4 {
		p := gopacket.NewPacket(membershipQuery.EncapsulatedQuery, layers.LayerTypeIPv4, gopacket.NoCopy)
		igmp, ok := p.Layer(layers.LayerTypeIGMP).(*layers.IGMP)
		if !ok {
			return fmt.Errorf("Invalid IGMP")
		}
		switch igmp.Type {
		case layers.IGMPMembershipQuery:
			if igmp.IntervalTime > 0 {
				g.intervalTime = igmp.IntervalTime
			}
		default:
			return fmt.Errorf("Unexpected IGMP Type %v", igmp)
		}
	}
	if g.leave {
		err = g.sendTeardown(*membershipQuery)
		if err != nil {
			return fmt.Errorf("Error in sendTeardown: %w", err)
		}
		err = g.sendMembershipLeave(*membershipQuery)
		if err != nil {
			return fmt.Errorf("Error in sendMembershipUpdate: %w", err)
		}
		return g.conn.Close()
	} else {
		err = g.sendMembershipUpdate(*membershipQuery)
		if err != nil {
			return fmt.Errorf("Error in sendMembershipUpdate: %w", err)
		}
	}
	return nil
}
func (g *Gateway) Close() error {
	g.leave = true
	buffer := make([]byte, g.MTU)
	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		for {
			if err := g.sendRequest(); err != nil {
				errc <- fmt.Errorf("failed to send request: %w", err)
				return
			}
			n, _, _, err := g.conn.ReadFrom(buffer)
			if err != nil {
				errc <- fmt.Errorf("Error reading from connection: %w", err)
				return
			}
			amtMessageType := determineAMTmessageType(buffer[:])
			if amtMessageType == m.MembershipQueryType {
				errc <- g.handleMembershipQuery(buffer[:n])
				return
			}
		}
	}()
	select {
	case <-time.After(5 * time.Second):
	case err := <-errc:
		g.conn.Close()
		return err
	}
	return g.conn.Close()
}
