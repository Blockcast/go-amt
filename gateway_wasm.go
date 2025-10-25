//go:build js && wasm

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

// GatewayWASM is a WASM-compatible AMT gateway using ChromeUDPConn
type GatewayWASM struct {
	conn         *ChromeUDPConn
	nonce        []byte
	RelayAddr    *net.UDPAddr
	SourceAddr   net.IP
	GroupAddr    net.IP
	MTU          int
	intervalTime time.Duration
	lastData     time.Time
	leave        bool

	// State for membership query handling
	requestNonce []byte
	responseMac  []byte
	gatewayIP    net.IP
	gatewayPort  uint16
}

// NewGatewayWASM creates a new WASM AMT gateway
func NewGatewayWASM(conn *ChromeUDPConn, relayAddr *net.UDPAddr, sourceAddr, groupAddr net.IP) *GatewayWASM {
	if len(sourceAddr) == 0 {
		sourceAddr = net.IPv4zero
	}

	return &GatewayWASM{
		conn:         conn,
		RelayAddr:    relayAddr,
		SourceAddr:   sourceAddr,
		GroupAddr:    groupAddr,
		MTU:          1500,
		intervalTime: 10 * time.Second,
		lastData:     time.Now(),
	}
}

// generateNonce creates a random 4-byte nonce
func generateNonce() []byte {
	nonce := make([]byte, 4)
	rand.Read(nonce)
	// Ensure non-zero
	for i, b := range nonce {
		if b == 0 {
			nonce[i] = 1
		}
	}
	return nonce
}

// SendDiscovery sends an AMT Discovery message to locate a relay
func (g *GatewayWASM) SendDiscovery() error {
	if g.nonce == nil {
		g.nonce = generateNonce()
	}

	msg := createDiscoveryMessage(g.nonce)
	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal discovery: %w", err)
	}

	_, err = g.conn.WriteTo(data, g.RelayAddr)
	return err
}

// SendRequest sends an AMT Request message to solicit a Membership Query
func (g *GatewayWASM) SendRequest() error {
	if g.requestNonce == nil {
		g.requestNonce = generateNonce()
	}

	msg := createRequestMessage(g.requestNonce)
	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	_, err = g.conn.WriteTo(data, g.RelayAddr)
	return err
}

// SendMembershipUpdate sends an IGMP membership update (join/leave)
func (g *GatewayWASM) SendMembershipUpdate(join bool) error {
	if g.requestNonce == nil || g.responseMac == nil {
		return fmt.Errorf("must receive Membership Query before sending Update")
	}

	msg := createMembershipUpdate(g.GroupAddr, g.SourceAddr, join, g.requestNonce, g.responseMac)
	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal membership update: %w", err)
	}

	_, err = g.conn.WriteTo(data, g.RelayAddr)
	return err
}

// SendTeardown sends an AMT Teardown message
func (g *GatewayWASM) SendTeardown() error {
	if g.requestNonce == nil || g.responseMac == nil {
		return fmt.Errorf("cannot send teardown without prior Query")
	}

	msg := createTeardownMessage(g.requestNonce, g.responseMac, g.gatewayIP, g.gatewayPort)
	data, err := msg.Body.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal teardown: %w", err)
	}

	_, err = g.conn.WriteTo(data, g.RelayAddr)
	return err
}

// ReadPacket reads and processes one AMT message
// Returns the multicast payload if it's a Data message, nil otherwise
func (g *GatewayWASM) ReadPacket(buf []byte) (payload []byte, sourceIP net.IP, err error) {
	n, _, err := g.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}

	if n == 0 {
		return nil, nil, nil
	}

	amtMessageType := determineAMTmessageType(buf[:n])

	switch amtMessageType {
	case m.RelayAdvertisementType:
		err = g.handleRelayAdvertisement(buf[:n])
		return nil, nil, err

	case m.MembershipQueryType:
		err = g.handleMembershipQuery(buf[:n])
		return nil, nil, err

	case m.MulticastDataType:
		g.lastData = time.Now()
		payload, sourceIP, err = g.decapsulateMulticastData(buf[:n])
		return payload, sourceIP, err

	default:
		return nil, nil, fmt.Errorf("unknown AMT message type: %d", amtMessageType)
	}
}

// handleRelayAdvertisement processes an AMT Relay Advertisement message
func (g *GatewayWASM) handleRelayAdvertisement(data []byte) error {
	relayAdvertisement := &m.RelayAdvertisementMessage{}
	err := relayAdvertisement.UnmarshalBinary(data)
	if err != nil {
		return fmt.Errorf("failed to read advertisement: %w", err)
	}

	// Verify nonce matches
	if g.nonce != nil {
		nonce := [4]byte(g.nonce)
		if relayAdvertisement.Nonce != nonce {
			return fmt.Errorf("advertisement nonce mismatch")
		}
	}

	// Advertisement received, can now send Request
	return nil
}

// handleMembershipQuery processes an AMT Membership Query message
func (g *GatewayWASM) handleMembershipQuery(data []byte) error {
	membershipQuery, err := m.DecodeMembershipQueryMessage(data)
	if err != nil {
		return fmt.Errorf("decode membership query: %w", err)
	}

	// Verify request nonce matches
	if g.requestNonce != nil {
		reqNonce := [4]byte(g.requestNonce)
		if membershipQuery.Nonce != reqNonce {
			return fmt.Errorf("query nonce mismatch")
		}
	}

	// Save response MAC and nonce for future updates
	g.responseMac = membershipQuery.ResponseMAC[:]
	g.requestNonce = membershipQuery.Nonce[:]

	// Save gateway address if provided (for teardown)
	if membershipQuery.HasGatewayAddress {
		g.gatewayPort = membershipQuery.GatewayPortNumber
		// Gateway IP is in last 16 bytes, extract IPv4 from last 4 bytes
		g.gatewayIP = net.IP(membershipQuery.GatewayIPAddress[12:16])
	}

	// Extract IGMP query interval if present
	if len(membershipQuery.EncapsulatedQuery) > 0 && membershipQuery.EncapsulatedQuery[0]>>4 == 4 {
		p := gopacket.NewPacket(membershipQuery.EncapsulatedQuery, layers.LayerTypeIPv4, gopacket.NoCopy)
		igmp, ok := p.Layer(layers.LayerTypeIGMP).(*layers.IGMP)
		if ok && igmp.Type == layers.IGMPMembershipQuery {
			if igmp.IntervalTime > 0 {
				g.intervalTime = igmp.IntervalTime
			}
		}
	}

	// Automatically send IGMP Join after receiving Query
	// This is necessary because the ReadFrom loop filters out control messages
	if err := g.SendMembershipUpdate(true); err != nil {
		return fmt.Errorf("auto-send join: %w", err)
	}

	return nil
}

// decapsulateMulticastData extracts the multicast payload from AMT Data message
func (g *GatewayWASM) decapsulateMulticastData(data []byte) (payload []byte, sourceIP net.IP, err error) {
	if len(data) < m.DataMsgHdrLen {
		return nil, nil, fmt.Errorf("data message too short: %d bytes", len(data))
	}

	// Skip AMT header (2 bytes: type + reserved)
	ipPacket := data[m.DataMsgHdrLen:]

	// Parse encapsulated IP packet
	p := gopacket.NewPacket(ipPacket, layers.LayerTypeIPv4, gopacket.NoCopy)

	ipHdr := p.NetworkLayer().(*layers.IPv4)
	if ipHdr == nil {
		return nil, nil, fmt.Errorf("no IPv4 header in multicast data")
	}

	// Verify destination matches our group
	if !ipHdr.DstIP.Equal(g.GroupAddr) {
		return nil, nil, fmt.Errorf("destination %s doesn't match group %s", ipHdr.DstIP, g.GroupAddr)
	}

	// Verify source matches if we're doing SSM
	if !g.SourceAddr.IsUnspecified() && !ipHdr.SrcIP.Equal(g.SourceAddr) {
		return nil, nil, fmt.Errorf("source %s doesn't match filter %s", ipHdr.SrcIP, g.SourceAddr)
	}

	// Extract UDP layer
	udpHdr, ok := p.TransportLayer().(*layers.UDP)
	if !ok || udpHdr == nil {
		return nil, nil, fmt.Errorf("no UDP layer in multicast data")
	}

	// Extract application payload
	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, nil, fmt.Errorf("no application payload")
	}

	return appLayer.Payload(), ipHdr.SrcIP, nil
}

// Close sends teardown and closes the connection
func (g *GatewayWASM) Close() error {
	g.leave = true

	// Send teardown if we have the necessary state
	if g.requestNonce != nil && g.responseMac != nil {
		_ = g.SendTeardown() // Best effort
	}

	return g.conn.Close()
}

// Helper functions to create AMT messages

func createDiscoveryMessage(nonce []byte) m.Message {
	return m.Message{
		Version: m.Version,
		Type:    m.RelayDiscoveryType,
		Body:    &m.DiscoveryMessage{Nonce: [4]byte(nonce)},
	}
}

func createRequestMessage(nonce []byte) m.Message {
	return m.Message{
		Version: m.Version,
		Type:    m.RequestType,
		Body:    &m.RequestMessage{Nonce: [4]byte(nonce), Reserved: uint16(0)},
	}
}

func createMembershipUpdate(groupIP, sourceIP net.IP, join bool, nonce, mac []byte) m.Message {
	multicast := groupIP.To4()

	// Create IGMPv3 group record
	var recordType uint8
	var sources [][4]byte

	if join {
		if sourceIP.IsUnspecified() {
			// ASM (*,G): MODE_IS_EXCLUDE with no sources
			recordType = m.IGMPv3ModeIsExclude
			sources = [][4]byte{}
		} else {
			// SSM (S,G): MODE_IS_INCLUDE with source
			recordType = m.IGMPv3ModeIsInclude
			src := sourceIP.To4()
			sources = [][4]byte{{src[0], src[1], src[2], src[3]}}
		}
	} else {
		// Leave: CHANGE_TO_INCLUDE_MODE with empty sources
		recordType = m.IGMPv3ChangeToIncludeMode
		sources = [][4]byte{}
	}

	groupRecord := m.IGMPv3GroupRecord{
		RecordType: recordType,
		AuxDataLen: 0,
		NumSources: uint16(len(sources)),
		Multicast:  [4]byte{multicast[0], multicast[1], multicast[2], multicast[3]},
		Sources:    sources,
	}

	membershipReport := m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport,
		NumGroupRecords: 1,
		GroupRecords:    []m.IGMPv3GroupRecord{groupRecord},
	}

	// Encapsulate in IPv4 packet
	length := uint16(40)
	if len(sources) > 0 {
		length += uint16(len(sources) * 4)
	}

	encapsulated, err := createIPv4MembershipReport(groupIP, sourceIP, length)
	if err != nil {
		// Return empty message on error (will be caught by caller)
		return m.Message{}
	}

	membershipReportBinary, err := membershipReport.MarshalBinary()
	if err != nil {
		return m.Message{}
	}

	encapsulated = append(encapsulated, membershipReportBinary...)

	// ResponseMAC is net.HardwareAddr ([]byte)
	return m.Message{
		Version: m.Version,
		Type:    m.MembershipUpdateType,
		Body: &m.MembershipUpdateMessage{
			ResponseMAC:  net.HardwareAddr(mac[:6]),
			Nonce:        [4]byte(nonce),
			Encapsulated: encapsulated,
		},
	}
}

func createTeardownMessage(nonce, mac []byte, gatewayIP net.IP, gatewayPort uint16) m.Message {
	var ipv6 = make([]byte, 16)
	if len(gatewayIP) >= 4 {
		copy(ipv6[12:], gatewayIP.To4())
	}

	// ResponseMAC in teardown is []byte
	return m.Message{
		Version: m.Version,
		Type:    m.TeardownType,
		Body: &m.MembershipTeardownMessage{
			ResponseMAC: mac[:6],
			Nonce:       [4]byte(nonce),
			GWPortNum:   gatewayPort,
			GWIPAddr:    ipv6,
		},
	}
}

func createIPv4MembershipReport(dstIP, srcIP net.IP, length uint16) ([]byte, error) {
	packet := gopacket.NewSerializeBuffer()
	ipv4Layer := &layers.IPv4{
		Version:    4,
		IHL:        6,
		TOS:        0xc0,
		Length:     length,
		Id:         1,
		Flags:      0,
		FragOffset: 0,
		TTL:        1,
		Protocol:   2, // IGMP
		Checksum:   0,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Options:    []layers.IPv4Option{},
	}

	err := gopacket.SerializeLayers(packet, gopacket.SerializeOptions{}, ipv4Layer)
	if err != nil {
		return nil, fmt.Errorf("serialize IPv4: %w", err)
	}

	packetBytes := packet.Bytes()

	// Add router alert option (4 bytes)
	var optionsarray byte
	packetBytes = append(packetBytes, optionsarray, optionsarray, optionsarray, optionsarray)

	// Calculate and set checksum
	checksum := calculateChecksum(packetBytes)
	binary.BigEndian.PutUint16(packetBytes[10:], checksum)

	return packetBytes, nil
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
	if len(data) == 0 {
		return 0
	}
	return m.MessageType(data[0])
}
