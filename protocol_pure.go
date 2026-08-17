package amt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	RegisterProtocol(ProtocolTypePureGo, func() (AMTProtocol, error) {
		return NewPureGoProtocol()
	})
}

// PureGoProtocol implements AMTProtocol in pure Go.
// Works on all platforms including iOS, Android, and WASM.
type PureGoProtocol struct {
	relayAddr   string
	relayPort   uint16
	state       AMTState
	nonce       [4]byte
	responseMAC []byte
	mu          sync.Mutex
}

// NewPureGoProtocol creates a new pure Go protocol instance
func NewPureGoProtocol() (*PureGoProtocol, error) {
	return &PureGoProtocol{
		state: AMTStateIdle,
	}, nil
}

func (p *PureGoProtocol) Initialize(relayAddr string, relayPort uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.relayAddr = relayAddr
	p.relayPort = relayPort
	if p.relayPort == 0 {
		p.relayPort = m.DefaultPort
	}
	p.state = AMTStateIdle
	p.responseMAC = nil

	return nil
}

func (p *PureGoProtocol) CreateDiscoveryMessage() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Generate random nonce
	if _, err := rand.Read(p.nonce[:]); err != nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "failed to generate nonce",
			Cause:   err,
		}
	}

	msg := &m.DiscoveryMessage{
		Nonce: p.nonce,
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "failed to marshal discovery message",
			Cause:   err,
		}
	}

	p.state = AMTStateDiscovering
	return data, nil
}

func (p *PureGoProtocol) HandleAdvertisement(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(data) < 8 {
		return &ProtocolError{
			State:   p.state,
			Message: "advertisement data too short",
		}
	}

	var adv m.RelayAdvertisementMessage
	if err := adv.UnmarshalBinary(data); err != nil {
		return &ProtocolError{
			State:   p.state,
			Message: "failed to unmarshal advertisement",
			Cause:   err,
		}
	}

	// Verify nonce matches
	if adv.Nonce != p.nonce {
		return &ProtocolError{
			State:   p.state,
			Message: "advertisement nonce mismatch",
		}
	}

	return nil
}

func (p *PureGoProtocol) CreateRequestMessage(preferNative bool) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	msg := &m.RequestMessage{
		Protocol: m.IGMPv3, // IPv4 IGMP
		Nonce:    p.nonce,
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "failed to marshal request message",
			Cause:   err,
		}
	}

	p.state = AMTStateRequesting
	return data, nil
}

func (p *PureGoProtocol) HandleQuery(data []byte) ([]byte, time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	mqm, err := m.DecodeMembershipQueryMessage(data)
	if err != nil {
		return nil, 0, &ProtocolError{
			State:   p.state,
			Message: "failed to decode membership query",
			Cause:   err,
		}
	}

	// Store response MAC and nonce for later use
	p.responseMAC = mqm.ResponseMAC
	p.nonce = mqm.Nonce

	// Parse IGMP query to get interval time
	intervalTime := 10 * time.Second // default
	if len(mqm.EncapsulatedQuery) > 0 && mqm.EncapsulatedQuery[0]>>4 == 4 {
		pkt := gopacket.NewPacket(mqm.EncapsulatedQuery, layers.LayerTypeIPv4, gopacket.NoCopy)
		igmp, ok := pkt.Layer(layers.LayerTypeIGMP).(*layers.IGMP)
		if ok && igmp.Type == layers.IGMPMembershipQuery && igmp.IntervalTime > 0 {
			intervalTime = igmp.IntervalTime
		}
	}

	p.state = AMTStateQuerying
	return mqm.EncapsulatedQuery, intervalTime, nil
}

func (p *PureGoProtocol) CreateIGMPJoinReport(source, group netip.Addr) ([]byte, error) {
	return p.CreateIGMPJoinReportMulti(source, []netip.Addr{group})
}

func (p *PureGoProtocol) CreateIGMPJoinReportMulti(source netip.Addr, groups []netip.Addr) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(groups) == 0 {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "no groups specified",
		}
	}

	// netip.Addr.As4 panics on a non-IPv4 address. This builder runs from the
	// batched-membership time.AfterFunc goroutine, where a panic is unrecoverable
	// by any caller, so validate before converting.
	if !source.Is4() && !source.Is4In6() {
		return nil, &ProtocolError{
			State:   p.state,
			Message: fmt.Sprintf("source address must be IPv4: %s", source),
		}
	}

	// Build IGMPv3 Membership Report
	groupRecords := make([]m.IGMPv3GroupRecord, len(groups))
	for i, g := range groups {
		if !g.Is4() && !g.Is4In6() {
			return nil, &ProtocolError{
				State:   p.state,
				Message: fmt.Sprintf("group address must be IPv4: %s", g),
			}
		}
		g4 := g.As4()
		s4 := source.As4()
		groupRecords[i] = m.IGMPv3GroupRecord{
			RecordType: m.IGMPv3AllowNewSources, // ALLOW_NEW_SOURCES for SSM join
			AuxDataLen: 0,
			NumSources: 1,
			Multicast:  g4,
			Sources:    [][4]byte{s4},
		}
	}

	report := &m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport, // 0x22
		Reserved1:       0,
		Checksum:        0, // Will be calculated
		Reserved2:       0,
		NumGroupRecords: uint16(len(groupRecords)),
		GroupRecords:    groupRecords,
	}

	igmpData, err := report.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "failed to marshal IGMP report",
			Cause:   err,
		}
	}

	// Encapsulate in IP header
	ipHeader := buildIGMPIPHeader(igmpData)
	return append(ipHeader, igmpData...), nil
}

func (p *PureGoProtocol) CreateIGMPLeaveReport(source, group netip.Addr) ([]byte, error) {
	return buildIGMPLeaveReport(source, group, p.State())
}

func (p *PureGoProtocol) CreateIGMPSourceLeaveReport(source, group netip.Addr) ([]byte, error) {
	return buildIGMPSourceLeaveReport(source, group, p.State())
}

func buildIGMPLeaveReport(source, group netip.Addr, state AMTState) ([]byte, error) {
	if !source.Is4() {
		return nil, fmt.Errorf("source address must be IPv4: %s", source)
	}
	if !group.Is4() {
		return nil, fmt.Errorf("group address must be IPv4: %s", group)
	}

	report := &m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport,
		NumGroupRecords: 1,
		GroupRecords: []m.IGMPv3GroupRecord{{
			// CHANGE_TO_INCLUDE_MODE with no sources is the IGMPv3 leave form.
			RecordType: m.IGMPv3ChangeToIncludeMode,
			Multicast:  group.As4(),
		}},
	}
	igmpData, err := report.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{State: state, Message: "failed to marshal IGMP leave report", Cause: err}
	}
	return append(buildIGMPIPHeader(igmpData), igmpData...), nil
}

func buildIGMPSourceLeaveReport(source, group netip.Addr, state AMTState) ([]byte, error) {
	if !source.Is4() {
		return nil, fmt.Errorf("source address must be IPv4: %s", source)
	}
	if !group.Is4() {
		return nil, fmt.Errorf("group address must be IPv4: %s", group)
	}

	report := &m.IGMPv3MembershipReport{
		Type:            m.IGMPv3TypeMembershipReport,
		NumGroupRecords: 1,
		GroupRecords: []m.IGMPv3GroupRecord{{
			RecordType: m.IGMPv3BlockOldSources,
			NumSources: 1,
			Multicast:  group.As4(),
			Sources:    [][4]byte{source.As4()},
		}},
	}
	igmpData, err := report.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{State: state, Message: "failed to marshal source-specific leave report", Cause: err}
	}
	return append(buildIGMPIPHeader(igmpData), igmpData...), nil
}

// igmpRouterAlert is the IPv4 Router Alert option (RFC 2113): option type 0x94,
// length 4, value 0. RFC 3376 requires it on every IGMPv3 message, and relays
// that enforce it drop reports that omit it. Being 4 bytes long, it also keeps
// the header 4-byte aligned with no separate padding.
var igmpRouterAlert = [4]byte{0x94, 0x04, 0x00, 0x00}

// igmpIPHeaderLen is the fixed 20-byte IPv4 header plus the Router Alert option.
const igmpIPHeaderLen = 20 + len(igmpRouterAlert)

// buildIGMPIPHeader builds the IPv4 header that carries an IGMPv3 message.
//
// Every IGMPv3 report this package emits is encapsulated here -- joins and
// leaves, pure-Go and CGO alike -- so the Router Alert option cannot be present
// on one path and missing on another. It briefly was: the join path and the
// leave path each had their own copy of this function, and only the join copy
// was given the option. Keep it that way; add report types, not headers.
//
// The header length, the IHL nibble, and the total-length field are all derived
// from igmpIPHeaderLen so they cannot disagree with each other or with the
// allocation.
func buildIGMPIPHeader(payload []byte) []byte {
	header := make([]byte, igmpIPHeaderLen)
	header[0] = 0x40 | byte(igmpIPHeaderLen/4) // Version (4) + IHL (6)
	header[1] = 0xc0                           // DSCP + ECN (0xc0 for IGMP)
	binary.BigEndian.PutUint16(header[2:4], uint16(igmpIPHeaderLen+len(payload)))
	binary.BigEndian.PutUint16(header[4:6], 0)   // Identification
	binary.BigEndian.PutUint16(header[6:8], 0)   // Flags + Fragment Offset
	header[8] = 1                                // TTL = 1 for IGMP
	header[9] = 2                                // Protocol = IGMP
	binary.BigEndian.PutUint16(header[10:12], 0) // Checksum (calculated below)

	// Source: 0.0.0.0 (will be filled by kernel/relay)
	copy(header[12:16], net.IPv4zero.To4())

	// Destination: 224.0.0.22 (IGMP report address)
	copy(header[16:20], net.ParseIP("224.0.0.22").To4())

	copy(header[20:], igmpRouterAlert[:])

	// Checksum covers the whole header, options included, and so must be
	// computed after the option is in place.
	binary.BigEndian.PutUint16(header[10:12], ipChecksum(header))

	return header
}

// ipChecksum is the standard RFC 1071 one's-complement checksum over header.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (p *PureGoProtocol) calculateIPChecksum(header []byte) uint16 {
	return ipChecksum(header)
}

func (p *PureGoProtocol) CreateMembershipUpdate(igmpReport []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.responseMAC) == 0 {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "no response MAC available (call HandleQuery first)",
		}
	}

	msg := &m.MembershipUpdateMessage{
		ResponseMAC:  p.responseMAC,
		Nonce:        p.nonce,
		Encapsulated: igmpReport,
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "failed to marshal membership update",
			Cause:   err,
		}
	}

	p.state = AMTStateActive
	return data, nil
}

func (p *PureGoProtocol) CreateTeardownMessage() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.responseMAC) == 0 {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "no response MAC available",
		}
	}

	msg := &m.MembershipTeardownMessage{
		ResponseMAC: p.responseMAC,
		Nonce:       p.nonce,
		GWPortNum:   0,
		GWIPAddr:    make([]byte, 16), // IPv6-compatible zeros
	}

	data, err := msg.MarshalBinary()
	if err != nil {
		return nil, &ProtocolError{
			State:   p.state,
			Message: "failed to marshal teardown message",
			Cause:   err,
		}
	}

	return data, nil
}

func (p *PureGoProtocol) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = AMTStateIdle
	p.responseMAC = nil
	// Keep nonce for potential re-discovery
}

func (p *PureGoProtocol) State() AMTState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func (p *PureGoProtocol) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = AMTStateClosed
}

// PureGoVersion returns version info for the pure Go implementation
func PureGoVersion() string {
	return fmt.Sprintf("pure-go-amt/1.0.0 (protocol-version=%d)", m.Version)
}
