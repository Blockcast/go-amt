package amt

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/miekg/dns"
)

// DRIAD constants per RFC 8777
const (
	// AMTRELAY DNS record type (RFC 8777)
	DNSTypeAMTRELAY uint16 = 260

	// Default DNS timeout
	DefaultDNSDTimeout = 5 * time.Second

	// DRIAD domain suffix
	DRIADSuffix = "in-addr.arpa."
)

// DRIADConfig contains configuration for DRIAD discovery
type DRIADConfig struct {
	// SourceAddr is the multicast source address to discover relay for
	SourceAddr netip.Addr

	// DNSServers is a list of DNS servers to query (optional, uses system default if empty)
	DNSServers []string

	// Timeout for DNS queries
	Timeout time.Duration
}

// DefaultDRIADConfig returns a config with sensible defaults
func DefaultDRIADConfig(sourceAddr netip.Addr) DRIADConfig {
	return DRIADConfig{
		SourceAddr: sourceAddr,
		DNSServers: nil, // Use system default
		Timeout:    DefaultDNSDTimeout,
	}
}

// AMTRelayRecord represents a parsed AMTRELAY DNS record (RFC 8777)
type AMTRelayRecord struct {
	// Precedence indicates priority (lower = higher priority)
	Precedence uint8

	// DFlag indicates if the relay supports DRIAD discovery itself
	DFlag bool

	// RelayType indicates the type of relay address
	// 0 = reserved, 1 = IPv4, 2 = IPv6, 3 = domain name
	RelayType uint8

	// RelayAddr is the relay address (IP or domain name)
	RelayAddr string

	// ResolvedAddr is the resolved IP address (if RelayType is domain name)
	ResolvedAddr netip.Addr
}

// DiscoverRelay performs DRIAD discovery for the given source address
// Returns the discovered relay address and port
func DiscoverRelay(ctx context.Context, config DRIADConfig) (*net.UDPAddr, error) {
	if !config.SourceAddr.IsValid() {
		return nil, fmt.Errorf("invalid source address")
	}

	// Build DRIAD query name
	queryName, err := BuildDRIADQuery(config.SourceAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to build DRIAD query: %w", err)
	}

	// Perform DNS query
	records, err := queryAMTRelayRecords(ctx, queryName, config)
	if err != nil {
		return nil, fmt.Errorf("DRIAD DNS query failed: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no AMTRELAY records found for %s", config.SourceAddr)
	}

	// Select best relay (lowest precedence)
	var bestRecord *AMTRelayRecord
	for i := range records {
		if bestRecord == nil || records[i].Precedence < bestRecord.Precedence {
			bestRecord = &records[i]
		}
	}

	// Resolve relay address if needed
	relayAddr, err := resolveRelayAddr(ctx, bestRecord, config)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve relay address: %w", err)
	}

	return &net.UDPAddr{
		IP:   relayAddr.AsSlice(),
		Port: m.DefaultPort,
	}, nil
}

// BuildDRIADQuery builds the DNS query name for DRIAD discovery (RFC 8777)
// For IPv4 source 192.0.2.1, returns: 1.2.0.192.in-addr.arpa.
// For IPv6 source, returns: nibble-reversed format in ip6.arpa.
func BuildDRIADQuery(sourceAddr netip.Addr) (string, error) {
	if !sourceAddr.IsValid() {
		return "", fmt.Errorf("invalid source address")
	}

	if sourceAddr.Is4() {
		// IPv4: reverse octets
		ip4 := sourceAddr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.",
			ip4[3], ip4[2], ip4[1], ip4[0]), nil
	}

	// IPv6: reverse nibbles
	ip6 := sourceAddr.As16()
	var parts []string
	for i := 15; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", ip6[i]&0x0f))
		parts = append(parts, fmt.Sprintf("%x", ip6[i]>>4))
	}
	return strings.Join(parts, ".") + ".ip6.arpa.", nil
}

// queryAMTRelayRecords queries DNS for AMTRELAY records
func queryAMTRelayRecords(ctx context.Context, queryName string, config DRIADConfig) ([]AMTRelayRecord, error) {
	c := new(dns.Client)
	c.Timeout = config.Timeout

	msg := new(dns.Msg)
	msg.SetQuestion(queryName, DNSTypeAMTRELAY)
	msg.RecursionDesired = true

	// Get DNS server to use
	dnsServer := getDefaultDNSServer(config.DNSServers)

	// Query with context
	var resp *dns.Msg
	var err error

	done := make(chan struct{})
	go func() {
		resp, _, err = c.Exchange(msg, dnsServer)
		close(done)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		if err != nil {
			return nil, err
		}
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		if resp != nil {
			return nil, fmt.Errorf("DNS query failed with rcode: %s", dns.RcodeToString[resp.Rcode])
		}
		return nil, fmt.Errorf("DNS query returned nil response")
	}

	// Parse AMTRELAY records from answer section
	var records []AMTRelayRecord
	for _, rr := range resp.Answer {
		record, ok := parseAMTRelayRR(rr)
		if ok {
			records = append(records, record)
		}
	}

	return records, nil
}

// parseAMTRelayRR parses an AMTRELAY resource record
// RDATA format (RFC 8777):
//   - Precedence: 1 byte
//   - D flag + Type: 1 byte (D flag in high bit, type in low 7 bits)
//   - Relay: variable (depends on type)
func parseAMTRelayRR(rr dns.RR) (AMTRelayRecord, bool) {
	// Check if it's an unknown RR type (since miekg/dns may not have AMTRELAY built-in)
	if rr.Header().Rrtype != DNSTypeAMTRELAY {
		return AMTRelayRecord{}, false
	}

	var record AMTRelayRecord

	// Try to get the raw RDATA
	// The miekg/dns library represents unknown types as RFC3597 format
	switch v := rr.(type) {
	case *dns.RFC3597:
		if len(v.Rdata) < 2 {
			return AMTRelayRecord{}, false
		}
		// Parse the hex-encoded RDATA
		rdata, err := parseRFC3597Rdata(v.Rdata)
		if err != nil || len(rdata) < 2 {
			return AMTRelayRecord{}, false
		}

		record.Precedence = rdata[0]
		record.DFlag = (rdata[1] & 0x80) != 0
		record.RelayType = rdata[1] & 0x7F

		switch record.RelayType {
		case 1: // IPv4
			if len(rdata) < 6 {
				return AMTRelayRecord{}, false
			}
			ip := netip.AddrFrom4([4]byte{rdata[2], rdata[3], rdata[4], rdata[5]})
			record.RelayAddr = ip.String()
			record.ResolvedAddr = ip

		case 2: // IPv6
			if len(rdata) < 18 {
				return AMTRelayRecord{}, false
			}
			var ip6 [16]byte
			copy(ip6[:], rdata[2:18])
			ip := netip.AddrFrom16(ip6)
			record.RelayAddr = ip.String()
			record.ResolvedAddr = ip

		case 3: // Domain name
			if len(rdata) < 3 {
				return AMTRelayRecord{}, false
			}
			// Parse DNS name from RDATA
			name, _, ok := parseDNSName(rdata[2:])
			if !ok {
				return AMTRelayRecord{}, false
			}
			record.RelayAddr = name

		default:
			return AMTRelayRecord{}, false
		}

		return record, true
	}

	return AMTRelayRecord{}, false
}

// parseRFC3597Rdata parses RFC 3597 hex-encoded RDATA
func parseRFC3597Rdata(s string) ([]byte, error) {
	// RFC 3597 format: \# <length> <hex>
	// miekg/dns stores just the hex part in Rdata
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return nil, nil
	}

	// Remove any whitespace
	s = strings.ReplaceAll(s, " ", "")

	// Convert hex to bytes
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex length")
	}

	data := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		_, err := fmt.Sscanf(s[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		data[i/2] = b
	}

	return data, nil
}

// parseDNSName parses a DNS name from wire format
func parseDNSName(data []byte) (string, int, bool) {
	var parts []string
	offset := 0

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		if length > 63 || offset+1+length > len(data) {
			return "", 0, false
		}
		parts = append(parts, string(data[offset+1:offset+1+length]))
		offset += 1 + length
	}

	return strings.Join(parts, ".") + ".", offset, true
}

// resolveRelayAddr resolves the relay address to an IP
func resolveRelayAddr(ctx context.Context, record *AMTRelayRecord, config DRIADConfig) (netip.Addr, error) {
	if record.ResolvedAddr.IsValid() {
		return record.ResolvedAddr, nil
	}

	// Need to resolve domain name
	if record.RelayType != 3 {
		return netip.Addr{}, fmt.Errorf("unexpected relay type %d without resolved address", record.RelayType)
	}

	// Use standard DNS resolution
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", record.RelayAddr)
	if err != nil {
		return netip.Addr{}, err
	}

	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no IP addresses found for %s", record.RelayAddr)
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), nil
		}
	}

	// Fall back to IPv6
	if len(ips[0]) == 16 {
		var ip6 [16]byte
		copy(ip6[:], ips[0])
		return netip.AddrFrom16(ip6), nil
	}

	return netip.Addr{}, fmt.Errorf("failed to parse resolved IP")
}

// getDefaultDNSServer returns a DNS server to use
func getDefaultDNSServer(configured []string) string {
	if len(configured) > 0 {
		server := configured[0]
		if !strings.Contains(server, ":") {
			server += ":53"
		}
		return server
	}

	// Try to get system DNS server
	// On most systems, we can use the local resolver
	return "127.0.0.53:53" // systemd-resolved default
}

// ParseAMTRelayRdata parses raw AMTRELAY RDATA bytes
func ParseAMTRelayRdata(rdata []byte) (*AMTRelayRecord, error) {
	if len(rdata) < 2 {
		return nil, fmt.Errorf("AMTRELAY RDATA too short")
	}

	record := &AMTRelayRecord{
		Precedence: rdata[0],
		DFlag:      (rdata[1] & 0x80) != 0,
		RelayType:  rdata[1] & 0x7F,
	}

	switch record.RelayType {
	case 0:
		// Empty relay - indicates no relay available
		return record, nil

	case 1: // IPv4
		if len(rdata) < 6 {
			return nil, fmt.Errorf("AMTRELAY IPv4 RDATA too short")
		}
		ip := netip.AddrFrom4([4]byte{rdata[2], rdata[3], rdata[4], rdata[5]})
		record.RelayAddr = ip.String()
		record.ResolvedAddr = ip

	case 2: // IPv6
		if len(rdata) < 18 {
			return nil, fmt.Errorf("AMTRELAY IPv6 RDATA too short")
		}
		var ip6 [16]byte
		copy(ip6[:], rdata[2:18])
		ip := netip.AddrFrom16(ip6)
		record.RelayAddr = ip.String()
		record.ResolvedAddr = ip

	case 3: // Domain name
		if len(rdata) < 3 {
			return nil, fmt.Errorf("AMTRELAY domain RDATA too short")
		}
		name, _, ok := parseDNSName(rdata[2:])
		if !ok {
			return nil, fmt.Errorf("failed to parse domain name from AMTRELAY RDATA")
		}
		record.RelayAddr = name

	default:
		return nil, fmt.Errorf("unknown AMTRELAY relay type: %d", record.RelayType)
	}

	return record, nil
}

// BuildAMTRelayRdata builds AMTRELAY RDATA for a relay address
func BuildAMTRelayRdata(precedence uint8, dFlag bool, relayAddr netip.Addr) []byte {
	var rdata []byte

	// Precedence byte
	rdata = append(rdata, precedence)

	// D flag + Type byte
	var typeFlag uint8
	if dFlag {
		typeFlag = 0x80
	}

	if relayAddr.Is4() {
		typeFlag |= 1 // IPv4
		rdata = append(rdata, typeFlag)
		ip4 := relayAddr.As4()
		rdata = append(rdata, ip4[:]...)
	} else {
		typeFlag |= 2 // IPv6
		rdata = append(rdata, typeFlag)
		ip6 := relayAddr.As16()
		rdata = append(rdata, ip6[:]...)
	}

	return rdata
}

// Placeholder for binary import usage
var _ = binary.BigEndian
