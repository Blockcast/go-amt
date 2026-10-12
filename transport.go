package amt

import (
	"context"
	"log/slog"
	"net"
	"time"

	m "github.com/blockcast/go-amt/messages"
)

// Transport abstracts the underlying network transport for AMT relay communication.
// UDPTransport is the primary implementation for all platforms.
type Transport interface {
	// Open initializes the transport connection
	Open(ctx context.Context) error

	// Close shuts down the transport
	Close() error

	// Send sends data to the relay
	Send(data []byte) error

	// Receive reads data from the relay with optional deadline
	// Returns the data, source address (if applicable), and any error
	Receive(buf []byte) (n int, addr net.Addr, err error)

	// SetReadDeadline sets the deadline for receive operations
	SetReadDeadline(t time.Time) error

	// LocalAddr returns the local address if applicable
	LocalAddr() net.Addr

	// RelayAddr returns the relay address currently being sent to. Before an
	// advertisement is adopted this is the configured (discovery) address.
	RelayAddr() net.Addr

	// AdoptAdvertisedRelay points subsequent sends at the relay named in a
	// Relay Advertisement, when it names one this transport can plausibly
	// reach. Takes the raw advertisement, already validated by the protocol.
	// A no-op when the advertisement is unusable; see advertisedRelayDest.
	AdoptAdvertisedRelay(data []byte)

	// SupportsTimestamp returns true if the transport supports packet timestamps
	SupportsTimestamp() bool

	// Type returns the transport type for logging/debugging
	Type() TransportType
}

// TransportType identifies the transport implementation
type TransportType string

const (
	TransportTypeUDP TransportType = "udp"
)

// TransportConfig contains configuration for UDP transport
type TransportConfig struct {
	// RelayAddr is the AMT relay address
	RelayAddr net.UDPAddr

	// Timeout bounds the AMT relay handshake, retransmissions included. Zero
	// selects the default, 10 s. ManagedConn sets it from
	// RelayHandshakeTimeout.
	Timeout time.Duration

	// EnableTimestamp enables packet timestamping (if supported)
	EnableTimestamp bool

	// MTU is the maximum transmission unit
	MTU int

	// RcvBufBytes and SndBufBytes, if > 0, are applied to the relay UDP socket
	// via applyForcedBuffers (SO_RCVBUFFORCE/SO_SNDBUFFORCE on Linux,
	// SO_RCVBUF/SO_SNDBUF on Darwin); see MulticastConn / Gateway for semantics.
	RcvBufBytes int
	SndBufBytes int
}

// DefaultTransportConfig returns a config with sensible defaults
func DefaultTransportConfig(relayAddr net.UDPAddr) TransportConfig {
	return TransportConfig{
		RelayAddr:       relayAddr,
		Timeout:         10 * time.Second,
		EnableTimestamp: true,
		MTU:             1500,
	}
}

// transportRegistry holds registered transport factories
var transportRegistry = make(map[TransportType]func(TransportConfig) (Transport, error))

// RegisterTransport registers a transport factory
func RegisterTransport(typ TransportType, factory func(TransportConfig) (Transport, error)) {
	transportRegistry[typ] = factory
}

// NewTransport creates a transport of the specified type
func NewTransport(typ TransportType, cfg TransportConfig) (Transport, error) {
	factory, ok := transportRegistry[typ]
	if !ok {
		return nil, &TransportError{
			Type:    typ,
			Message: "transport type not registered",
		}
	}
	return factory(cfg)
}

// TransportError represents a transport-level error
type TransportError struct {
	Type    TransportType
	Message string
	Cause   error
}

func (e *TransportError) Error() string {
	if e.Cause != nil {
		return string(e.Type) + ": " + e.Message + ": " + e.Cause.Error()
	}
	return string(e.Type) + ": " + e.Message
}

func (e *TransportError) Unwrap() error {
	return e.Cause
}

// advertisedRelayDest returns the unicast relay address carried by a Relay
// Advertisement, or nil when the advertisement does not name one we could
// plausibly send to. RFC 7450 section 5.1.2.4: the advertisement names the
// relay that actually answered, and the Request and everything after it go
// there. discovered is the address the Discovery was sent to, which in an
// anycast deployment is not that relay.
//
// The address arrives off the wire, so it is adopted only when it survives
// three plausibility tests. Each of the rejected shapes would black-hole every
// message after the Discovery, and the discovery address is at least known to
// work:
//
//   - absent or unspecified;
//   - a different address family from the one we reached the relay on. Our
//     sockets are AF_INET, so a 24-byte advertisement carrying a global IPv6
//     address is unsendable however routable it looks;
//   - private or link-local from a relay we reached at a global address -- a
//     relay behind NAT advertising its inside address.
//
// nil is also returned when the advertisement merely repeats the discovery
// address, so the caller leaves its current destination alone.
//
// Shared by Gateway and UDPTransport: both learn their relay the same way, and
// an advertisement one of them would refuse is not one the other should take.
func advertisedRelayDest(data []byte, discovered *net.UDPAddr) *net.UDPAddr {
	var adv m.RelayAdvertisementMessage
	if err := adv.UnmarshalBinary(data); err != nil {
		return nil
	}
	if discovered == nil || len(adv.RelayAddr) == 0 || adv.RelayAddr.IsUnspecified() {
		return nil
	}
	if (adv.RelayAddr.To4() != nil) != (discovered.IP.To4() != nil) {
		slog.Warn("amt: ignoring advertised relay address from another family",
			"advertised", adv.RelayAddr.String(), "discovery", discovered.String())
		return nil
	}
	if !routableBeyondSite(adv.RelayAddr) && routableBeyondSite(discovered.IP) {
		slog.Warn("amt: ignoring unroutable advertised relay address",
			"advertised", adv.RelayAddr.String(), "discovery", discovered.String())
		return nil
	}
	if adv.RelayAddr.Equal(discovered.IP) {
		return nil
	}
	slog.Debug("amt: using advertised relay address",
		"advertised", adv.RelayAddr.String(), "discovery", discovered.String())
	return &net.UDPAddr{IP: adv.RelayAddr, Port: discovered.Port, Zone: discovered.Zone}
}

func routableBeyondSite(ip net.IP) bool {
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}
