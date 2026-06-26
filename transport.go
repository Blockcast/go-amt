package amt

import (
	"context"
	"net"
	"time"
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

	// RelayAddr returns the relay address
	RelayAddr() net.Addr

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

	// Timeout for connection establishment
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
