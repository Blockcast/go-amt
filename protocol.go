package amt

import (
	"net/netip"
	"time"
)

// AMTProtocol abstracts the AMT protocol implementation.
// Implementations:
// - CGOProtocol: Uses Rust library via CGO (Linux/macOS desktop)
// - PureGoProtocol: Pure Go implementation (all platforms)
type AMTProtocol interface {
	// Initialize sets up the protocol state for a relay
	Initialize(relayAddr string, relayPort uint16) error

	// CreateDiscoveryMessage creates an AMT Relay Discovery message
	CreateDiscoveryMessage() ([]byte, error)

	// HandleAdvertisement processes an AMT Relay Advertisement response
	HandleAdvertisement(data []byte) error

	// CreateRequestMessage creates an AMT Request message
	CreateRequestMessage(preferNative bool) ([]byte, error)

	// HandleQuery processes an AMT Membership Query and returns IGMP data
	HandleQuery(data []byte) (igmpData []byte, intervalTime time.Duration, err error)

	// CreateIGMPJoinReport creates an IGMPv3 SSM join report for a single (S,G)
	CreateIGMPJoinReport(source, group netip.Addr) ([]byte, error)

	// CreateIGMPJoinReportMulti creates an IGMPv3 report for multiple groups from same source
	CreateIGMPJoinReportMulti(source netip.Addr, groups []netip.Addr) ([]byte, error)

	// CreateMembershipUpdate creates an AMT Membership Update message with IGMP report
	CreateMembershipUpdate(igmpReport []byte) ([]byte, error)

	// CreateTeardownMessage creates an AMT Teardown message
	CreateTeardownMessage() ([]byte, error)

	// Reset resets the protocol state to idle
	Reset()

	// State returns the current protocol state
	State() AMTState

	// Close frees protocol resources
	Close()
}

// AMTState represents the AMT gateway state machine states
type AMTState int

const (
	AMTStateIdle AMTState = iota
	AMTStateDiscovering
	AMTStateRequesting
	AMTStateQuerying
	AMTStateActive
	AMTStateClosed
)

func (s AMTState) String() string {
	switch s {
	case AMTStateIdle:
		return "Idle"
	case AMTStateDiscovering:
		return "Discovering"
	case AMTStateRequesting:
		return "Requesting"
	case AMTStateQuerying:
		return "Querying"
	case AMTStateActive:
		return "Active"
	case AMTStateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// ProtocolError represents an AMT protocol error
type ProtocolError struct {
	State   AMTState
	Message string
	Cause   error
}

func (e *ProtocolError) Error() string {
	if e.Cause != nil {
		return "AMT protocol error (" + e.State.String() + "): " + e.Message + ": " + e.Cause.Error()
	}
	return "AMT protocol error (" + e.State.String() + "): " + e.Message
}

func (e *ProtocolError) Unwrap() error {
	return e.Cause
}

// ProtocolFactory creates protocol implementations based on platform
type ProtocolFactory interface {
	// Create creates a new protocol instance
	Create() (AMTProtocol, error)

	// Type returns the protocol implementation type
	Type() ProtocolType
}

// ProtocolType identifies the protocol implementation
type ProtocolType string

const (
	ProtocolTypeCGO    ProtocolType = "cgo"
	ProtocolTypePureGo ProtocolType = "pure-go"
)

// protocolRegistry holds registered protocol factories
var protocolRegistry = make(map[ProtocolType]func() (AMTProtocol, error))

// RegisterProtocol registers a protocol factory
func RegisterProtocol(typ ProtocolType, factory func() (AMTProtocol, error)) {
	protocolRegistry[typ] = factory
}

// NewProtocol creates a protocol of the specified type
func NewProtocol(typ ProtocolType) (AMTProtocol, error) {
	factory, ok := protocolRegistry[typ]
	if !ok {
		return nil, &ProtocolError{
			State:   AMTStateIdle,
			Message: "protocol type not registered: " + string(typ),
		}
	}
	return factory()
}

// DefaultProtocol creates the default protocol for the current platform
func DefaultProtocol() (AMTProtocol, error) {
	// Try CGO first (more efficient, tested)
	if factory, ok := protocolRegistry[ProtocolTypeCGO]; ok {
		if p, err := factory(); err == nil {
			return p, nil
		}
	}
	// Fall back to pure Go
	if factory, ok := protocolRegistry[ProtocolTypePureGo]; ok {
		return factory()
	}
	return nil, &ProtocolError{
		State:   AMTStateIdle,
		Message: "no protocol implementation available",
	}
}

// IsCGOAvailable returns true if CGO protocol is available
func IsCGOAvailable() bool {
	_, ok := protocolRegistry[ProtocolTypeCGO]
	return ok
}
