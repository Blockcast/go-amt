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

	// CreateIGMPLeaveReport creates an IGMPv3 report that leaves one (S,G) pair.
	CreateIGMPLeaveReport(source, group netip.Addr) ([]byte, error)

	// CreateMembershipUpdate creates an AMT Membership Update message with IGMP report
	//
	// Precondition, and it is the same for both implementations: a Membership
	// Query must have been processed by HandleQuery, so a response MAC is
	// available. There is deliberately NO further state precondition — an
	// Update is valid for every membership change on a live tunnel, not just
	// the first one after a Query. RFC 7450 §4.2.1.2: the nonce and MAC are
	// taken from the last Membership Query, and subsequent report/leave
	// messages are "immediately encapsulated and transmitted to the relay".
	//
	// This contract is stated here because the two implementations disagreed
	// on it (BLO-28805): the Rust FFI path guarded on Querying and consumed it,
	// making the call single-shot per Query, so every leave and every second
	// join failed with InvalidState while the pure-Go path succeeded.
	//
	// "The same for both implementations" is a claim about this precondition,
	// not blanket parity. The IGMP encapsulation is not fully in agreement: a
	// join report's IPv4 destination is the multicast group on the Rust path
	// and 224.0.0.22 on the pure-Go one (BLO-29419). Everything else in that
	// envelope is pinned across implementations by
	// TestIGMPEnvelopeParityAcrossImplementations.
	//
	// igmpReport must be non-empty. The implementations diverge on an empty
	// slice rather than agreeing on an error: the cgo path takes
	// &igmpReport[0] (protocol_cgo.go:279) and panics, where pure-Go marshals
	// it into an empty Encapsulated field. No caller can reach it today —
	// every CreateIGMP*Report builder returns a non-empty slice on success —
	// so this is a documented precondition rather than a latent panic, and a
	// new caller should treat it as one.
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

// SourceSpecificLeaveReporter preserves other sources in a group when one
// local (S,G) subscription is removed.
type SourceSpecificLeaveReporter interface {
	CreateIGMPSourceLeaveReport(source, group netip.Addr) ([]byte, error)
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
