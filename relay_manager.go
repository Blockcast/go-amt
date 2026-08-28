package amt

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/puzpuzpuz/xsync/v3"
	"go.uber.org/atomic"
)

// SubscriptionKey uniquely identifies a multicast subscription
type SubscriptionKey struct {
	Source netip.Addr
	Group  netip.Addr
	Port   uint16
}

func (k SubscriptionKey) String() string {
	return fmt.Sprintf("(%s,%s):%d", k.Source, k.Group, k.Port)
}

// RelayState represents the AMT relay connection state
type RelayState int

const (
	RelayStateIdle RelayState = iota
	RelayStateDiscovering
	RelayStateRequesting
	RelayStateQuerying
	RelayStateActive
	RelayStateReconnecting
	RelayStateClosed
	RelayStateError
)

func (s RelayState) String() string {
	switch s {
	case RelayStateIdle:
		return "Idle"
	case RelayStateDiscovering:
		return "Discovering"
	case RelayStateRequesting:
		return "Requesting"
	case RelayStateQuerying:
		return "Querying"
	case RelayStateActive:
		return "Active"
	case RelayStateReconnecting:
		return "Reconnecting"
	case RelayStateClosed:
		return "Closed"
	case RelayStateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// SubscriptionState represents a subscription's state
type SubscriptionState int

const (
	SubscriptionStateInitializing SubscriptionState = iota
	SubscriptionStateJoining
	SubscriptionStateActive
	SubscriptionStateSuspended
	SubscriptionStateClosed
	SubscriptionStateError
)

func (s SubscriptionState) String() string {
	switch s {
	case SubscriptionStateInitializing:
		return "Initializing"
	case SubscriptionStateJoining:
		return "Joining"
	case SubscriptionStateActive:
		return "Active"
	case SubscriptionStateSuspended:
		return "Suspended"
	case SubscriptionStateClosed:
		return "Closed"
	case SubscriptionStateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// DataPacket represents a received multicast data packet
type DataPacket struct {
	Data      []byte
	Source    net.Addr
	Timestamp time.Time
}

// SubscriptionCallbacks defines callbacks for subscription events
type SubscriptionCallbacks struct {
	// OnPacket is called when data is received for this subscription
	OnPacket func(data []byte, src net.Addr) error

	// OnStateChange is called when subscription state changes
	OnStateChange func(old, new SubscriptionState)

	// OnError is called when an error occurs
	OnError func(err error)
}

// Subscription represents a single (S,G) multicast subscription
type Subscription struct {
	key       SubscriptionKey
	state     atomic.Value // SubscriptionState
	callbacks SubscriptionCallbacks
	dataChan  chan *DataPacket
	ctx       context.Context
	cancel    context.CancelFunc
	manager   *RelayManager

	// Statistics
	packetsReceived atomic.Uint64
	bytesReceived   atomic.Uint64
	lastPacketTime  atomic.Time
}

// Key returns the subscription key
func (s *Subscription) Key() SubscriptionKey {
	return s.key
}

// State returns the current subscription state
func (s *Subscription) State() SubscriptionState {
	return s.state.Load().(SubscriptionState)
}

// Stats returns subscription statistics
func (s *Subscription) Stats() SubscriptionStats {
	return SubscriptionStats{
		PacketsReceived: s.packetsReceived.Load(),
		BytesReceived:   s.bytesReceived.Load(),
		LastPacketTime:  s.lastPacketTime.Load(),
		State:           s.State(),
	}
}

// SubscriptionStats contains subscription statistics
type SubscriptionStats struct {
	PacketsReceived uint64
	BytesReceived   uint64
	LastPacketTime  time.Time
	State           SubscriptionState
}

// DataChan returns the channel for receiving data packets
func (s *Subscription) DataChan() <-chan *DataPacket {
	return s.dataChan
}

func (s *Subscription) setState(state SubscriptionState) {
	old := s.State()
	s.state.Store(state)
	if s.callbacks.OnStateChange != nil && old != state {
		s.callbacks.OnStateChange(old, state)
	}
}

// RelayManagerConfig contains configuration for RelayManager
type RelayManagerConfig struct {
	// RelayAddr is the AMT relay address (can be empty if EnableDRIAD is true)
	RelayAddr net.UDPAddr

	// EnableDRIAD enables DRIAD discovery (RFC 8777) when RelayAddr is empty
	EnableDRIAD bool

	// SourceAddr is the multicast source address (required for DRIAD discovery)
	SourceAddr netip.Addr

	// DNSServers is a list of DNS servers for DRIAD discovery (optional)
	DNSServers []string

	// DNSTimeout is the timeout for DRIAD DNS queries
	DNSTimeout time.Duration

	// MTU is the maximum transmission unit
	MTU int

	// TransportConfig for transport layer
	TransportConfig TransportConfig

	// BackoffConfig for reconnection
	InitialBackoff    time.Duration
	MaxBackoff        time.Duration
	BackoffMultiplier float64

	// DataChannelSize is the buffer size for subscription data channels
	DataChannelSize int

	// KeepaliveInterval is the interval for sending keepalive requests
	KeepaliveInterval time.Duration

	// TransportFactory, when non-nil, constructs the Transport in place of
	// CreatePlatformTransport. Production callers leave it nil; it exists so a
	// test can wrap or replace the transport, which is otherwise unreachable
	// because Open assigns rm.transport itself and swapping the field afterwards
	// races the running readLoop.
	//
	// Open calls it exactly once. Reconnection reuses that same Transport through
	// its Close/Open methods rather than building a new one, so a decorator
	// installed here observes every generation, including the reconnect
	// handshake.
	TransportFactory func(TransportConfig) (Transport, error)
}

// DefaultRelayManagerConfig returns a config with sensible defaults
func DefaultRelayManagerConfig(relayAddr net.UDPAddr) RelayManagerConfig {
	return RelayManagerConfig{
		RelayAddr:         relayAddr,
		EnableDRIAD:       false,
		DNSTimeout:        DefaultDNSDTimeout,
		MTU:               1500,
		TransportConfig:   DefaultTransportConfig(relayAddr),
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        30 * time.Second,
		BackoffMultiplier: 2.0,
		DataChannelSize:   100,
		KeepaliveInterval: 10 * time.Second,
	}
}

// DefaultRelayManagerConfigWithDRIAD returns a config with DRIAD discovery enabled
func DefaultRelayManagerConfigWithDRIAD(sourceAddr netip.Addr) RelayManagerConfig {
	return RelayManagerConfig{
		EnableDRIAD:       true,
		SourceAddr:        sourceAddr,
		DNSTimeout:        DefaultDNSDTimeout,
		MTU:               1500,
		InitialBackoff:    1 * time.Second,
		MaxBackoff:        30 * time.Second,
		BackoffMultiplier: 2.0,
		DataChannelSize:   100,
		KeepaliveInterval: 10 * time.Second,
	}
}

// RelayManagerStats contains relay manager statistics
type RelayManagerStats struct {
	State             RelayState
	SubscriptionCount int
	TotalPackets      uint64
	TotalBytes        uint64
	ReconnectCount    uint64
	LastReconnectTime time.Time
	TransportType     TransportType
	ProtocolType      ProtocolType
}

// RelayManager manages a shared AMT relay connection for multiple subscriptions
type RelayManager struct {
	config        RelayManagerConfig
	state         atomic.Value // RelayState
	transport     Transport
	protocol      AMTProtocol
	subscriptions *xsync.MapOf[SubscriptionKey, *Subscription]
	pendingJoins  *xsync.MapOf[SubscriptionKey, *Subscription]

	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	handshakeMu     sync.Mutex
	receiveMu       sync.Mutex
	loopsMu         sync.Mutex
	loopsCancel     context.CancelFunc
	loopsWG         sync.WaitGroup
	loopGeneration  uint64
	intervalTime    time.Duration
	lastAnyMessage  atomic.Time
	lastDataMessage atomic.Time
	reconnectCount  atomic.Uint64

	// For batched IGMP
	joinPending atomic.Bool
	joinTimer   *time.Timer
}

// NewRelayManager creates a new RelayManager
func NewRelayManager(config RelayManagerConfig) *RelayManager {
	rm := &RelayManager{
		config:        config,
		subscriptions: xsync.NewMapOf[SubscriptionKey, *Subscription](),
		pendingJoins:  xsync.NewMapOf[SubscriptionKey, *Subscription](),
		intervalTime:  config.KeepaliveInterval,
	}
	rm.state.Store(RelayStateIdle)
	return rm
}

// Open initializes and connects the relay manager
func (rm *RelayManager) Open(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.State() != RelayStateIdle {
		return fmt.Errorf("relay manager not in idle state: %s", rm.State())
	}

	rm.ctx, rm.cancel = context.WithCancel(ctx)

	// Perform DRIAD discovery if enabled and no relay address provided
	relayAddr := rm.config.RelayAddr
	if len(relayAddr.IP) == 0 && rm.config.EnableDRIAD {
		if !rm.config.SourceAddr.IsValid() {
			return fmt.Errorf("DRIAD enabled but no source address provided")
		}

		discoveredRelay, err := DiscoverRelay(ctx, DRIADConfig{
			SourceAddr: rm.config.SourceAddr,
			DNSServers: rm.config.DNSServers,
			Timeout:    rm.config.DNSTimeout,
		})
		if err != nil {
			return fmt.Errorf("DRIAD discovery failed: %w", err)
		}

		relayAddr = *discoveredRelay
		rm.config.RelayAddr = relayAddr
		rm.config.TransportConfig.RelayAddr = relayAddr
	}

	if len(relayAddr.IP) == 0 {
		return fmt.Errorf("no relay address provided and DRIAD discovery not enabled")
	}

	// Create transport
	newTransport := rm.config.TransportFactory
	if newTransport == nil {
		newTransport = CreatePlatformTransport
	}
	transport, err := newTransport(rm.config.TransportConfig)
	if err != nil {
		return fmt.Errorf("failed to create transport: %w", err)
	}
	rm.transport = transport

	// Create protocol
	protocol, err := DefaultProtocol()
	if err != nil {
		return fmt.Errorf("failed to create protocol: %w", err)
	}
	rm.protocol = protocol

	// Initialize protocol
	if err := rm.protocol.Initialize(
		relayAddr.IP.String(),
		uint16(relayAddr.Port),
	); err != nil {
		return fmt.Errorf("failed to initialize protocol: %w", err)
	}

	// Open transport
	if err := rm.transport.Open(rm.ctx); err != nil {
		return fmt.Errorf("failed to open transport: %w", err)
	}

	// Perform discovery handshake
	if err := rm.performHandshake(); err != nil {
		rm.transport.Close()
		return fmt.Errorf("handshake failed: %w", err)
	}

	rm.state.Store(RelayStateActive)
	now := time.Now()
	rm.lastAnyMessage.Store(now)
	rm.lastDataMessage.Store(now)

	// Start exactly one read/keepalive pair for the initial generation.
	rm.startLoops()

	return nil
}

// Close shuts down the relay manager
func (rm *RelayManager) Close() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.cancel != nil {
		rm.cancel()
	}
	rm.stopLoops()

	rm.state.Store(RelayStateClosed)

	// Close all subscriptions
	rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
		sub.setState(SubscriptionStateClosed)
		if sub.cancel != nil {
			sub.cancel()
		}
		close(sub.dataChan)
		return true
	})
	rm.subscriptions.Clear()

	// Send teardown if connected
	if rm.protocol != nil && rm.transport != nil {
		if teardown, err := rm.protocol.CreateTeardownMessage(); err == nil {
			_ = rm.transport.Send(teardown)
		}
		rm.protocol.Close()
	}

	if rm.transport != nil {
		err := rm.transport.Close()
		rm.waitLoops()
		return err
	}

	return nil
}

// Subscribe creates a new subscription for the given (S,G,Port)
// canonicalSubscriptionKey normalises a v4-mapped IPv6 address (::ffff:a.b.c.d)
// down to canonical IPv4. Subscribe accepts both forms, but the IGMP report
// builders require strictly Is4(); storing the mapped form lets a subscription
// join successfully and then fail to build its leave report, which strands the
// membership on the relay. Normalising at the boundary keeps one representation
// in the maps so every downstream Is4() holds.
func canonicalSubscriptionKey(key SubscriptionKey) SubscriptionKey {
	key.Source = key.Source.Unmap()
	key.Group = key.Group.Unmap()
	return key
}

func (rm *RelayManager) Subscribe(key SubscriptionKey, callbacks SubscriptionCallbacks) (*Subscription, error) {
	// Reject non-IPv4 (S,G) synchronously. The IGMPv3 report builder converts
	// these with netip.Addr.As4, which panics, and it runs from the batched
	// membership time.AfterFunc goroutine where no recover() can catch it.
	if !key.Source.IsValid() || (!key.Source.Is4() && !key.Source.Is4In6()) {
		return nil, fmt.Errorf("subscription source address must be IPv4: %s", key.Source)
	}
	if !key.Group.IsValid() || (!key.Group.Is4() && !key.Group.Is4In6()) {
		return nil, fmt.Errorf("subscription group address must be IPv4: %s", key.Group)
	}
	key = canonicalSubscriptionKey(key)

	rm.mu.RLock()
	state := rm.State()
	rm.mu.RUnlock()

	if state == RelayStateClosed || state == RelayStateError {
		return nil, fmt.Errorf("relay manager not active: %s", state)
	}

	// Check if already subscribed
	if existing, ok := rm.subscriptions.Load(key); ok {
		return existing, nil
	}

	ctx, cancel := context.WithCancel(rm.ctx)
	sub := &Subscription{
		key:       key,
		callbacks: callbacks,
		dataChan:  make(chan *DataPacket, rm.config.DataChannelSize),
		ctx:       ctx,
		cancel:    cancel,
		manager:   rm,
	}
	sub.state.Store(SubscriptionStateInitializing)

	// Add to pending joins
	rm.pendingJoins.Store(key, sub)

	// Schedule batched join
	rm.scheduleBatchedJoin()

	return sub, nil
}

// Unsubscribe removes a subscription.
//
// The subscription is always torn down and removed, regardless of the returned
// error: a non-nil return reports that the leave could not be delivered to the
// relay, not that the caller still holds the subscription. Retrying is
// pointless — a second call short-circuits to nil because the entry is already
// gone. Callers should log the error (the relay will keep forwarding until its
// membership times out) rather than loop on it.
func (rm *RelayManager) Unsubscribe(key SubscriptionKey) error {
	// Match the normalisation Subscribe applied, or a caller passing the
	// v4-mapped form it subscribed with would miss the stored entry.
	key = canonicalSubscriptionKey(key)

	sub, ok := rm.subscriptions.LoadAndDelete(key)
	if !ok {
		// Also check pending
		sub, ok = rm.pendingJoins.LoadAndDelete(key)
		if !ok {
			return nil // Already unsubscribed
		}
	}

	sub.setState(SubscriptionStateClosed)
	if sub.cancel != nil {
		sub.cancel()
	}
	close(sub.dataChan)

	// A relay keeps the previous membership until it receives a leave report.
	// Preserve other sources in the same group with a source-specific leave.
	var leaveErr error
	if rm.State() == RelayStateActive || rm.State() == RelayStateQuerying {
		stillSubscribed := false
		otherGroupSource := false

		// Both maps must be consulted. Subscribe parks a new subscription in
		// pendingJoins until the debounced batch promotes it, so scanning only
		// subscriptions misses a sibling source joined within that window and
		// emits a group-wide leave that withdraws its membership too.
		scan := func(otherKey SubscriptionKey, _ *Subscription) bool {
			if otherKey.Source == key.Source && otherKey.Group == key.Group {
				stillSubscribed = true
			}
			if otherKey.Group == key.Group {
				otherGroupSource = true
			}
			return true
		}
		// Scan order is load-bearing, not stylistic. Promotion in
		// sendBatchedMembershipUpdate stores into subscriptions before it
		// clears pendingJoins, so scanning in the opposite direction to that
		// transfer observes a concurrently-promoted sibling in at least one
		// map: absence from pendingJoins implies the clear already ran, which
		// implies the store landed, and subscriptions is scanned strictly
		// later. Scanning subscriptions first leaves the entry invisible to
		// both ranges and emits a group-wide leave.
		rm.pendingJoins.Range(scan)
		rm.subscriptions.Range(scan)

		if !stillSubscribed {
			var report []byte
			var err error
			if otherGroupSource {
				sourceLeaver, ok := rm.protocol.(SourceSpecificLeaveReporter)
				if !ok {
					// A group-wide leave is safer than reporting an error after
					// teardown: the removed source must not remain subscribed.
					report, err = rm.protocol.CreateIGMPLeaveReport(key.Source, key.Group)
				} else {
					report, err = sourceLeaver.CreateIGMPSourceLeaveReport(key.Source, key.Group)
				}
			} else {
				report, err = rm.protocol.CreateIGMPLeaveReport(key.Source, key.Group)
			}
			// Do not swallow this. A leave that is never sent leaves the relay
			// forwarding the stream for the life of the session while the caller
			// believes it detached, which is indistinguishable from success.
			if err != nil {
				leaveErr = fmt.Errorf("failed to build leave report for %s: %w", key.String(), err)
			} else {
				update, uerr := rm.protocol.CreateMembershipUpdate(report)
				if uerr != nil {
					leaveErr = fmt.Errorf("failed to build membership update for %s: %w", key.String(), uerr)
				} else if serr := rm.transport.Send(update); serr != nil {
					leaveErr = fmt.Errorf("failed to send leave for %s: %w", key.String(), serr)
				}
			}
		}
	}

	// Re-send batched membership update without this subscription
	rm.scheduleBatchedJoin()

	return leaveErr
}

// State returns the current relay state
func (rm *RelayManager) State() RelayState {
	return rm.state.Load().(RelayState)
}

// Stats returns relay manager statistics
func (rm *RelayManager) Stats() RelayManagerStats {
	var totalPackets, totalBytes uint64
	subCount := 0

	rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
		subCount++
		totalPackets += sub.packetsReceived.Load()
		totalBytes += sub.bytesReceived.Load()
		return true
	})

	stats := RelayManagerStats{
		State:             rm.State(),
		SubscriptionCount: subCount,
		TotalPackets:      totalPackets,
		TotalBytes:        totalBytes,
		ReconnectCount:    rm.reconnectCount.Load(),
	}

	if rm.transport != nil {
		stats.TransportType = rm.transport.Type()
	}

	return stats
}

// performHandshake performs the AMT discovery handshake
func (rm *RelayManager) performHandshake() error {
	rm.handshakeMu.Lock()
	defer rm.handshakeMu.Unlock()

	rm.state.Store(RelayStateDiscovering)

	// Send discovery
	discovery, err := rm.protocol.CreateDiscoveryMessage()
	if err != nil {
		return fmt.Errorf("failed to create discovery: %w", err)
	}
	if err := rm.transport.Send(discovery); err != nil {
		return fmt.Errorf("failed to send discovery: %w", err)
	}

	// Wait for responses
	buffer := make([]byte, rm.config.MTU)
	if err := rm.transport.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	for {
		rm.receiveMu.Lock()
		n, _, err := rm.transport.Receive(buffer)
		rm.receiveMu.Unlock()
		if err != nil {
			return fmt.Errorf("failed to receive response: %w", err)
		}

		msgType := m.MessageType(buffer[0] & 0x0F)
		switch msgType {
		case m.RelayAdvertisementType:
			rm.state.Store(RelayStateRequesting)
			if err := rm.protocol.HandleAdvertisement(buffer[:n]); err != nil {
				return fmt.Errorf("failed to handle advertisement: %w", err)
			}

			// Send request
			request, err := rm.protocol.CreateRequestMessage(false)
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}
			if err := rm.transport.Send(request); err != nil {
				return fmt.Errorf("failed to send request: %w", err)
			}

		case m.MembershipQueryType:
			rm.state.Store(RelayStateQuerying)
			_, interval, err := rm.protocol.HandleQuery(buffer[:n])
			if err != nil {
				return fmt.Errorf("failed to handle query: %w", err)
			}
			rm.intervalTime = interval

			// Answer the Query with a current-state Membership Update before
			// declaring the handshake complete. This is not optional bookkeeping:
			// the Query leaves the gateway in Querying, and that state can send
			// nothing further. On the cgo/Rust path -- the one production uses --
			// request_membership admits only Idle or Active
			// (amt-protocol@44ff7e1d `src/gateway.rs:257`), so a gateway parked in
			// Querying fails every keepalive with InvalidState. keepaliveLoop
			// discards that error and continues (see the comment there), so no
			// Request reaches the wire, no Query comes back, and the tunnel
			// reconnects every intervalTime*2 forever while still reporting
			// Active. send_update is the only transition into Active
			// (`gateway.rs:332`) and it accepts Querying (`gateway.rs:325`), so
			// this single Update is what makes the tunnel keepalive-capable.
			//
			// Sending it here rather than on first subscribe is what the wire
			// contract requires: Querying is designed to be zero-width, and
			// amt-protocol's reference driver answers every Query synchronously
			// with a current-state report, empty when it holds no groups
			// (`src/subscription/mod.rs:278`). A gateway with no subscriptions
			// still owes the relay that empty report. BLO-28805.
			report, err := buildIGMPCurrentStateReport()
			if err != nil {
				return fmt.Errorf("failed to build current-state report: %w", err)
			}
			update, err := rm.protocol.CreateMembershipUpdate(report)
			if err != nil {
				return fmt.Errorf("failed to create current-state membership update: %w", err)
			}
			if err := rm.transport.Send(update); err != nil {
				return fmt.Errorf("failed to send current-state membership update: %w", err)
			}

			// Clear deadline for normal operation
			_ = rm.transport.SetReadDeadline(time.Time{})
			return nil

		default:
			return fmt.Errorf("unexpected message type during handshake: %d", msgType)
		}
	}
}

// scheduleBatchedJoin schedules a batched IGMP join
func (rm *RelayManager) scheduleBatchedJoin() {
	if rm.joinPending.CompareAndSwap(false, true) {
		// Debounce joins by 50ms to batch multiple subscriptions
		rm.joinTimer = time.AfterFunc(50*time.Millisecond, func() {
			rm.joinPending.Store(false)
			if err := rm.sendBatchedMembershipUpdate(); err != nil {
				// Log error but don't fail
				_ = err
			}
		})
	}
}

// sendBatchedMembershipUpdate sends a batched IGMP membership update
func (rm *RelayManager) sendBatchedMembershipUpdate() error {
	if rm.State() != RelayStateActive && rm.State() != RelayStateQuerying {
		return nil
	}

	// Collect all subscriptions grouped by source
	sourceGroups := make(map[netip.Addr][]netip.Addr)

	// Process pending joins
	rm.pendingJoins.Range(func(key SubscriptionKey, sub *Subscription) bool {
		sourceGroups[key.Source] = append(sourceGroups[key.Source], key.Group)
		sub.setState(SubscriptionStateJoining)
		rm.subscriptions.Store(key, sub)
		return true
	})
	rm.pendingJoins.Clear()

	// Add existing active subscriptions
	rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
		if sub.State() == SubscriptionStateActive || sub.State() == SubscriptionStateSuspended {
			sourceGroups[key.Source] = append(sourceGroups[key.Source], key.Group)
		}
		return true
	})

	if len(sourceGroups) == 0 {
		return nil
	}

	// Create and send IGMP reports for each source
	for source, groups := range sourceGroups {
		igmpReport, err := rm.protocol.CreateIGMPJoinReportMulti(source, groups)
		if err != nil {
			return fmt.Errorf("failed to create IGMP report: %w", err)
		}

		update, err := rm.protocol.CreateMembershipUpdate(igmpReport)
		if err != nil {
			return fmt.Errorf("failed to create membership update: %w", err)
		}

		if err := rm.transport.Send(update); err != nil {
			return fmt.Errorf("failed to send membership update: %w", err)
		}
	}

	// Mark all joining subscriptions as active
	rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
		if sub.State() == SubscriptionStateJoining {
			sub.setState(SubscriptionStateActive)
		}
		return true
	})

	return nil
}

// startLoops launches one read/keepalive pair and records its generation.
func (rm *RelayManager) startLoops() {
	rm.loopsMu.Lock()
	defer rm.loopsMu.Unlock()
	if rm.loopsCancel != nil {
		return
	}
	loopCtx, cancel := context.WithCancel(rm.ctx)
	rm.loopsCancel = cancel
	rm.loopGeneration++
	generation := rm.loopGeneration
	rm.loopsWG.Add(2)
	go rm.readLoop(loopCtx, generation)
	go rm.keepaliveLoop(loopCtx, generation)
}

// stopLoops cancels the current generation. Transport closure during reconnect
// releases any receive blocked by the old generation.
func (rm *RelayManager) stopLoops() {
	rm.loopsMu.Lock()
	defer rm.loopsMu.Unlock()
	if rm.loopsCancel != nil {
		rm.loopsCancel()
		rm.loopsCancel = nil
	}
}

func (rm *RelayManager) waitLoops() {
	rm.loopsWG.Wait()
}

func (rm *RelayManager) generationActive(generation uint64) bool {
	rm.loopsMu.Lock()
	defer rm.loopsMu.Unlock()
	return rm.loopGeneration == generation && rm.loopsCancel != nil
}

// readLoop continuously reads from the transport
func (rm *RelayManager) readLoop(ctx context.Context, generation uint64) {
	defer rm.loopsWG.Done()
	buffer := make([]byte, rm.config.MTU)

	for {
		if !rm.generationActive(generation) {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}

		rm.receiveMu.Lock()
		n, _, err := rm.transport.Receive(buffer)
		rm.receiveMu.Unlock()
		if err != nil {
			if ctx.Err() != nil || rm.ctx.Err() != nil {
				return // Context cancelled
			}
			// Trigger reconnection
			go rm.reconnectWithBackoff()
			return
		}

		rm.lastAnyMessage.Store(time.Now())

		msgType := m.MessageType(buffer[0] & 0x0F)
		switch msgType {
		case m.MulticastDataType:
			rm.lastDataMessage.Store(time.Now())
			rm.routeDataToSubscription(buffer[:n])

		case m.MembershipQueryType:
			if _, _, err := rm.protocol.HandleQuery(buffer[:n]); err != nil {
				continue
			}
			// Re-send membership update
			_ = rm.sendBatchedMembershipUpdate()

		case m.RelayAdvertisementType:
			// During active state, advertisement means we need to re-request
			if err := rm.protocol.HandleAdvertisement(buffer[:n]); err != nil {
				continue
			}
			request, err := rm.protocol.CreateRequestMessage(false)
			if err != nil {
				continue
			}
			_ = rm.transport.Send(request)
		}
	}
}

// routeDataToSubscription routes multicast data to the appropriate subscription
func (rm *RelayManager) routeDataToSubscription(data []byte) {
	if len(data) < m.DataMsgHdrLen {
		return
	}

	// Parse IP/UDP headers to extract (S,G,Port)
	pkt := gopacket.NewPacket(data[m.DataMsgHdrLen:], layers.LayerTypeIPv4, gopacket.NoCopy)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp := udpLayer.(*layers.UDP)

	srcAddr, _ := netip.AddrFromSlice(ip.SrcIP)
	dstAddr, _ := netip.AddrFromSlice(ip.DstIP)

	key := SubscriptionKey{
		Source: srcAddr,
		Group:  dstAddr,
		Port:   uint16(udp.DstPort),
	}

	sub, ok := rm.subscriptions.Load(key)
	if !ok {
		// Try without port (some subscriptions may not care about port)
		key.Port = 0
		sub, ok = rm.subscriptions.Load(key)
		if !ok {
			return
		}
	}

	if sub.State() != SubscriptionStateActive {
		return
	}

	// Extract and own the payload before the read loop reuses its receive buffer.
	payload := pkt.ApplicationLayer()
	if payload == nil {
		return
	}
	payloadData := append([]byte(nil), payload.Payload()...)

	// ip.SrcIP aliases the read buffer too (gopacket.NoCopy), and the address we
	// hand out outlives this iteration via dataChan. Own those bytes as well.
	srcIP := append(net.IP(nil), ip.SrcIP...)
	srcPort := int(udp.SrcPort)

	// Update stats
	sub.packetsReceived.Add(1)
	sub.bytesReceived.Add(uint64(len(payloadData)))
	sub.lastPacketTime.Store(time.Now())

	// Send to callback or channel
	if sub.callbacks.OnPacket != nil {
		srcUDP := &net.UDPAddr{
			IP:   srcIP,
			Port: srcPort,
		}
		if err := sub.callbacks.OnPacket(payloadData, srcUDP); err != nil {
			if sub.callbacks.OnError != nil {
				sub.callbacks.OnError(err)
			}
		}
	}

	// Also send to channel (non-blocking)
	select {
	case sub.dataChan <- &DataPacket{
		Data:      payloadData,
		Source:    &net.UDPAddr{IP: srcIP, Port: srcPort},
		Timestamp: time.Now(),
	}:
	default:
		// Channel full, drop packet
	}
}

// keepaliveLoop sends periodic keepalive requests
func (rm *RelayManager) keepaliveLoop(ctx context.Context, generation uint64) {
	defer rm.loopsWG.Done()
	ticker := time.NewTicker(rm.intervalTime)
	defer ticker.Stop()

	for {
		if !rm.generationActive(generation) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rm.State() != RelayStateActive {
				continue
			}

			// Check if we've received data recently
			if time.Since(rm.lastDataMessage.Load()) > rm.intervalTime*2 {
				// No data received: reconnectWithBackoff is the only recovery
				// path so the reader is stopped before the handshake begins.
				go rm.reconnectWithBackoff()
				return
			} else {
				// Send keepalive request
				request, err := rm.protocol.CreateRequestMessage(false)
				if err != nil {
					continue
				}
				_ = rm.transport.Send(request)
			}
		}
	}
}

// reconnectWithBackoff attempts to reconnect with exponential backoff
func (rm *RelayManager) reconnectWithBackoff() {
	rm.mu.Lock()
	if rm.State() == RelayStateReconnecting || rm.State() == RelayStateClosed {
		rm.mu.Unlock()
		return
	}
	rm.state.Store(RelayStateReconnecting)
	rm.mu.Unlock()
	rm.stopLoops()

	// Suspend all subscriptions
	rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
		sub.setState(SubscriptionStateSuspended)
		return true
	})

	// Configure exponential backoff
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = rm.config.InitialBackoff
	b.MaxInterval = rm.config.MaxBackoff
	b.Multiplier = rm.config.BackoffMultiplier
	b.MaxElapsedTime = 0 // Retry forever

	operation := func() error {
		select {
		case <-rm.ctx.Done():
			return backoff.Permanent(rm.ctx.Err())
		default:
		}

		// Reset protocol
		rm.protocol.Reset()

		// Close the transport and wait for the old reader before reopening it.
		// Otherwise a receive blocked in the old generation can consume the new
		// generation's handshake response after the socket is reopened.
		_ = rm.transport.Close()
		rm.waitLoops()
		if err := rm.transport.Open(rm.ctx); err != nil {
			return err
		}

		// Re-perform handshake
		if err := rm.performHandshake(); err != nil {
			return err
		}

		// Re-send membership updates
		return rm.sendBatchedMembershipUpdate()
	}

	notify := func(err error, duration time.Duration) {
		rm.reconnectCount.Add(1)
	}

	if err := backoff.RetryNotify(operation, b, notify); err != nil {
		rm.state.Store(RelayStateError)
		rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
			sub.setState(SubscriptionStateError)
			if sub.callbacks.OnError != nil {
				sub.callbacks.OnError(err)
			}
			return true
		})
		return
	}

	rm.state.Store(RelayStateActive)
	now := time.Now()
	rm.lastAnyMessage.Store(now)
	rm.lastDataMessage.Store(now)
	rm.startLoops()

	// Restore all subscriptions
	rm.subscriptions.Range(func(key SubscriptionKey, sub *Subscription) bool {
		sub.setState(SubscriptionStateActive)
		return true
	})
}

// Global registry for RelayManagers (one per relay address)
var (
	relayManagerRegistry = xsync.NewMapOf[string, *RelayManager]()
	registryMu           sync.Mutex
)

// GetOrCreateRelayManager returns an existing or creates a new RelayManager for the relay address
func GetOrCreateRelayManager(relayAddr net.UDPAddr, config *RelayManagerConfig) (*RelayManager, error) {
	key := relayAddr.String()

	// Fast path: check if exists
	if rm, ok := relayManagerRegistry.Load(key); ok {
		if rm.State() == RelayStateActive || rm.State() == RelayStateReconnecting {
			return rm, nil
		}
	}

	// Slow path: create new
	registryMu.Lock()
	defer registryMu.Unlock()

	// Double-check after acquiring lock
	if rm, ok := relayManagerRegistry.Load(key); ok {
		if rm.State() == RelayStateActive || rm.State() == RelayStateReconnecting {
			return rm, nil
		}
		// Clean up closed/errored manager
		relayManagerRegistry.Delete(key)
	}

	// Create new manager
	cfg := DefaultRelayManagerConfig(relayAddr)
	if config != nil {
		cfg = *config
	}

	rm := NewRelayManager(cfg)
	if err := rm.Open(context.Background()); err != nil {
		return nil, err
	}

	relayManagerRegistry.Store(key, rm)
	return rm, nil
}

// CloseRelayManager closes and removes a RelayManager from the registry
func CloseRelayManager(relayAddr net.UDPAddr) error {
	key := relayAddr.String()
	rm, ok := relayManagerRegistry.LoadAndDelete(key)
	if !ok {
		return nil
	}
	return rm.Close()
}
