package amt

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"golang.org/x/net/ipv4"
)

// Ensure ManagedConn implements net.PacketConn
var _ net.PacketConn = (*ManagedConn)(nil)

// ManagedConn provides a backward-compatible wrapper around RelayManager subscriptions.
// It implements net.PacketConn and can be used as a drop-in replacement for MulticastConn.
//
// Key differences from MulticastConn:
// - Shares a single socket per relay across multiple (S,G) subscriptions
// - Automatic reconnection with exponential backoff
// - Supports DRIAD discovery (RFC 8777) when EnableDRIAD is true
type ManagedConn struct {
	// Configuration (same fields as MulticastConn for compatibility)
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16
	TTL       int
	IFace     *net.Interface
	Timeout   time.Duration
	Timestamp bool

	// RcvBufBytes and SndBufBytes are forwarded to the native multicast
	// socket; see MulticastConn for semantics.
	RcvBufBytes int
	SndBufBytes int

	// Mode selects native-vs-tunnel, and mirrors MulticastConn.Mode field for
	// field. The zero value (AMTModeAuto) keeps the historical inference, where a
	// configured RelayAddr makes the native join provisional. Set it explicitly
	// to stop a relay address that was inherited by configuration clone from
	// deciding the delivery path (BLO-28640).
	Mode AMTMode

	// DRIAD discovery configuration (RFC 8777)
	// When EnableDRIAD is true and RelayAddr is empty, discovers relay via DNS
	EnableDRIAD bool
	DNSServers  []string // Optional, uses system default if empty

	// Internal state
	rm         *RelayManager
	sub        *Subscription
	readBuffer chan *DataPacket
	done       chan struct{}
	mu         sync.RWMutex
	// openMu serializes Open against itself. mu deliberately no longer spans
	// the whole of Open — the native probe and the relay handshake both block
	// for seconds and must not be holding an exclusive lock while they do — so
	// without a separate gate two concurrent Opens could each bind a socket and
	// the loser's would leak. openMu preserves the serialization the single
	// full-length mu.Lock used to provide, without the lock-hold.
	openMu      sync.Mutex
	closed      bool
	usingTunnel bool
	localAddr   net.Addr

	// For native multicast fallback
	nativeConn *ipv4.PacketConn
}

// Open initializes the connection, trying native multicast first, then AMT relay
//
// Open can take seconds to return — up to MinUsefulProbeWindow proving the
// native join, plus the relay handshake — but it holds mc.mu only for short
// sections at each end. That split is deliberate: when the probe window ran
// inside the exclusive lock, Close() had to wait the whole window out with no
// cancellation path, and because Go's RWMutex queues new readers behind a
// waiting writer, one pending Close also stalled every IsUsingTunnel/LocalAddr/
// Stats reader for the remainder of it. Callers concurrent with Open therefore
// observe a not-yet-open connection rather than blocking on one.
func (mc *ManagedConn) Open() error {
	mc.openMu.Lock()
	defer mc.openMu.Unlock()

	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return fmt.Errorf("connection already closed")
	}
	if !mc.SrcAddr.Is4() {
		mc.mu.Unlock()
		return fmt.Errorf("AMT source address must be IPv4: %s", mc.SrcAddr)
	}
	if !mc.GroupAddr.Is4() {
		mc.mu.Unlock()
		return fmt.Errorf("AMT group address must be IPv4: %s", mc.GroupAddr)
	}
	mc.done = make(chan struct{})
	// Allocated here rather than beside the subscription below, so a Read racing
	// Open cannot select on a nil channel. mc.done goes live in this same
	// section, so a nil buffer would park that reader until Close instead of it
	// simply finding no packets yet.
	mc.readBuffer = make(chan *DataPacket, 100)
	done, readBuffer := mc.done, mc.readBuffer
	mc.mu.Unlock()

	hasRelay := len(mc.RelayAddr.IP) > 0
	plan := planManagedOpen(mc.Mode, hasRelay, mc.EnableDRIAD, mc.Timeout)
	useDRIAD := plan.UseDRIAD

	// Try native multicast first unless the operator asked outright for the
	// tunnel. An unset or absurdly short Timeout used to skip the native attempt
	// entirely (hasRelay && mc.Timeout > 0), which meant a missing configuration
	// value silently removed native multicast — the BLO-28640 defect, in this
	// file rather than conn.go.
	if plan.AttemptNative {
		// Runs outside mc.mu: this is the multi-second call. dialNativeMulticast
		// returns the socket rather than installing it, so the only thing that
		// needs the lock is the handful of assignments below.
		conn, err := mc.dialNativeMulticast(plan.Probe)
		if err == nil {
			mc.mu.Lock()
			if mc.closed {
				// Close ran while we were probing. It could not have seen this
				// socket, so installing it now would strand a live descriptor on
				// a closed connection — drop it here instead.
				mc.mu.Unlock()
				conn.Close()
				return fmt.Errorf("connection closed while opening")
			}
			mc.nativeConn = conn
			mc.localAddr = conn.LocalAddr()
			mc.usingTunnel = false
			mc.mu.Unlock()
			return nil
		}
		if !plan.Probe.TunnelOnFailure {
			// No relay to fall back to, or AMTModeNative: the native failure is
			// the outcome, not a reason to tunnel.
			return err
		}
		// Native multicast failed or the probe timed out, so use the AMT relay.
	}

	// Use RelayManager for AMT tunnel. usingTunnel, rm and sub are installed
	// together in the commit section at the end rather than here, so no reader
	// can observe a connection that claims to be tunnelling before it has a
	// subscription to tunnel through.

	// Build transport config
	transportCfg := TransportConfig{
		RelayAddr: mc.RelayAddr,
		// gatewayOpenTimeout, not mc.Timeout: the operator's relay timeout is
		// also the probe window, and a value too short to complete a round trip
		// to the relay must not become the handshake bound. Production's 50ms did
		// exactly that, so the tunnel replacing native could not come up either.
		Timeout:         gatewayOpenTimeout(mc.Timeout),
		EnableTimestamp: mc.Timestamp,
		MTU:             1500,
		RcvBufBytes:     mc.RcvBufBytes,
		SndBufBytes:     mc.SndBufBytes,
	}
	if mc.IFace != nil {
		transportCfg.MTU = mc.IFace.MTU
	}

	// Get or create RelayManager for this relay
	var config RelayManagerConfig
	if useDRIAD {
		// Use DRIAD discovery
		config = DefaultRelayManagerConfigWithDRIAD(mc.SrcAddr)
		config.DNSServers = mc.DNSServers
	} else {
		config = DefaultRelayManagerConfig(mc.RelayAddr)
	}
	config.TransportConfig = transportCfg

	// For DRIAD, use source address as registry key since relay is unknown
	registryKey := mc.RelayAddr
	if useDRIAD {
		// Use a placeholder key based on source address for DRIAD
		registryKey = net.UDPAddr{
			IP:   mc.SrcAddr.AsSlice(),
			Port: m.DefaultPort,
		}
	}

	rm, err := GetOrCreateRelayManager(registryKey, &config)
	if err != nil {
		return fmt.Errorf("failed to get relay manager: %w", err)
	}

	// Create subscription
	key := SubscriptionKey{
		Source: mc.SrcAddr,
		Group:  mc.GroupAddr,
		Port:   mc.GroupPort,
	}

	sub, err := rm.Subscribe(key, SubscriptionCallbacks{
		OnPacket: func(data []byte, src net.Addr) error {
			select {
			case <-done:
				return nil
			case readBuffer <- &DataPacket{
				Data:      data,
				Source:    src,
				Timestamp: time.Now(),
			}:
			default:
				// Buffer full, drop packet
			}
			return nil
		},
		OnStateChange: func(old, new SubscriptionState) {
			// Could log state changes here
		},
		OnError: func(err error) {
			// Could log errors here
		},
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	mc.mu.Lock()
	if mc.closed {
		// Close ran during the handshake, so it saw a nil sub and could not have
		// unsubscribed this one. Undo it here rather than leaving the relay
		// manager holding a subscription for a closed connection.
		mc.mu.Unlock()
		if unsubErr := rm.Unsubscribe(sub.Key()); unsubErr != nil {
			return fmt.Errorf("connection closed while opening, and unsubscribing failed: %w", unsubErr)
		}
		return fmt.Errorf("connection closed while opening")
	}
	mc.usingTunnel = true
	mc.rm = rm
	mc.sub = sub
	mc.mu.Unlock()

	return nil
}

// IsUsingTunnel returns true if the connection is using AMT tunneling
func (mc *ManagedConn) IsUsingTunnel() bool {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.usingTunnel
}

// ReadFrom reads a packet from the connection
func (mc *ManagedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, nil, fmt.Errorf("connection closed")
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	readBuffer := mc.readBuffer
	done := mc.done
	mc.mu.RUnlock()

	if !usingTunnel && nativeConn != nil {
		n, _, src, err := nativeConn.ReadFrom(p)
		return n, src, err
	}

	// Read from subscription channel
	select {
	case <-done:
		return 0, nil, fmt.Errorf("connection closed")
	case pkt, ok := <-readBuffer:
		if !ok {
			return 0, nil, fmt.Errorf("connection closed")
		}
		n = copy(p, pkt.Data)
		return n, pkt.Source, nil
	}
}

// ReadFromWithControlMessage reads a packet with control message
func (mc *ManagedConn) ReadFromWithControlMessage(buf []byte) (n int, cm *ipv4.ControlMessage, src net.Addr, err error) {
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, nil, nil, fmt.Errorf("connection closed")
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	readBuffer := mc.readBuffer
	done := mc.done
	mc.mu.RUnlock()

	if !usingTunnel && nativeConn != nil {
		return nativeConn.ReadFrom(buf)
	}

	// Read from subscription channel (no control message available for AMT)
	select {
	case <-done:
		return 0, nil, nil, fmt.Errorf("connection closed")
	case pkt, ok := <-readBuffer:
		if !ok {
			return 0, nil, nil, fmt.Errorf("connection closed")
		}
		n = copy(buf, pkt.Data)
		return n, nil, pkt.Source, nil
	}
}

// ReadBatch reads multiple packets efficiently
func (mc *ManagedConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, fmt.Errorf("connection closed")
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	readBuffer := mc.readBuffer
	done := mc.done
	mc.mu.RUnlock()

	if !usingTunnel && nativeConn != nil {
		return nativeConn.ReadBatch(ms, flags)
	}

	// Read from subscription channel
	count := 0
	for i := range ms {
		select {
		case <-done:
			if count > 0 {
				return count, nil
			}
			return 0, fmt.Errorf("connection closed")
		case pkt, ok := <-readBuffer:
			if !ok {
				if count > 0 {
					return count, nil
				}
				return 0, fmt.Errorf("connection closed")
			}
			if len(ms[i].Buffers) == 0 || len(ms[i].Buffers[0]) == 0 {
				continue
			}
			ms[i].N = copy(ms[i].Buffers[0], pkt.Data)
			ms[i].Addr = pkt.Source
			count++
		default:
			// No more packets available
			if count > 0 {
				return count, nil
			}
			// Block for at least one packet
			select {
			case <-done:
				return 0, fmt.Errorf("connection closed")
			case pkt, ok := <-readBuffer:
				if !ok {
					return 0, fmt.Errorf("connection closed")
				}
				if len(ms[i].Buffers) > 0 && len(ms[i].Buffers[0]) > 0 {
					ms[i].N = copy(ms[i].Buffers[0], pkt.Data)
					ms[i].Addr = pkt.Source
					count++
				}
			}
			return count, nil
		}
	}
	return count, nil
}

// WriteTo writes a packet (not supported for AMT tunnel)
func (mc *ManagedConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if mc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if !mc.usingTunnel && mc.nativeConn != nil {
		cm := new(ipv4.ControlMessage)
		return mc.nativeConn.WriteTo(p, cm, addr)
	}

	return 0, fmt.Errorf("write not supported for AMT tunnel")
}

// WriteToWithControlMessage writes a packet with an IPv4 control message.
func (mc *ManagedConn) WriteToWithControlMessage(p []byte, cm *ipv4.ControlMessage, addr net.Addr) (n int, err error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if mc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.WriteTo(p, cm, addr)
	}

	return 0, fmt.Errorf("write not supported for AMT tunnel")
}

// WriteBatch writes multiple packets (not supported for AMT tunnel)
func (mc *ManagedConn) WriteBatch(msg []ipv4.Message, flags int) (int, error) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if mc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.WriteBatch(msg, flags)
	}

	return 0, fmt.Errorf("write not supported for AMT tunnel")
}

// Close closes the connection
func (mc *ManagedConn) Close() error {
	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return nil
	}
	mc.closed = true
	if mc.done != nil {
		close(mc.done)
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	rm := mc.rm
	sub := mc.sub
	mc.mu.Unlock()

	if !usingTunnel && nativeConn != nil {
		return nativeConn.Close()
	}

	// Unsubscribe from RelayManager
	if rm != nil && sub != nil {
		return rm.Unsubscribe(sub.Key())
	}

	return nil
}

// LocalAddr returns the local address
func (mc *ManagedConn) LocalAddr() net.Addr {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.LocalAddr()
	}

	return mc.localAddr
}

// SetDeadline sets the read and write deadlines
func (mc *ManagedConn) SetDeadline(t time.Time) error {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.SetDeadline(t)
	}

	// Deadline handling for AMT would require more complex implementation
	return nil
}

// SetReadDeadline sets the read deadline
func (mc *ManagedConn) SetReadDeadline(t time.Time) error {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.SetReadDeadline(t)
	}

	return nil
}

// SetWriteDeadline sets the write deadline
func (mc *ManagedConn) SetWriteDeadline(t time.Time) error {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.SetWriteDeadline(t)
	}

	return nil
}

// Stats returns connection statistics
func (mc *ManagedConn) Stats() *ManagedConnStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	stats := &ManagedConnStats{
		UsingTunnel: mc.usingTunnel,
	}

	if mc.sub != nil {
		subStats := mc.sub.Stats()
		stats.PacketsReceived = subStats.PacketsReceived
		stats.BytesReceived = subStats.BytesReceived
		stats.LastPacketTime = subStats.LastPacketTime
	}

	if mc.rm != nil {
		rmStats := mc.rm.Stats()
		stats.RelayState = rmStats.State.String()
		stats.ReconnectCount = rmStats.ReconnectCount
		stats.TransportType = string(rmStats.TransportType)
	}

	return stats
}

// ManagedConnStats contains connection statistics
type ManagedConnStats struct {
	UsingTunnel     bool
	PacketsReceived uint64
	BytesReceived   uint64
	LastPacketTime  time.Time
	RelayState      string
	ReconnectCount  uint64
	TransportType   string
}

// RelayManager returns the underlying RelayManager (for advanced use)
func (mc *ManagedConn) RelayManager() *RelayManager {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.rm
}

// Subscription returns the underlying Subscription (for advanced use)
func (mc *ManagedConn) Subscription() *Subscription {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.sub
}
