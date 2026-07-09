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

	// DRIAD discovery configuration (RFC 8777)
	// When EnableDRIAD is true and RelayAddr is empty, discovers relay via DNS
	EnableDRIAD bool
	DNSServers  []string // Optional, uses system default if empty

	// Internal state
	rm          *RelayManager
	sub         *Subscription
	readBuffer  chan *DataPacket
	mu          sync.RWMutex
	closed      bool
	usingTunnel bool
	localAddr   net.Addr

	// For native multicast fallback
	nativeConn *ipv4.PacketConn
}

// Open initializes the connection, trying native multicast first, then AMT relay
func (mc *ManagedConn) Open() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.closed {
		return fmt.Errorf("connection already closed")
	}

	hasRelay := len(mc.RelayAddr.IP) > 0
	useDRIAD := mc.EnableDRIAD && !hasRelay

	// Try native multicast first (if relay timeout is configured)
	if hasRelay && mc.Timeout > 0 {
		if err := mc.tryNativeMulticast(); err == nil {
			mc.usingTunnel = false
			return nil
		}
		// Native multicast failed or timed out, use AMT relay
	} else if !hasRelay && !useDRIAD {
		// No relay or DRIAD discovery configured, use native multicast only.
		return mc.tryNativeMulticast()
	}

	// Use RelayManager for AMT tunnel
	mc.usingTunnel = true

	// Build transport config
	transportCfg := TransportConfig{
		RelayAddr:       mc.RelayAddr,
		Timeout:         mc.Timeout,
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
	mc.rm = rm

	// Create subscription
	key := SubscriptionKey{
		Source: mc.SrcAddr,
		Group:  mc.GroupAddr,
		Port:   mc.GroupPort,
	}

	mc.readBuffer = make(chan *DataPacket, 100)

	sub, err := rm.Subscribe(key, SubscriptionCallbacks{
		OnPacket: func(data []byte, src net.Addr) error {
			select {
			case mc.readBuffer <- &DataPacket{
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
	mc.sub = sub

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
	defer mc.mu.RUnlock()

	if mc.closed {
		return 0, nil, fmt.Errorf("connection closed")
	}

	if !mc.usingTunnel && mc.nativeConn != nil {
		n, _, src, err := mc.nativeConn.ReadFrom(p)
		return n, src, err
	}

	// Read from subscription channel
	select {
	case pkt, ok := <-mc.readBuffer:
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
	defer mc.mu.RUnlock()

	if mc.closed {
		return 0, nil, nil, fmt.Errorf("connection closed")
	}

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.ReadFrom(buf)
	}

	// Read from subscription channel (no control message available for AMT)
	select {
	case pkt, ok := <-mc.readBuffer:
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
	defer mc.mu.RUnlock()

	if mc.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.ReadBatch(ms, flags)
	}

	// Read from subscription channel
	count := 0
	for i := range ms {
		select {
		case pkt, ok := <-mc.readBuffer:
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
			pkt, ok := <-mc.readBuffer
			if !ok {
				return 0, fmt.Errorf("connection closed")
			}
			if len(ms[i].Buffers) > 0 && len(ms[i].Buffers[0]) > 0 {
				ms[i].N = copy(ms[i].Buffers[0], pkt.Data)
				ms[i].Addr = pkt.Source
				count++
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
	defer mc.mu.Unlock()

	if mc.closed {
		return nil
	}
	mc.closed = true

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.Close()
	}

	// Unsubscribe from RelayManager
	if mc.rm != nil && mc.sub != nil {
		return mc.rm.Unsubscribe(mc.sub.Key())
	}

	if mc.readBuffer != nil {
		close(mc.readBuffer)
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
