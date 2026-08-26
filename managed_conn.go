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
	openMu sync.Mutex
	// openDone is closed when an in-flight Open reaches a final state. It is
	// what lets the data-plane methods resume against the finished connection
	// instead of a half-built one — see waitOpen for why that is load-bearing.
	openDone    chan struct{}
	closed      bool
	usingTunnel bool
	localAddr   net.Addr

	// For native multicast fallback
	nativeConn *ipv4.PacketConn

	// pending holds the datagram a successful native probe consumed, so the
	// caller's first read gets it instead of waiting a whole signalling interval
	// for the next one. Atomic, so it is outside mu deliberately; see probe.go.
	pending pendingStore
}

// Open initializes the connection, trying native multicast first, then AMT relay
//
// Open can take seconds to return — up to MinUsefulProbeWindow proving the
// native join, plus the relay handshake — but it holds mc.mu only for short
// sections at each end. That split is deliberate: when the probe window ran
// inside the exclusive lock, Close() had to wait the whole window out with no
// cancellation path, and because Go's RWMutex queues new readers behind a
// waiting writer, one pending Close also stalled every IsUsingTunnel/LocalAddr/
// Stats reader for the remainder of it.
//
// Two consequences of that split are worth stating rather than leaving to be
// discovered. The observers — IsUsingTunnel, LocalAddr, Stats — may return a
// provisional value while Open is in flight, which is deliberate: a stale-but-
// immediate answer beats a ten-second stall. The data-plane methods do NOT get
// that treatment; they call waitOpen first, because a reader that snapshots a
// half-built connection can park forever rather than merely read a stale field.
//
// The deadline setters — SetDeadline, SetReadDeadline, SetWriteDeadline — wait
// too. They look like small setters but they belong with the data plane, not the
// observers, because they MUTATE the connection and no provisional answer is
// available to them: racing Open they would find nativeConn nil, fall through to
// the tunnel branch, and return nil having set nothing. Open then installs the
// native socket with no deadline on it, so a caller that opened in a goroutine
// and set a deadline on the main path gets a socket that blocks forever on a
// group that goes idle — and a nil error, so there is nothing to retry on. On
// the tunnel branch returning nil without setting anything remains a documented
// limitation; on the native branch it used to work, because mu was held for the
// whole of Open, and narrowing it exposed these three alongside the six.
//
// Close does not *cancel* an in-flight Open, it marks the connection. The probe
// has no cancellation path plumbed into it, so after Close returns, a concurrent
// Open can still hold the native socket and its IGMP join for the remainder of
// the probe window before noticing and undoing its own work. Nothing leaks and
// every commit point re-checks closed, but a caller cannot treat Close returning
// as proof the join is already gone.
func (mc *ManagedConn) Open() error {
	mc.openMu.Lock()
	defer mc.openMu.Unlock()

	mc.mu.Lock()
	if mc.closed {
		mc.mu.Unlock()
		return fmt.Errorf("connection already closed")
	}
	mc.done = make(chan struct{})
	// Allocated here rather than beside the subscription below, so a Read racing
	// Open cannot select on a nil channel. mc.done goes live in this same
	// section, so a nil buffer would park that reader until Close instead of it
	// simply finding no packets yet.
	mc.readBuffer = make(chan *DataPacket, 100)
	// Must be closed on EVERY exit path below, including the validation errors,
	// or a data-plane call that is waiting on it never wakes. The deferred close
	// immediately after this section is what guarantees that.
	mc.openDone = make(chan struct{})
	done, readBuffer, openDone := mc.done, mc.readBuffer, mc.openDone
	mc.mu.Unlock()
	defer close(openDone)

	if !mc.SrcAddr.Is4() {
		return fmt.Errorf("AMT source address must be IPv4: %s", mc.SrcAddr)
	}
	if !mc.GroupAddr.Is4() {
		return fmt.Errorf("AMT group address must be IPv4: %s", mc.GroupAddr)
	}

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
		conn, pkt, err := mc.dialNativeMulticast(plan.Probe)
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
			// Installed after the lock is dropped: pendingStore is atomic, so it
			// needs no help from mu, and the readers that drain it call waitOpen
			// first — so none of them can look before this line runs.
			if pkt != nil {
				mc.pending.put(pkt)
			}
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

	// Re-check before the expensive relay work. Close cannot interrupt the probe
	// above, but there is no reason to run a full AMT handshake against a
	// connection the caller has already closed just to unsubscribe from it again
	// at the commit point below.
	mc.mu.RLock()
	closedDuringProbe := mc.closed
	mc.mu.RUnlock()
	if closedDuringProbe {
		return fmt.Errorf("connection closed while opening")
	}

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

// waitOpen blocks until an in-flight Open has reached a final state, so a
// data-plane call that races Open resumes against the finished connection
// rather than a half-built one.
//
// This is the serialization mc.mu used to provide for free: Open held the write
// lock for its whole duration, so every RLock below queued behind it and always
// saw the final state. Narrowing that lock — so Close and the health readers
// stop stalling for the probe window — removed the serialization, and without a
// replacement ReadFrom could snapshot usingTunnel=false, nativeConn=nil and then
// park on readBuffer forever: if Open goes on to succeed NATIVELY, nothing ever
// writes readBuffer, because only the tunnel's OnPacket callback does. The
// parked reader would wake only at Close. Allocating readBuffer early avoids a
// select on a nil channel but does not fix that — it is the same hang one line
// further along (Ally review on go-amt#49).
//
// The observers (IsUsingTunnel, LocalAddr, Stats) deliberately do NOT call this.
// Returning a provisional value is better than stalling for them, and unlike a
// blocking read they cannot hang on a half-open connection.
func (mc *ManagedConn) waitOpen() {
	mc.mu.RLock()
	openDone, done := mc.openDone, mc.done
	mc.mu.RUnlock()

	if openDone == nil {
		// Open has never been called on this conn. There is nothing to wait for,
		// and the caller's own closed/nil-conn checks produce the right error.
		return
	}
	select {
	case <-openDone:
	case <-done:
		// Close releases waiters even while Open is still running, so a shutdown
		// is never held up for the remainder of a probe window.
	}
}

// ReadFrom reads a packet from the connection.
//
// On the AMT tunnel path, a zero-length buffer returns (0, nil) without
// consuming the queued packet. A non-zero buffer that is shorter than the
// packet follows net.PacketConn semantics: the packet is consumed and its
// payload is truncated to fit. The native path delegates to the underlying
// connection and retains its standard-library behavior.
func (mc *ManagedConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	mc.waitOpen()
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, nil, fmt.Errorf("connection closed")
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	readBuffer := mc.readBuffer
	done := mc.done
	// Drained inside the read lock, so the closed check above is exact rather
	// than advisory: Close takes the write lock, so it cannot interleave between
	// the two and leave a closed connection serving a packet it still holds. A
	// closed connection owes the caller an error, not a packet.
	//
	pending := mc.pending.take()
	mc.mu.RUnlock()

	if pending != nil {
		return copy(p, pending.buf), pending.src, nil
	}

	if !usingTunnel && nativeConn != nil {
		n, _, src, err := nativeConn.ReadFrom(p)
		return n, src, err
	}
	if len(p) == 0 {
		return 0, nil, nil
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

// ReadFromWithControlMessage reads a packet with control message.
//
// On the AMT tunnel path, a zero-length buffer returns (0, nil, nil) without
// consuming the queued packet. A non-zero buffer that is shorter than the
// packet follows net.PacketConn semantics: the packet is consumed and its
// payload is truncated to fit. The native path delegates to the underlying
// connection and retains its standard-library behavior.
func (mc *ManagedConn) ReadFromWithControlMessage(buf []byte) (n int, cm *ipv4.ControlMessage, src net.Addr, err error) {
	mc.waitOpen()
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, nil, nil, fmt.Errorf("connection closed")
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	readBuffer := mc.readBuffer
	done := mc.done
	// See ReadFrom: taken inside the read lock so the closed check is exact.
	pending := mc.pending.take()
	mc.mu.RUnlock()

	if pending != nil {
		return copy(buf, pending.buf), pending.cm, pending.src, nil
	}

	if !usingTunnel && nativeConn != nil {
		return nativeConn.ReadFrom(buf)
	}
	if len(buf) == 0 {
		return 0, nil, nil, nil
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

// ReadBatch reads multiple packets efficiently.
//
// The return count describes the contiguous filled prefix: exactly ms[:count]
// received a packet, so a caller must iterate that prefix and must not inspect
// ms[count:]. On the tunnel path a message with no room — no Buffers, or a
// zero-length Buffers[0] — ends the batch and returns the count filled so far,
// rather than being skipped over. That keeps the prefix honest and, because a
// packet already taken off the subscription channel cannot be put back, is what
// stops a no-room slot from silently destroying a packet (BLO-29454). A batch
// whose first message has no room therefore reads (0, nil) without consuming
// anything, the same shape as an empty ms.
func (mc *ManagedConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	mc.waitOpen()
	mc.mu.RLock()
	if mc.closed {
		mc.mu.RUnlock()
		return 0, fmt.Errorf("connection closed")
	}
	usingTunnel := mc.usingTunnel
	nativeConn := mc.nativeConn
	readBuffer := mc.readBuffer
	done := mc.done
	// See ReadFrom for why the store is touched inside the read lock. Room is
	// checked first, and a no-room batch only ever peeks: take-then-put-back
	// leaves the store momentarily empty, which lets a concurrent reader fall
	// through to the socket and deliver a later packet ahead of this one.
	//
	// "Room" must include a non-empty *first buffer*, not merely a non-empty
	// Buffers slice: copy into a zero-length buffer moves no bytes, so taking
	// the packet there would return (1, nil) with N=0 and an emptied store —
	// a loss reported as success, and indistinguishable from a legitimately
	// received zero-length datagram. This is the same predicate the
	// subscription path below uses (see the len(ms[i].Buffers[0]) checks).
	var pending *pendingPacket
	pendingWaiting := false
	if len(ms) == 0 || len(ms[0].Buffers) == 0 || len(ms[0].Buffers[0]) == 0 {
		pendingWaiting = mc.pending.peek() != nil
	} else {
		pending = mc.pending.take()
	}
	mc.mu.RUnlock()

	if pendingWaiting {
		// Nowhere to put it. Leave it for the next call rather than drop it.
		return 0, nil
	}
	if pending != nil {
		ms[0].N = copy(ms[0].Buffers[0], pending.buf)
		ms[0].Addr = pending.src
		return 1, nil
	}

	if !usingTunnel && nativeConn != nil {
		return nativeConn.ReadBatch(ms, flags)
	}

	// Read from subscription channel.
	//
	// The room check is deliberately *before* the channel receive, in both arms.
	// A packet taken off readBuffer cannot be put back — unlike the pending
	// store there is nowhere to hold it — so checking room afterwards means a
	// slot that cannot accept the packet has already destroyed it (BLO-29454).
	//
	// A no-room slot returns the short count rather than skipping on to the next
	// slot. count describes the contiguous filled prefix ms[:count], matching
	// ipv4.PacketConn.ReadBatch, and every caller iterates that prefix
	// (cmd/amt_bridge/main.go:155, cmd/amt_gw/main.go:70). Advancing i past an
	// unfilled slot would keep it inside the prefix, so the caller would read a
	// message that never received a packet — amt_bridge would re-emit a
	// zero-length payload — on top of losing the packet the slot consumed.
	count := 0
	for i := range ms {
		if len(ms[i].Buffers) == 0 || len(ms[i].Buffers[0]) == 0 {
			return count, nil
		}
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
	mc.waitOpen()
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
	mc.waitOpen()
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
	mc.waitOpen()
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

// SetDeadline sets the read and write deadlines.
//
// Waits for Open for the reason given on Open: racing it, this would find
// nativeConn nil, fall through, and return nil having set nothing.
func (mc *ManagedConn) SetDeadline(t time.Time) error {
	mc.waitOpen()

	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.SetDeadline(t)
	}

	// Deadline handling for AMT would require more complex implementation
	return nil
}

// SetReadDeadline sets the read deadline. Waits for Open; see SetDeadline.
func (mc *ManagedConn) SetReadDeadline(t time.Time) error {
	mc.waitOpen()

	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if !mc.usingTunnel && mc.nativeConn != nil {
		return mc.nativeConn.SetReadDeadline(t)
	}

	return nil
}

// SetWriteDeadline sets the write deadline. Waits for Open; see SetDeadline.
func (mc *ManagedConn) SetWriteDeadline(t time.Time) error {
	mc.waitOpen()

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
