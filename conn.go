//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"fmt"
	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"net/netip"
	"sync"
	"time"
)

var _ net.PacketConn = (*MulticastConn)(nil)

// nativeConn and probeNativeTraffic live in probe.go, which carries no build
// tags so ManagedConn can share them; see the note there.

// listenMulticastUDP4, the seam the v4 group join below goes through, lives in
// listen_seam.go. It is tagged `linux || darwin` rather than declared here so
// ManagedConn's native path — a different tag set, no cgo — reaches the same
// seam instead of calling ListenMulticastUDP4 directly; see the note there.

type MulticastConn struct {
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16
	TTL       int
	IFace     *net.Interface
	// Timeout is deprecated. It seeds ProbeWindow and RelayHandshakeTimeout when
	// either explicit field is unset.
	Timeout time.Duration
	// ProbeWindow controls how long native multicast is probed before fallback.
	ProbeWindow time.Duration
	// RelayHandshakeTimeout bounds the AMT relay handshake.
	RelayHandshakeTimeout time.Duration
	Timestamp             bool

	// RcvBufBytes, if > 0, requests this size on the underlying UDP socket via
	// SetForcedReceiveBuffer (SO_RCVBUFFORCE on Linux, SO_RCVBUF on Darwin).
	// SO_RCVBUFFORCE requires CAP_NET_ADMIN; on EPERM it falls back to
	// SO_RCVBUF, which is capped at 2*net.core.rmem_max.
	RcvBufBytes int
	// SndBufBytes is the send-side counterpart of RcvBufBytes.
	SndBufBytes int

	// Mode selects native-vs-tunnel. The zero value (AMTModeAuto) keeps the
	// historical inference, where a configured RelayAddr makes the native join
	// provisional. Set it explicitly to stop a relay address that was inherited
	// by configuration clone from deciding the delivery path (BLO-28640).
	Mode AMTMode

	conn4 *ipv4.PacketConn
	conn6 *ipv6.PacketConn
	amtGw *Gateway

	pathMu         sync.RWMutex
	activeTunnel   bool
	wantTunnel     bool
	closed         bool
	tunnelReady    chan struct{}
	tunnelStart    chan struct{}
	tunnelDecision chan struct{}
	tunnelDecided  bool

	// pending holds the datagram a successful probe consumed, so the first read
	// after Open returns it instead of the caller waiting a whole signalling
	// interval for the next one. Drained by ReadFromWithControlMessage and
	// ReadBatch; see pendingPacket in probe.go.
	pending pendingStore
}

// activeConn returns the version-agnostic view of whichever native PacketConn
// is currently open (v4 or v6), or nil when neither is set (e.g. AMT tunnel).
func (mc *MulticastConn) activeConn() nativeConn {
	if mc.conn4 != nil {
		return mc.conn4
	}
	if mc.conn6 != nil {
		return mc.conn6
	}
	return nil
}

func (mc *MulticastConn) Open() error {
	var prog []bpf.RawInstruction
	addr := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort)
	dstAddr := net.UDPAddrFromAddrPort(addr)
	probeWindow, _ := resolveTimeouts(mc.Timeout, mc.ProbeWindow, mc.RelayHandshakeTimeout)

	if mc.GroupAddr.Is6() {
		// The plan is consulted BEFORE the socket is bound. Binding first made
		// AMTModeTunnel fail closed in its own use case: a bind error returned
		// here, so mc.amtGw was never constructed on precisely the hosts where
		// an operator selects the mode. See probePlan.attemptNative.
		plan := planProbe(mc.Mode, len(mc.RelayAddr.IP) > 0, probeWindow)

		if plan.attemptNative() {
			flags6 := ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagHopLimit
			conn, err := ListenMulticastUDP6("udp6", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags6, mc.RcvBufBytes, mc.SndBufBytes)
			if err != nil {
				return fmt.Errorf("failed to create conn %s on %s: %w", addr.String(), mc.IFace.Name, err)
			}
			// Publish under pathMu, and only onto a conn that is still open.
			//
			// Close reads conn4/conn6/amtGw under this lock and closes whatever
			// it snapshots; IsUsingTunnel reads them under RLock. amtGw was
			// already written under it in openTunnel; these two native
			// assignments were the only one-sided writes left, so a consumer
			// calling Close while Open was binding raced on the field itself.
			//
			// The mc.closed check closes the wider hole the lock alone leaves. A
			// Close that completes entirely between the bind above and this
			// publish snapshots conn6 as nil and so closes nothing; without the
			// check, this assignment would then hand a live bound socket to a
			// conn nobody will ever close again, leaking the fd and its group
			// membership for the process lifetime while Open still returned nil.
			// openTunnel guards the gateway publication exactly this way, so the
			// native path is no longer the odd one out.
			//
			// These fields are written ONCE, here, under the lock, and are then
			// read WITHOUT it by activeConn, ReadBatch,
			// ReadFromWithControlMessage, WriteToWithControlMessage, WriteBatch,
			// probeNativeV4, probeNativeV6 and watchNativeV4. That is safe only
			// because of write-once plus the happens-before edges from Open's
			// return and from the probe goroutine's start. All three probe/watch
			// readers sit behind that second edge: the publish above happens
			// before the `go mc.probeNative*` below, and watchNativeV4 is reached
			// only through probeNativeV4's synchronous call, so it inherits that
			// edge rather than needing one of its own. A second write — a re-bind,
			// a reconnect, a nil-out on close — would be racy against every one of
			// those readers while looking correct next to this comment.
			//
			// Bind-then-guard is deliberate, and the tests depend on the order. An
			// Open that races a Close therefore performs a real join and
			// immediately leaves: exactly the IGMP join/leave pair for a group
			// nothing here will read that the decide-then-bind ordering otherwise
			// exists to avoid. Testing mc.closed *before* binding would not close
			// the window — Close can still land during the bind — so that pair is
			// the price of closing it completely rather than narrowing it. Do not
			// "optimise" it into an early return: the deterministic guard test
			// asserts the bind seam ran exactly once and fails with "the guard was
			// reached without binding, so this test is vacuous".
			//
			// Scoped, not deferred: prepareTunnel below takes the same
			// non-reentrant lock.
			mc.pathMu.Lock()
			if mc.closed {
				mc.pathMu.Unlock()
				_ = conn.Close()
				return net.ErrClosed
			}
			mc.conn6 = conn
			mc.pathMu.Unlock()

			if plan.TunnelOnFailure {
				mc.prepareTunnel()
				go mc.openTunnel()
			}
			if plan.Probe && plan.TunnelOnFailure {
				go mc.probeNativeV6(plan.Window)
			}
			if !plan.TunnelOnFailure {
				return nil
			}
			return nil
		}

		// Native v6 produced no traffic — or was never attempted, because the
		// operator asked for the tunnel outright — and a tunnel was asked for,
		// but the AMT tunnel data plane is v4-only. Surface a clear error rather
		// than silently falling back to an unsupported path.
		return fmt.Errorf("v6 AMT tunnel fallback not yet supported")
	}

	// Same ordering as the v6 branch above: decide, then bind. An operator who
	// selected AMTModeTunnel never pays for a socket on this path, so the bind
	// can neither fail the tunnel out from under them nor emit an IGMP
	// join/leave pair for a group nothing here will read.
	plan := planProbe(mc.Mode, len(mc.RelayAddr.IP) > 0, probeWindow)

	if plan.attemptNative() {
		flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL
		conn, err := listenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
		if err != nil {
			return fmt.Errorf("failed to create conn %s on %s: %w", addr.String(), mc.IFace.Name, err)
		}
		// See the v6 branch above for the full rationale. In short: publish under
		// pathMu so Close and IsUsingTunnel cannot read this field while Open
		// writes it; refuse to publish onto an already-closed conn so a Close
		// that landed during the bind cannot leak this socket; written once here
		// and read unlocked afterwards, so do not add a second write; bind before
		// testing mc.closed, deliberately, which conn_close_during_open_test.go
		// asserts. Scoped rather than deferred because prepareTunnel takes the
		// same non-reentrant lock.
		mc.pathMu.Lock()
		if mc.closed {
			mc.pathMu.Unlock()
			_ = conn.Close()
			return net.ErrClosed
		}
		mc.conn4 = conn
		mc.pathMu.Unlock()

		if plan.TunnelOnFailure {
			mc.prepareTunnel()
			go mc.openTunnel()
		}
		if plan.Probe && plan.TunnelOnFailure {
			go mc.probeNativeV4(plan.Window)
		}
		if !plan.TunnelOnFailure {
			return nil
		}
		return nil
	}
	return mc.startTunnel()
}

func (mc *MulticastConn) prepareTunnel() {
	mc.pathMu.Lock()
	mc.wantTunnel = true
	// Native delivery remains the preferred path until the probe proves it
	// silent. The AMT opener may run in parallel, but it is only active after
	// arbitration selects it.
	mc.activeTunnel = false
	mc.tunnelReady = make(chan struct{})
	mc.tunnelStart = make(chan struct{})
	mc.tunnelDecision = make(chan struct{})
	mc.tunnelDecided = false
	mc.pathMu.Unlock()
}

func (mc *MulticastConn) startTunnel() error {
	mc.prepareTunnel()
	mc.releaseTunnelStart()
	return mc.openTunnel()
}

func (mc *MulticastConn) probeNativeV4(window time.Duration) {
	var cm *ipv4.ControlMessage
	var src net.Addr
	pkt, native, err := probeNativeTraffic(mc.conn4, window, mc.IFace.MTU, func(b []byte) (int, error) {
		n, c, s, err := mc.conn4.ReadFrom(b)
		cm, src = c, s
		return n, err
	})
	if err != nil {
		mc.setActiveTunnel(true)
		mc.releaseTunnelStart()
		return
	}
	if mc.isClosed() {
		return
	}
	if native {
		mc.pending.put(&pendingPacket{buf: pkt, cm: cm, src: src})
		mc.setActiveTunnel(false)
		mc.releaseTunnelStart()
		return
	}
	mc.pathMu.Lock()
	mc.wantTunnel = true
	mc.activeTunnel = true
	mc.pathMu.Unlock()
	mc.releaseTunnelStart()
	mc.watchNativeV4()
}

func (mc *MulticastConn) probeNativeV6(window time.Duration) {
	var src net.Addr
	pkt, native, err := probeNativeTraffic(mc.conn6, window, mc.IFace.MTU, func(b []byte) (int, error) {
		n, _, s, err := mc.conn6.ReadFrom(b)
		src = s
		return n, err
	})
	if err != nil {
		mc.setActiveTunnel(true)
		mc.releaseTunnelStart()
		return
	}
	if mc.isClosed() {
		return
	}
	if native {
		mc.pending.put(&pendingPacket{buf: pkt, src: src})
		mc.setActiveTunnel(false)
		mc.releaseTunnelStart()
		return
	}
	mc.pathMu.Lock()
	mc.wantTunnel = true
	mc.activeTunnel = true
	mc.pathMu.Unlock()
	mc.releaseTunnelStart()
}

func (mc *MulticastConn) releaseTunnelStart() {
	mc.pathMu.Lock()
	if !mc.tunnelDecided {
		mc.tunnelDecided = true
		if mc.tunnelDecision != nil {
			close(mc.tunnelDecision)
		}
	}
	if mc.tunnelStart != nil {
		close(mc.tunnelStart)
		mc.tunnelStart = nil
	}
	mc.pathMu.Unlock()
}

func (mc *MulticastConn) watchNativeV4() {
	buf := make([]byte, mc.IFace.MTU)
	for !mc.isClosed() && mc.IsUsingTunnel() {
		n, cm, src, err := mc.conn4.ReadFrom(buf)
		if err != nil {
			return
		}
		mc.pending.put(&pendingPacket{buf: append([]byte(nil), buf[:n]...), cm: cm, src: src})
		mc.setActiveTunnel(false)
		return
	}
}

func (mc *MulticastConn) openTunnel() (err error) {
	_, relayHandshakeTimeout := resolveTimeouts(mc.Timeout, mc.ProbeWindow, mc.RelayHandshakeTimeout)
	mc.pathMu.RLock()
	decision := mc.tunnelDecision
	mc.pathMu.RUnlock()
	if decision != nil {
		<-decision
		mc.pathMu.RLock()
		open := !mc.closed && (mc.activeTunnel || (mc.wantTunnel && mc.conn4 == nil && mc.conn6 == nil))
		mc.pathMu.RUnlock()
		if !open {
			mc.pathMu.Lock()
			if mc.tunnelReady != nil {
				close(mc.tunnelReady)
				mc.tunnelReady = nil
			}
			mc.pathMu.Unlock()
			return nil
		}
	}
	defer func() {
		mc.pathMu.Lock()
		if mc.tunnelReady != nil {
			close(mc.tunnelReady)
			mc.tunnelReady = nil
		}
		mc.pathMu.Unlock()
	}()
	dstAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort))

	gw := &Gateway{
		RelayAddr:   &mc.RelayAddr,
		GroupAddr:   dstAddr.IP,
		MTU:         mc.IFace.MTU,
		RcvBufBytes: mc.RcvBufBytes,
		SndBufBytes: mc.SndBufBytes,
		Timeout:     gatewayOpenTimeout(relayHandshakeTimeout),
	}
	if mc.SrcAddr.IsValid() && !mc.SrcAddr.IsUnspecified() {
		gw.SourceAddr = mc.SrcAddr.AsSlice()
	}
	if err := gw.Open(); err != nil {
		gw.abortOpen()
		return err
	}
	mc.pathMu.Lock()
	if mc.closed {
		mc.pathMu.Unlock()
		gw.abortOpen()
		return net.ErrClosed
	}
	mc.amtGw = gw
	// Keep a native-preferred arbitration decision intact when AMT finishes
	// opening first. AMT-only construction has no native socket, so it still
	// becomes active immediately.
	mc.activeTunnel = mc.activeTunnel || (mc.wantTunnel && mc.conn4 == nil && mc.conn6 == nil)
	mc.pathMu.Unlock()
	return nil
}

func (mc *MulticastConn) waitTunnel() *Gateway {
	for {
		mc.pathMu.RLock()
		gw, ready := mc.amtGw, mc.tunnelReady
		mc.pathMu.RUnlock()
		if gw != nil || ready == nil {
			return gw
		}
		<-ready
	}
}

func (mc *MulticastConn) isClosed() bool {
	mc.pathMu.RLock()
	defer mc.pathMu.RUnlock()
	return mc.closed
}

func (mc *MulticastConn) setActiveTunnel(active bool) {
	mc.pathMu.Lock()
	mc.activeTunnel = active
	// A native packet is authoritative for path selection. Clear the tunnel
	// intent as well so an opener racing this decision cannot reactivate AMT
	// when it publishes its gateway.
	mc.wantTunnel = active
	mc.pathMu.Unlock()
}

func (mc *MulticastConn) IsUsingTunnel() bool {
	mc.pathMu.RLock()
	defer mc.pathMu.RUnlock()
	// A gateway-backed connection with no native socket is tunnel-active even
	// when it was constructed by an older call site that did not set the path
	// flag explicitly.
	return mc.activeTunnel || (mc.amtGw != nil && mc.conn4 == nil && mc.conn6 == nil)
}
func (mc *MulticastConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	// A packet the probe consumed is owed to the caller before anything read
	// from the socket, or the stream would be delivered out of order.
	//
	// Room is checked first, and a no-room batch only ever peeks: taking the
	// packet just to put it back leaves the store empty in between, which lets a
	// concurrent reader fall through to the socket and deliver a later packet
	// ahead of this one — the reordering this check exists to prevent.
	//
	// "Room" must include a non-empty *first buffer*, not merely a non-empty
	// Buffers slice: copy into a zero-length buffer moves no bytes, so taking
	// the packet there would return (1, nil) with N=0 and an emptied store — a
	// loss reported as success, and indistinguishable from a legitimately
	// received zero-length datagram. That coupling of "did the path deliver?"
	// to "how big was the payload?" is exactly what the ([]byte, bool, error)
	// probe signature exists to make unrepresentable.
	if len(ms) == 0 || len(ms[0].Buffers) == 0 || len(ms[0].Buffers[0]) == 0 {
		if mc.pending.peek() != nil {
			// Nowhere to put it. Leave it for the next call rather than drop it.
			return 0, nil
		}
	} else if pkt := mc.pending.take(); pkt != nil {
		n := copy(ms[0].Buffers[0], pkt.buf)
		ms[0].N = n
		ms[0].Addr = pkt.src
		return 1, nil
	}
	if !mc.IsUsingTunnel() {
		if mc.conn6 != nil {
			// ipv6.Message and ipv4.Message are both aliases for socket.Message.
			return mc.conn6.ReadBatch(ms, flags)
		}
		return mc.conn4.ReadBatch(ms, flags)
	}
	gw := mc.waitTunnel()
	if gw == nil {
		return 0, net.ErrClosed
	}
	if err := gw.loopErr.Swap(nil); err != nil {
		return 0, err
	}
	N, err := gw.conn.ReadBatch(ms, flags)
	if err != nil {
		return 0, fmt.Errorf("error reading from connection: %w", err)
	}
	return mc.processAMTBatch(gw, ms, N)
}

// processAMTBatch dispatches and compacts the messages returned by an AMT
// socket read. The active portion of ms is [i, N-bad): control and unwanted
// messages are moved to the tail, while the replacement at i is examined on
// the next iteration. Keeping this separate from the socket read makes the
// compaction invariant directly testable without depending on platform-specific
// ReadBatch batching behavior.
func (mc *MulticastConn) processAMTBatch(gw *Gateway, ms []ipv4.Message, N int) (int, error) {
	var i, bad int
	var err error
	// The live portion is [i, N-bad). A dropped message is replaced from the
	// tail and the same index is examined again; shrinking the loop bound with
	// bad is what prevents re-dispatching a message that was already at that
	// tail.
	for i = 0; i < N-bad; i++ {
		cur := ms[i]
		n := cur.N
		// Drop a zero-length datagram before dispatch, and read the type from
		// the bytes actually received rather than from the buffer's stale tail.
		// This is the same guard Gateway.Open carries, for the same reason; it
		// was not mirrored here when the [:n] slicing below was introduced.
		//
		// A zero-length UDP datagram is legal and carries no type byte. Two
		// things then go wrong, and neither is visible in the tests:
		//
		//  1. determineAMTmessageType was handed cur.Buffers[0] UNSLICED, so it
		//     read whatever byte was left at offset 0 of this reused buffer by
		//     an earlier ReadBatch. After any batch that carried an
		//     advertisement (0x02) or a query (0x04), that stale byte routes the
		//     empty datagram into one of the control arms below.
		//  2. Those arms pass cur.Buffers[0][:n] — a len-0 slice — to
		//     handleRelayAdvertisement / handleMembershipQuery, which both take
		//     &data[0] unconditionally to reach the FFI. That panics with
		//     "index out of range [0] with length 0".
		//
		// Before the [:n] change the handlers got the whole caller-allocated
		// buffer, so &data[0] was always valid. A freshly zeroed buffer reads
		// type 0 and falls to default:, which is why a test never sees this.
		//
		// The MulticastDataType arm is covered too: [m.DataMsgHdrLen:n] at n == 0
		// is an invalid slice (low > high) and panics as well. That one predates
		// this change; the same guard closes it.
		if n == 0 {
			bad++
			ms[i] = ms[N-bad]
			i--
			continue
		}
		amtMessageType := determineAMTmessageType(cur.Buffers[0][:n])
		switch amtMessageType {
		case m.MulticastDataType:
			// A data message must carry its 2-byte header. The n == 0 guard
			// above does not cover n == 1: [m.DataMsgHdrLen:n] is then [2:1],
			// low > high, which panics exactly like the zero-length case it
			// was written for. One 1-byte 0x06 datagram on the tunnel socket
			// is enough. RelayManager.routeDataToSubscription already drops
			// these (relay_manager.go:848); this path never did.
			if n < m.DataMsgHdrLen {
				bad++
				ms[i] = ms[N-bad]
				i--
				break
			}
			gw.lastData.Store(time.Now())
			p := gopacket.NewPacket(cur.Buffers[0][m.DataMsgHdrLen:n], layers.LayerTypeIPv4, gopacket.NoCopy)
			ipHdr := p.NetworkLayer().(*layers.IPv4)
			udpHdr, ok := p.TransportLayer().(*layers.UDP)
			if p.ErrorLayer() != nil {
				remainLayer := p.ErrorLayer()
				return i, remainLayer.Error()
			}
			if !ok || !ipHdr.DstIP.Equal(mc.GroupAddr.AsSlice()) {
				bad++
				ms[i] = ms[N-bad]
				i--
				break
			}
			var srcAddr []byte
			if n+4 < cap(cur.Buffers[0]) {
				copy(cur.Buffers[0][n:n+4], ipHdr.SrcIP)
				srcAddr = cur.Buffers[0][n : n+4]
			} else {
				srcAddr = make([]byte, 4)
				copy(srcAddr, ipHdr.SrcIP)
			}
			stream := p.ApplicationLayer()
			ms[i].Addr = &net.UDPAddr{IP: srcAddr, Port: int(udpHdr.DstPort)}
			ms[i].N = len(stream.Payload())
			ms[i].Buffers[0] = stream.Payload()
		case m.MembershipQueryType:
			// [:n], not the whole buffer — see the slicing note in Gateway.Open.
			// The Rust Relay Advertisement decoder matches on EXACT length (12
			// or 24), so handing it a full-MTU buffer makes re-discovery in
			// steady state fail the same way the initial handshake did under
			// BLO-29437. The Query decoder is length-tolerant, but is sliced
			// here too so the "decode what you received" invariant holds
			// uniformly and nobody has to re-derive which decoders forgive
			// padding.
			err = mc.amtGw.handleMembershipQuery(cur.Buffers[0][:n])
			bad++
			ms[i] = ms[N-bad]
			i--
		case m.RelayAdvertisementType:
			err = mc.amtGw.handleRelayAdvertisement(cur.Buffers[0][:n])
			bad++
			ms[i] = ms[N-bad]
			i--
		default:
			bad++
			ms[i] = ms[N-bad]
			i--
			err = fmt.Errorf("unknown data type: %d", amtMessageType) // TODO: see how to handle
			break
		}
	}
	return N - bad, err
}

func (mc *MulticastConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, _, src, err := mc.ReadFromWithControlMessage(p)
	return n, src, err
}
func (mc *MulticastConn) ReadFromWithControlMessage(buf []byte) (n int, cm *ipv4.ControlMessage, src net.Addr, err error) {
	// See ReadBatch: the probe's packet is owed to the caller first.
	if pkt := mc.pending.take(); pkt != nil {
		return copy(buf, pkt.buf), pkt.cm, pkt.src, nil
	}
	if !mc.IsUsingTunnel() {
		if mc.conn6 != nil {
			// Native v6 receive: the v6 control message has a different type, so
			// it is dropped here. Callers only consume cm on the v4 path.
			n, _, src, err = mc.conn6.ReadFrom(buf)
			return n, nil, src, err
		}
		return mc.conn4.ReadFrom(buf)
	}
	gw := mc.waitTunnel()
	if gw == nil {
		return 0, nil, nil, net.ErrClosed
	}
	if err := gw.loopErr.Swap(nil); err != nil {
		return 0, nil, nil, err
	}
	for {
		n, cm, src, err = gw.conn.ReadFrom(buf)
		if n == 0 || err != nil {
			return
		}
		// n >= 1 is guaranteed by the return above, and determineAMTmessageType
		// reads only index 0, so this slice does NOT change today's
		// classification — buf[:] and buf[:n] are identical here for every
		// n >= 1. It is passed anyway so the call site stops depending on that
		// property of the callee: if the type read ever widens past byte 0,
		// this path would otherwise start reading the reused buffer's stale
		// tail while the batch path above stayed correct.
		amtMessageType := determineAMTmessageType(buf[:n])
		data := buf[:n]
		switch amtMessageType {
		case m.RelayAdvertisementType:
			err = gw.handleRelayAdvertisement(data)
			n = 0
		case m.MembershipQueryType:
			err = gw.handleMembershipQuery(data)
			n = 0
		case m.MulticastDataType:
			// Same received-length invariant as the batch path above. The
			// n == 0 return at the top of this loop does not cover n == 1:
			// data[m.DataMsgHdrLen:] is then a low > high slice and panics.
			// Drop the runt and read the next datagram, as the mismatched-group
			// case below does.
			if n < m.DataMsgHdrLen {
				break
			}
			mc.amtGw.lastData.Store(time.Now())
			p := gopacket.NewPacket(data[m.DataMsgHdrLen:], layers.LayerTypeIPv4, gopacket.NoCopy)
			ipHdr := p.NetworkLayer().(*layers.IPv4)
			udpHdr, ok := p.TransportLayer().(*layers.UDP)
			if !ok || !ipHdr.DstIP.Equal(mc.GroupAddr.AsSlice()) {
				break
			}
			stream := p.ApplicationLayer()
			var srcAddr []byte
			if n+4 < cap(data) {
				copy(data[n:n+4], ipHdr.SrcIP)
				srcAddr = data[n : n+4]
			} else {
				srcAddr = make([]byte, 4)
				copy(srcAddr, ipHdr.SrcIP)
			}
			src = &net.UDPAddr{IP: srcAddr, Port: int(udpHdr.DstPort)}
			n = copy(buf, stream.Payload())
			return
		default:
			return 0, cm, nil, fmt.Errorf("unknown data type %d", n)
		}
	}
}

func (mc *MulticastConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	cm := new(ipv4.ControlMessage)
	return mc.WriteToWithControlMessage(p, cm, addr)
}

func (mc *MulticastConn) WriteToWithControlMessage(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (n int, err error) {
	if !mc.IsUsingTunnel() {
		if mc.conn6 != nil {
			// The v4 control message does not apply to the v6 socket.
			return mc.conn6.WriteTo(b, nil, dst)
		}
		return mc.conn4.WriteTo(b, cm, dst)
	}
	return 0, fmt.Errorf("write not implemented for amt gatway")
}

func (mc *MulticastConn) Close() error {
	mc.pathMu.Lock()
	mc.closed = true
	gw := mc.amtGw
	if mc.tunnelStart != nil {
		if !mc.tunnelDecided {
			mc.tunnelDecided = true
			if mc.tunnelDecision != nil {
				close(mc.tunnelDecision)
			}
		}
		close(mc.tunnelStart)
		mc.tunnelStart = nil
	}
	if mc.tunnelReady != nil {
		close(mc.tunnelReady)
		mc.tunnelReady = nil
	}
	conn4, conn6 := mc.conn4, mc.conn6
	mc.pathMu.Unlock()
	var closeErr error
	if conn4 != nil {
		closeErr = conn4.Close()
	}
	if conn6 != nil {
		if err := conn6.Close(); closeErr == nil {
			closeErr = err
		}
	}
	if gw != nil {
		if err := gw.Close(); closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (mc *MulticastConn) LocalAddr() net.Addr {
	if !mc.IsUsingTunnel() {
		if c := mc.activeConn(); c != nil {
			return c.LocalAddr()
		}
		return nil
	}
	if gw := mc.waitTunnel(); gw != nil {
		return gw.conn.LocalAddr()
	}
	return nil
}

func (mc *MulticastConn) SetDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		if c := mc.activeConn(); c != nil {
			return c.SetDeadline(t)
		}
		return net.ErrClosed
	}
	if gw := mc.waitTunnel(); gw != nil {
		return gw.conn.SetDeadline(t)
	}
	return net.ErrClosed
}

func (mc *MulticastConn) SetReadDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		if c := mc.activeConn(); c != nil {
			return c.SetReadDeadline(t)
		}
		return net.ErrClosed
	}
	if gw := mc.waitTunnel(); gw != nil {
		return gw.conn.SetReadDeadline(t)
	}
	return net.ErrClosed
}

func (mc *MulticastConn) SetWriteDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		if c := mc.activeConn(); c != nil {
			return c.SetWriteDeadline(t)
		}
		return net.ErrClosed
	}
	if gw := mc.waitTunnel(); gw != nil {
		return gw.conn.SetWriteDeadline(t)
	}
	return net.ErrClosed
}

func (mc *MulticastConn) WriteBatch(msg []ipv4.Message, i int) (int, error) {
	if !mc.IsUsingTunnel() {
		if mc.conn6 != nil {
			// ipv6.Message and ipv4.Message are both aliases for socket.Message.
			return mc.conn6.WriteBatch(msg, i)
		}
		return mc.conn4.WriteBatch(msg, i)
	}
	return 0, fmt.Errorf("writebatch not implemented for amt gatway")
}
