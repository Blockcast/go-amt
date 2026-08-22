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
	// Timeout is the operator's relay timeout, and it sizes two unrelated things:
	// the native probe window (floored at MinUsefulProbeWindow, because a shorter
	// window is not evidence) and the AMT handshake bound (dropped below
	// MinRelayHandshakeTimeout, so Gateway.Open applies DefaultOpenTimeout
	// instead of failing every handshake).
	//
	// That overloading is what let one bad value break both paths at once in
	// BLO-28640. This is the seam a split into two explicit config keys lands on;
	// multicast-api has since done so (probeWindow + relayHandshakeTimeout, with
	// timeout kept as a deprecated alias seeding both).
	Timeout   time.Duration
	Timestamp bool

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

	if mc.GroupAddr.Is6() {
		// The plan is consulted BEFORE the socket is bound. Binding first made
		// AMTModeTunnel fail closed in its own use case: a bind error returned
		// here, so mc.amtGw was never constructed on precisely the hosts where
		// an operator selects the mode. See probePlan.attemptNative.
		plan := planProbe(mc.Mode, len(mc.RelayAddr.IP) > 0, mc.Timeout)

		if plan.attemptNative() {
			flags6 := ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagHopLimit
			conn, err := ListenMulticastUDP6("udp6", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags6, mc.RcvBufBytes, mc.SndBufBytes)
			if err != nil {
				return fmt.Errorf("failed to create conn %s on %s: %w", addr.String(), mc.IFace.Name, err)
			}
			mc.conn6 = conn

			if plan.Probe {
				var src net.Addr
				pkt, native, err := probeNativeTraffic(mc.conn6, plan.Window, mc.IFace.MTU, func(b []byte) (int, error) {
					n, _, s, err := mc.conn6.ReadFrom(b)
					src = s
					return n, err
				})
				if err != nil {
					return err
				}
				if native {
					// cm stays nil: the v6 read path drops the control message
					// anyway, since ipv6.ControlMessage is a different type.
					mc.pending.put(&pendingPacket{buf: pkt, src: src})
					return nil
				}
			}
			if !plan.TunnelOnFailure {
				return nil
			}

			if err := mc.conn6.Close(); err != nil {
				return err
			}
			mc.conn6 = nil
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
	plan := planProbe(mc.Mode, len(mc.RelayAddr.IP) > 0, mc.Timeout)

	if plan.attemptNative() {
		flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL
		conn, err := listenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
		if err != nil {
			return fmt.Errorf("failed to create conn %s on %s: %w", addr.String(), mc.IFace.Name, err)
		}
		mc.conn4 = conn

		if plan.Probe {
			var cm *ipv4.ControlMessage
			var src net.Addr
			pkt, native, err := probeNativeTraffic(mc.conn4, plan.Window, mc.IFace.MTU, func(b []byte) (int, error) {
				n, c, s, err := mc.conn4.ReadFrom(b)
				cm, src = c, s
				return n, err
			})
			if err != nil {
				return err
			}
			if native {
				mc.pending.put(&pendingPacket{buf: pkt, cm: cm, src: src})
				return nil
			}
		}
		if !plan.TunnelOnFailure {
			return nil
		}

		// Hand the group over to an AMT tunnel. The native join is dropped only here,
		// once the plan has actually concluded native is not deliverable — never on
		// the strength of a window too short to be evidence (BLO-28640).
		if err := mc.conn4.Close(); err != nil {
			return err
		}
		mc.conn4 = nil
	}

	mc.amtGw = &Gateway{
		RelayAddr:   &mc.RelayAddr,
		GroupAddr:   dstAddr.IP,
		MTU:         mc.IFace.MTU,
		RcvBufBytes: mc.RcvBufBytes,
		SndBufBytes: mc.SndBufBytes,
		Timeout:     gatewayOpenTimeout(mc.Timeout),
	}
	if mc.SrcAddr.IsValid() && !mc.SrcAddr.IsUnspecified() {
		mc.amtGw.SourceAddr = mc.SrcAddr.AsSlice()
	}
	if err := mc.amtGw.Open(); err != nil {
		return fmt.Errorf("Error setting up socket: %w", err)
	}
	return nil
}

func (mc *MulticastConn) IsUsingTunnel() bool {
	return mc.amtGw != nil
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
	if err := mc.amtGw.loopErr.Swap(nil); err != nil {
		return 0, err
	}
	N, err := mc.amtGw.conn.ReadBatch(ms, flags)
	if err != nil {
		return 0, fmt.Errorf("error reading from connection: %w", err)
	}
	var i, bad int
	for i = 0; i < N && N > bad; i++ {
		cur := ms[i]
		n := cur.N
		amtMessageType := determineAMTmessageType(cur.Buffers[0])
		switch amtMessageType {
		case m.MulticastDataType:
			mc.amtGw.lastData.Store(time.Now())
			p := gopacket.NewPacket(cur.Buffers[0][m.DataMsgHdrLen:n], layers.LayerTypeIPv4, gopacket.NoCopy)
			ipHdr := p.NetworkLayer().(*layers.IPv4)
			udpHdr, ok := p.TransportLayer().(*layers.UDP)
			if p.ErrorLayer() != nil {
				remainLayer := p.ErrorLayer()
				return i, remainLayer.Error()
			}
			if !ok || !ipHdr.DstIP.Equal(mc.GroupAddr.AsSlice()) {
				bad++
				cur = ms[N-bad]
				ms[N-bad] = cur
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
			err = mc.amtGw.handleMembershipQuery(cur.Buffers[0])
			bad++
			cur = ms[N-bad]
			ms[N-bad] = cur
			i--
		case m.RelayAdvertisementType:
			err = mc.amtGw.handleRelayAdvertisement(cur.Buffers[0])
			bad++
			cur = ms[N-bad]
			ms[N-bad] = cur
			i--
		default:
			bad++
			cur = ms[N-bad]
			ms[N-bad] = cur
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
	if err := mc.amtGw.loopErr.Swap(nil); err != nil {
		return 0, nil, nil, err
	}
	for {
		n, cm, src, err = mc.amtGw.conn.ReadFrom(buf)
		if n == 0 || err != nil {
			return
		}
		amtMessageType := determineAMTmessageType(buf[:])
		data := buf[:n]
		switch amtMessageType {
		case m.RelayAdvertisementType:
			err = mc.amtGw.handleRelayAdvertisement(data)
			n = 0
		case m.MembershipQueryType:
			err = mc.amtGw.handleMembershipQuery(data)
			n = 0
		case m.MulticastDataType:
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
	if !mc.IsUsingTunnel() {
		if c := mc.activeConn(); c != nil {
			return c.Close()
		}
	}
	if mc.amtGw != nil {
		return mc.amtGw.Close()
	}
	return nil
}

func (mc *MulticastConn) LocalAddr() net.Addr {
	if !mc.IsUsingTunnel() {
		return mc.activeConn().LocalAddr()
	}
	return mc.amtGw.conn.LocalAddr()
}

func (mc *MulticastConn) SetDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		return mc.activeConn().SetDeadline(t)
	}
	return mc.amtGw.conn.SetDeadline(t)
}

func (mc *MulticastConn) SetReadDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		return mc.activeConn().SetReadDeadline(t)
	}
	return mc.amtGw.conn.SetReadDeadline(t)
}

func (mc *MulticastConn) SetWriteDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		return mc.activeConn().SetWriteDeadline(t)
	}
	return mc.amtGw.conn.SetWriteDeadline(t)
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
