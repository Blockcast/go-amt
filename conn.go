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

// nativeConn is the subset of methods shared by *ipv4.PacketConn and
// *ipv6.PacketConn that the non-data-plane bookkeeping (Close, deadlines,
// local address) needs, independent of the IP version's control-message type.
type nativeConn interface {
	Close() error
	LocalAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type MulticastConn struct {
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16
	TTL       int
	IFace     *net.Interface
	Timeout   time.Duration
	Timestamp bool

	// RcvBufBytes, if > 0, requests this size on the underlying UDP socket via
	// SetForcedReceiveBuffer (SO_RCVBUFFORCE on Linux, SO_RCVBUF on Darwin).
	// SO_RCVBUFFORCE requires CAP_NET_ADMIN; on EPERM it falls back to
	// SO_RCVBUF, which is capped at 2*net.core.rmem_max.
	RcvBufBytes int
	// SndBufBytes is the send-side counterpart of RcvBufBytes.
	SndBufBytes int

	conn4 *ipv4.PacketConn
	conn6 *ipv6.PacketConn
	amtGw *Gateway
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
		flags6 := ipv6.FlagDst | ipv6.FlagInterface | ipv6.FlagHopLimit
		conn, err := ListenMulticastUDP6("udp6", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags6, mc.RcvBufBytes, mc.SndBufBytes)
		if err != nil {
			return fmt.Errorf("failed to create conn %s on %s: %w", addr.String(), mc.IFace.Name, err)
		}
		mc.conn6 = conn

		if len(mc.RelayAddr.IP) > 0 {
			if err = mc.conn6.SetReadDeadline(time.Now().Add(mc.Timeout)); err != nil {
				return err
			}
			discard := make([]byte, mc.IFace.MTU)
			n, _, _, err := mc.conn6.ReadFrom(discard)
			_ = n
			if err, ok := err.(net.Error); ok && err.Timeout() {
				if err := mc.conn6.Close(); err != nil {
					return err
				}
				mc.conn6 = nil
				// Native v6 join produced no traffic and a relay is configured,
				// but the AMT tunnel data plane is v4-only. Surface a clear error
				// rather than silently falling back to an unsupported path.
				return fmt.Errorf("v6 AMT tunnel fallback not yet supported")
			} else if err != nil {
				return err
			} else {
				return mc.conn6.SetReadDeadline(time.Time{})
			}
		}
		return nil
	}

	flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL
	conn, err := ListenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return fmt.Errorf("failed to create conn %s on %s: %w", addr.String(), mc.IFace.Name, err)
	}
	mc.conn4 = conn

	if len(mc.RelayAddr.IP) > 0 {
		if err = mc.conn4.SetReadDeadline(time.Now().Add(mc.Timeout)); err != nil {
			return err
		}
		discard := make([]byte, mc.IFace.MTU)
		n, _, _, err := mc.conn4.ReadFrom(discard)
		_ = n
		if err, ok := err.(net.Error); ok && err.Timeout() {
			if err := mc.conn4.Close(); err != nil {
				return err
			}
			mc.amtGw = &Gateway{
				RelayAddr:   &mc.RelayAddr,
				GroupAddr:   dstAddr.IP,
				MTU:         mc.IFace.MTU,
				RcvBufBytes: mc.RcvBufBytes,
				SndBufBytes: mc.SndBufBytes,
				Timeout:     mc.Timeout,
			}
			if mc.SrcAddr.IsValid() && !mc.SrcAddr.IsUnspecified() {
				mc.amtGw.SourceAddr = mc.SrcAddr.AsSlice()
			}
			if err := mc.amtGw.Open(); err != nil {
				return fmt.Errorf("Error setting up socket: %w", err)
			}
		} else if err != nil {
			return err
		} else {
			return mc.conn4.SetReadDeadline(time.Time{})
		}
	}
	return nil
}

func (mc *MulticastConn) IsUsingTunnel() bool {
	return mc.amtGw != nil
}
func (mc *MulticastConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
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

var _ int = "deliberate type error: BLO-28739 negative control"
