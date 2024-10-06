package amt

import (
	"fmt"
	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"net"
	"net/netip"
	"time"
)

var _ net.PacketConn = (*MutlicastConn)(nil)

type MutlicastConn struct {
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16
	TTL       int
	IFace     *net.Interface
	Timeout   time.Duration
	Timestamp bool

	conn4 *ipv4.PacketConn
	amtGw *Gateway
}

func (mc *MutlicastConn) Open() error {
	var prog []bpf.RawInstruction
	addr := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort)
	dstAddr := net.UDPAddrFromAddrPort(addr)
	conn, err := ListenMulticastUDP4("udp4", mc.IFace, dstAddr, prog, mc.Timestamp)
	if _, ok := conn.(net.Conn); !ok || err != nil {
		return fmt.Errorf("failed to create conn %s on %s: %s, %w", addr.String(), mc.IFace.Name, conn, err)
	}
	mc.conn4 = ipv4.NewPacketConn(conn)
	flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL
	if mc.SrcAddr.IsValid() && !mc.SrcAddr.IsUnspecified() {
		flags4 |= ipv4.FlagSrc
		srcAddr := &net.IPAddr{
			IP:   mc.SrcAddr.AsSlice(),
			Zone: mc.SrcAddr.Zone(),
		}
		if err := mc.conn4.JoinSourceSpecificGroup(mc.IFace, dstAddr, srcAddr); err != nil {
			return fmt.Errorf("join ssg: %w", err)
		}
	} else {
		err := mc.conn4.JoinGroup(mc.IFace, dstAddr)
		if err != nil {
			return fmt.Errorf("join group: %w", err)
		}
	}

	if err := mc.conn4.SetMulticastInterface(mc.IFace); err != nil {
		return err
	}
	//if err := mc.conn4.SetMulticastLoopback(true); err != nil {
	//	return err
	//}
	if err := mc.conn4.SetMulticastTTL(mc.TTL); err != nil {
		return err
	}
	if err := mc.conn4.SetTTL(mc.TTL); err != nil {
		return err
	}
	if err := mc.conn4.SetControlMessage(flags4, true); err != nil {
		return err
	}

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
				RelayAddr: &mc.RelayAddr,
				GroupAddr: dstAddr.IP,
				MTU:       mc.IFace.MTU,
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

func (mc *MutlicastConn) IsUsingTunnel() bool {
	return mc.amtGw != nil
}
func (mc *MutlicastConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if !mc.IsUsingTunnel() {
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

func (mc *MutlicastConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, _, src, err := mc.ReadFromWithControlMessage(p)
	return n, src, err
}
func (mc *MutlicastConn) ReadFromWithControlMessage(buf []byte) (n int, cm *ipv4.ControlMessage, src net.Addr, err error) {
	if !mc.IsUsingTunnel() {
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

func (mc *MutlicastConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	cm := new(ipv4.ControlMessage)
	return mc.WriteToWithControlMessage(p, cm, addr)
}

func (mc *MutlicastConn) WriteToWithControlMessage(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (n int, err error) {
	if !mc.IsUsingTunnel() {
		return mc.conn4.WriteTo(b, cm, dst)
	}
	return 0, fmt.Errorf("write not implemented for amt gatway")
}

func (mc *MutlicastConn) Close() error {
	if !mc.IsUsingTunnel() && mc.conn4 != nil {
		return mc.conn4.Close()
	}
	if mc.amtGw != nil {
		return mc.amtGw.Close()
	}
	return nil
}

func (mc *MutlicastConn) LocalAddr() net.Addr {
	if !mc.IsUsingTunnel() {
		return mc.conn4.LocalAddr()
	}
	return mc.amtGw.conn.LocalAddr()
}

func (mc *MutlicastConn) SetDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		return mc.conn4.SetDeadline(t)
	}
	return mc.amtGw.conn.SetDeadline(t)
}

func (mc *MutlicastConn) SetReadDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		return mc.conn4.SetReadDeadline(t)
	}
	return mc.amtGw.conn.SetReadDeadline(t)
}

func (mc *MutlicastConn) SetWriteDeadline(t time.Time) error {
	if !mc.IsUsingTunnel() {
		return mc.conn4.SetWriteDeadline(t)
	}
	return mc.amtGw.conn.SetWriteDeadline(t)
}

func (mc *MutlicastConn) WriteBatch(msg []ipv4.Message, i int) (int, error) {
	if !mc.IsUsingTunnel() {
		return mc.conn4.WriteBatch(msg, i)
	}
	return 0, fmt.Errorf("writebatch not implemented for amt gatway")
}
