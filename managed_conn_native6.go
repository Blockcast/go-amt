//go:build (linux && !android) || (darwin && !ios)

package amt

import (
	"net"
	"net/netip"

	"golang.org/x/net/ipv6"
)

// dialNativeMulticast6 is dialNativeMulticast for an IPv6 group: an MLDv2
// source-specific join through the listenMulticastUDP6 seam, probed the same
// way. It has dialNativeMulticast's contract, and the pending packet it returns
// carries no control message, an ipv6.ControlMessage being of another type.
//
// Tagged as the seam is: ListenMulticastUDP6 has no mobile implementation, so
// android and ios take managed_conn_non_native6.go.
func (mc *ManagedConn) dialNativeMulticast6(plan probePlan) (*ipv6.PacketConn, *pendingPacket, error) {
	dstAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort))
	conn, err := listenMulticastUDP6("udp6", mc.IFace, mc.SrcAddr, dstAddr, nil, mc.Timestamp, mc.TTL, ControlFlags6, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return nil, nil, err
	}
	if !plan.Probe {
		return conn, nil, nil
	}
	var src net.Addr
	pkt, err := mc.probeJoin(conn, plan, func(b []byte) (int, error) {
		n, _, s, err := conn.ReadFrom(b)
		src = s
		return n, err
	})
	if err != nil {
		return nil, nil, err
	}
	return conn, &pendingPacket{buf: pkt, src: src}, nil
}
