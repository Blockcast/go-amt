//go:build linux || darwin

package amt

import (
	"net"
	"net/netip"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// dialNativeMulticast joins the multicast group natively, honouring plan for
// whether to prove the join carries traffic before keeping it, and returns the
// socket for its caller to install.
//
// When the plan probes, the packet that proved the path is returned alongside
// the socket rather than discarded, so Open can install it as pending and the
// caller's first read gets it instead of waiting for the next one. A nil packet
// means the plan did not probe; a non-nil one is owed to the caller.
//
// It deliberately returns the socket instead of assigning mc.nativeConn. The
// probe blocks for plan.Window, floored at MinUsefulProbeWindow, so Open runs
// this outside mc.mu and installs the result under the lock afterwards. A helper
// that wrote the field itself would force the entire window inside the exclusive
// section — which is what made Close block for ten seconds (Ally review on
// go-amt#49).
//
// The join is torn down only when the plan actually concludes native is not
// deliverable. It is never dropped on the strength of a window too short to be
// evidence: this path used to apply mc.Timeout literally, so the production 50ms
// closed a healthy socket byte for byte the way conn.go did (BLO-28640).
func (mc *ManagedConn) dialNativeMulticast(plan probePlan) (*ipv4.PacketConn, *pendingPacket, error) {
	addr := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort)
	dstAddr := net.UDPAddrFromAddrPort(addr)
	flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL

	var prog []bpf.RawInstruction
	conn, err := ListenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return nil, nil, err
	}

	if plan.Probe {
		mtu := 1500
		if mc.IFace != nil {
			mtu = mc.IFace.MTU
		}
		var cm *ipv4.ControlMessage
		var src net.Addr
		pkt, native, err := probeNativeTraffic(conn, plan.Window, mtu, func(b []byte) (int, error) {
			n, c, s, err := conn.ReadFrom(b)
			cm, src = c, s
			return n, err
		})
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if !native {
			conn.Close()
			return nil, nil, errNativeProbeTimedOut
		}
		return conn, &pendingPacket{buf: pkt, cm: cm, src: src}, nil
	}

	return conn, nil, nil
}
