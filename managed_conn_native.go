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

	var prog []bpf.RawInstruction
	// Through the shared seam, not ListenMulticastUDP4 directly: this call site
	// used to be the unsubstitutable one, so a test could control what
	// MulticastConn's join delivered and had no way to do the same here. See
	// listen_seam.go.
	conn, err := listenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, ControlFlags4, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return nil, nil, err
	}

	if plan.Probe {
		var cm *ipv4.ControlMessage
		var src net.Addr
		pkt, err := mc.probeJoin(conn, plan, func(b []byte) (int, error) {
			n, c, s, err := conn.ReadFrom(b)
			cm, src = c, s
			return n, err
		})
		if err != nil {
			return nil, nil, err
		}
		return conn, &pendingPacket{buf: pkt, cm: cm, src: src}, nil
	}

	return conn, nil, nil
}

// probeJoin waits plan.Window for the native join conn to deliver, through
// read, and returns the datagram that proved it. When nothing arrives, or the
// read fails, it closes conn and says why. Shared by both families' dials.
func (mc *ManagedConn) probeJoin(conn nativeConn, plan probePlan, read func([]byte) (int, error)) ([]byte, error) {
	mtu := 1500
	if mc.IFace != nil {
		mtu = mc.IFace.MTU
	}
	pkt, native, err := probeNativeTraffic(conn, plan.Window, mtu, read)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !native {
		conn.Close()
		return nil, errNativeProbeTimedOut
	}
	return pkt, nil
}
