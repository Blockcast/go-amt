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
func (mc *ManagedConn) dialNativeMulticast(plan probePlan) (*ipv4.PacketConn, error) {
	addr := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort)
	dstAddr := net.UDPAddrFromAddrPort(addr)
	flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL

	var prog []bpf.RawInstruction
	// Through the shared seam, not ListenMulticastUDP4 directly: this call site
	// used to be the unsubstitutable one, so a test could control what
	// MulticastConn's join delivered and had no way to do the same here. See
	// listen_seam.go.
	conn, err := listenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return nil, err
	}

	if plan.Probe {
		mtu := 1500
		if mc.IFace != nil {
			mtu = mc.IFace.MTU
		}
		native, err := probeNativeTraffic(conn, plan.Window, mtu, func(b []byte) error {
			_, _, _, err := conn.ReadFrom(b)
			return err
		})
		if err != nil {
			conn.Close()
			return nil, err
		}
		if !native {
			conn.Close()
			return nil, errNativeProbeTimedOut
		}
	}

	return conn, nil
}
