//go:build linux || darwin

package amt

import (
	"net"
	"net/netip"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// tryNativeMulticast attempts to join the multicast group natively, honouring
// plan for whether to prove the join carries traffic before keeping it.
//
// The join is torn down only when the plan actually concludes native is not
// deliverable. It is never dropped on the strength of a window too short to be
// evidence: this path used to apply mc.Timeout literally, so the production 50ms
// closed a healthy socket byte for byte the way conn.go did (BLO-28640).
func (mc *ManagedConn) tryNativeMulticast(plan probePlan) error {
	addr := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort)
	dstAddr := net.UDPAddrFromAddrPort(addr)
	flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL

	var prog []bpf.RawInstruction
	conn, err := ListenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return err
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
			return err
		}
		if !native {
			conn.Close()
			return errNativeProbeTimedOut
		}
	}

	mc.nativeConn = conn
	mc.localAddr = conn.LocalAddr()
	return nil
}
