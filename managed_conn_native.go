//go:build (linux || darwin) && !ios && !android

package amt

import (
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// tryNativeMulticast attempts to join the multicast group natively.
func (mc *ManagedConn) tryNativeMulticast() error {
	addr := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort)
	dstAddr := net.UDPAddrFromAddrPort(addr)
	flags4 := ipv4.FlagDst | ipv4.FlagInterface | ipv4.FlagTTL

	var prog []bpf.RawInstruction
	conn, err := ListenMulticastUDP4("udp4", mc.IFace, mc.SrcAddr, dstAddr, prog, mc.Timestamp, mc.TTL, flags4, mc.RcvBufBytes, mc.SndBufBytes)
	if err != nil {
		return err
	}

	// If relay is configured, test if we receive packets.
	if len(mc.RelayAddr.IP) > 0 && mc.Timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(mc.Timeout)); err != nil {
			conn.Close()
			return err
		}
		discard := make([]byte, 1500)
		if mc.IFace != nil {
			discard = make([]byte, mc.IFace.MTU)
		}
		_, _, _, err := conn.ReadFrom(discard)
		if err != nil {
			conn.Close()
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return err // Timeout - need to use AMT.
			}
			return err
		}
		// Reset deadline for normal operation.
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			conn.Close()
			return err
		}
	}

	mc.nativeConn = conn
	mc.localAddr = conn.LocalAddr()
	return nil
}
