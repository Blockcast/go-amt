package txfeed

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// ListenSSM listens on port and joins the SSM channel (source, group) on the
// interface holding ifaceIP.
//
// Go binds the wildcard for a multicast address, so the socket clears
// IP_MULTICAST_ALL or IPV6_MULTICAST_ALL to receive only the channel it joins.
// Linux defaults them to 1, which hands the socket every group the host has
// joined on the port, whatever the socket joined itself. Unicast to the port
// still reaches it.
func ListenSSM(source, group netip.Addr, port int, ifaceIP netip.Addr, rcvbuf int) (*net.UDPConn, error) {
	ifi, err := interfaceWith(ifaceIP)
	if err != nil {
		return nil, err
	}
	network, level, all := "udp4", unix.IPPROTO_IP, unix.IP_MULTICAST_ALL
	if !group.Is4() {
		network, level, all = "udp6", unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_ALL
	}
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = errors.Join(
					unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1),
					unix.SetsockoptInt(int(fd), level, all, 0))
				// SO_RCVBUFFORCE passes net.core.rmem_max but needs
				// CAP_NET_ADMIN; without it, SO_RCVBUF, capped at rmem_max.
				if unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcvbuf) != nil {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf)
				}
			}); err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), network, netip.AddrPortFrom(group, uint16(port)).String())
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	g, s := &net.UDPAddr{IP: group.AsSlice()}, &net.UDPAddr{IP: source.AsSlice()}
	if group.Is4() {
		err = ipv4.NewPacketConn(c).JoinSourceSpecificGroup(ifi, g, s)
	} else {
		err = ipv6.NewPacketConn(c).JoinSourceSpecificGroup(ifi, g, s)
	}
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("SSM join (%s, %s) on %s: %w", source, group, ifi.Name, err)
	}
	return c, nil
}

// EmitSocket returns a UDP socket that sends multicast from src. An IPv4
// socket binds the wildcard and pins IP_MULTICAST_IF to src. An IPv6 socket
// binds src, which fixes the SSM source whatever else the interface holds,
// and pins IPV6_MULTICAST_IF to that interface. A ttl of 0 keeps multicast on
// this host: with loop it reaches local receivers, and it is never
// transmitted.
func EmitSocket(src netip.Addr, ttl int, loop bool) (*net.UDPConn, error) {
	lp := 0
	if loop {
		lp = 1
	}
	ifi, err := interfaceWith(src)
	if err != nil {
		return nil, err
	}
	var uc *net.UDPConn
	if src.Is4() {
		uc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	} else {
		uc, err = net.ListenUDP("udp6", &net.UDPAddr{IP: src.AsSlice()})
	}
	if err != nil {
		return nil, err
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		uc.Close()
		return nil, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		if src.Is4() {
			serr = errors.Join(
				unix.SetsockoptInet4Addr(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_IF, src.As4()),
				unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, ttl),
				unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, lp))
		} else {
			serr = errors.Join(
				unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, ifi.Index),
				unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, ttl),
				unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, lp))
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
	}); err != nil {
		serr = err
	}
	if serr != nil {
		uc.Close()
		return nil, serr
	}
	return uc, nil
}

// interfaceWith returns the interface that holds ip.
func interfaceWith(ip netip.Addr) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for i := range ifs {
		addrs, err := ifs[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if have, ok := netip.AddrFromSlice(n.IP); ok && have.Unmap() == ip.Unmap() {
					return &ifs[i], nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no interface holds %s", ip)
}
