//go:build android || ios

package amt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// ListenMulticastUDP4 listens for IPv4 multicast on mobile platforms using
// Go's UDP socket path plus x/net/ipv4 multicast controls. The desktop
// implementation uses raw socket setup and optional BPF attachment; those are
// not suitable for gomobile targets.
func ListenMulticastUDP4(network string, ifi *net.Interface, saddr netip.Addr, gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, ttl int, flags4 ipv4.ControlFlags, rcvBufBytes int, sndBufBytes int) (*ipv4.PacketConn, error) {
	if gaddr == nil || gaddr.IP.To4() == nil {
		return nil, errors.New("invalid ipv4 address")
	}
	if len(f) > 0 {
		return nil, fmt.Errorf("mobile native multicast does not support BPF filters")
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				controlErr = applyForcedBuffers(int(fd), rcvBufBytes, sndBufBytes)
				if controlErr != nil || !timestamp {
					return
				}
				// Best effort only: packet timestamps are an optimization for
				// desktop diagnostics and are not required for mobile receive.
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), network, gaddr.String())
	if err != nil {
		return nil, fmt.Errorf("could not listen multicast udp: %w", err)
	}

	conn := ipv4.NewPacketConn(pc)
	closeOnErr := func(err error) (*ipv4.PacketConn, error) {
		_ = conn.Close()
		return nil, err
	}

	if ifi != nil {
		if err := conn.SetMulticastInterface(ifi); err != nil {
			return closeOnErr(fmt.Errorf("set multicast interface: %w", err))
		}
	}
	if err := conn.SetMulticastLoopback(true); err != nil {
		return closeOnErr(fmt.Errorf("could not enable multicast loopback: %w", err))
	}
	if err := conn.SetMulticastTTL(ttl); err != nil {
		return closeOnErr(fmt.Errorf("could not set multicast TTL: %w", err))
	}
	if flags4 != 0 {
		if err := conn.SetControlMessage(flags4, true); err != nil {
			return closeOnErr(err)
		}
	}

	if saddr.IsValid() && !saddr.IsUnspecified() {
		srcAddr := &net.IPAddr{
			IP:   saddr.AsSlice(),
			Zone: saddr.Zone(),
		}
		if err := conn.JoinSourceSpecificGroup(ifi, gaddr, srcAddr); err == nil {
			return conn, nil
		} else if !canFallbackToASM(err) {
			return closeOnErr(fmt.Errorf("join ssg (%s): %w", saddr.String(), err))
		}
	}

	if err := conn.JoinGroup(ifi, gaddr); err != nil {
		return closeOnErr(fmt.Errorf("join group: %w", err))
	}

	return conn, nil
}

func canFallbackToASM(err error) bool {
	return errors.Is(err, syscall.ENOPROTOOPT) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EINVAL)
}
