//go:build linux && !android

package amt

import (
	"errors"
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// ListenMulticastUDP6 is the IPv6 counterpart of ListenMulticastUDP4. It binds
// an AF_INET6 UDP socket and issues a source-specific (MLDv2) join for the
// given (source, group) pair, falling back to an any-source (ASM) join when no
// source is supplied.
func ListenMulticastUDP6(network string, ifi *net.Interface, saddr netip.Addr, gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, hoplimit int, flags6 ipv6.ControlFlags, rcvBufBytes int, sndBufBytes int) (*ipv6.PacketConn, error) {

	if gaddr == nil || gaddr.IP.To4() != nil || gaddr.IP.To16() == nil {
		return nil, errors.New("invalid ipv6 address")
	}

	// Create socket
	sock, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("could not get socket: %w", err)
	}

	// Reuse the address
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("could not set socket reuseaddr: %w", err)
	}

	// Reuse the port
	const SO_REUSEPORT = 0x0f
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_REUSEPORT, 1); err != nil {
		return nil, fmt.Errorf("could not set socket reuseport: %w", err)
	}

	if err := applyForcedBuffers(sock, rcvBufBytes, sndBufBytes); err != nil {
		_ = syscall.Close(sock)
		return nil, err
	}

	// Apply BPF filter if needed
	if len(f) > 0 {
		prog := unix.SockFprog{
			Len:    uint16(len(f)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&f[0])),
		}
		b := (*[unix.SizeofSockFprog]byte)(unsafe.Pointer(&prog))[:unix.SizeofSockFprog]
		err := syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, string(b))
		if err != nil {
			return nil, fmt.Errorf("failed to set bpf: %w", err)
		}
	}

	// Allow timestamps if needed
	if timestamp {
		if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
				return nil, fmt.Errorf("failed to enable SO_TIMESTAMP: %w", err)
			}
		}
	}

	lsa := syscall.SockaddrInet6{Port: gaddr.Port}
	// Bind to in6addr_any ([::]); lsa.Addr stays zeroed.
	if ifi != nil {
		lsa.ZoneId = uint32(ifi.Index)
	}
	if err := syscall.Bind(sock, &lsa); err != nil {
		return nil, fmt.Errorf("could not bind socket: %w", err)
	}

	// Convert the file descriptor into an *os.File and then into net.PacketConn
	file := os.NewFile(uintptr(sock), "")
	fconn, err := net.FilePacketConn(file)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("could not wrap filepacketconn: %w", err)
	}

	conn := ipv6.NewPacketConn(fconn)

	// Set multicast interface for both sending and receiving
	if err := conn.SetMulticastInterface(ifi); err != nil {
		return nil, fmt.Errorf("set multicast interface: %w", err)
	}

	// Optional: Enable multicast loopback if you want to receive your own multicast packets
	if err := conn.SetMulticastLoopback(true); err != nil {
		return nil, fmt.Errorf("could not enable multicast loopback: %w", err)
	}

	// Set multicast hop limit (the IPv6 analogue of the IPv4 multicast TTL)
	if err := conn.SetMulticastHopLimit(hoplimit); err != nil {
		return nil, fmt.Errorf("could not set multicast hop limit: %w", err)
	}

	if err := conn.SetControlMessage(flags6, true); err != nil {
		return nil, err
	}

	// Join the multicast group or source-specific group
	if saddr.IsValid() && !saddr.IsUnspecified() {
		srcAddr := &net.IPAddr{
			IP:   saddr.AsSlice(),
			Zone: saddr.Zone(),
		}
		err = conn.JoinSourceSpecificGroup(ifi, gaddr, srcAddr)
	} else {
		err = conn.JoinGroup(ifi, gaddr)
	}
	if err != nil {
		return nil, fmt.Errorf("join ssg (%s): %w", saddr.String(), err)
	}

	return conn, nil
}
