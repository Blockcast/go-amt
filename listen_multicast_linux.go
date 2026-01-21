//go:build linux && !android

package amt

import (
	"errors"
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// ListenMulticastUDP4 listens for multicast UDP packets on the given address. This actually binds
// to the IP address given vs the built-in net.ListenMulticastUDP will listen to ALL IP addresses
// regardless of the address you tell it to listen on.
func ListenMulticastUDP4(network string, ifi *net.Interface, saddr netip.Addr, gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, ttl int, flags4 ipv4.ControlFlags) (*ipv4.PacketConn, error) {

	if gaddr == nil || gaddr.IP.To4() == nil {
		return nil, errors.New("invalid ipv4 address")
	}

	// Create socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
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

	lsa := syscall.SockaddrInet4{Port: gaddr.Port}
	copy(lsa.Addr[:], net.IPv4zero.To4()) // Bind to 0.0.0.0
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

	conn := ipv4.NewPacketConn(fconn)

	// Set multicast interface for both sending and receiving
	if err := conn.SetMulticastInterface(ifi); err != nil {
		return nil, fmt.Errorf("set multicast interface: %w", err)
	}

	// Optional: Enable multicast loopback if you want to receive your own multicast packets
	if err := conn.SetMulticastLoopback(true); err != nil {
		return nil, fmt.Errorf("could not enable multicast loopback: %w", err)
	}

	// Set multicast TTL
	if err := conn.SetMulticastTTL(ttl); err != nil {
		return nil, fmt.Errorf("could not set multicast TTL: %w", err)
	}

	if err := conn.SetControlMessage(flags4, true); err != nil {
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
