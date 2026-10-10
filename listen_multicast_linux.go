//go:build linux && !android

package amt

import (
	"errors"
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"
)

// ListenMulticastUDP4 listens for multicast UDP packets sent to gaddr. It binds
// 0.0.0.0 on gaddr's port and receives only the group it joins (see
// IP_MULTICAST_ALL below).
func ListenMulticastUDP4(network string, ifi *net.Interface, saddr netip.Addr, gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, ttl int, flags4 ipv4.ControlFlags, rcvBufBytes int, sndBufBytes int) (*ipv4.PacketConn, error) {

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
		_ = syscall.Close(sock)
		return nil, fmt.Errorf("could not set socket reuseaddr: %w", err)
	}

	// Reuse the port
	const SO_REUSEPORT = 0x0f
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_REUSEPORT, 1); err != nil {
		_ = syscall.Close(sock)
		return nil, fmt.Errorf("could not set socket reuseport: %w", err)
	}

	// Receive only the groups this socket joins. Linux defaults
	// IP_MULTICAST_ALL to 1, which also hands every socket bound to this port
	// any group that another socket on the host joined: one blockcast-shreds
	// --feed per layer, all on :5001, read every layer (BLO-41383). A kernel or
	// sandbox without the option keeps that behaviour rather than failing, and
	// logs it.
	if err := unix.SetsockoptInt(sock, unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); err != nil {
		if !errors.Is(err, unix.ENOPROTOOPT) {
			_ = syscall.Close(sock)
			return nil, fmt.Errorf("could not clear IP_MULTICAST_ALL: %w", err)
		}
		slog.Warn("amt: IP_MULTICAST_ALL unsupported, host-wide delivery stays on: this socket also receives groups other sockets joined on its port",
			"group", gaddr.IP, "port", gaddr.Port)
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
			_ = syscall.Close(sock)
			return nil, fmt.Errorf("failed to set bpf: %w", err)
		}
	}

	// Allow timestamps if needed
	if timestamp {
		if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
				_ = syscall.Close(sock)
				return nil, fmt.Errorf("failed to enable SO_TIMESTAMP: %w", err)
			}
		}
	}

	lsa := syscall.SockaddrInet4{Port: gaddr.Port}
	copy(lsa.Addr[:], net.IPv4zero.To4()) // Bind to 0.0.0.0
	if err := syscall.Bind(sock, &lsa); err != nil {
		_ = syscall.Close(sock)
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
		_ = conn.Close()
		return nil, fmt.Errorf("set multicast interface: %w", err)
	}

	// Optional: Enable multicast loopback if you want to receive your own multicast packets
	if err := conn.SetMulticastLoopback(true); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("could not enable multicast loopback: %w", err)
	}

	// Set multicast TTL
	if err := conn.SetMulticastTTL(ttl); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("could not set multicast TTL: %w", err)
	}

	if err := conn.SetControlMessage(flags4, true); err != nil {
		_ = conn.Close()
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
		_ = conn.Close()
		return nil, fmt.Errorf("join ssg (%s): %w", saddr.String(), err)
	}

	return conn, nil
}
