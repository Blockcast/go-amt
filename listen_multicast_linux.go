package amt

import (
	"errors"
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// ListenMulticastUDP4 listens for multicast UDP packets on the given address. This actually binds
// to the IP address given vs the built-in net.ListenMulticastUDP will listen to ALL IP addresses
// regardless of the address you tell it to listen on. The network and address gaddr parameters
// work like any others and if ifname is not specified it lets the OS decide
// which interface to listen on.
func ListenMulticastUDP4(network string, ifi *net.Interface, gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool) (net.PacketConn, error) {

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

	if timestamp {
		// Allow reading of hardware timestamps via socket
		if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
			// If we can't have hardware timestamps - use kernel timestamps
			if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
				return nil, fmt.Errorf("failed to enable SO_TIMESTAMP: %w", err)
			}
		}
	}

	// Attach to specific interface if requested
	if ifi != nil {
		if err := syscall.SetsockoptString(sock, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifi.Name); err != nil {
			return nil, fmt.Errorf("could not bind to interface: %w", err)
		}
	}

	// Bind the socket to the listening IP and Port
	lsa := syscall.SockaddrInet4{Port: gaddr.Port}
	copy(lsa.Addr[:], gaddr.IP.To4())
	if err := syscall.Bind(sock, &lsa); err != nil {
		_ = syscall.Close(sock)
		return nil, fmt.Errorf("could not bind socket: %w", err)
	}

	// Turn the socket file descriptor into an *os.File
	file := os.NewFile(uintptr(sock), "")

	// Turn it into a net.PacketConn
	conn, err := net.FilePacketConn(file)
	file.Close() // We no longer need the file
	if err != nil {
		return nil, fmt.Errorf("could not wrap filepacketconn: %w", err)
	}

	return conn, nil

}
