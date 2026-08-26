//go:build linux || darwin

package amt

import (
	"net"
	"os"
	"syscall"
)

// openUDPConn keeps the raw-socket setup used by the platforms that expose
// the socket options and descriptor types used by the AMT native path.
func openUDPConn(cfg TransportConfig) (net.PacketConn, error) {
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}

	if cfg.EnableTimestamp {
		_ = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
	}
	if err := applyForcedBuffers(sock, cfg.RcvBufBytes, cfg.SndBufBytes); err != nil {
		_ = syscall.Close(sock)
		return nil, err
	}

	file := os.NewFile(uintptr(sock), "")
	conn, err := net.FilePacketConn(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	_ = file.Close()
	return conn, nil
}
