package amt

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

func init() {
	RegisterTransport(TransportTypeUDP, func(cfg TransportConfig) (Transport, error) {
		return NewUDPTransport(cfg)
	})
}

// UDPTransport implements Transport using UDP sockets.
// This is the primary transport for all platforms.
type UDPTransport struct {
	cfg       TransportConfig
	conn      *ipv4.PacketConn
	relayAddr *net.UDPAddr
	cm        *ipv4.ControlMessage
}

// NewUDPTransport creates a new UDP transport
func NewUDPTransport(cfg TransportConfig) (*UDPTransport, error) {
	return &UDPTransport{
		cfg:       cfg,
		relayAddr: &cfg.RelayAddr,
		cm:        &ipv4.ControlMessage{},
	}, nil
}

func (t *UDPTransport) Open(ctx context.Context) error {
	// Create UDP socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return &TransportError{
			Type:    TransportTypeUDP,
			Message: "failed to create socket",
			Cause:   err,
		}
	}

	// Enable timestamps if supported
	if t.cfg.EnableTimestamp {
		_ = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
	}

	// Apply forced socket buffers (mirrors Gateway.setupSocket); clamps are
	// logged + counted as non-fatal, real syscall errors abort setup.
	if err := applyForcedBuffers(sock, t.cfg.RcvBufBytes, t.cfg.SndBufBytes); err != nil {
		_ = syscall.Close(sock)
		return &TransportError{
			Type:    TransportTypeUDP,
			Message: "failed to apply socket buffers",
			Cause:   err,
		}
	}

	// Convert socket to PacketConn
	file := os.NewFile(uintptr(sock), "")
	conn, err := net.FilePacketConn(file)
	if err != nil {
		_ = file.Close()
		return &TransportError{
			Type:    TransportTypeUDP,
			Message: "failed to create packet conn",
			Cause:   err,
		}
	}
	_ = file.Close()

	t.conn = ipv4.NewPacketConn(conn)

	// Set read deadline for context cancellation
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetReadDeadline(deadline); err != nil {
			return &TransportError{
				Type:    TransportTypeUDP,
				Message: "failed to set deadline",
				Cause:   err,
			}
		}
	}

	return nil
}

func (t *UDPTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *UDPTransport) Send(data []byte) error {
	if t.conn == nil {
		return &TransportError{
			Type:    TransportTypeUDP,
			Message: "transport not open",
		}
	}
	_, err := t.conn.WriteTo(data, t.cm, t.relayAddr)
	if err != nil {
		return &TransportError{
			Type:    TransportTypeUDP,
			Message: "send failed",
			Cause:   err,
		}
	}
	return nil
}

func (t *UDPTransport) Receive(buf []byte) (n int, addr net.Addr, err error) {
	if t.conn == nil {
		return 0, nil, &TransportError{
			Type:    TransportTypeUDP,
			Message: "transport not open",
		}
	}
	n, _, addr, err = t.conn.ReadFrom(buf)
	return n, addr, err
}

func (t *UDPTransport) SetReadDeadline(deadline time.Time) error {
	if t.conn == nil {
		return nil
	}
	return t.conn.SetReadDeadline(deadline)
}

func (t *UDPTransport) LocalAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.LocalAddr()
}

func (t *UDPTransport) RelayAddr() net.Addr {
	return t.relayAddr
}

func (t *UDPTransport) SupportsTimestamp() bool {
	return t.cfg.EnableTimestamp
}

func (t *UDPTransport) Type() TransportType {
	return TransportTypeUDP
}

// ReadBatch reads multiple messages for efficiency
func (t *UDPTransport) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if t.conn == nil {
		return 0, &TransportError{
			Type:    TransportTypeUDP,
			Message: "transport not open",
		}
	}
	return t.conn.ReadBatch(ms, flags)
}

// WriteBatch writes multiple messages for efficiency
func (t *UDPTransport) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	if t.conn == nil {
		return 0, &TransportError{
			Type:    TransportTypeUDP,
			Message: "transport not open",
		}
	}
	return t.conn.WriteBatch(ms, flags)
}

// Conn returns the underlying ipv4.PacketConn for advanced operations
func (t *UDPTransport) Conn() *ipv4.PacketConn {
	return t.conn
}

// PlatformUDPAvailable returns true - UDP is available on all platforms
func PlatformUDPAvailable() bool {
	return true
}

// CreatePlatformTransport creates UDP transport (the default for all platforms)
func CreatePlatformTransport(cfg TransportConfig) (Transport, error) {
	return NewUDPTransport(cfg)
}
