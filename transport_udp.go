package amt

import (
	"context"
	"net"
	"sync/atomic"
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
	cfg  TransportConfig
	conn *ipv4.PacketConn
	// relayAddr is where Send writes. It starts as cfg.RelayAddr -- the
	// discovery address -- and moves to the advertised relay once one is
	// adopted. Atomic because Send runs on the keepalive goroutine and on
	// Close's while the read loop adopts.
	relayAddr atomic.Pointer[net.UDPAddr]
	cm        *ipv4.ControlMessage
}

// NewUDPTransport creates a new UDP transport
func NewUDPTransport(cfg TransportConfig) (*UDPTransport, error) {
	t := &UDPTransport{cfg: cfg, cm: &ipv4.ControlMessage{}}
	t.relayAddr.Store(&cfg.RelayAddr)
	return t, nil
}

func (t *UDPTransport) Open(ctx context.Context) error {
	// Each connection generation starts from the configured address again.
	// reconnectWithBackoff reuses this transport, and an adopted relay that
	// has since died would otherwise capture every reconnect: the Discovery
	// would go to the dead relay instead of back to the anycast address that
	// could hand us a live one.
	relayAddr := t.cfg.RelayAddr
	t.relayAddr.Store(&relayAddr)

	conn, err := openUDPConn(t.cfg)
	if err != nil {
		return &TransportError{
			Type:    TransportTypeUDP,
			Message: "failed to create packet conn",
			Cause:   err,
		}
	}

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
	_, err := t.conn.WriteTo(data, t.cm, t.relayAddr.Load())
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
	return t.relayAddr.Load()
}

// AdoptAdvertisedRelay redirects Send at the relay the advertisement names,
// so the Request and every keepalive after it reach the relay that actually
// answered rather than the anycast address the Discovery went to. The
// plausibility tests are in advertisedRelayDest, shared with Gateway.
func (t *UDPTransport) AdoptAdvertisedRelay(data []byte) {
	if dest := advertisedRelayDest(data, &t.cfg.RelayAddr); dest != nil {
		t.relayAddr.Store(dest)
	}
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
