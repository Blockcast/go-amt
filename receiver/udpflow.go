package receiver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"

	"github.com/blockcast/go-amt/metrics"
)

// UDPFlowConfig configures one connected feed socket. The broker layer owns the
// authorization exchange that establishes the NAT return path.
type UDPFlowConfig struct {
	BindAddress netip.AddrPort
	Remote      netip.AddrPort
	Interface   string
	RcvBufBytes int
}

// OpenUDPFlow connects a local UDP socket to a broker-selected feed endpoint.
// The caller must complete the broker-defined authorization exchange before
// reading shreds; keeping that exchange above this layer avoids freezing its
// wire format or datagram ordering here.
func OpenUDPFlow(ctx context.Context, config UDPFlowConfig) (*net.UDPConn, error) {
	if err := validateUDPFlowConfig(config); err != nil {
		return nil, err
	}

	dialer := net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(config.BindAddress),
	}
	if config.Interface != "" {
		dialer.Control = func(network, address string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(fd uintptr) {
				controlErr = bindToInterface(int(fd), config.Interface)
			}); err != nil {
				return err
			}
			return controlErr
		}
	}

	conn, err := dialer.DialContext(ctx, "udp", config.Remote.String())
	if err != nil {
		return nil, fmt.Errorf("connect UDP feed %s: %w", config.Remote, err)
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("connected UDP feed did not return a UDP socket")
	}
	if err := applyUDPFlowReceiveBuffer(udpConn, config.RcvBufBytes); err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("set UDP feed receive buffer: %w", err)
	}
	return udpConn, nil
}

func validateUDPFlowConfig(config UDPFlowConfig) error {
	if !validLocalAddress(config.BindAddress) {
		return errors.New("UDP feed bind address must be an unspecified, loopback, or unicast IP")
	}
	if !validRemoteAddress(config.Remote) || config.Remote.Port() == 0 {
		return errors.New("UDP feed remote must be a unicast IP with a non-zero port")
	}
	if config.RcvBufBytes <= 0 {
		return errors.New("UDP feed receive buffer must be positive")
	}
	return nil
}

func applyUDPFlowReceiveBuffer(conn *net.UDPConn, bytes int) error {
	got, clamped, err := setUDPFlowReceiveBuffer(conn, bytes)
	if err != nil {
		return err
	}
	if clamped {
		slog.Warn("receiver: UDP feed receive buffer clamped",
			"requested", bytes, "got", got)
		metrics.IncSocketBufferClamped(metrics.BufferKindReceive)
	}
	return nil
}

func validLocalAddress(address netip.AddrPort) bool {
	addr := address.Addr()
	return addr.IsValid() && !addr.IsMulticast() &&
		(addr.IsUnspecified() || addr.IsLoopback() || addr.IsGlobalUnicast())
}

func validRemoteAddress(address netip.AddrPort) bool {
	addr := address.Addr()
	return addr.IsValid() && !addr.IsMulticast() &&
		(addr.IsLoopback() || addr.IsGlobalUnicast())
}
