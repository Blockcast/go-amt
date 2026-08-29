//go:build android || ios

package amt

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
)

var _ net.PacketConn = (*MulticastConn)(nil)

// MulticastConn is the mobile implementation used by gomobile builds. It
// delegates to ManagedConn so native multicast and AMT relay fallback share the
// same code path on Android and iOS.
type MulticastConn struct {
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16
	TTL       int
	IFace     *net.Interface
	// Timeout is deprecated. It seeds ProbeWindow and RelayHandshakeTimeout when
	// either explicit field is unset.
	Timeout               time.Duration
	ProbeWindow           time.Duration
	RelayHandshakeTimeout time.Duration
	Timestamp             bool
	RcvBufBytes           int
	SndBufBytes           int
	// Mode mirrors the cgo build's field so callers can set it under any build
	// configuration without tag-specific code. It is forwarded to ManagedConn
	// below, which is where this build makes the native-vs-tunnel decision.
	Mode AMTMode

	managed *ManagedConn
}

func (mc *MulticastConn) Open() error {
	managed := &ManagedConn{
		RelayAddr:             mc.RelayAddr,
		SrcAddr:               mc.SrcAddr,
		GroupAddr:             mc.GroupAddr,
		GroupPort:             mc.GroupPort,
		TTL:                   mc.TTL,
		IFace:                 mc.IFace,
		Timeout:               mc.Timeout,
		ProbeWindow:           mc.ProbeWindow,
		RelayHandshakeTimeout: mc.RelayHandshakeTimeout,
		Timestamp:             mc.Timestamp,
		RcvBufBytes:           mc.RcvBufBytes,
		SndBufBytes:           mc.SndBufBytes,
		Mode:                  mc.Mode,
	}
	if err := managed.Open(); err != nil {
		return err
	}
	mc.managed = managed
	return nil
}

func (mc *MulticastConn) IsUsingTunnel() bool {
	if mc.managed == nil {
		return false
	}
	return mc.managed.IsUsingTunnel()
}

func (mc *MulticastConn) managedConn() (*ManagedConn, error) {
	if mc.managed == nil {
		return nil, fmt.Errorf("multicast connection is not open")
	}
	return mc.managed, nil
}

func (mc *MulticastConn) ReadFrom(p []byte) (int, net.Addr, error) {
	managed, err := mc.managedConn()
	if err != nil {
		return 0, nil, err
	}
	return managed.ReadFrom(p)
}

func (mc *MulticastConn) ReadFromWithControlMessage(buf []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	managed, err := mc.managedConn()
	if err != nil {
		return 0, nil, nil, err
	}
	return managed.ReadFromWithControlMessage(buf)
}

func (mc *MulticastConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	managed, err := mc.managedConn()
	if err != nil {
		return 0, err
	}
	return managed.ReadBatch(ms, flags)
}

func (mc *MulticastConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	managed, err := mc.managedConn()
	if err != nil {
		return 0, err
	}
	return managed.WriteTo(p, addr)
}

func (mc *MulticastConn) WriteToWithControlMessage(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error) {
	managed, err := mc.managedConn()
	if err != nil {
		return 0, err
	}
	return managed.WriteToWithControlMessage(b, cm, dst)
}

func (mc *MulticastConn) WriteBatch(msg []ipv4.Message, flags int) (int, error) {
	managed, err := mc.managedConn()
	if err != nil {
		return 0, err
	}
	return managed.WriteBatch(msg, flags)
}

func (mc *MulticastConn) Close() error {
	if mc.managed == nil {
		return nil
	}
	return mc.managed.Close()
}

func (mc *MulticastConn) LocalAddr() net.Addr {
	if mc.managed == nil {
		return nil
	}
	return mc.managed.LocalAddr()
}

func (mc *MulticastConn) SetDeadline(t time.Time) error {
	managed, err := mc.managedConn()
	if err != nil {
		return err
	}
	return managed.SetDeadline(t)
}

func (mc *MulticastConn) SetReadDeadline(t time.Time) error {
	managed, err := mc.managedConn()
	if err != nil {
		return err
	}
	return managed.SetReadDeadline(t)
}

func (mc *MulticastConn) SetWriteDeadline(t time.Time) error {
	managed, err := mc.managedConn()
	if err != nil {
		return err
	}
	return managed.SetWriteDeadline(t)
}
