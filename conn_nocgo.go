//go:build ((!cgo || purego) && !android && !ios) || js || wasm

package amt

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
)

// MulticastConn is a stub for non-CGO builds.
// The real implementation requires CGO for raw multicast socket operations.
// This stub allows packages that reference the type to compile without CGO,
// but all methods return errors indicating CGO is required.
type MulticastConn struct {
	RelayAddr   net.UDPAddr
	SrcAddr     netip.Addr
	GroupAddr   netip.Addr
	GroupPort   uint16
	TTL         int
	IFace       *net.Interface
	Timeout     time.Duration
	Timestamp   bool
	RcvBufBytes int
	SndBufBytes int
}

var errNoCGO = fmt.Errorf("multicast connections require CGO; rebuild with CGO_ENABLED=1")

func (mc *MulticastConn) Open() error                        { return errNoCGO }
func (mc *MulticastConn) IsUsingTunnel() bool                { return false }
func (mc *MulticastConn) Close() error                       { return nil }
func (mc *MulticastConn) LocalAddr() net.Addr                { return nil }
func (mc *MulticastConn) SetDeadline(t time.Time) error      { return errNoCGO }
func (mc *MulticastConn) SetReadDeadline(t time.Time) error  { return errNoCGO }
func (mc *MulticastConn) SetWriteDeadline(t time.Time) error { return errNoCGO }

func (mc *MulticastConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errNoCGO
}

func (mc *MulticastConn) ReadFromWithControlMessage(buf []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	return 0, nil, nil, errNoCGO
}

func (mc *MulticastConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return 0, errNoCGO
}

func (mc *MulticastConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errNoCGO
}

func (mc *MulticastConn) WriteToWithControlMessage(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error) {
	return 0, errNoCGO
}

func (mc *MulticastConn) WriteBatch(msg []ipv4.Message, i int) (int, error) {
	return 0, errNoCGO
}
