//go:build !cgo || ios || android || js || wasm

package amt

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/ipv4"
)

// MutlicastConn is a stub for non-CGO builds.
// The real implementation requires CGO for raw multicast socket operations.
// This stub allows packages that reference the type to compile without CGO,
// but all methods return errors indicating CGO is required.
type MutlicastConn struct {
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16
	TTL       int
	IFace     *net.Interface
	Timeout   time.Duration
	Timestamp bool
}

var errNoCGO = fmt.Errorf("multicast connections require CGO; rebuild with CGO_ENABLED=1")

func (mc *MutlicastConn) Open() error                        { return errNoCGO }
func (mc *MutlicastConn) IsUsingTunnel() bool                { return false }
func (mc *MutlicastConn) Close() error                       { return nil }
func (mc *MutlicastConn) LocalAddr() net.Addr                { return nil }
func (mc *MutlicastConn) SetDeadline(t time.Time) error      { return errNoCGO }
func (mc *MutlicastConn) SetReadDeadline(t time.Time) error  { return errNoCGO }
func (mc *MutlicastConn) SetWriteDeadline(t time.Time) error { return errNoCGO }

func (mc *MutlicastConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, nil, errNoCGO
}

func (mc *MutlicastConn) ReadFromWithControlMessage(buf []byte) (int, *ipv4.ControlMessage, net.Addr, error) {
	return 0, nil, nil, errNoCGO
}

func (mc *MutlicastConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	return 0, errNoCGO
}

func (mc *MutlicastConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return 0, errNoCGO
}

func (mc *MutlicastConn) WriteToWithControlMessage(b []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error) {
	return 0, errNoCGO
}

func (mc *MutlicastConn) WriteBatch(msg []ipv4.Message, i int) (int, error) {
	return 0, errNoCGO
}
