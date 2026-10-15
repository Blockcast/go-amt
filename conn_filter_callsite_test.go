//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// TestOpenPassesFilterToNativeBind pins that MulticastConn.Filter reaches the
// native bind (BLO-40191). Before the field existed Open passed a literal nil,
// so a caller sharding one group across sockets had no way to attach its
// per-socket filter.
func TestOpenPassesFilterToNativeBind(t *testing.T) {
	want := []bpf.RawInstruction{{Op: 0x06, K: 0}} // ret #0
	errStop := errors.New("stop after bind")
	var got []bpf.RawInstruction
	orig := listenMulticastUDP4
	listenMulticastUDP4 = func(_ string, _ *net.Interface, _ netip.Addr, _ *net.UDPAddr,
		f []bpf.RawInstruction, _ bool, _ int, _ ipv4.ControlFlags, _, _ int) (*ipv4.PacketConn, error) {
		got = f
		return nil, errStop
	}
	t.Cleanup(func() { listenMulticastUDP4 = orig })

	mc := &MulticastConn{
		GroupAddr: netip.MustParseAddr("232.0.0.1"),
		GroupPort: 1234,
		IFace:     &net.Interface{Index: 1, Name: "lo", MTU: 1500},
		Mode:      AMTModeNative,
		Filter:    want,
	}
	if err := mc.Open(); !errors.Is(err, errStop) {
		t.Fatalf("Open err = %v, want the stub's error", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bind got filter %v, want %v", got, want)
	}
}
