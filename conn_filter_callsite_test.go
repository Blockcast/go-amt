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
	"golang.org/x/net/ipv6"
)

var testFilter = []bpf.RawInstruction{{Op: 0x06, K: 0}} // ret #0

// stubBinds replaces both native binds with stubs that record the filter they
// were handed and stop Open there.
func stubBinds(t *testing.T) (got *[]bpf.RawInstruction, bound *bool, errStop error) {
	t.Helper()
	errStop = errors.New("stop after bind")
	var f []bpf.RawInstruction
	var b bool
	o4, o6 := listenMulticastUDP4, listenMulticastUDP6
	listenMulticastUDP4 = func(_ string, _ *net.Interface, _ netip.Addr, _ *net.UDPAddr,
		p []bpf.RawInstruction, _ bool, _ int, _ ipv4.ControlFlags, _, _ int) (*ipv4.PacketConn, error) {
		f, b = p, true
		return nil, errStop
	}
	listenMulticastUDP6 = func(_ string, _ *net.Interface, _ netip.Addr, _ *net.UDPAddr,
		p []bpf.RawInstruction, _ bool, _ int, _ ipv6.ControlFlags, _, _ int) (*ipv6.PacketConn, error) {
		f, b = p, true
		return nil, errStop
	}
	t.Cleanup(func() { listenMulticastUDP4, listenMulticastUDP6 = o4, o6 })
	return &f, &b, errStop
}

// TestOpenPassesFilterToNativeBind pins that MulticastConn.Filter reaches the
// native bind on both address families (BLO-40191). Before the field existed
// Open passed a literal nil, so a caller sharding one group across sockets had
// no way to attach its per-socket filter.
func TestOpenPassesFilterToNativeBind(t *testing.T) {
	for _, group := range []string{"232.0.0.1", "ff3e::1"} {
		t.Run(group, func(t *testing.T) {
			got, _, errStop := stubBinds(t)
			mc := &MulticastConn{
				GroupAddr: netip.MustParseAddr(group),
				GroupPort: 1234,
				IFace:     &net.Interface{Index: 1, Name: "lo", MTU: 1500},
				Mode:      AMTModeNative,
				Filter:    testFilter,
			}
			if err := mc.Open(); !errors.Is(err, errStop) {
				t.Fatalf("Open err = %v, want the stub's error", err)
			}
			if !reflect.DeepEqual(*got, testFilter) {
				t.Fatalf("bind got filter %v, want %v", *got, testFilter)
			}
		})
	}
}

// TestOpenRejectsFilterThatCouldReachTheTunnel pins that a Filter is refused,
// before any bind, whenever the plan could fall back to the AMT tunnel. The
// tunnel cannot apply the filter, so a shard there would silently receive the
// whole flow (BLO-40191).
func TestOpenRejectsFilterThatCouldReachTheTunnel(t *testing.T) {
	relay := net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 2268}
	for _, tc := range []struct {
		name    string
		mode    AMTMode
		relay   bool
		wantErr bool
	}{
		{"auto+relay", AMTModeAuto, true, true},
		{"tunnel+relay", AMTModeTunnel, true, true},
		{"native+relay", AMTModeNative, true, false},
		{"auto/no-relay", AMTModeAuto, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, bound, errStop := stubBinds(t)
			mc := &MulticastConn{
				GroupAddr: netip.MustParseAddr("232.0.0.1"),
				GroupPort: 1234,
				IFace:     &net.Interface{Index: 1, Name: "lo", MTU: 1500},
				Mode:      tc.mode,
				Filter:    testFilter,
			}
			if tc.relay {
				mc.RelayAddr = relay
			}
			err := mc.Open()
			if tc.wantErr {
				if !errors.Is(err, errFilterNeedsNative) || *bound {
					t.Fatalf("Open err = %v bound = %v, want errFilterNeedsNative and no bind", err, *bound)
				}
				return
			}
			if !errors.Is(err, errStop) {
				t.Fatalf("Open err = %v, want the stub's error (bind reached)", err)
			}
		})
	}
}
