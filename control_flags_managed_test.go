//go:build linux || darwin

package amt

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// TestDialNativeMulticastPassesTheExportedControlFlags is the ManagedConn half
// of the guard in control_flags_conn_test.go, and it is a separate file because
// it has to run in a lane that one cannot.
//
// conn.go is tagged `... && cgo && !purego`, so the MulticastConn guard is
// selected only in the cgo lane. managed_conn_native.go is `linux || darwin`,
// which means this join site is the one that ships in the CGO_ENABLED=0 and
// -tags purego builds — precisely where the other guard is absent. Covering
// only the cgo lane would leave the third copy of the flag set unwatched in the
// builds that actually carry it, which is the asymmetry listen_seam.go exists
// to talk about.
//
// Seam is package state, so no t.Parallel.
func TestDialNativeMulticastPassesTheExportedControlFlags(t *testing.T) {
	var got ipv4.ControlFlags
	var seen bool
	orig := listenMulticastUDP4
	listenMulticastUDP4 = func(_ string, _ *net.Interface, _ netip.Addr, _ *net.UDPAddr,
		_ []bpf.RawInstruction, _ bool, _ int, flags ipv4.ControlFlags, _, _ int) (*ipv4.PacketConn, error) {
		got, seen = flags, true
		return nil, errCaptureBindManaged
	}
	t.Cleanup(func() { listenMulticastUDP4 = orig })

	mc := &ManagedConn{
		GroupAddr: netip.MustParseAddr("232.0.0.1"),
		GroupPort: 1234,
		SrcAddr:   netip.MustParseAddr("10.0.0.1"),
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
	}

	// The zero plan does not probe, so dialNativeMulticast returns as soon as
	// the join call comes back.
	if _, _, err := mc.dialNativeMulticast(probePlan{}); !errors.Is(err, errCaptureBindManaged) {
		t.Fatalf("dialNativeMulticast() = %v, want the capturing seam's error: if the "+
			"bind did not come through the seam this test observed nothing", err)
	}

	if !seen {
		t.Fatal("dialNativeMulticast never called the listen seam, so the assertion below is vacuous")
	}
	if got != ControlFlags4 {
		t.Errorf("dialNativeMulticast passed v4 flags %v, want ControlFlags4 (%v): this "+
			"call site has its own copy again, so it can drift from the constant callers "+
			"size their OOB buffers from", got, ControlFlags4)
	}
}

// errCaptureBindManaged mirrors errCaptureBind in control_flags_conn_test.go.
// Not shared: that file is cgo-tagged, and this test runs in lanes where it is
// deselected.
var errCaptureBindManaged = errors.New("control-flag capture: bind refused")
