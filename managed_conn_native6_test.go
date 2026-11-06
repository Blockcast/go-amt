//go:build (linux && !android) || (darwin && !ios)

package amt

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TestManagedConnJoinsIPv6GroupNatively opens a ManagedConn on an IPv6 (S,G)
// with no relay and reads and writes through it with each data-plane method. The listenMulticastUDP6 seam
// stands in for the MLDv2 join, which a runner without an IPv6 multicast route
// cannot satisfy, by handing back a [::1] socket the test sends to. It fails if
// Open refuses an IPv6 (S,G), joins through anything but the v6 seam, passes
// the join the wrong (S,G) or flags, or if any read or write method, LocalAddr
// or Close misses the IPv6 socket.
func TestManagedConnJoinsIPv6GroupNatively(t *testing.T) {
	source, group := netip.MustParseAddr("2001:db8::57"), netip.MustParseAddr("ff3e::8000:57")
	var joined *ipv6.PacketConn
	orig := listenMulticastUDP6
	t.Cleanup(func() { listenMulticastUDP6 = orig })
	listenMulticastUDP6 = func(network string, _ *net.Interface, saddr netip.Addr, gaddr *net.UDPAddr, _ []bpf.RawInstruction, _ bool, _ int, flags ipv6.ControlFlags, _, _ int) (*ipv6.PacketConn, error) {
		if network != "udp6" || saddr != source || !gaddr.IP.Equal(group.AsSlice()) || gaddr.Port != 5001 || flags != ControlFlags6 {
			t.Errorf("v6 join (%s, %s, %s, %v), want (udp6, %s, [%s]:5001, ControlFlags6)", network, saddr, gaddr, flags, source, group)
		}
		c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
		if err != nil {
			t.Skipf("no IPv6 loopback: %v", err)
		}
		joined = ipv6.NewPacketConn(c)
		return joined, nil
	}

	mc := &ManagedConn{SrcAddr: source, GroupAddr: group, GroupPort: 5001, Mode: AMTModeNative}
	if err := mc.Open(); err != nil {
		t.Fatalf("Open on an IPv6 (S,G): %v", err)
	}
	if joined == nil {
		t.Fatal("Open never reached the IPv6 join seam")
	}
	if mc.IsUsingTunnel() || mc.LocalAddr().String() != joined.LocalAddr().String() {
		t.Fatalf("tunnel %v, local %v; want native on %v", mc.IsUsingTunnel(), mc.LocalAddr(), joined.LocalAddr())
	}

	sender, err := net.DialUDP("udp6", nil, joined.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if err := mc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}

	// Each read runs in a goroutine, so a method that misses the socket and
	// waits on the tunnel's queue, which no deadline bounds, fails here rather
	// than hanging.
	read := func(method string, f func(buf []byte) (int, net.Addr, error)) {
		t.Helper()
		want := []byte(method)
		if _, err := sender.Write(want); err != nil {
			t.Fatal(err)
		}
		type result struct {
			b    []byte
			from net.Addr
			err  error
		}
		got := make(chan result, 1)
		go func() {
			buf := make([]byte, 64)
			n, from, err := f(buf)
			got <- result{buf[:n], from, err}
		}()
		select {
		case r := <-got:
			if r.err != nil || !bytes.Equal(r.b, want) {
				t.Fatalf("%s = %q, %v; want the datagram sent to the IPv6 socket", method, r.b, r.err)
			}
			if r.from == nil || r.from.String() != sender.LocalAddr().String() {
				t.Errorf("%s source %v, want %v", method, r.from, sender.LocalAddr())
			}
		case <-time.After(6 * time.Second):
			_ = mc.Close()
			t.Fatalf("%s did not read the IPv6 socket", method)
		}
	}
	read("ReadFrom", mc.ReadFrom)
	read("ReadBatch", func(buf []byte) (int, net.Addr, error) {
		ms := []ipv4.Message{{Buffers: [][]byte{buf}}}
		if n, err := mc.ReadBatch(ms, 0); n != 1 || err != nil {
			return 0, nil, fmt.Errorf("read %d messages: %v", n, err)
		}
		return ms[0].N, ms[0].Addr, nil
	})
	read("ReadFromWithControlMessage", func(buf []byte) (int, net.Addr, error) {
		n, cm, from, err := mc.ReadFromWithControlMessage(buf)
		if cm != nil {
			return 0, nil, fmt.Errorf("an ipv4.ControlMessage %v from an IPv6 socket", cm)
		}
		return n, from, err
	})

	// The sender is connected to the IPv6 socket, so it takes only what that
	// socket sends: a write through any other path is not read back.
	to := sender.LocalAddr()
	for _, w := range []struct {
		method string
		write  func([]byte) (int, error)
	}{
		{"WriteTo", func(b []byte) (int, error) { return mc.WriteTo(b, to) }},
		{"WriteToWithControlMessage", func(b []byte) (int, error) { return mc.WriteToWithControlMessage(b, nil, to) }},
		{"WriteBatch", func(b []byte) (int, error) {
			return mc.WriteBatch([]ipv4.Message{{Buffers: [][]byte{b}, Addr: to}}, 0)
		}},
	} {
		if _, err := w.write([]byte(w.method)); err != nil {
			t.Fatalf("%s through the IPv6 socket: %v", w.method, err)
		}
		if err := sender.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := sender.Read(buf)
		if err != nil || string(buf[:n]) != w.method {
			t.Fatalf("%s: the sender read %q, %v; want what was written", w.method, buf[:n], err)
		}
	}

	if err := mc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := joined.WriteTo([]byte("x"), nil, sender.LocalAddr()); err == nil {
		t.Error("the IPv6 socket is still open after Close")
	}
}

// TestManagedConnProbesIPv6Group opens an IPv6 (S,G) the way blockcast-shreds
// opens an ssm:// feed with ?relay=: AMTModeAuto with a relay, the only mode
// that probes the native join. The fake relay is on [::1] and the
// listenMulticastUDP6 seam hands back a [::1] socket, so the test controls
// whether native delivers.
//
// The first subtest fails if the datagram that proved the native join is
// dropped instead of handed to the first read, the defect pendingPacket exists
// to prevent. The second fails if a silent IPv6 join is kept, or if the tunnel
// a ManagedConn falls back to does not deliver IPv6 data. It pays
// MinUsefulProbeWindow once.
func TestManagedConnProbesIPv6Group(t *testing.T) {
	fr := newFakeRelay(t, withIPv6())
	t.Cleanup(func() { _ = CloseRelayManager(fr.Addr()) })

	var nativeSender *net.UDPConn // sends to the joined socket; nil keeps native silent
	deliver := false
	orig := listenMulticastUDP6
	t.Cleanup(func() { listenMulticastUDP6 = orig })
	listenMulticastUDP6 = func(string, *net.Interface, netip.Addr, *net.UDPAddr, []bpf.RawInstruction, bool, int, ipv6.ControlFlags, int, int) (*ipv6.PacketConn, error) {
		c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
		if err != nil {
			return nil, err
		}
		if deliver {
			// Sent before the probe starts: it waits in the socket's buffer
			// until the probe reads it. A failure here fails the join, which
			// the subtest sees as a tunnel it did not expect.
			if nativeSender, err = net.DialUDP("udp6", nil, c.LocalAddr().(*net.UDPAddr)); err == nil {
				_, err = nativeSender.Write([]byte("probe"))
			}
			if err != nil {
				c.Close()
				return nil, err
			}
		}
		return ipv6.NewPacketConn(c), nil
	}
	open := func(t *testing.T) *ManagedConn {
		mc := &ManagedConn{SrcAddr: v6Source, GroupAddr: v6Groups[0], GroupPort: v6Port, RelayAddr: fr.Addr(),
			Timeout: 2 * time.Second, Mode: AMTModeAuto}
		t.Cleanup(func() { _ = mc.Close() })
		if err := mc.Open(); err != nil {
			t.Fatalf("Open: %v", err)
		}
		return mc
	}
	// readFrom reads once, bounded: a tunnel read has no deadline.
	readFrom := func(t *testing.T, mc *ManagedConn) ([]byte, net.Addr) {
		t.Helper()
		type result struct {
			b    []byte
			from net.Addr
			err  error
		}
		got := make(chan result, 1)
		go func() {
			buf := make([]byte, 64)
			n, from, err := mc.ReadFrom(buf)
			got <- result{buf[:n], from, err}
		}()
		select {
		case r := <-got:
			if r.err != nil {
				t.Fatalf("ReadFrom: %v", r.err)
			}
			return r.b, r.from
		case <-time.After(6 * time.Second):
			_ = mc.Close()
			t.Fatal("ReadFrom delivered nothing")
		}
		return nil, nil
	}

	t.Run("native delivers inside the probe window", func(t *testing.T) {
		deliver = true
		mc := open(t)
		if mc.IsUsingTunnel() {
			t.Fatal("tunnelling although native delivered inside the probe window")
		}
		if err := mc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		defer nativeSender.Close()
		b, from := readFrom(t, mc)
		if string(b) != "probe" || from == nil || from.String() != nativeSender.LocalAddr().String() {
			t.Fatalf("first read %q from %v; want the probe's datagram from %v", b, from, nativeSender.LocalAddr())
		}
	})

	t.Run("native silent falls back to the tunnel", func(t *testing.T) {
		deliver = false
		mc := open(t)
		if !mc.IsUsingTunnel() {
			t.Fatal("kept a native IPv6 join that never delivered")
		}
		waitTunnelReady(t, mc, 5*time.Second)
		fr.SendData(v6Source, v6Groups[0], 40000, v6Port, []byte("tunnel"))
		if b, _ := readFrom(t, mc); string(b) != "tunnel" {
			t.Fatalf("read %q through the tunnel, want %q", b, "tunnel")
		}
	})
}
