package amt

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The frames in testdata are real txframes from a receive-only native capture
// of shred-txfeed on 2026-10-13: 69.25.95.57 -> 232.0.3.1:5003 (non-vote) and
// 232.0.3.21:5003 (jupiter-v6). 101 of 600 non-vote and 34 of 300 Jupiter
// frames were over 1,472 B, so the source fragments them. No test here leaves
// the process except through loopback, to the in-process fake relay.

var (
	fragSource = netip.MustParseAddr("69.25.95.57")
	fragGroup  = netip.MustParseAddr("232.0.3.1")
)

const fragPort = 5003

func txframe(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ipv4UDP wraps payload in IPv4/UDP from fragSource to fragGroup:fragPort.
func ipv4UDP(t *testing.T, id uint16, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Id: id, Protocol: layers.IPProtocolUDP,
		SrcIP: fragSource.AsSlice(), DstIP: fragGroup.AsSlice()}
	udp := &layers.UDP{SrcPort: 40000, DstPort: fragPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fragmentIPv4 splits an IPv4 packet with a 20-byte header into fragments of
// at most mtu bytes, as a router on a path of that MTU would (RFC 791).
func fragmentIPv4(pkt []byte, mtu int) [][]byte {
	hdr, data := pkt[:20], pkt[20:]
	step := (mtu - 20) &^ 7
	var out [][]byte
	for off := 0; off < len(data); off += step {
		chunk := data[off:min(off+step, len(data))]
		f := append(append([]byte(nil), hdr...), chunk...)
		ff := uint16(off / 8)
		if off+len(chunk) < len(data) {
			ff |= 0x2000 // MF
		}
		binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
		binary.BigEndian.PutUint16(f[6:8], ff)
		binary.BigEndian.PutUint16(f[10:12], 0)
		binary.BigEndian.PutUint16(f[10:12], onesComplementChecksum(f[:20]))
		out = append(out, f)
	}
	return out
}

// amtData is an AMT Multicast Data message carrying ip.
func amtData(ip []byte) []byte {
	return append([]byte{byte(m.MulticastDataType), 0}, ip...)
}

// subscribed is a RelayManager with active subscriptions to fragGroup on
// fragPort and on port 0, so a payload is caught whatever port it claims.
func subscribed(t *testing.T) (*RelayManager, *Subscription) {
	t.Helper()
	rm := NewRelayManager(DefaultRelayManagerConfig(net.UDPAddr{}))
	var sub *Subscription
	for _, port := range []uint16{fragPort, 0} {
		key := SubscriptionKey{Source: fragSource, Group: fragGroup, Port: port}
		s := &Subscription{key: key, dataChan: make(chan *DataPacket, 16)}
		s.state.Store(SubscriptionStateActive)
		rm.subscriptions.Store(key, s)
		if sub == nil {
			sub = s
		} else {
			// Both deliver into one channel, so a test reads one place.
			s.dataChan = sub.dataChan
		}
	}
	return rm, sub
}

func delivered(sub *Subscription) [][]byte {
	var got [][]byte
	for {
		select {
		case p := <-sub.dataChan:
			got = append(got, p.Data)
		default:
			return got
		}
	}
}

func route(rm *RelayManager, ips ...[]byte) {
	for _, ip := range ips {
		rm.routeDataToSubscription(amtData(ip))
	}
}

func reversed(s [][]byte) [][]byte {
	r := make([][]byte, len(s))
	for i, b := range s {
		r[len(s)-1-i] = b
	}
	return r
}

func TestFragmentedTxframesReassemble(t *testing.T) {
	for _, name := range []string{"txframe-nonvote-3394.bin", "txframe-jupiter-2102.bin"} {
		frame := txframe(t, name)
		frags := fragmentIPv4(ipv4UDP(t, 0x4242, frame), 1480)
		if len(frags) < 2 {
			t.Fatalf("%s: %d fragments; the fixture should need several", name, len(frags))
		}
		dup := append([][]byte{frags[0]}, frags...)
		for order, in := range map[string][][]byte{"in order": frags, "reversed": reversed(frags), "duplicate": dup} {
			rm, sub := subscribed(t)
			route(rm, in...)
			got := delivered(sub)
			if len(got) != 1 || !bytes.Equal(got[0], frame) {
				t.Errorf("%s %s: delivered %d datagrams, want the %d-byte frame once, byte-identical", name, order, len(got), len(frame))
			}
			if s := rm.Stats().Decap; s.Fragments != uint64(len(in)) || s.Reassembled != 1 || s.ReassemblyInvalid != 0 {
				t.Errorf("%s %s: stats %+v", name, order, s)
			}
		}
	}
}

func TestUnfragmentedTxframeUnchanged(t *testing.T) {
	frame := txframe(t, "txframe-nonvote-small.bin")
	rm, sub := subscribed(t)
	route(rm, ipv4UDP(t, 1, frame))
	if got := delivered(sub); len(got) != 1 || !bytes.Equal(got[0], frame) {
		t.Fatalf("delivered %d datagrams, want the %d-byte frame once", len(got), len(frame))
	}
	if s := rm.Stats().Decap; s != (DecapStats{}) {
		t.Errorf("an unfragmented datagram moved a counter: %+v", s)
	}
}

// TestMissingFragmentExpires: the datagram is never delivered, and its
// reassembly is counted expired once the timeout passes.
func TestMissingFragmentExpires(t *testing.T) {
	frags := fragmentIPv4(ipv4UDP(t, 7, txframe(t, "txframe-nonvote-3394.bin")), 1480)
	var d decapsulator
	t0 := time.Unix(1_000_000, 0)
	for _, f := range [][]byte{frags[0], frags[2]} {
		if _, ok := d.decap(f, t0); ok {
			t.Fatal("an incomplete datagram was delivered")
		}
	}
	// The missing fragment arrives too late: it must not complete the old
	// fragments, only start a reassembly of its own.
	if _, ok := d.decap(frags[1], t0.Add(reassemblyTimeout+time.Millisecond)); ok {
		t.Fatal("a fragment completed a reassembly that had expired")
	}
	if s := d.stats(); s.ReassemblyExpired != 1 || s.Reassembled != 0 {
		t.Errorf("stats %+v, want one expired reassembly", s)
	}
	if len(d.pending) != 1 {
		t.Errorf("%d reassemblies pending, want only the late fragment's", len(d.pending))
	}
}

// TestInvalidFragmentsDropDatagram: an overlap with different bytes, a second
// last fragment that ends elsewhere, or a non-last fragment off an 8-byte
// boundary drops the whole datagram, and the rest of its fragments cannot
// complete it.
func TestInvalidFragmentsDropDatagram(t *testing.T) {
	frags := fragmentIPv4(ipv4UDP(t, 9, txframe(t, "txframe-nonvote-3394.bin")), 1480)
	// forge returns frags[0]'s header carrying n bytes at offset off*8, with
	// flags/offset ff.
	forge := func(off uint16, mf bool, n int) []byte {
		f := append([]byte(nil), frags[0][:20+n]...)
		binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
		ff := off
		if mf {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(f[6:8], ff)
		for i := 20; i < len(f); i++ {
			f[i] ^= 0xff
		}
		return f
	}
	for name, c := range map[string]struct {
		bad       []byte
		immediate bool // the forged fragment alone is enough to drop the datagram
	}{
		"overlap":         {forge(1, true, 64), true},      // inside fragment 0, different bytes
		"misaligned more": {forge(500, true, 63), true},    // a non-last fragment must be a multiple of 8
		"second last":     {forge(1000, false, 64), false}, // the real last fragment then ends elsewhere
	} {
		rm, sub := subscribed(t)
		route(rm, frags[0], c.bad)
		if s := rm.Stats().Decap; c.immediate && s.ReassemblyInvalid != 1 {
			t.Errorf("%s: stats %+v after the forged fragment, want it dropped at once", name, s)
		}
		// Every real fragment follows, fragment 0 again included: none of them
		// may complete the datagram once it has been dropped.
		route(rm, frags...)
		if got := delivered(sub); len(got) != 0 {
			t.Errorf("%s: delivered %d datagrams, want none", name, len(got))
		}
		if s := rm.Stats().Decap; s.ReassemblyInvalid != 1 || s.Reassembled != 0 {
			t.Errorf("%s: stats %+v, want one invalid reassembly", name, s)
		}
	}
}

// TestNonFirstFragmentNeverDelivered: a non-first fragment carries no UDP
// header, so its leading bytes must never be read as one, even when they look
// like a valid header for a subscribed port.
func TestNonFirstFragmentNeverDelivered(t *testing.T) {
	frags := fragmentIPv4(ipv4UDP(t, 11, txframe(t, "txframe-nonvote-3394.bin")), 1480)
	last := append([]byte(nil), frags[len(frags)-1]...)
	// Make the fragment's first 8 bytes a UDP header for fragPort whose length
	// fits the fragment.
	binary.BigEndian.PutUint16(last[20:22], 40000)
	binary.BigEndian.PutUint16(last[22:24], fragPort)
	binary.BigEndian.PutUint16(last[24:26], 16)
	rm, sub := subscribed(t)
	route(rm, frags[1], last)
	if got := delivered(sub); len(got) != 0 {
		t.Fatalf("delivered %d payloads from non-first fragments, want none", len(got))
	}
}

// TestTruncatedInnerPacketCounted: an inner packet shorter than its IPv4
// header says, as a 1,500 B read buffer made of every larger datagram, is
// counted and never delivered.
func TestTruncatedInnerPacketCounted(t *testing.T) {
	pkt := ipv4UDP(t, 13, txframe(t, "txframe-nonvote-3394.bin"))
	// A UDP length past the IP payload is cut short too.
	long := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(long[24:26], uint16(len(long)-20+1))
	rm, sub := subscribed(t)
	route(rm, pkt[:1500-m.DataMsgHdrLen], long)
	if got := delivered(sub); len(got) != 0 {
		t.Fatalf("delivered %d truncated payloads, want none", len(got))
	}
	if s := rm.Stats().Decap; s.Truncated != 2 {
		t.Errorf("stats %+v, want two truncated", s)
	}
}

func TestInnerIPv6Unsupported(t *testing.T) {
	ip6 := make([]byte, 48)
	ip6[0] = 0x60
	ip6[6] = 44 // a Fragment header next
	rm, sub := subscribed(t)
	route(rm, ip6)
	if got := delivered(sub); len(got) != 0 {
		t.Fatal("an IPv6 inner packet was delivered")
	}
	if s := rm.Stats().Decap; s.Unsupported != 1 {
		t.Errorf("stats %+v, want one unsupported", s)
	}
}

// TestReassemblyBounded: datagrams that never complete cannot hold more than
// maxReassemblies reassemblies.
func TestReassemblyBounded(t *testing.T) {
	var d decapsulator
	now := time.Unix(1_000_000, 0)
	for id := range uint16(maxReassemblies + 10) {
		d.decap(fragmentIPv4(ipv4UDP(t, id, txframe(t, "txframe-jupiter-2102.bin")), 1480)[0], now)
	}
	if len(d.pending) != maxReassemblies || d.stats().ReassemblyExpired != 10 {
		t.Errorf("%d pending, %d evicted; want %d and 10", len(d.pending), d.stats().ReassemblyExpired, maxReassemblies)
	}
}

// sendRaw sends b to the gateway as is.
func (fr *fakeRelay) sendRaw(b []byte) {
	fr.t.Helper()
	fr.mu.Lock()
	gw := fr.gateway
	fr.mu.Unlock()
	if _, err := fr.conn.WriteToUDP(b, gw); err != nil {
		fr.t.Fatalf("fake relay send: %v", err)
	}
}

// TestTunnelDeliversLargeTxframes drives the whole client path: a ManagedConn
// tunnelled to the in-process fake relay over loopback. It receives one
// txframe as inner fragments, reversed, and another in a single data message
// whose UDP datagram is over 1,500 B, as the relay's own fragmentation
// reaches the gateway once the kernel reassembles it.
func TestTunnelDeliversLargeTxframes(t *testing.T) {
	fr := newFakeRelay(t)
	mc := &ManagedConn{SrcAddr: fragSource, GroupAddr: fragGroup, GroupPort: fragPort,
		RelayAddr: fr.Addr(), Mode: AMTModeTunnel, Timeout: 2 * time.Second}
	t.Cleanup(func() { _ = mc.Close(); _ = CloseRelayManager(fr.Addr()) })
	if err := mc.Open(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if sub := mc.Subscription(); sub != nil && sub.State() == SubscriptionStateActive {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the tunnel subscription never became active")
		}
	}

	frame := txframe(t, "txframe-nonvote-3394.bin")
	frags := fragmentIPv4(ipv4UDP(t, 21, frame), 1480)
	for _, f := range reversed(frags) {
		fr.sendRaw(amtData(f))
	}
	whole := amtData(ipv4UDP(t, 22, frame))
	if len(whole) <= 1500 {
		t.Fatalf("data message is %d B; it must exceed 1,500 B", len(whole))
	}
	fr.sendRaw(whole)

	// A tunnelled ManagedConn ignores read deadlines, so the reads time out here.
	reads := make(chan []byte)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := mc.ReadFrom(buf)
			if err != nil {
				return
			}
			reads <- bytes.Clone(buf[:n])
		}
	}()
	for _, how := range []string{"from fragments", "whole"} {
		select {
		case got := <-reads:
			if !bytes.Equal(got, frame) {
				t.Errorf("%s: read %d B, want the %d-byte frame byte-identical", how, len(got), len(frame))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: nothing read", how)
		}
	}
	if s := mc.Stats().Decap; s.Fragments != uint64(len(frags)) || s.Reassembled != 1 || s.Truncated != 0 {
		t.Errorf("ManagedConn stats %+v", s)
	}
}
