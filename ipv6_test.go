package amt

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// The IPv6 (S,G) the shred-merger's IPv6 mirror emits on.
var (
	v6Source = netip.MustParseAddr("2001:db8:1:5::57")
	v6Groups = []netip.Addr{netip.MustParseAddr("ff3e::232:201"), netip.MustParseAddr("ff3e::232:202")}
)

const v6Port = 5001

// mldGolden is what amt-protocol ef1bf21a's MldV2Report::encode_with_ip(::,
// ff02::16) emits for the same records, the encoder amt-verify joined IPv6
// groups through the production relay with. Generated with rustc from that
// commit's src/mld.rs, then the source moved to the documentation prefix
// 2001:db8::/32 with each ICMPv6 checksum recomputed (RFC 4443 pseudo-header).
var mldGolden = map[string]string{
	"allow2": "600000000058000100000000000000000000000000000000ff020000000000000000000000000016" +
		"3a00050200000100" +
		"8f00044700000002" +
		"05000001ff3e0000000000000000000002320201" + "20010db8000100050000000000000057" +
		"05000001ff3e0000000000000000000002320202" + "20010db8000100050000000000000057",
	"block1": "600000000034000100000000000000000000000000000000ff020000000000000000000000000016" +
		"3a00050200000100" +
		"8f0039f400000001" +
		"06000001ff3e0000000000000000000002320203" + "20010db8000100050000000000000057",
}

// TestMLDReportMatchesRFC3810Layout pins buildMLDReport's bytes three ways: a
// known answer from a second implementation, the RFC 3810 §5.2 fields read back
// at their offsets and by gopacket's decoder, and the ICMPv6 checksum verified
// over the IPv6 pseudo-header. It fails on any changed byte, a record type or
// field out of place, or a checksum taken without the pseudo-header.
func TestMLDReportMatchesRFC3810Layout(t *testing.T) {
	for name, tc := range map[string]struct {
		recordType byte
		groups     []netip.Addr
	}{
		"allow2": {m.IGMPv3AllowNewSources, v6Groups},
		"block1": {m.IGMPv3BlockOldSources, []netip.Addr{netip.MustParseAddr("ff3e::232:203")}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := buildMLDReport(tc.recordType, v6Source, tc.groups)
			if err != nil {
				t.Fatal(err)
			}
			if want := mldGolden[name]; hex.EncodeToString(got) != want {
				t.Fatalf("report\n got %x\nwant %s", got, want)
			}

			// IPv6 header: version 6, payload length, Hop-by-Hop next, hop limit 1,
			// :: to ff02::16. Then the 8-byte Hop-by-Hop header: ICMPv6 next,
			// the MLD Router Alert, PadN.
			if got[0] != 0x60 || int(got[4])<<8|int(got[5]) != len(got)-40 || got[6] != 0 || got[7] != 1 ||
				!bytes.Equal(got[8:24], make([]byte, 16)) || netip.AddrFrom16([16]byte(got[24:40])) != mldReportsGroup {
				t.Fatalf("IPv6 header %x", got[:40])
			}
			if !bytes.Equal(got[40:48], []byte{58, 0, 5, 2, 0, 0, 1, 0}) {
				t.Fatalf("Hop-by-Hop header %x", got[40:48])
			}
			mld := got[48:]
			if mld[0] != 143 || mld[1] != 0 || mld[4] != 0 || mld[5] != 0 || int(mld[6])<<8|int(mld[7]) != len(tc.groups) {
				t.Fatalf("MLDv2 report header %x", mld[:8])
			}

			// RFC 8200 §8.1: the one's-complement sum over the pseudo-header and
			// the message, checksum included, is all ones.
			pseudo := append(append(append([]byte(nil), got[8:40]...), 0, 0, byte(len(mld)>>8), byte(len(mld)), 0, 0, 0, 58), mld...)
			if c := onesComplementChecksum(pseudo); c != 0 {
				t.Fatalf("ICMPv6 checksum does not verify over the pseudo-header: residue %#04x", c)
			}

			pkt := gopacket.NewPacket(got, layers.LayerTypeIPv6, gopacket.Default)
			report, ok := pkt.Layer(layers.LayerTypeMLDv2MulticastListenerReport).(*layers.MLDv2MulticastListenerReportMessage)
			if !ok {
				t.Fatalf("gopacket finds no MLDv2 report: %v", pkt.ErrorLayer())
			}
			if len(report.MulticastAddressRecords) != len(tc.groups) {
				t.Fatalf("%d records, want %d", len(report.MulticastAddressRecords), len(tc.groups))
			}
			for i, r := range report.MulticastAddressRecords {
				if byte(r.RecordType) != tc.recordType || r.AuxDataLen != 0 || r.N != 1 ||
					!r.MulticastAddress.Equal(tc.groups[i].AsSlice()) || !r.SourceAddresses[0].Equal(v6Source.AsSlice()) {
					t.Errorf("record %d = %+v, want type %d (%s,%s)", i, r, tc.recordType, v6Source, tc.groups[i])
				}
			}
		})
	}
}

// TestMLDReportRejectsIPv4 kills a builder that wrote an IPv4 or v4-mapped
// address into an MLD record instead of refusing it.
func TestMLDReportRejectsIPv4(t *testing.T) {
	for _, tc := range []struct{ source, group string }{
		{"192.0.2.1", "ff3e::1"},
		{"::ffff:192.0.2.1", "ff3e::1"},
		{"2001:db8::1", "232.0.0.1"},
		{"2001:db8::1", "::ffff:232.0.0.1"},
	} {
		if _, err := buildMLDReport(m.IGMPv3AllowNewSources, netip.MustParseAddr(tc.source), []netip.Addr{netip.MustParseAddr(tc.group)}); err == nil {
			t.Errorf("buildMLDReport(%s, %s) accepted", tc.source, tc.group)
		}
	}
}

// ipv6UDP wraps payload in IPv6/UDP from v6Source:40000 to group:v6Port.
func ipv6UDP(t *testing.T, group netip.Addr, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
		SrcIP: v6Source.AsSlice(), DstIP: group.AsSlice()}
	udp := &layers.UDP{SrcPort: 40000, DstPort: v6Port}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestInnerIPv6Decapsulated routes crafted AMT Multicast Data messages carrying
// IPv6 through the read path. A whole IPv6 UDP datagram reaches the (S,G)
// subscription with its payload and source; one cut short and one with an
// extension header before UDP are counted and never delivered. It fails if
// IPv6 is not decapsulated, if the address offsets or payload bounds are off,
// or if a short packet is delivered.
func TestInnerIPv6Decapsulated(t *testing.T) {
	rm := NewRelayManager(DefaultRelayManagerConfig(net.UDPAddr{}))
	key := SubscriptionKey{Source: v6Source, Group: v6Groups[0], Port: v6Port}
	sub := &Subscription{key: key, dataChan: make(chan *DataPacket, 4)}
	sub.state.Store(SubscriptionStateActive)
	rm.subscriptions.Store(key, sub)

	payload := []byte("shred over ipv6")
	whole := ipv6UDP(t, v6Groups[0], payload)
	hbh := append([]byte(nil), whole...)
	hbh[6] = 0 // a Hop-by-Hop header next, where UDP is
	route(rm, whole, whole[:len(whole)-1], hbh)

	got := delivered(sub)
	if len(got) != 1 || !bytes.Equal(got[0], payload) {
		t.Fatalf("delivered %q, want exactly %q", got, payload)
	}
	if s := rm.Stats().Decap; s.Truncated != 1 || s.Unsupported != 1 {
		t.Errorf("stats %+v, want one truncated and one unsupported", s)
	}
	if n := sub.Stats().PacketsReceived; n != 1 {
		t.Errorf("subscription counted %d packets, want 1", n)
	}
}

// mldRecords decodes the MLDv2 report a Membership Update carries, or returns
// nil for an Update whose report is not MLDv2 (the handshake's IGMP one).
// Update layout: 12 bytes of AMT header, response MAC and nonce, then the
// encapsulated IP packet.
func mldRecords(u []byte) []layers.MLDv2MulticastAddressRecord {
	if len(u) <= 12 || u[12]>>4 != 6 {
		return nil
	}
	pkt := gopacket.NewPacket(u[12:], layers.LayerTypeIPv6, gopacket.Default)
	if r, ok := pkt.Layer(layers.LayerTypeMLDv2MulticastListenerReport).(*layers.MLDv2MulticastListenerReportMessage); ok {
		return r.MulticastAddressRecords
	}
	return nil
}

// waitForMLD returns the first record of the next Update carrying an MLDv2
// record of type want.
func waitForMLD(t *testing.T, fr *fakeRelay, want byte) layers.MLDv2MulticastAddressRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		u, err := fr.WaitForUpdate(time.Until(deadline))
		if err != nil {
			break
		}
		if rs := mldRecords(u); len(rs) > 0 && byte(rs[0].RecordType) == want {
			return rs[0]
		}
	}
	t.Fatalf("no Membership Update with an MLDv2 record of type %d", want)
	return layers.MLDv2MulticastAddressRecord{}
}

// TestRelayManagerJoinsIPv6GroupOverIPv6 runs the whole IPv6 tunnel against the
// fake relay on [::1]: the handshake over an AF_INET6 outer socket, the join
// as an MLDv2 ALLOW_NEW_SOURCES record, IPv6 data delivered with its source,
// and the leave as BLOCK_OLD_SOURCES. It fails if the transport opens an IPv4
// socket for an IPv6 relay (no handshake), if Subscribe refuses an IPv6 (S,G),
// if the join or leave is not MLDv2, or if IPv6 data is not delivered.
func TestRelayManagerJoinsIPv6GroupOverIPv6(t *testing.T) {
	fr := newFakeRelay(t, withIPv6())
	rm := newTestManager(t, fr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against the IPv6 relay: %v", err)
	}
	if la, ok := rm.transport.LocalAddr().(*net.UDPAddr); !ok || la.IP.To4() != nil {
		t.Fatalf("tunnel local address %v, want an IPv6 outer socket", rm.transport.LocalAddr())
	}

	key := SubscriptionKey{Source: v6Source, Group: v6Groups[0], Port: v6Port}
	sub := subscribeActive(t, rm, key)
	join := waitForMLD(t, fr, m.IGMPv3AllowNewSources)
	if !join.MulticastAddress.Equal(key.Group.AsSlice()) || len(join.SourceAddresses) != 1 || !join.SourceAddresses[0].Equal(key.Source.AsSlice()) {
		t.Fatalf("join record %+v, want ALLOW (%s,%s)", join, key.Source, key.Group)
	}

	payload := []byte("ipv6 through the tunnel")
	fr.SendData(key.Source, key.Group, 40000, v6Port, payload)
	select {
	case p := <-sub.DataChan():
		if !bytes.Equal(p.Data, payload) {
			t.Fatalf("payload %q, want %q", p.Data, payload)
		}
		if src := packetSourceIP(t, p); !src.Equal(key.Source.AsSlice()) {
			t.Fatalf("source %s, want %s", src, key.Source)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no IPv6 data delivered through the tunnel")
	}

	fr.DrainUpdates()
	if err := rm.Unsubscribe(key); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	leave := waitForMLD(t, fr, m.IGMPv3BlockOldSources)
	if !leave.MulticastAddress.Equal(key.Group.AsSlice()) || len(leave.SourceAddresses) != 1 || !leave.SourceAddresses[0].Equal(key.Source.AsSlice()) {
		t.Fatalf("leave record %+v, want BLOCK (%s,%s)", leave, key.Source, key.Group)
	}
}

// TestSubscriptionKeyDropsZone: a tunnelled packet's addresses carry no zone,
// so a key that kept one would join and then match none of its packets. It
// fails if canonicalSubscriptionKey leaves the zone on the source or the group.
func TestSubscriptionKeyDropsZone(t *testing.T) {
	key := canonicalSubscriptionKey(SubscriptionKey{
		Source: netip.MustParseAddr("fe80::57%eth0"),
		Group:  netip.MustParseAddr("ff3e::232:201%eth0"),
		Port:   v6Port,
	})
	if key.Source.Zone() != "" || key.Group.Zone() != "" {
		t.Fatalf("canonical key (%s,%s) keeps a zone", key.Source, key.Group)
	}
}
