package shred

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestReplayPCAPParsesForwarderUDPPayloadWithoutReframing(t *testing.T) {
	payload := dataPacket(42, 0, 0)
	var fixture bytes.Buffer
	writer := pcapgo.NewWriter(&fixture)
	if err := writer.WriteFileHeader(2048, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}

	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(239, 1, 1, 1),
	}
	udp := &layers.UDP{SrcPort: 20000, DstPort: 20001}
	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Fatal(err)
	}
	serialized := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(serialized, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ipv4, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	packet := serialized.Bytes()
	if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(3, 0), CaptureLength: len(packet), Length: len(packet)}, packet); err != nil {
		t.Fatal(err)
	}

	scorer := NewScorer()
	if err := ReplayPCAP(&fixture, scorer); err != nil {
		t.Fatal(err)
	}
	if got := scorer.Receipt(); got.SetsTotal != 1 || got.SetsErased != 1 {
		t.Fatalf("raw UDP shred payload was not scored: %+v", got)
	}
}
