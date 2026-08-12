package shred

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

//go:embed testdata/fixture.pcap
var fixturePCAP []byte

// ReplayPCAP sends UDP payloads from a pcap through the production scorer.
func ReplayPCAP(reader io.Reader, scorer *Scorer) error {
	pcap, err := pcapgo.NewReader(reader)
	if err != nil {
		return fmt.Errorf("read pcap header: %w", err)
	}
	for {
		data, info, err := pcap.ReadPacketData()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read pcap packet: %w", err)
		}
		packet := gopacket.NewPacket(data, pcap.LinkType(), gopacket.NoCopy)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp := udpLayer.(*layers.UDP)
		if _, err := scorer.Observe(udp.Payload, info.Timestamp); err != nil {
			return fmt.Errorf("score packet at %s: %w", info.Timestamp.Format(time.RFC3339Nano), err)
		}
	}
}

func ReplayFixture(scorer *Scorer) error {
	return ReplayPCAP(bytes.NewReader(fixturePCAP), scorer)
}
