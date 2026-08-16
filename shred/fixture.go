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

// Observer is the scoring seam the replay path drives. Both *Scorer and
// *GenericScorer satisfy it, which is what keeps shred mode and generic mode one
// client with a mode flag rather than two replay paths that can drift.
//
// FeedScorer deliberately does not satisfy it: its Observe takes the feed name
// first, because per-feed accounting is a different contract from single-stream
// scoring.
type Observer interface {
	Observe(packet []byte, receivedAt time.Time) (bool, error)
}

// ReplayPCAP sends UDP payloads from a pcap through the supplied scorer.
func ReplayPCAP(reader io.Reader, scorer Observer) error {
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
