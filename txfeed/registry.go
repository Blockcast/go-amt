package txfeed

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// The W9 channel registry, Blockcast/channel-registry, is a Solana program
// whose channel accounts say which filter channels a publisher sends. The
// publisher reads only the first RegistryChannelPrefix bytes of each, which
// sit at the same offsets in every layout version so far:
//
//	0    discriminator, 2 for a channel
//	1    layout version
//	2    kind (ChannelKind)
//	3    status (RegistryStatus)
//	4    key, 32 bytes: the program or account
//	36   publisher, 32 bytes
//	68   payer, 32 bytes
//	100  group, 16 bytes, network byte order
//	116  port, u16 little-endian
const (
	// RegistryChannelPrefix is how much of a channel account
	// ParseRegistryChannel reads, so a poll can ask for just that much.
	RegistryChannelPrefix = 118
	// RegistryChannelDiscriminator is the first byte of every channel
	// account. A config is 1 and a subscription 3, and a subscription has
	// its status and publisher at a channel's offsets, so a poll must match
	// on it.
	RegistryChannelDiscriminator = 2
	// RegistryVersion is the layout version ParseRegistryChannel accepts:
	// channel-registry main 4d693c4.
	RegistryVersion = 3
	// RegistryStatusOffset and RegistryPublisherOffset are where a poll
	// filters.
	RegistryStatusOffset    = 3
	RegistryPublisherOffset = 36
)

// RegistryStatus is a registry channel's state.
type RegistryStatus byte

const (
	RegistryPending RegistryStatus = 0
	RegistryActive  RegistryStatus = 1
	RegistryRevoked RegistryStatus = 2
	RegistryLapsed  RegistryStatus = 3 // its payer ran out of funds
)

// RegistryChannel is what the publisher reads from a channel account.
type RegistryChannel struct {
	Channel
	Status    RegistryStatus
	Publisher Pubkey
	Port      uint16
}

// ParseRegistryChannel parses a registry channel account, or its first
// RegistryChannelPrefix bytes. It recomputes the channel's group rather than
// trust the stored one, and refuses an account whose stored group differs:
// the group a publisher sends to is always ChannelGroup(kind, key).
func ParseRegistryChannel(d []byte) (RegistryChannel, error) {
	if len(d) > 0 && d[0] != RegistryChannelDiscriminator {
		return RegistryChannel{}, fmt.Errorf("registry account discriminator %d, want %d (a channel)", d[0], RegistryChannelDiscriminator)
	}
	if len(d) < RegistryChannelPrefix {
		return RegistryChannel{}, fmt.Errorf("registry account of %d bytes, want at least %d", len(d), RegistryChannelPrefix)
	}
	if d[1] != RegistryVersion {
		return RegistryChannel{}, fmt.Errorf("registry channel layout version %d, want %d", d[1], RegistryVersion)
	}
	c := RegistryChannel{
		Channel:   Channel{Kind: ChannelKind(d[2]), Key: Pubkey(d[4:36])},
		Status:    RegistryStatus(d[3]),
		Publisher: Pubkey(d[36:68]),
		Port:      binary.LittleEndian.Uint16(d[116:118]),
	}
	if c.Kind != ChannelProgram && c.Kind != ChannelAccount {
		return RegistryChannel{}, fmt.Errorf("registry channel %s: unknown kind", c.Kind)
	}
	if c.Status > RegistryLapsed {
		return RegistryChannel{}, fmt.Errorf("registry channel %s: unknown status %d", c.Channel, c.Status)
	}
	stored := netip.AddrFrom16([16]byte(d[100:116]))
	if g := ChannelGroup(c.Kind, c.Key); stored != g {
		return RegistryChannel{}, fmt.Errorf("registry channel %s: stored group %s, spec v1 gives %s", c.Channel, stored, g)
	}
	return c, nil
}
