package txfeed

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// channelDomain separates channel hashes from other uses of SHA-256.
const channelDomain = "blockcast/txfeed/channel/v1"

// ChannelKind is what a filter channel matches.
type ChannelKind byte

const (
	// ChannelProgram matches a transaction that invokes the program in a
	// top-level instruction. A program called by CPI is not visible in a
	// transaction, so not in shreds: a Raydium channel misses a Raydium swap
	// routed through Jupiter. The callee is one of the transaction's
	// accounts, though, so its ChannelAccount channel matches when the
	// transaction lists it as a static key.
	ChannelProgram ChannelKind = 0x01
	// ChannelAccount matches a transaction that lists the account among its
	// message's static account keys (Tx.Keys). An account a version-0 message
	// loads from an address lookup table is not matched.
	ChannelAccount ChannelKind = 0x02
)

func (k ChannelKind) String() string {
	switch k {
	case ChannelProgram:
		return "program"
	case ChannelAccount:
		return "account"
	}
	return fmt.Sprintf("kind 0x%02x", byte(k))
}

// Channel is a filter channel (W9): the transactions that match one program or
// account, sent on an IPv6 SSM group of its own, so that a receiver joins
// exactly the filter it wants.
type Channel struct {
	Kind ChannelKind
	Key  Pubkey
}

// String returns c as KIND:BASE58, which ParseChannel parses.
func (c Channel) String() string { return c.Kind.String() + ":" + c.Key.String() }

// ParseChannel parses a channel, KIND:BASE58, where KIND is program or
// account.
func ParseChannel(s string) (Channel, error) {
	kind, key, ok := strings.Cut(s, ":")
	if !ok {
		return Channel{}, fmt.Errorf("channel %q: want KIND:BASE58", s)
	}
	var c Channel
	for _, k := range []ChannelKind{ChannelProgram, ChannelAccount} {
		if kind == k.String() {
			c.Kind = k
		}
	}
	if c.Kind == 0 {
		return Channel{}, fmt.Errorf("channel %q: kind %q, want program or account", s, kind)
	}
	var err error
	if c.Key, err = ParsePubkey(key); err != nil {
		return Channel{}, fmt.Errorf("channel %q: %w", s, err)
	}
	return c, nil
}

// RefusedKeys can have no channel, of either kind. Nearly every transaction
// invokes the compute budget program, so its channel would be the whole feed.
// The vote program stays refused so that no channel stands in for the retired
// vote group (BLO-22812).
var RefusedKeys = []Named{
	{"vote", VoteProgram},
	{"compute-budget", ComputeBudgetProgram},
}

// ChannelGroup returns the IPv6 SSM group of the channel (kind, key), spec v1:
// ff3e:0000:, then the first 12 bytes of
//
//	SHA-256(channelDomain || kind || key)
//
// where kind is one byte and key the program's or account's 32 bytes. The 96
// hashed bits are bits 32..127 of the group: outside FF3x::/96, where RFC 4607
// allocates SSM groups because RFC 3307 zeroes the network prefix, but inside
// FF3x::/32, all of which it says a system should treat as SSM. The MX does
// (verified 2026-10-14). Hash bytes 8..11 are the low 32 bits, which the 33:33
// MAC mapping keeps. testdata/channel-vectors.json holds the vectors, which
// the registry program, the Rust tools and the JS page are to assert too.
func ChannelGroup(kind ChannelKind, key Pubkey) netip.Addr {
	h := sha256.Sum256(append(append([]byte(channelDomain), byte(kind)), key[:]...))
	g := [16]byte{0xff, 0x3e} // ff3e:0000:
	copy(g[4:], h[:12])
	return netip.AddrFrom16(g)
}

// MatchChannels returns the channels in active that tx matches, each once: the
// program channels of the programs it invokes, in first-use order, then the
// account channels of its static account keys, in message order. A vote
// matches as any other transaction does. Only a channel in active is ever
// returned.
func MatchChannels[V any](tx Tx, active map[Channel]V) []Channel {
	if len(active) == 0 {
		return nil
	}
	var out []Channel
	add := func(c Channel) {
		if _, ok := active[c]; ok && !slices.Contains(out, c) { // a key listed twice matches once
			out = append(out, c)
		}
	}
	for _, p := range tx.Programs {
		add(Channel{ChannelProgram, p})
	}
	for i := 0; i+32 <= len(tx.Keys); i += 32 {
		add(Channel{ChannelAccount, Pubkey(tx.Keys[i : i+32])})
	}
	return out
}
