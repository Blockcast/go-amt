package txfeed

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
)

// A partition is an offset from a group base: partition p is carried on the
// group whose last byte is p.
const (
	PartNonVote    = 1
	PartVote       = 2
	PartNamedBase  = 16 // up to 16 named programs, offsets 16..31
	PartBucketBase = 64 // NumBuckets program buckets, offsets 64..127
	NumBuckets     = 64
)

// Named is a program with its own partition.
type Named struct {
	Name string
	ID   Pubkey
}

// DefaultPrograms are the named partitions, in offset order: program i is
// carried on PartNamedBase+i.
var DefaultPrograms = []Named{
	{"token", mustPubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")},
	{"token-2022", mustPubkey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")},
	{"associated-token", mustPubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")},
	{"system", mustPubkey("11111111111111111111111111111111")},
	{"memo", mustPubkey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")},
	{"jupiter-v6", mustPubkey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")},
	{"raydium-amm-v4", mustPubkey("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8")},
	{"raydium-clmm", mustPubkey("CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK")},
	{"raydium-cpmm", mustPubkey("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C")},
	{"orca-whirlpool", mustPubkey("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")},
	{"meteora-dlmm", mustPubkey("LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo")},
	{"pump-fun", mustPubkey("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")},
	{"pump-amm", mustPubkey("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA")},
	{"phoenix", mustPubkey("PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY")},
	{"openbook-v2", mustPubkey("opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb")},
	{"stake", mustPubkey("Stake11111111111111111111111111111111111111")},
}

// Bucket is the program bucket of p: FNV-1a 32 of its bytes, mod NumBuckets.
func Bucket(p Pubkey) int {
	h := fnv.New32a()
	h.Write(p[:])
	return int(h.Sum32() % NumBuckets)
}

// Partitions returns the partitions tx is carried on, ascending. A vote goes
// to PartVote only. Any other transaction goes to PartNonVote, to
// PartNamedBase+i for each named[i] it invokes (named has at most 16
// entries), and to the bucket of each program it invokes except the compute
// budget program, which nearly every transaction invokes.
func Partitions(tx Tx, named []Pubkey) []int {
	if tx.Vote {
		return []int{PartVote}
	}
	parts := []int{PartNonVote}
	for i, p := range named {
		if slices.Contains(tx.Programs, p) {
			parts = append(parts, PartNamedBase+i)
		}
	}
	for _, p := range tx.Programs {
		if p != ComputeBudgetProgram {
			parts = append(parts, PartBucketBase+Bucket(p))
		}
	}
	slices.Sort(parts)
	return slices.Compact(parts)
}

// Group returns the group carrying partition off: base with off as its last
// byte, which must be 0 in base. For an IPv6 base such as ff3e::232:300 the
// groups stay inside the SSM range FF3x::/96.
func Group(base netip.Addr, off int) (netip.Addr, error) {
	b := base.AsSlice()
	if len(b) == 0 || b[len(b)-1] != 0 {
		return netip.Addr{}, fmt.Errorf("group base %v: want an address whose last byte is 0", base)
	}
	if off < 0 || off > 255 {
		return netip.Addr{}, fmt.Errorf("partition offset %d outside 0..255", off)
	}
	b[len(b)-1] = byte(off)
	a, _ := netip.AddrFromSlice(b)
	return a, nil
}

// ParseSSM parses an SSM channel, SOURCE@GROUP:PORT. An IPv6 GROUP is
// bracketed: SOURCE@[GROUP]:PORT.
func ParseSSM(s string) (source netip.Addr, group netip.AddrPort, err error) {
	src, grp, ok := strings.Cut(s, "@")
	if !ok {
		return source, group, fmt.Errorf("SSM channel %q: want SOURCE@GROUP:PORT", s)
	}
	if source, err = netip.ParseAddr(src); err != nil {
		return source, group, fmt.Errorf("SSM channel %q: %w", s, err)
	}
	if group, err = netip.ParseAddrPort(grp); err != nil {
		return source, group, fmt.Errorf("SSM channel %q: %w", s, err)
	}
	return source, group, nil
}
