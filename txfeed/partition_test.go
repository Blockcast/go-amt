package txfeed

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDefaultPrograms(t *testing.T) {
	// The spec's table, an oracle independent of DefaultPrograms.
	want := []struct{ name, id string }{
		{"token", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"},
		{"token-2022", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"},
		{"associated-token", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"},
		{"system", "11111111111111111111111111111111"},
		{"memo", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"},
		{"jupiter-v6", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"},
		{"raydium-amm-v4", "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8"},
		{"raydium-clmm", "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"},
		{"raydium-cpmm", "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C"},
		{"orca-whirlpool", "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"},
		{"meteora-dlmm", "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"},
		{"pump-fun", "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"},
		{"pump-amm", "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"},
		{"phoenix", "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY"},
		{"openbook-v2", "opnb2LAfJYbRMAHHvqjCwQxanZn7ReEHp1k81EohpZb"},
		{"stake", "Stake11111111111111111111111111111111111111"},
	}
	if len(DefaultPrograms) != len(want) {
		t.Fatalf("%d default programs, want %d", len(DefaultPrograms), len(want))
	}
	for i, w := range want {
		b, err := Base58Decode(w.id)
		if err != nil || len(b) != 32 {
			t.Errorf("%s: %s decodes to %d bytes (%v), want 32", w.name, w.id, len(b), err)
		}
		if got := DefaultPrograms[i]; got.Name != w.name || got.ID.String() != w.id {
			t.Errorf("DefaultPrograms[%d] = %s %s, want %s %s", i, got.Name, got.ID, w.name, w.id)
		}
	}
}

func TestBucket(t *testing.T) {
	// FNV-1a 32 mod 64, computed independently.
	for p, want := range map[Pubkey]int{token: 20, jupiter: 8, ComputeBudgetProgram: 62, VoteProgram: 44, memo: 17, system: 5} {
		if got := Bucket(p); got != want {
			t.Errorf("Bucket(%s) = %d, want %d", p, got, want)
		}
	}
}

func TestPartitions(t *testing.T) {
	named := make([]Pubkey, len(DefaultPrograms))
	for i, n := range DefaultPrograms {
		named[i] = n.ID
	}
	for _, c := range []struct {
		name string
		tx   Tx
		want []int
	}{
		{"a vote goes to the vote group only", Tx{Vote: true, Programs: []Pubkey{VoteProgram, token}}, []int{PartVote}},
		// token is named 0, jupiter named 5; their buckets are 20 and 8.
		// The compute budget program gets no bucket.
		{"a swap", Tx{Programs: []Pubkey{ComputeBudgetProgram, jupiter, token}}, []int{PartNonVote, 16, 21, 64 + 8, 64 + 20}},
		{"a compute budget only transaction", Tx{Programs: []Pubkey{ComputeBudgetProgram}}, []int{PartNonVote}},
		{"an unnamed program", Tx{Programs: []Pubkey{VoteProgram}}, []int{PartNonVote, 64 + 44}},
	} {
		if got := Partitions(c.tx, named); !slices.Equal(got, c.want) {
			t.Errorf("%s: Partitions = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestGroup(t *testing.T) {
	v4, v6 := netip.MustParseAddr("232.0.3.0"), netip.MustParseAddr("ff3e::232:300")
	for _, c := range []struct {
		base netip.Addr
		off  int
		want string
	}{
		{v4, PartVote, "232.0.3.2"},
		{v4, 255, "232.0.3.255"},
		{v6, 1, "ff3e::232:301"},
		{v6, 64, "ff3e::232:340"},
	} {
		if got, err := Group(c.base, c.off); err != nil || got.String() != c.want {
			t.Errorf("Group(%s, %d) = %s, %v; want %s", c.base, c.off, got, err, c.want)
		}
	}
	for _, c := range []struct {
		base netip.Addr
		off  int
	}{{netip.MustParseAddr("232.0.3.1"), 1}, {v4, 256}, {v4, -1}, {netip.Addr{}, 1}} {
		if got, err := Group(c.base, c.off); err == nil {
			t.Errorf("Group(%s, %d) = %s; want an error", c.base, c.off, got)
		}
	}
}

func TestParseSSM(t *testing.T) {
	for s, want := range map[string]string{
		"69.25.95.57@232.0.0.2:5001":     "69.25.95.57 232.0.0.2:5001",
		"2602:f74d:1::32@[ff3e::1]:5003": "2602:f74d:1::32 [ff3e::1]:5003",
	} {
		src, grp, err := ParseSSM(s)
		if got := src.String() + " " + grp.String(); err != nil || got != want {
			t.Errorf("ParseSSM(%q) = %s, %v; want %s", s, got, err, want)
		}
	}
	for _, s := range []string{"232.0.0.2:5001", "69.25.95.57@232.0.0.2", "x@232.0.0.2:5001", "69.25.95.57@232.0.0.2:x"} {
		if _, _, err := ParseSSM(s); err == nil {
			t.Errorf("ParseSSM(%q): want an error", s)
		}
	}
}
