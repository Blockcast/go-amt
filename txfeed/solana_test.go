package txfeed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"slices"
	"testing"
)

// appendShortVec appends n as a compact-u16.
func appendShortVec(b []byte, n int) []byte {
	for ; n >= 0x80; n >>= 7 {
		b = append(b, byte(n)|0x80)
	}
	return append(b, byte(n))
}

func appendVec(b, v []byte) []byte { return append(appendShortVec(b, len(v)), v...) }

type ix struct {
	program        int // index into the account keys
	accounts, data []byte
}

type lookup struct {
	table              Pubkey
	writable, readonly []byte
}

// testTx builds a transaction. The signers come first in the account keys,
// then extra; v0 makes a version-0 message carrying lookups, v1 a SIMD-0385
// version-1 transaction with mask's config values.
type testTx struct {
	signers []ed25519.PrivateKey
	extra   []Pubkey
	ixs     []ix
	v0      bool
	lookups []lookup
	v1      bool
	mask    uint32
}

func (tt testTx) build() []byte {
	if tt.v1 {
		return tt.buildV1()
	}
	var msg []byte
	if tt.v0 {
		msg = append(msg, 0x80)
	}
	msg = append(msg, byte(len(tt.signers)), 0, byte(len(tt.extra)))
	msg = appendShortVec(msg, len(tt.signers)+len(tt.extra))
	for _, k := range tt.signers {
		msg = append(msg, k.Public().(ed25519.PublicKey)...)
	}
	for _, k := range tt.extra {
		msg = append(msg, k[:]...)
	}
	msg = append(msg, bytes.Repeat([]byte{0xbb}, 32)...) // recent_blockhash
	msg = appendShortVec(msg, len(tt.ixs))
	for _, in := range tt.ixs {
		msg = appendVec(appendVec(append(msg, byte(in.program)), in.accounts), in.data)
	}
	if tt.v0 {
		msg = appendShortVec(msg, len(tt.lookups))
		for _, l := range tt.lookups {
			msg = appendVec(appendVec(append(msg, l.table[:]...), l.writable), l.readonly)
		}
	}
	tx := appendShortVec(nil, len(tt.signers))
	for _, k := range tt.signers {
		tx = append(tx, ed25519.Sign(k, msg)...)
	}
	return append(tx, msg...)
}

func (tt testTx) buildV1() []byte {
	msg := []byte{0x81, byte(len(tt.signers)), 0, byte(len(tt.extra))}
	msg = binary.LittleEndian.AppendUint32(msg, tt.mask)
	msg = append(msg, bytes.Repeat([]byte{0xbb}, 32)...) // lifetime specifier
	msg = append(msg, byte(len(tt.ixs)), byte(len(tt.signers)+len(tt.extra)))
	for _, k := range tt.signers {
		msg = append(msg, k.Public().(ed25519.PublicKey)...)
	}
	for _, k := range tt.extra {
		msg = append(msg, k[:]...)
	}
	for i := 0; i < 32; i++ {
		if tt.mask&(1<<i) != 0 {
			msg = append(msg, 0xc0, 0xff, 0xee, byte(i)) // one config value slot
		}
	}
	for _, in := range tt.ixs {
		msg = binary.LittleEndian.AppendUint16(append(msg, byte(in.program), byte(len(in.accounts))), uint16(len(in.data)))
	}
	for _, in := range tt.ixs {
		msg = append(append(msg, in.accounts...), in.data...)
	}
	tx := msg
	for _, k := range tt.signers {
		tx = append(tx, ed25519.Sign(k, msg)...)
	}
	return tx
}

func key(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

var (
	system  = Pubkey{}
	memo    = mustPubkey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
	jupiter = mustPubkey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")
	token   = mustPubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

	// A legacy transfer and memo: system is invoked twice, listed once.
	legacyTx = testTx{
		signers: []ed25519.PrivateKey{key(1), key(2)},
		extra:   []Pubkey{system, memo},
		ixs: []ix{
			{program: 2, accounts: []byte{0, 1}, data: []byte{2, 0, 0, 0, 0x40, 0x42, 0x0f, 0, 0, 0, 0, 0}},
			{program: 3, data: []byte("gm")},
			{program: 2, accounts: []byte{1, 0}, data: make([]byte, 200)}, // a 2-byte short_vec
		},
	}
	// A v0 swap through an address lookup table.
	v0Tx = testTx{
		signers: []ed25519.PrivateKey{key(3)},
		extra:   []Pubkey{ComputeBudgetProgram, jupiter},
		ixs: []ix{
			{program: 1, data: []byte{2, 0x40, 0x0d, 3, 0}},
			{program: 2, accounts: []byte{0, 3, 4, 5}, data: []byte{0xe5, 0x17}},
		},
		v0:      true,
		lookups: []lookup{{table: token, writable: []byte{7, 9}, readonly: []byte{1}}},
	}
	voteTx = testTx{
		signers: []ed25519.PrivateKey{key(4)},
		extra:   []Pubkey{VoteProgram},
		ixs:     []ix{{program: 1, accounts: []byte{0}, data: []byte{14, 0, 0, 0}}},
	}
	// A version-1 swap: priority fee, compute-unit and loaded-data limits in
	// the config mask instead of ComputeBudget instructions, and instruction
	// data longer than 255 bytes, so its u16 length takes both bytes.
	v1Tx = testTx{
		signers: []ed25519.PrivateKey{key(5), key(6)},
		extra:   []Pubkey{jupiter, token},
		ixs: []ix{
			{program: 2, accounts: []byte{0, 1, 3}, data: make([]byte, 300)},
			{program: 3, accounts: []byte{0}, data: []byte{3}},
		},
		v1:   true,
		mask: 0x0f,
	}
)

func TestParseTx(t *testing.T) {
	for _, c := range []struct {
		name     string
		tx       testTx
		programs []Pubkey
		vote     bool
	}{
		{"legacy", legacyTx, []Pubkey{system, memo}, false},
		{"v0 with a lookup table", v0Tx, []Pubkey{ComputeBudgetProgram, jupiter}, false},
		{"simple vote", voteTx, []Pubkey{VoteProgram}, true},
		{"v1 with config values", v1Tx, []Pubkey{jupiter, token}, false},
		// Agave's is_simple_vote_transaction also requires a legacy message and
		// fewer than three signatures.
		{"vote in a v0 message is not simple", testTx{signers: voteTx.signers, extra: voteTx.extra, ixs: voteTx.ixs, v0: true},
			[]Pubkey{VoteProgram}, false},
		{"vote in a v1 transaction is not simple", testTx{signers: voteTx.signers, extra: voteTx.extra, ixs: voteTx.ixs, v1: true},
			[]Pubkey{VoteProgram}, false},
		{"vote with three signatures is not simple", testTx{
			signers: []ed25519.PrivateKey{key(4), key(5), key(6)},
			extra:   voteTx.extra,
			ixs:     []ix{{program: 3, accounts: []byte{0}, data: voteTx.ixs[0].data}},
		}, []Pubkey{VoteProgram}, false},
		{"vote with a compute budget instruction is not simple", testTx{
			signers: voteTx.signers,
			extra:   []Pubkey{VoteProgram, ComputeBudgetProgram},
			ixs:     []ix{{program: 2, data: []byte{3}}, voteTx.ixs[0]},
		}, []Pubkey{ComputeBudgetProgram, VoteProgram}, false},
	} {
		raw := c.tx.build()
		tx, n, err := ParseTx(append(raw, 0xff, 0xff)) // what follows is not read
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		// The id is the first signature: right after the count byte, or for
		// version 1 where the signatures start, at the end.
		sig := raw[1:65]
		if c.tx.v1 {
			sig = raw[len(raw)-64*len(c.tx.signers):][:64]
		}
		if !bytes.Equal(tx.Sig, sig) {
			t.Errorf("%s: Sig is not the first signature", c.name)
		}
		if n != len(raw) || !bytes.Equal(tx.Raw, raw) || tx.NumSigs != len(c.tx.signers) ||
			!slices.Equal(tx.Programs, c.programs) || tx.Vote != c.vote {
			t.Errorf("%s: ParseTx = %d bytes, %d sigs, programs %v, vote %t; want %d, %d, %v, %t",
				c.name, n, tx.NumSigs, tx.Programs, tx.Vote, len(raw), len(c.tx.signers), c.programs, c.vote)
		}
	}
}

func TestParseTxRefuses(t *testing.T) {
	lookupProgram := v0Tx
	lookupProgram.ixs = []ix{{program: 3}} // the lookup table's first address
	versioned := v0Tx.build()
	versioned[1+64] = 0x81
	v1BadProgram := v1Tx
	v1BadProgram.ixs = []ix{{program: 4}} // one past the four addresses
	for _, c := range []struct {
		name string
		raw  []byte
	}{
		{"a program loaded from a lookup table", lookupProgram.build()},
		{"message version 1", versioned},
		{"a short_vec with a zero continuation byte", append([]byte{0x82, 0x00}, make([]byte, 200)...)},
		{"a v1 program index outside the addresses", v1BadProgram.build()},
		{"a v1 transaction without a signer", append([]byte{0x81}, make([]byte, 200)...)},
		{"a short_vec whose third byte continues", append([]byte{0x80, 0x80, 0x80}, make([]byte, 200)...)},
	} {
		if _, _, err := ParseTx(c.raw); err == nil {
			t.Errorf("%s: ParseTx accepted it", c.name)
		}
	}
}

// entries serializes a bincode Vec<Entry>, one Entry per element of txs.
func entries(txs ...[][]byte) []byte {
	b := binary.LittleEndian.AppendUint64(nil, uint64(len(txs)))
	for i, e := range txs {
		b = binary.LittleEndian.AppendUint64(b, uint64(1000+i)) // num_hashes
		b = append(b, bytes.Repeat([]byte{byte(i)}, 32)...)     // hash
		b = binary.LittleEndian.AppendUint64(b, uint64(len(e)))
		for _, tx := range e {
			b = append(b, tx...)
		}
	}
	return b
}

func TestParseEntries(t *testing.T) {
	legacy, v0, vote, v1 := legacyTx.build(), v0Tx.build(), voteTx.build(), v1Tx.build()
	batch := entries(nil, [][]byte{vote, v0}, [][]byte{legacy, v1}) // a tick, then two entries
	txs, err := ParseEntries(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 4 || !bytes.Equal(txs[0].Raw, vote) || !bytes.Equal(txs[1].Raw, v0) ||
		!bytes.Equal(txs[2].Raw, legacy) || !bytes.Equal(txs[3].Raw, v1) {
		t.Fatalf("ParseEntries returned %d transactions, want vote, v0, legacy, v1 in order", len(txs))
	}
	if !txs[0].Vote || txs[1].Vote || txs[2].Vote || txs[3].Vote {
		t.Error("only the first transaction is a vote")
	}

	// Agave's bincode::deserialize ignores bytes after the entries; so does
	// ParseEntries.
	if padded, err := ParseEntries(append(bytes.Clone(batch), 0, 0, 0)); err != nil || len(padded) != 4 {
		t.Errorf("ParseEntries with trailing bytes = %d transactions, %v; want the same 4", len(padded), err)
	}
	// Truncation anywhere is an error, never a panic.
	for n := range len(batch) {
		if _, err := ParseEntries(batch[:n]); err == nil {
			t.Fatalf("ParseEntries accepted the first %d of %d bytes", n, len(batch))
		}
	}
	for _, raw := range [][]byte{legacy, v0, vote} {
		for n := range len(raw) {
			if _, _, err := ParseTx(raw[:n]); err == nil {
				t.Fatalf("ParseTx accepted the first %d of %d bytes", n, len(raw))
			}
		}
	}
}

func FuzzParseEntries(f *testing.F) {
	legacy, v0, vote, v1 := legacyTx.build(), v0Tx.build(), voteTx.build(), v1Tx.build()
	f.Add(entries(nil, [][]byte{vote, v0}, [][]byte{legacy}))
	f.Add(entries([][]byte{v1, legacy}, [][]byte{v1}))
	f.Add(entries([][]byte{v0}))
	f.Add(entries())
	f.Add([]byte{})
	f.Add(binary.LittleEndian.AppendUint64(nil, 1<<62)) // a huge entry count
	f.Fuzz(func(t *testing.T, b []byte) {
		txs, err := ParseEntries(b)
		if err != nil {
			return
		}
		for _, tx := range txs {
			again, n, err := ParseTx(tx.Raw)
			if err != nil || n != len(tx.Raw) || !slices.Equal(again.Programs, tx.Programs) || again.Vote != tx.Vote {
				t.Fatalf("a parsed transaction does not parse alone: %d of %d bytes, %v", n, len(tx.Raw), err)
			}
			VerifyTx(tx.Raw) // must not panic, whatever the bytes
		}
	})
}

func TestVerifyTx(t *testing.T) {
	for _, tt := range []testTx{legacyTx, v0Tx, voteTx, v1Tx} {
		raw := tt.build()
		if ok, err := VerifyTx(raw); !ok || err != nil {
			t.Errorf("VerifyTx of a correctly signed transaction = %t, %v", ok, err)
		}
		// First and last signature byte, and a message byte.
		at := []int{1, 1 + 64*len(tt.signers) - 1, len(raw) - 1}
		if tt.v1 { // the signatures are last
			at = []int{len(raw) - 64*len(tt.signers), len(raw) - 1, 1}
		}
		for _, at := range at {
			bad := bytes.Clone(raw)
			bad[at] ^= 0x01
			if ok, err := VerifyTx(bad); ok {
				t.Errorf("VerifyTx passed a transaction with byte %d flipped (err %v)", at, err)
			}
		}
	}

	// One signature where the header requires two.
	tt := legacyTx
	raw := tt.build()
	short := append(appendShortVec(nil, 1), raw[1:1+64]...)
	short = append(short, raw[1+2*64:]...)
	if _, err := VerifyTx(short); err == nil {
		t.Error("VerifyTx accepted fewer signatures than the header requires")
	}
	if _, err := VerifyTx(append(raw, 0)); err == nil {
		t.Error("VerifyTx accepted a trailing byte")
	}
}
