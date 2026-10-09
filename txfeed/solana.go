package txfeed

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

// Pubkey is a Solana account address.
type Pubkey [32]byte

// String returns the key in base58.
func (p Pubkey) String() string { return Base58Encode(p[:]) }

// ParsePubkey decodes a base58 address, which must be exactly 32 bytes.
func ParsePubkey(s string) (Pubkey, error) {
	b, err := Base58Decode(s)
	if err != nil {
		return Pubkey{}, err
	}
	if len(b) != len(Pubkey{}) {
		return Pubkey{}, fmt.Errorf("pubkey %q decodes to %d bytes, want 32", s, len(b))
	}
	return Pubkey(b), nil
}

func mustPubkey(s string) Pubkey {
	p, err := ParsePubkey(s)
	if err != nil {
		panic(err)
	}
	return p
}

var (
	VoteProgram          = mustPubkey("Vote111111111111111111111111111111111111111")
	ComputeBudgetProgram = mustPubkey("ComputeBudget111111111111111111111111111111")
)

// Tx is one transaction of an entry batch.
type Tx struct {
	Raw      []byte // exact serialized VersionedTransaction (sub-slice of the batch)
	NumSigs  int
	Sig      []byte   // the first signature, the transaction's id (sub-slice of Raw)
	Programs []Pubkey // distinct top-level program ids, first-use order
	// Vote marks a simple vote as Agave's is_simple_vote_transaction defines
	// it: a legacy message, one or two signatures, and exactly one
	// instruction, to VoteProgram.
	Vote bool
}

var errTruncated = errors.New("truncated")

// reader walks a byte slice. Every read is bounds-checked; the first failure
// sticks in err, and later reads return zero values.
type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b)-r.off {
		r.err = fmt.Errorf("%w: need %d bytes at offset %d of %d", errTruncated, n, r.off, len(r.b))
		return nil
	}
	b := r.b[r.off : r.off+n]
	r.off += n
	return b
}

func (r *reader) u8() byte {
	if b := r.bytes(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.bytes(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

// shortVec reads a compact-u16 length: 7 bits per byte, low bits first, 0x80
// to continue, at most 3 bytes. Like Solana's decoder, it refuses a zero
// continuation byte (an alias of a shorter encoding), a third byte that
// continues, and a value above 0xffff.
func (r *reader) shortVec() int {
	v := 0
	for i := range 3 {
		c := r.u8()
		if r.err != nil {
			return 0
		}
		if i > 0 && c == 0 || i == 2 && c&0x80 != 0 {
			r.err = fmt.Errorf("non-canonical short_vec at offset %d", r.off-1)
			return 0
		}
		v |= int(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			break
		}
	}
	if v > 0xffff {
		r.err = fmt.Errorf("short_vec %d overflows u16", v)
		return 0
	}
	return v
}

// skipVec skips a short_vec of size-byte elements.
func (r *reader) skipVec(size int) {
	r.bytes(r.shortVec() * size)
}

// message is what ParseTx learns beyond Tx, for VerifyTx.
type message struct {
	signed   []byte // the bytes the signatures sign
	sigs     []byte // the signatures, 64 bytes each
	required int    // header.num_required_signatures
	keys     []byte // static account keys, 32 bytes each
}

func parseTx(b []byte) (Tx, message, error) {
	if len(b) > 0 && b[0] == txV1 {
		return parseTxV1(b)
	}
	r := &reader{b: b}
	numSigs := r.shortVec()
	sigs := r.bytes(64 * numSigs)
	m := message{sigs: sigs}
	start := r.off
	v0 := false
	if r.err == nil && r.off < len(b) && b[r.off]&0x80 != 0 {
		if version := r.u8() & 0x7f; version != 0 {
			return Tx{}, m, fmt.Errorf("unsupported message version %d", version)
		}
		v0 = true
	}
	m.required = int(r.u8())
	if r.err == nil && m.required == 0 {
		// The fee payer always signs; with no signer VerifyTx would have
		// nothing to check and report a pass.
		return Tx{}, m, errors.New("transaction without a signer")
	}
	r.bytes(2) // num_readonly_signed, num_readonly_unsigned
	m.keys = r.bytes(32 * r.shortVec())
	r.bytes(32) // recent_blockhash

	n := r.shortVec()
	var programs []Pubkey
	for i := 0; i < n && r.err == nil; i++ {
		idx := int(r.u8())
		r.skipVec(1) // accounts
		r.skipVec(1) // data
		if r.err != nil {
			break
		}
		// A program id must be a static key: lookup-table addresses are
		// only resolved against on-chain state.
		if idx >= len(m.keys)/32 {
			return Tx{}, m, fmt.Errorf("instruction %d: program index %d outside %d static keys", i, idx, len(m.keys)/32)
		}
		if p := Pubkey(m.keys[32*idx : 32*idx+32]); !slices.Contains(programs, p) {
			programs = append(programs, p)
		}
	}
	if v0 {
		for range r.shortVec() {
			r.bytes(32)  // account_key
			r.skipVec(1) // writable_indexes
			r.skipVec(1) // readonly_indexes
			if r.err != nil {
				break
			}
		}
	}
	if r.err != nil {
		return Tx{}, m, r.err
	}
	m.signed = b[start:r.off]
	return Tx{
		Raw:      b[:r.off:r.off],
		NumSigs:  numSigs,
		Sig:      firstSig(sigs),
		Programs: programs,
		Vote:     !v0 && numSigs < 3 && n == 1 && programs[0] == VoteProgram,
	}, m, nil
}

func firstSig(sigs []byte) []byte {
	if len(sigs) < 64 {
		return nil
	}
	return sigs[:64:64]
}

// txV1 is the first byte of a SIMD-0385 version-1 transaction. Legacy and v0
// transactions start with a short_vec signature count, whose first byte is
// below 0x80, so the first byte tells the formats apart.
const txV1 = 0x81

// parseTxV1 parses a version-1 transaction (SIMD-0385, on mainnet since epoch
// 1035). The message comes first and the signatures last:
//
//	[0]      0x81
//	[1:4]    num_required_signatures, num_readonly_signed, num_readonly_unsigned
//	[4:8]    TransactionConfigMask, u32 LE: 4 bytes of config value per set bit
//	[8:40]   lifetime specifier (the recent blockhash)
//	[40]     num_instructions, u8
//	[41]     num_addresses, u8
//	         addresses, 32 bytes each; then the config values
//	         instruction headers, 4 bytes each: program index u8,
//	         num_accounts u8, data_len u16 LE
//	         instruction payloads: each one's account indexes, then its data
//	         num_required_signatures signatures, 64 bytes each
//
// The signatures sign everything before them. There are no address lookup
// tables, so every program id is a static key.
func parseTxV1(b []byte) (Tx, message, error) {
	r := &reader{b: b}
	r.u8() // version
	m := message{required: int(r.u8())}
	if r.err == nil && m.required == 0 {
		return Tx{}, m, errors.New("version-1 transaction without a signer")
	}
	r.bytes(2) // num_readonly_signed, num_readonly_unsigned
	var mask uint32
	if mb := r.bytes(4); mb != nil {
		mask = binary.LittleEndian.Uint32(mb)
	}
	r.bytes(32) // lifetime specifier
	n := int(r.u8())
	m.keys = r.bytes(32 * int(r.u8()))
	r.bytes(4 * bits.OnesCount32(mask))
	headers := r.bytes(4 * n)
	var programs []Pubkey
	payload := 0
	for i := 0; i < n && r.err == nil; i++ {
		h := headers[4*i : 4*i+4]
		idx := int(h[0])
		if idx >= len(m.keys)/32 {
			return Tx{}, m, fmt.Errorf("instruction %d: program index %d outside %d addresses", i, idx, len(m.keys)/32)
		}
		if p := Pubkey(m.keys[32*idx : 32*idx+32]); !slices.Contains(programs, p) {
			programs = append(programs, p)
		}
		payload += int(h[1]) + int(binary.LittleEndian.Uint16(h[2:4]))
	}
	r.bytes(payload)
	signed := r.off
	m.sigs = r.bytes(64 * m.required)
	if r.err != nil {
		return Tx{}, m, r.err
	}
	m.signed = b[:signed]
	return Tx{
		Raw:      b[:r.off:r.off],
		NumSigs:  m.required,
		Sig:      firstSig(m.sigs),
		Programs: programs, // never a simple vote: Agave requires a legacy message
	}, m, nil
}

// ParseTx parses one VersionedTransaction at the start of b and returns it
// with its length.
func ParseTx(b []byte) (Tx, int, error) {
	tx, _, err := parseTx(b)
	return tx, len(tx.Raw), err
}

// ParseEntries parses an entry batch, a bincode Vec<Entry>, and returns its
// transactions in order. Bytes after the entries are ignored, as Agave's
// bincode::deserialize ignores them.
func ParseEntries(batch []byte) ([]Tx, error) {
	r := &reader{b: batch}
	var txs []Tx
	// Every entry and transaction consumes bytes or fails, so a hostile
	// count runs out of input instead of looping.
	for n := r.u64(); n > 0 && r.err == nil; n-- {
		r.bytes(8 + 32) // num_hashes, hash
		for m := r.u64(); m > 0 && r.err == nil; m-- {
			tx, _, err := parseTx(batch[r.off:])
			if err != nil {
				return nil, fmt.Errorf("transaction %d at offset %d: %w", len(txs), r.off, err)
			}
			txs = append(txs, tx)
			r.off += len(tx.Raw)
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	return txs, nil
}

// VerifyTx checks every signature of the transaction raw: signature i signs
// the message with account_keys[i]. It returns an error when raw is not
// exactly one well-formed transaction, or its signature count is not
// header.num_required_signatures.
func VerifyTx(raw []byte) (bool, error) {
	tx, m, err := parseTx(raw)
	if err != nil {
		return false, err
	}
	if len(tx.Raw) != len(raw) {
		return false, fmt.Errorf("%d trailing bytes after the transaction", len(raw)-len(tx.Raw))
	}
	if tx.NumSigs != m.required || m.required > len(m.keys)/32 {
		return false, fmt.Errorf("%d signatures, %d required, %d static keys", tx.NumSigs, m.required, len(m.keys)/32)
	}
	for i := range tx.NumSigs {
		if !ed25519.Verify(m.keys[32*i:32*i+32], m.signed, m.sigs[64*i:64*i+64]) {
			return false, nil
		}
	}
	return true, nil
}
