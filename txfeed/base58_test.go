package txfeed

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestBase58(t *testing.T) {
	for _, c := range []struct {
		raw []byte
		enc string
	}{
		{nil, ""},
		{[]byte("Hello World"), "JxF12TrwUP45BMd"},
		{[]byte{0, 0, 1, 2}, "115T"}, // one '1' per leading zero byte
		{make([]byte, 32), "11111111111111111111111111111111"},
	} {
		if got := Base58Encode(c.raw); got != c.enc {
			t.Errorf("Base58Encode(%x) = %q, want %q", c.raw, got, c.enc)
		}
		if got, err := Base58Decode(c.enc); err != nil || !bytes.Equal(got, c.raw) {
			t.Errorf("Base58Decode(%q) = %x, %v; want %x", c.enc, got, err, c.raw)
		}
	}

	rng := rand.New(rand.NewPCG(1, 2))
	for range 1000 {
		b := make([]byte, rng.IntN(70))
		for i := range b {
			if rng.IntN(4) > 0 { // keep some zeros, leading ones included
				b[i] = byte(rng.Uint32())
			}
		}
		if got, err := Base58Decode(Base58Encode(b)); err != nil || !bytes.Equal(got, b) {
			t.Fatalf("round trip of %x: %x, %v", b, got, err)
		}
	}

	for _, s := range []string{"0", "O", "I", "l", "abc+"} {
		if _, err := Base58Decode(s); err == nil {
			t.Errorf("Base58Decode(%q): want an error, it is not in the alphabet", s)
		}
	}
}

func TestParsePubkey(t *testing.T) {
	p, err := ParsePubkey("11111111111111111111111111111111")
	if err != nil || p != (Pubkey{}) {
		t.Errorf("the system program = %x, %v; want 32 zero bytes", p, err)
	}
	if p.String() != "11111111111111111111111111111111" {
		t.Errorf("String() = %q", p.String())
	}
	for _, s := range []string{"1111111111111111111111111111111", "JxF12TrwUP45BMd", ""} {
		if _, err := ParsePubkey(s); err == nil {
			t.Errorf("ParsePubkey(%q): want an error, it is not 32 bytes", s)
		}
	}
}
