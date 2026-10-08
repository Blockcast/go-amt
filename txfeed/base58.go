package txfeed

import (
	"fmt"
	"strings"
)

// base58Alphabet is the Bitcoin alphabet, which Solana uses for keys and
// signatures.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58Encode encodes b, one '1' per leading zero byte.
func Base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	var digits []byte // base-58 digits, least significant first
	for _, c := range b[zeros:] {
		carry := int(c)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for ; carry > 0; carry /= 58 {
			digits = append(digits, byte(carry%58))
		}
	}
	out := make([]byte, zeros+len(digits))
	for i := range zeros {
		out[i] = '1'
	}
	for i, d := range digits {
		out[len(out)-1-i] = base58Alphabet[d]
	}
	return string(out)
}

// Base58Decode decodes s, one zero byte per leading '1'.
func Base58Decode(s string) ([]byte, error) {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	var digits []byte // base-256 digits, least significant first
	for i := zeros; i < len(s); i++ {
		carry := strings.IndexByte(base58Alphabet, s[i])
		if carry < 0 {
			return nil, fmt.Errorf("base58: invalid character %q at offset %d", s[i], i)
		}
		for j := range digits {
			carry += int(digits[j]) * 58
			digits[j] = byte(carry)
			carry >>= 8
		}
		for ; carry > 0; carry >>= 8 {
			digits = append(digits, byte(carry))
		}
	}
	out := make([]byte, zeros+len(digits))
	for i, d := range digits {
		out[len(out)-1-i] = d
	}
	return out, nil
}
