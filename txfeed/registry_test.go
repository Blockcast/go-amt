package txfeed

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// registryFixture is testdata/registry-accounts-v3.json: accounts that
// channel-registry main 4d693c4 wrote itself, in LiteSVM.
type registryFixture struct {
	Publisher string
	Accounts  []struct {
		Name    string
		DataHex string `json:"data_hex"`
	}
}

func loadRegistryFixture(t *testing.T) (registryFixture, map[string][]byte) {
	t.Helper()
	b, err := os.ReadFile("testdata/registry-accounts-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var f registryFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	data := map[string][]byte{}
	for _, a := range f.Accounts {
		if data[a.Name], err = hex.DecodeString(a.DataHex); err != nil {
			t.Fatal(err)
		}
	}
	return f, data
}

func TestParseRegistryChannel(t *testing.T) {
	f, data := loadRegistryFixture(t)
	publisher, err := ParsePubkey(f.Publisher)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		channel string
		status  RegistryStatus
	}{
		{"channel-program-jupiter-active", "program:JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", RegistryActive},
		{"channel-account-usdc-pending", "account:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", RegistryPending},
		{"channel-program-token-revoked", "program:TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", RegistryRevoked},
	} {
		want, err := ParseChannel(tc.channel)
		if err != nil {
			t.Fatal(err)
		}
		d := data[tc.name]
		// The whole account, and the prefix a poll's dataSlice returns, read the same.
		for _, b := range [][]byte{d, d[:RegistryChannelPrefix]} {
			got, err := ParseRegistryChannel(b)
			if err != nil {
				t.Fatalf("%s (%d bytes): %v", tc.name, len(b), err)
			}
			if got.Channel != want || got.Status != tc.status || got.Publisher != publisher || got.Port != 5003 {
				t.Errorf("%s (%d bytes) = %+v; want %s, status %d, publisher %s, port 5003", tc.name, len(b), got, want, tc.status, publisher)
			}
		}
	}
	for _, name := range []string{"subscription-shreds-active", "config"} {
		if _, err := ParseRegistryChannel(data[name]); err == nil || !strings.Contains(err.Error(), "discriminator") {
			t.Errorf("%s: err = %v; want a discriminator error", name, err)
		}
	}
}

func TestParseRegistryChannelRefuses(t *testing.T) {
	_, data := loadRegistryFixture(t)
	good := data["channel-program-jupiter-active"]
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want string
	}{
		{"short", func(d []byte) []byte { return d[:RegistryChannelPrefix-1] }, "at least"},
		{"version", func(d []byte) []byte { d[1] = RegistryVersion + 1; return d }, "version"},
		{"kind", func(d []byte) []byte { d[2] = 3; return d }, "kind"},
		{"status", func(d []byte) []byte { d[3] = 4; return d }, "status"},
		// The program computes the group on-chain; a publisher still never sends to a stored one.
		{"group", func(d []byte) []byte { d[115] ^= 1; return d }, "stored group"},
		{"key", func(d []byte) []byte { d[4] ^= 1; return d }, "stored group"},
	} {
		if _, err := ParseRegistryChannel(tc.edit(append([]byte(nil), good...))); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v; want one containing %q", tc.name, err, tc.want)
		}
	}
}
