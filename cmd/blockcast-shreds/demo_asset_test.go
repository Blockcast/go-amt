package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The demo asset carries claims that were negotiated rather than chosen, so the
// wording is a contract and not prose. Asserting it in CI is what stops a later
// well-meant edit from widening the claim: a reviewer checklist that lives only
// in a comment thread is not enforced by anything.
const demoAssetPath = "../../docs/demo/d5-payload-agnostic-receipt.md"

func readDemoAsset(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(demoAssetPath)
	if err != nil {
		t.Fatalf("read demo asset: %v", err)
	}
	return string(content)
}

func TestDemoAssetCarriesTheExactApprovedClaim(t *testing.T) {
	const claim = "the same delivery receipt, on a payload that isn't shreds"
	if !strings.Contains(readDemoAsset(t), claim) {
		t.Errorf("demo asset must contain the approved claim verbatim: %q", claim)
	}
}

func TestDemoAssetFramesD3D4D5AsThreeModesOfOnePrototype(t *testing.T) {
	asset := readDemoAsset(t)
	if !strings.Contains(asset, "three modes of one prototype") {
		t.Error("demo asset must present D3/D4/D5 as three modes of one prototype")
	}
	for _, mode := range []string{"D3", "D4", "D5"} {
		if !strings.Contains(asset, mode) {
			t.Errorf("demo asset must name %s among the three modes", mode)
		}
	}
}

// Each pattern is a claim this demo is explicitly not entitled to make. They are
// matched case-insensitively against the asset, with the asset's own explicit
// disclaimers removed first — the "What this does not show" section names these
// concepts precisely in order to disclaim them, and must not trip its own guard.
func TestDemoAssetMakesNoProhibitedClaim(t *testing.T) {
	asset := readDemoAsset(t)
	disclaimer := strings.Index(asset, "## What this does not show")
	if disclaimer < 0 {
		t.Fatal("demo asset must carry an explicit 'What this does not show' section")
	}
	end := strings.Index(asset[disclaimer:], "\n## ")
	if end < 0 {
		t.Fatal("the disclaimer section must be followed by another section")
	}
	claiming := asset[:disclaimer] + asset[disclaimer+end:]

	prohibited := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"market-data product", regexp.MustCompile(`(?i)market[ -]data`)},
		{"publisher integration", regexp.MustCompile(`(?i)publisher`)},
		{"redistribution rights", regexp.MustCompile(`(?i)redistribution rights|licensed|we have rights`)},
		{"recovery or repair", regexp.MustCompile(`(?i)\b(recovery|repair|retransmit|reconstruct)`)},
		{"entitlement", regexp.MustCompile(`(?i)\b(entitlement|entitled to receive|metering|access control)`)},
		{"operational readiness", regexp.MustCompile(`(?i)production[ -]ready|operationally ready|ready for production|operational handoff`)},
	}
	for _, claim := range prohibited {
		if match := claim.pattern.FindString(claiming); match != "" {
			t.Errorf("demo asset makes a prohibited %s claim: found %q outside the disclaimer section", claim.name, match)
		}
	}
}

// The receipt quoted in the asset must be the one the code actually produces.
// A demo asset whose numbers have drifted from the binary is worse than none.
//
// Caveat this test cannot close on its own: the literals below are a second
// copy of the golden, not a derivation of it. This asserts asset-vs-literal;
// literal-vs-code is asserted by TestGenericFixtureReceiptIsDeterministic in
// the shred package. So a spec change has to move three things in lockstep —
// that golden, the asset, and these strings — and nothing here will catch it if
// only two of the three move. Deriving these from a ReplayGenericFixture receipt
// would collapse them to one.
func TestDemoAssetQuotesTheFixtureReceipt(t *testing.T) {
	asset := readDemoAsset(t)
	for _, line := range []string{
		"completeness windows=6 complete=4 expected=192 received=186 fraction=0.968750",
		"loss interior=3 trailing=3 duplicates=2 out_of_order=2",
	} {
		if !strings.Contains(asset, line) {
			t.Errorf("demo asset must quote the receipt line produced by the code: %q", line)
		}
	}
}
