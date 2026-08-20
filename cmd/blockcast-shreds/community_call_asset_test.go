package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/blockcast/go-amt/shred"
)

// The community-call asset is an operator script that will be read aloud on a
// live call, so two classes of drift in it are worse than an ordinary doc bug: a
// flag that does not exist exits 1 in front of an audience, and a quoted number
// that no longer matches the binary is a false claim made on the record. Both
// have already happened once. The reviewed revision of this script called a
// --duration and an --output that were never registered, and it recorded an md5
// of `selftest --fixture` that a working build no longer reproduced.
//
// These tests make both a build failure instead of a rehearsal finding.
const communityCallAsset = "../../docs/demo/community-call-two-arm-receipt.md"

func readCommunityCallAsset(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(communityCallAsset)
	if err != nil {
		t.Fatalf("read %s: %v", communityCallAsset, err)
	}
	return string(content)
}

// TestCommunityCallAssetMentionsNoUndefinedFlag is the --duration guard. It
// mirrors TestNoUndefinedFlagMentionedAnywhereInDoc, pointed at this asset, and
// reuses the same registeredFlags scan so the two documents cannot disagree
// about what the binary accepts.
func TestCommunityCallAssetMentionsNoUndefinedFlag(t *testing.T) {
	registered := map[string]bool{}
	for _, name := range registeredFlags(t) {
		registered[name] = true
	}
	// Deliberate exemptions, each a real flag of some other command the asset
	// legitimately invokes. A phantom blockcast-shreds flag still fails.
	allowed := map[string]bool{
		"fixture": true, // blockcast-shreds selftest sub-command
	}

	token := regexp.MustCompile(`--([a-z][a-z0-9-]{2,})`)
	seen := map[string]bool{}
	for _, match := range token.FindAllStringSubmatch(readCommunityCallAsset(t), -1) {
		name := match[1]
		if seen[name] || registered[name] || allowed[name] {
			continue
		}
		seen[name] = true
		t.Errorf("%s tells the operator to pass --%s, which blockcast-shreds does "+
			"not register. On this document that is not a typo: the command is read "+
			"off the page during a live call and a parse error exits 1 on camera.",
			communityCallAsset, name)
	}
}

// TestCommunityCallAssetQuotesTheControlItActuallyProduces derives the control
// receipt from the code and requires the asset to quote it verbatim.
//
// Deriving rather than restating is the point. The comment on
// TestDemoAssetQuotesTheFixtureReceipt notes that its literals are "a second
// copy of the golden, not a derivation of it", so a spec change has to move
// three things in lockstep and nothing catches it if only two move. Replaying
// the fixture here collapses that to one: the asset is checked against what the
// binary prints today, so a completion-ladder change like the one that
// invalidated the recorded md5 fails this test with the new line in the message
// rather than surfacing during a rehearsal.
func TestCommunityCallAssetQuotesTheControlItActuallyProduces(t *testing.T) {
	scorer := shred.NewScorer()
	if err := shred.ReplayFixture(scorer); err != nil {
		t.Fatalf("replay fixture: %v", err)
	}
	produced := scorer.Receipt().String()

	asset := readCommunityCallAsset(t)
	for _, line := range strings.Split(strings.TrimSpace(produced), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(asset, line) {
			t.Errorf("%s must quote the control receipt the binary prints, but is "+
				"missing this line:\n\t%s\nUpdate the asset's \"Reproducing it\" "+
				"block to the current output.", communityCallAsset, line)
		}
	}
}

// TestCommunityCallAssetHonoursTheFramingRules pins the framing constraints the
// demo was approved under. Each pattern is a claim this demo is not entitled to
// make, matched with the asset's own disclaimer section removed first — that
// section names these concepts precisely in order to rule them out, and must not
// trip its own guard.
func TestCommunityCallAssetHonoursTheFramingRules(t *testing.T) {
	asset := readCommunityCallAsset(t)
	disclaimer := strings.Index(asset, "## What this does not show")
	if disclaimer < 0 {
		t.Fatal("the asset must carry an explicit 'What this does not show' section")
	}
	end := strings.Index(asset[disclaimer:], "\n## ")
	if end < 0 {
		end = len(asset) - disclaimer
	}
	claiming := asset[:disclaimer] + asset[disclaimer+end:]

	prohibited := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"open-access", regexp.MustCompile(`(?i)open[ -]access`)},
		{"attestation", regexp.MustCompile(`(?i)attest(ed|ation)`)},
		{"decorrelated-paths", regexp.MustCompile(`(?i)independently operated|decorrelated`)},
	}
	for _, claim := range prohibited {
		if match := claim.pattern.FindString(claiming); match != "" {
			t.Errorf("the asset makes a prohibited %s claim: found %q outside the "+
				"disclaimer section", claim.name, match)
		}
	}
}

// TestCommunityCallAssetWarnsThatTheReceiptPrintsOnlyOnce keeps the correction
// that motivated this revision. The client writes nothing to stdout until the
// signal path runs, so a narration that promises a live-updating receipt is
// describing a blank screen. The asset must keep both halves: that the receipt
// is terminal, and that /metrics is the live surface.
func TestCommunityCallAssetWarnsThatTheReceiptPrintsOnlyOnce(t *testing.T) {
	asset := readCommunityCallAsset(t)
	for _, required := range []string{"prints **once**", "/metrics"} {
		if !strings.Contains(asset, required) {
			t.Errorf("the asset must keep the live-surface correction; missing %q. "+
				"Without it an operator narrates five minutes over an empty terminal.",
				required)
		}
	}
	// SIGKILL discards the receipt entirely, so the asset must never hand the
	// operator that form.
	if regexp.MustCompile(`timeout\s+-s\s+KILL\s+blockcast-shreds`).MatchString(asset) {
		t.Error("the asset must not invoke blockcast-shreds under `timeout -s KILL`: " +
			"SIGKILL skips the receipt print and the run is lost")
	}
}
