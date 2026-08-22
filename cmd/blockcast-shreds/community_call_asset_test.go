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

// sectionBounds locates a `## ` section by its exact heading and returns the
// offsets of the heading and of the following heading (or end of file for a
// trailing section). Both the extract-one-section and the remove-one-section
// callers below need the same "to the next heading, or to EOF" rule, and they
// disagreed about it while it was written out twice.
func sectionBounds(asset, heading string) (start, end int, ok bool) {
	start = strings.Index(asset, heading)
	if start < 0 {
		return 0, 0, false
	}
	next := strings.Index(asset[start:], "\n## ")
	if next < 0 {
		return start, len(asset), true
	}
	return start, start + next, true
}

// fencedBlocks returns the contents of each ``` fenced block in s, with the
// fence lines themselves dropped. An unterminated final fence yields no block,
// so a truncated document fails the callers below rather than matching on a
// partial one.
func fencedBlocks(s string) []string {
	var blocks []string
	var current []string
	inside := false
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			if inside {
				blocks = append(blocks, strings.Join(current, "\n"))
				current = nil
			}
			inside = !inside
			continue
		}
		if inside {
			current = append(current, line)
		}
	}
	return blocks
}

// normalizeReceiptBlock makes a comparison insensitive to indentation and blank
// lines but exact about content, so reflowing the markdown is allowed and
// changing a number is not.
func normalizeReceiptBlock(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// TestCommunityCallAssetQuotesTheControlItActuallyProduces derives the control
// receipt from the code and requires the asset's "Reproducing it" block to be
// that receipt.
//
// Deriving rather than restating is the point. The comment on
// TestDemoAssetQuotesTheFixtureReceipt notes that its literals are "a second
// copy of the golden, not a derivation of it", so a spec change has to move
// three things in lockstep and nothing catches it if only two move. Replaying
// the fixture here collapses that to one: the asset is checked against what the
// binary prints today, so a completion-ladder change like the one that
// invalidated the recorded md5 fails this test with the new line in the message
// rather than surfacing during a rehearsal.
//
// The comparison is scoped to the fenced block under "## Reproducing it", and is
// whole-block rather than line-by-line. Searching the entire document for each
// line — the first form of this test — accepted the lines appearing in prose, in
// the checklist, or in an unrelated example, so the operator-facing control
// block it names in its own failure message could be edited away or padded with
// extra lines while CI stayed green.
func TestCommunityCallAssetQuotesTheControlItActuallyProduces(t *testing.T) {
	scorer := shred.NewScorer()
	if err := shred.ReplayFixture(scorer); err != nil {
		t.Fatalf("replay fixture: %v", err)
	}
	produced := normalizeReceiptBlock(scorer.Receipt().String())

	const heading = "## Reproducing it"
	asset := readCommunityCallAsset(t)
	start, end, ok := sectionBounds(asset, heading)
	if !ok {
		t.Fatalf("%s must keep a %q section: it is the block the audience is told "+
			"they can recompute, and this test has nothing to check without it.",
			communityCallAsset, heading)
	}

	blocks := fencedBlocks(asset[start:end])
	for _, block := range blocks {
		if normalizeReceiptBlock(block) == produced {
			return
		}
	}
	t.Errorf("no fenced block under %q in %s is the control receipt the binary "+
		"prints. Replace that block with the current output.\n\nwant:\n%s\n\n"+
		"found %d fenced block(s) in that section:\n%s",
		heading, communityCallAsset, produced, len(blocks),
		strings.Join(blocks, "\n---\n"))
}

// TestCommunityCallAssetHonoursTheFramingRules pins the framing constraints the
// demo was approved under. Each pattern is a claim this demo is not entitled to
// make, matched with the asset's own disclaimer section removed first — that
// section names these concepts precisely in order to rule them out, and must not
// trip its own guard.
func TestCommunityCallAssetHonoursTheFramingRules(t *testing.T) {
	const heading = "## What this does not show"
	asset := readCommunityCallAsset(t)
	start, end, ok := sectionBounds(asset, heading)
	if !ok {
		t.Fatalf("the asset must carry an explicit %q section", heading)
	}
	claiming := asset[:start] + asset[end:]

	prohibited := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"open-access", regexp.MustCompile(`(?i)open[ -]access`)},
		// Match the stem with word boundaries, not two inflections of it. The
		// first form of this guard was `attest(ed|ation)`, which let "we attest",
		// "this attests" and "attesting" through — and "nothing here is attested"
		// is a line the disclaimer already carries, so the prohibited forms are
		// the ones a later edit is most likely to reach for.
		{"attestation", regexp.MustCompile(`(?i)\battest(ed|ation|ations|ing|s)?\b`)},
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
