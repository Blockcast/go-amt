package main

import (
	"fmt"
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

// receiptHeading is the section holding the control the audience is told they
// can recompute. Named once so the guard and its mutation tests cannot drift
// apart about which section is authoritative.
const receiptHeading = "## Reproducing it"

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

// fencedBlock is one ``` fenced block: the info string on its opening fence
// (`sh` in "```sh", empty when the fence is bare) and its content with both
// fence lines dropped. The info string is what separates a command the operator
// types from the output they should see, and that distinction is what lets
// receiptBlock below name one specific block instead of accepting whichever one
// happens to match.
type fencedBlock struct {
	info    string
	content string
}

// fencedBlocks returns each ``` fenced block in s. An unterminated final fence
// yields no block, so a truncated document fails the callers below rather than
// matching on a partial one.
func fencedBlocks(s string) []fencedBlock {
	var blocks []fencedBlock
	var current []string
	var info string
	inside := false
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if inside {
				blocks = append(blocks, fencedBlock{info: info, content: strings.Join(current, "\n")})
				current, info = nil, ""
			} else {
				info = strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
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

// receiptBlock returns the operator-facing receipt under heading: the section's
// single *bare* fence. A "```sh" fence is a command the operator types; a bare
// fence is output they are told they can recompute, and the receipt is the
// latter.
//
// Selecting the block by its role rather than by content is the point, and the
// reason is that the two differ in exactly the case that matters. Matching on
// content — "return once some block in this section equals the receipt", the
// previous form of this guard — is satisfied by a *duplicate* of the receipt
// added anywhere in the section, so the primary block the audience is pointed
// at can drift to something wrong while CI stays green. That form also could
// not honour its own failure message, which promises to name the one block to
// replace. Selecting by role means there is exactly one candidate, it is fixed
// before any comparison happens, and it is the one the reader's eye lands on.
//
// Two bare fences are an error rather than a choice: at that point the section
// no longer has a single operator-facing control, and picking either one would
// reintroduce the ambiguity this function exists to remove.
func receiptBlock(asset, heading string) (string, error) {
	start, end, ok := sectionBounds(asset, heading)
	if !ok {
		return "", fmt.Errorf("no %q section: it is the block the audience is told "+
			"they can recompute, and this guard has nothing to check without it", heading)
	}
	var bare []string
	for _, block := range fencedBlocks(asset[start:end]) {
		if block.info == "" {
			bare = append(bare, block.content)
		}
	}
	switch len(bare) {
	case 1:
		return bare[0], nil
	case 0:
		return "", fmt.Errorf("the %q section has no bare ``` fence, so it shows no "+
			"output for the operator to recompute (a ```sh fence is the command, not "+
			"the receipt)", heading)
	default:
		return "", fmt.Errorf("the %q section has %d bare ``` fences, so which one is "+
			"the receipt is ambiguous. Keep exactly one: a second copy lets the first "+
			"drift while a guard that matched on content stayed green", heading, len(bare))
	}
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
// The comparison is scoped to one specific fenced block — the bare output fence
// under "## Reproducing it" — and is whole-block rather than line-by-line.
// Searching the entire document for each line, the first form of this test,
// accepted the lines appearing in prose, in the checklist, or in an unrelated
// example. Accepting whichever block in the section matched, the second form,
// still let a duplicate satisfy the guard while the operator-facing block
// drifted. receiptBlock fixes the block before comparing, so both are closed.
func TestCommunityCallAssetQuotesTheControlItActuallyProduces(t *testing.T) {
	scorer := shred.NewScorer()
	if err := shred.ReplayFixture(scorer); err != nil {
		t.Fatalf("replay fixture: %v", err)
	}
	produced := normalizeReceiptBlock(scorer.Receipt().String())

	block, err := receiptBlock(readCommunityCallAsset(t), receiptHeading)
	if err != nil {
		t.Fatalf("%s: %v", communityCallAsset, err)
	}
	if got := normalizeReceiptBlock(block); got != produced {
		t.Errorf("the receipt block under %q in %s is not what the binary prints. "+
			"Replace that block with the current output.\n\nwant:\n%s\n\ngot:\n%s",
			receiptHeading, communityCallAsset, produced, got)
	}
}

// TestReceiptBlockNamesOneSpecificFence is the mutation test for the selector.
// It runs against synthetic documents rather than the asset so it can express
// the drift that the previous content-matching guard accepted, which by
// definition cannot be staged in the real asset while that asset is correct.
func TestReceiptBlockNamesOneSpecificFence(t *testing.T) {
	const good = "receipt line one\nreceipt line two"
	section := func(body string) string {
		return "# Doc\n\n## Reproducing it\n\n" + body + "\n## Next section\n\nprose\n"
	}

	for _, tc := range []struct {
		name    string
		asset   string
		want    string
		wantErr string
	}{
		{
			name:  "picks the bare output fence, not the sh command fence",
			asset: section("```sh\nblockcast-shreds selftest --fixture\n```\n\n```\n" + good + "\n```\n"),
			want:  good,
		},
		{
			// The exact drift Ally described: the operator-facing block is
			// wrong, and a correct duplicate elsewhere in the section would
			// have satisfied a guard that returned on the first match.
			name: "rejects a drifted primary block kept green by a correct duplicate",
			asset: section("```\nreceipt line one\nreceipt line WRONG\n```\n\n" +
				"more prose\n\n```\n" + good + "\n```\n"),
			wantErr: "ambiguous",
		},
		{
			name:    "rejects a section with no output fence at all",
			asset:   section("```sh\nblockcast-shreds selftest --fixture\n```\n"),
			wantErr: "no bare",
		},
		{
			name:    "fails closed when the heading is renamed",
			asset:   "# Doc\n\n## Reproducing them\n\n```\n" + good + "\n```\n",
			wantErr: "no \"## Reproducing it\" section",
		},
		{
			name: "does not reach into a later section for a matching fence",
			asset: "# Doc\n\n## Reproducing it\n\n```sh\ncmd\n```\n\n## Appendix\n\n```\n" +
				good + "\n```\n",
			wantErr: "no bare",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := receiptBlock(tc.asset, receiptHeading)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want an error containing %q, got block:\n%s", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want an error containing %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if normalizeReceiptBlock(got) != normalizeReceiptBlock(tc.want) {
				t.Errorf("want block:\n%s\n\ngot:\n%s", tc.want, got)
			}
		})
	}
}

// TestReceiptBlockRejectsDriftThePreviousGuardAccepted pins the regression
// itself rather than the new behaviour, so the duplicate case above cannot
// quietly become a tautology. It reproduces the discarded "return on the first
// block in the section that matches" logic and shows the two disagree on the
// same input: the old form is satisfied, the selector is not.
func TestReceiptBlockRejectsDriftThePreviousGuardAccepted(t *testing.T) {
	const produced = "receipt line one\nreceipt line two"
	asset := "## Reproducing it\n\n```\nreceipt line one\nreceipt line WRONG\n```\n\n" +
		"```\n" + produced + "\n```\n"

	start, end, ok := sectionBounds(asset, receiptHeading)
	if !ok {
		t.Fatal("fixture must contain the section")
	}
	acceptedByPreviousGuard := false
	for _, block := range fencedBlocks(asset[start:end]) {
		if normalizeReceiptBlock(block.content) == normalizeReceiptBlock(produced) {
			acceptedByPreviousGuard = true
		}
	}
	if !acceptedByPreviousGuard {
		t.Fatal("fixture no longer reproduces the accepted-by-the-old-guard case, " +
			"so it is not testing the regression it claims to")
	}
	if _, err := receiptBlock(asset, receiptHeading); err == nil {
		t.Error("receiptBlock accepted a drifted primary block that a correct " +
			"duplicate kept green; that is the regression this guard exists to stop")
	}
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
