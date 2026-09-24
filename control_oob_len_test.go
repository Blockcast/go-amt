package amt

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// timestampSockoptsCoveredBy32 are the SOL_SOCKET timestamp options whose
// control message fits in TimestampControlMessageLen. Both carry a 16-byte
// payload — timespec for SO_TIMESTAMPNS, timeval for SO_TIMESTAMP — so both
// land at CmsgSpace(16).
//
// SO_TIMESTAMPING is deliberately absent: it delivers three timespecs, so
// CmsgSpace(48) = 64, and adopting it without moving the constant is exactly
// the change this guard exists to fail on.
var timestampSockoptsCoveredBy32 = map[string]bool{
	"SO_TIMESTAMP":   true,
	"SO_TIMESTAMPNS": true,
}

// TestTimestampSockoptsAreAllAccountedFor pins that no listen file sets a
// timestamp option TimestampControlMessageLen does not cover.
//
// This is the half of BLO-34983 the flag-set guards structurally cannot reach.
// control_flags_conn_test.go compares the argument a join site passes against
// ControlFlags4/6, which works because the flags are a value crossing a
// function boundary. The timestamp option is not: it is a setsockopt(2) call
// inside a platform file, contributing a cmsg to the same buffer with nothing
// linking it to any symbol a consumer can see. Swapping SO_TIMESTAMPNS for
// SO_TIMESTAMPING here would compile, pass every other test in this package,
// pass multicast's guards too — and put 64 bytes of cmsg into a buffer sized
// for 32, so the kernel sets MSG_CTRUNC, drops Dst, and multicast's group
// filter discards every datagram with no error on any surface.
//
// Reading the source is the only way to see it, because the option's size never
// appears as a value anywhere. Parsed rather than grepped so that prose naming
// SO_TIMESTAMPING — this file's own comments do — cannot turn the lane red.
//
// Untagged, like control_flags.go: every platform file must be checked from
// whichever one job compiles, and the AST walk does not need the file it reads
// to be selected by the current build tags.
func TestTimestampSockoptsAreAllAccountedFor(t *testing.T) {
	// Every non-test file in the package, not just the listen files: gateway.go
	// and transport_udp_posix.go set the option on sockets whose cmsgs land in
	// the same caller-supplied OOB buffer this constant sizes, and a glob that
	// covered only the listen files kept seen > 0 while those two drifted.
	// Test files are skipped because they name SO_TIMESTAMPING in prose and
	// fixtures, which would satisfy the seen == 0 check without a real caller.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no .go files matched in the package directory, so this guard " +
			"is inspecting nothing. Re-point the glob rather than deleting it: a " +
			"guard that silently matches an empty set reports success for every " +
			"possible upstream change")
	}

	seen := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || len(id.Name) < len("SO_TIMESTAMP") || id.Name[:len("SO_TIMESTAMP")] != "SO_TIMESTAMP" {
				return true
			}
			seen++
			if !timestampSockoptsCoveredBy32[id.Name] {
				t.Errorf("%s sets %s, which TimestampControlMessageLen (%d) does not "+
					"cover. Every option in this family writes a cmsg into the OOB "+
					"buffer callers size from ControlMessageOOBLen; adopting a wider "+
					"one without raising that constant truncates Dst and takes a "+
					"receiver's group filter dark with no error. Raise the constant "+
					"and add the option here, in the same change",
					path, id.Name, TimestampControlMessageLen)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no SO_TIMESTAMP* option found in any non-test file of this package. Either this " +
			"package stopped requesting timestamps — in which case " +
			"TimestampControlMessageLen is now dead weight in every caller's " +
			"buffer — or the option moved somewhere this guard does not look, " +
			"which leaves it covering nothing")
	}
}

// TestSetControlMessageUsesPassedFlags pins the effective IP-level control
// flags at every platform listen site. The seam test in
// control_flags_conn_test.go checks what Open passes into the listen function;
// this AST guard checks that the listen function does not add a computed flag
// expression or OR another bit when it applies that argument to the socket.
//
// Parsed rather than grepped so comments and string literals cannot satisfy
// the guard. Keep the vacuity check: if SetControlMessage moves out of the
// package files this test must fail rather than silently stop protecting the
// five platform sites.
func TestSetControlMessageUsesPassedFlags(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package files: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no .go files matched in the package directory, so this guard is " +
			"inspecting nothing")
	}

	seen := 0
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "SetControlMessage" {
				return true
			}
			seen++
			if len(call.Args) == 0 {
				t.Errorf("%s calls SetControlMessage without a control-flag argument", path)
				return true
			}
			if _, ok := call.Args[0].(*ast.Ident); !ok {
				t.Errorf("%s applies a computed control-flag expression at the "+
					"socket call site; pass the flags argument unchanged so the "+
					"exported OOB accounting cannot drift", path)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no SetControlMessage call found in any non-test file of this " +
			"package; either the platform sites moved or this guard is inspecting " +
			"nothing")
	}
}

// TestControlMessageOOBLenCoversBothFamiliesAndTheTimestamp pins that the
// exported length is the sum a caller actually needs, per term.
//
// Value-equality against a restatement of the same expression would be circular
// — that is the defect BLO-34983 was filed about. So each term is asserted to
// FIT, from the narrower side: each family's cmsgs must fit, whichever of the
// two is larger, plus the timestamp. An upstream flag addition correctly stays
// green, because the length grew with the requirement.
//
// That is weaker than "dropping any one term fails here", which this comment
// used to claim, and the difference is worth stating. Dropping the v4 term
// stays green today — v6 (64) exceeds v4 (56), so the value is unchanged and
// still sufficient. What these assertions pin is the terms that are load-bearing
// at current sizes: the timestamp term always, and whichever family is wider.
// If x/net ever made v4's cmsgs the wider ones, a v6-only expression would start
// failing at the first loop arm on its own.
func TestControlMessageOOBLenCoversBothFamiliesAndTheTimestamp(t *testing.T) {
	oobLen := ControlMessageOOBLen()
	v4 := len(ipv4.NewControlMessage(ControlFlags4))
	v6 := len(ipv6.NewControlMessage(ControlFlags6))
	if v4 == 0 || v6 == 0 {
		t.Fatalf("NewControlMessage returned an empty buffer (v4=%d v6=%d); the "+
			"flag sets are not requesting anything, so every assertion below "+
			"passes vacuously", v4, v6)
	}
	for _, tc := range []struct {
		name string
		need int
	}{
		{"v4 cmsgs + timestamp", v4 + TimestampControlMessageLen},
		{"v6 cmsgs + timestamp", v6 + TimestampControlMessageLen},
	} {
		if oobLen < tc.need {
			t.Errorf("ControlMessageOOBLen() = %d, too small for %s (%d). A short "+
				"buffer makes the kernel set MSG_CTRUNC and drop whichever cmsgs "+
				"did not fit, Dst first", oobLen, tc.name, tc.need)
		}
	}
	if oobLen <= max(v4, v6) {
		t.Errorf("ControlMessageOOBLen() = %d does not exceed the IP-level cmsgs "+
			"alone (%d), so the SOL_SOCKET timestamp term is not in it. That term "+
			"is unreachable from ControlFlags4/6 and is the one a caller cannot "+
			"derive for itself", oobLen, max(v4, v6))
	}
}
