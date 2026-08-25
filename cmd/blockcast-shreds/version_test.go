package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blockcast/go-amt/broker"
)

// TestReleaseStampIsNotDevUnstamped guards the one failure in the version path
// that is silent in both directions.
//
// The Go linker discards an -X for an unknown symbol without a warning, so a
// build whose symbol path has drifted — the easy mistake being goreleaser's
// default -X main.version, since package main has no such symbol — compiles
// clean, ships, and reports "dev-unstamped" on every heartbeat forever. Nothing
// errors; the fleet simply collapses into one indistinguishable bucket for the
// report_schema census, and the version loses its value as the field-rollback
// lever W4 enforces at the billing edge.
//
// This builds the real binary with the same ldflags shape .goreleaser.yaml, the
// Dockerfile and .github/workflows/packaging.yml use, then asks it what version
// it is. It is the executable form of "the symbol path must be exact and
// asserted, not assumed".
//
// The unstamped half is asserted too: without it, a broker.version whose
// default had been changed to a plausible release string would pass the stamped
// check while making an unstamped build indistinguishable from a released one.
func TestReleaseStampIsNotDevUnstamped(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}

	const stampedVersion = "v0.0.0-stamp-test"
	const symbol = "github.com/blockcast/go-amt/broker.version"

	build := func(t *testing.T, ldflags string) string {
		t.Helper()
		binary := filepath.Join(t.TempDir(), "blockcast-shreds")
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags="+ldflags, "-o", binary, ".")
		cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build -ldflags=%q: %v\n%s", ldflags, err, output)
		}
		output, err := exec.Command(binary, "--version").CombinedOutput()
		if err != nil {
			t.Fatalf("%s --version: %v\n%s", binary, err, output)
		}
		return strings.TrimSpace(string(output))
	}

	t.Run("stamped", func(t *testing.T) {
		got := build(t, "-s -w -X "+symbol+"="+stampedVersion)
		if got == "dev-unstamped" {
			t.Fatalf("--version = %q: the -X stamp was silently discarded. "+
				"Check that the symbol path %q is exact in .goreleaser.yaml, "+
				"the Dockerfile and .github/workflows/packaging.yml.", got, symbol)
		}
		if got != stampedVersion {
			t.Errorf("--version = %q, want %q", got, stampedVersion)
		}
	})

	t.Run("unstamped", func(t *testing.T) {
		got := build(t, "-s -w")
		if got != broker.Version() {
			t.Errorf("--version = %q, want the compiled-in default %q", got, broker.Version())
		}
		if got != "dev-unstamped" {
			t.Errorf("unstamped build reports %q; the default must stay implausible "+
				"as a release string so an unstamped build is obvious in the "+
				"broker's records rather than blending in", got)
		}
	})
}
