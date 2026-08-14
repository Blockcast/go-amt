package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// captureStdout runs work with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, work func() error) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	workErr := work()
	_ = write.Close()
	os.Stdout = original
	if workErr != nil {
		t.Fatal(workErr)
	}
	var output bytes.Buffer
	if _, err := output.ReadFrom(read); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func TestSelftestFixturePrintsOrderedReceipt(t *testing.T) {
	output := captureStdout(t, func() error { return selftest([]string{"--fixture"}) })
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "time_to_32nd_shred") || !strings.HasPrefix(lines[1], "erasure") || !strings.HasPrefix(lines[2], "gap_ms") {
		t.Fatalf("receipt output = %q", output)
	}
}

func TestSelftestFixtureJSONIsMachineReadable(t *testing.T) {
	output := captureStdout(t, func() error { return selftest([]string{"--fixture", "--json"}) })
	var receipt struct {
		SetsTotal        int      `json:"sets_total"`
		ErasureFraction  *float64 `json:"erasure_fraction"`
		MeanShredsPerSet *float64 `json:"mean_shreds_per_set"`
	}
	if err := json.Unmarshal([]byte(output), &receipt); err != nil {
		t.Fatalf("selftest --json output is not JSON: %v\n%s", err, output)
	}
	if receipt.SetsTotal == 0 || receipt.ErasureFraction == nil || receipt.MeanShredsPerSet == nil {
		t.Fatalf("JSON receipt is missing fields: %s", output)
	}
}

func TestSelftestRequiresFixture(t *testing.T) {
	if err := selftest(nil); err == nil {
		t.Fatal("selftest without --fixture succeeded")
	}
}

func TestRunRejectsDuplicateFeedNames(t *testing.T) {
	err := run([]string{"--feed", "same=127.0.0.1:20001", "--feed", "same=127.0.0.1:20002"})
	if err == nil || !strings.Contains(err.Error(), "duplicate --feed name") {
		t.Fatalf("run() error = %v", err)
	}
}
