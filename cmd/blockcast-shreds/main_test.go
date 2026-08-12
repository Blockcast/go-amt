package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestSelftestFixturePrintsOrderedReceipt(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	err = selftest([]string{"--fixture"})
	_ = write.Close()
	os.Stdout = original
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := output.ReadFrom(read); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "time_to_32nd_shred") || !strings.HasPrefix(lines[1], "erasure") || !strings.HasPrefix(lines[2], "gap_ms") {
		t.Fatalf("receipt output = %q", output.String())
	}
}

func TestSelftestRequiresFixture(t *testing.T) {
	if err := selftest(nil); err == nil {
		t.Fatal("selftest without --fixture succeeded")
	}
}
