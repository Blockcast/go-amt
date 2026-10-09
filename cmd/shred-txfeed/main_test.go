//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/blockcast/go-amt/txfeed"
)

func TestParsePrograms(t *testing.T) {
	if got, err := parsePrograms(nil); err != nil || len(got) != len(txfeed.DefaultPrograms) {
		t.Errorf("no -program: %d programs, %v; want the defaults", len(got), err)
	}
	got, err := parsePrograms([]string{"jup=JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "memo=MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"})
	if err != nil || len(got) != 2 || got[0].Name != "jup" || got[1].ID != txfeed.DefaultPrograms[4].ID {
		t.Errorf("parsePrograms = %v, %v; want jup then memo, replacing the defaults", got, err)
	}
	for _, specs := range [][]string{
		{"JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"},                                          // no name
		{"=JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"},                                         // empty name
		{"x=JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV"},                                         // 31 bytes
		strings.Fields(strings.Repeat("s=11111111111111111111111111111111 ", txfeed.NumNamed+1)), // too many
	} {
		if _, err := parsePrograms(specs); err == nil {
			t.Errorf("parsePrograms(%q): want an error", specs)
		}
	}
}
