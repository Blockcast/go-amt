// Package blo28195probe exists only to prove that branch protection on `main`
// actually blocks a merge when the required `test` / `race` checks are red.
// It is opened as a throwaway PR, read, and closed. It must never be merged.
package blo28195probe

import "testing"

func TestBranchProtectionProbeDeliberatelyFails(t *testing.T) {
	t.Fatal("BLO-28195 negative control: this failure is intentional")
}
