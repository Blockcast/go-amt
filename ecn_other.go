//go:build !linux

package amt

// ParseECN reports unavailable: the ECN read is implemented on linux only, and
// "unavailable" is the honest answer elsewhere, not a silent Not-ECT.
func ParseECN(oob []byte) (ECN, bool) { return 0, false }
