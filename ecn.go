package amt

// ECN is the two-bit ECN field of an IP header (RFC 3168).
type ECN uint8

const (
	NotECT ECN = 0b00
	ECT1   ECN = 0b01
	ECT0   ECN = 0b10
	CE     ECN = 0b11
)

// ECNControlMessageLen is the OOB space the IPv4 IP_TOS control message
// occupies (CmsgSpace(1) on a 64-bit ABI). x/net/ipv4 has no TOS flag, so the
// option is set raw and is a term of its own in ControlMessageOOBLen; leaving it
// out truncates silently and darkens the group filter (BLO-34983).
// TestECNControlMessageLenMatchesTheABI checks the literal.
const ECNControlMessageLen = 24
