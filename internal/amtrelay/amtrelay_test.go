package amtrelay

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestParse pins the relay forms both commands accept. The IPv4 rows are the
// pre-IPv6 behaviour, so a change to them is a regression. The IPv6 rows fail
// if Parse resolves as udp4 again (every IPv6 literal refused), or if a bare
// or bracketed IPv6 relay without a port misses the default port. The family
// rows fail if Parse ignores network: a literal of the other family would be
// accepted, and a dual-stack name would resolve to its IPv4 address for an
// IPv6 group.
func TestParse(t *testing.T) {
	for _, tc := range []struct{ relay, network, want string }{
		{"203.0.113.128", "udp", "203.0.113.128:2268"},
		{"203.0.113.128:2269", "udp", "203.0.113.128:2269"},
		{"203.0.113.128", "udp4", "203.0.113.128:2268"},
		{"2001:db8:1::128", "udp", "[2001:db8:1::128]:2268"},
		{"[2001:db8:1::128]", "udp", "[2001:db8:1::128]:2268"},
		{"[2001:db8:1::128]:2269", "udp6", "[2001:db8:1::128]:2269"},
	} {
		got, err := Parse(tc.relay, tc.network)
		if err != nil || got.String() != tc.want {
			t.Errorf("Parse(%q, %s) = %v, %v; want %s", tc.relay, tc.network, &got, err, tc.want)
		}
	}
	if a, err := Parse("203.0.113.128", "udp"); err != nil || a.IP.To4() == nil {
		t.Errorf("Parse of an IPv4 relay = %v, %v; want an IPv4 address", &a, err)
	}

	for _, tc := range []struct{ relay, network string }{
		{"", "udp"},
		{":2268", "udp"},
		{"[2001:db8:1::128]:", "udp"},
		{"203.0.113.128:", "udp"},
		{"203.0.113.128", "udp6"},
		{"2001:db8:1::128", "udp4"},
		{"[::ffff:203.0.113.128]", "udp6"},
	} {
		if a, err := Parse(tc.relay, tc.network); err == nil {
			t.Errorf("Parse(%q, %s) = %v, want an error", tc.relay, tc.network, &a)
		}
	}
	for _, relay := range []string{"[2001:db8:1::128]:", "203.0.113.128:"} {
		if _, err := Parse(relay, "udp"); !errors.Is(err, ErrPortZero) {
			t.Errorf("Parse(%q) = %v, want ErrPortZero", relay, err)
		}
	}

	// localhost is the dual-stack name every host has; "udp" takes its IPv4
	// address, so this row is what tells network apart from "udp".
	if v6, err := (&net.Resolver{}).LookupNetIP(context.Background(), "ip6", "localhost"); err != nil || len(v6) == 0 {
		t.Skipf("localhost has no IPv6 address here (%v); the dual-stack row cannot run", err)
	}
	for network, want := range map[string]string{"udp6": "[::1]:2268", "udp4": "127.0.0.1:2268"} {
		if a, err := Parse("localhost", network); err != nil || a.String() != want {
			t.Errorf("Parse(localhost, %s) = %v, %v; want %s", network, &a, err, want)
		}
	}
}
