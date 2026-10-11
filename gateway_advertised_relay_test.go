//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
)

// The Relay Advertisement names a unicast address of the relay that answered
// (RFC 7450 section 5.1.2.4), and the Request and everything after it go there.
// Sending them back to the discovery address instead is invisible when that
// address already is the relay -- the two are equal -- and breaks outright the
// moment discovery is anycast, which is the deployment AMT discovery exists
// for: the Request lands on whichever relay the anycast route happens to pick,
// which did not issue that nonce and rejects it.
//
// So the assertion here is about the *destination* of the Request datagram, not
// about the handshake completing. The advertised socket is a second listener
// that answers nothing, so Open goes on to time out; that it timed out is not
// what is under test and is not asserted.
func TestGatewaySendsRequestToAdvertisedRelay(t *testing.T) {
	advertised := net.IPv4(127, 0, 0, 2)

	fr := newFakeRelay(t, withAdvertisedAddress(advertised))
	t.Cleanup(fr.Close)
	discovery := fr.Addr()

	// The advertised relay listens on the same port at a different address --
	// AMTRELAY and the advertisement both carry an address, never a port, so
	// the port can only come from the discovery endpoint.
	advConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: advertised, Port: discovery.Port})
	if err != nil {
		// 127.0.0.2 is configured on Linux and not on a stock macOS; CI is Linux.
		t.Skipf("cannot listen on %s:%d: %v", advertised, discovery.Port, err)
	}
	t.Cleanup(func() { _ = advConn.Close() })

	g := &Gateway{
		RelayAddr:  &net.UDPAddr{IP: discovery.IP, Port: discovery.Port},
		SourceAddr: net.IPv4(10, 1, 2, 3),
		GroupAddr:  net.IPv4(232, 1, 2, 3),
		MTU:        1500,
		Timeout:    2 * time.Second,
	}
	t.Cleanup(func() { _ = g.Close() })

	done := make(chan error, 1)
	go func() { done <- g.Open() }()

	if err := advConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := advConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no datagram reached the advertised relay %s: %v (relay saw %d requests at the discovery address)",
			advertised, err, fr.requests.Load())
	}
	<-done

	if n < 1 || m.MessageType(buf[0]) != m.RequestType {
		t.Fatalf("advertised relay received type %d from %s, want a Request (%d)", buf[0], from, m.RequestType)
	}
	if got := fr.requests.Load(); got != 0 {
		t.Fatalf("%d Requests went to the discovery address; after an advertisement none should", got)
	}
}

func TestGatewayDestKeepsDiscoveryAddressWhenAdvertisementIsUnusable(t *testing.T) {
	discovery := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 2268}

	cases := []struct {
		name      string
		relayAddr net.IP
		want      string
	}{
		// A relay behind NAT advertising its inside address, or a bug
		// advertising none at all, would black-hole every message after
		// discovery. The discovery address is at least known to have answered.
		{"unspecified", net.IPv4zero, discovery.String()},
		{"private from a global relay", net.IPv4(10, 0, 0, 9), discovery.String()},
		{"link-local from a global relay", net.IPv4(169, 254, 0, 9), discovery.String()},
		{"global", net.IPv4(203, 0, 113, 9), "203.0.113.9:2268"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &Gateway{RelayAddr: discovery}
			adv := m.RelayAdvertisementMessage{Nonce: [4]byte{1, 2, 3, 4}, RelayAddr: tc.relayAddr.To4()}
			data, err := adv.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}

			g.adoptAdvertisedRelay(data)

			if got := g.dest().String(); got != tc.want {
				t.Fatalf("dest() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestGatewayDestFallsBackBeforeAnyAdvertisement(t *testing.T) {
	discovery := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 2268}
	g := &Gateway{RelayAddr: discovery}
	if got := g.dest(); got != net.Addr(discovery) {
		t.Fatalf("dest() = %v before any advertisement, want the discovery address %v", got, discovery)
	}
}
