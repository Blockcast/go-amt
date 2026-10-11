package amt

import (
	"context"
	"net"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
)

// The advertised-relay destination matters most on the path that does DRIAD,
// and that path is RelayManager, not Gateway: Gateway is always pointed at an
// operator-configured address, while RelayManager is the one Open feeds a
// discovered candidate. Fixing only Gateway leaves the Request and every
// keepalive going to the discovery address exactly where anycast makes that
// wrong -- the relay that answered is not the relay the next datagram reaches,
// and it rejects a nonce it never issued.
//
// As in the Gateway case the assertion is about the *destination* of the
// Request datagram. The advertised socket answers nothing, so the handshake
// goes on to fail; that is not what is under test and is not asserted.
func TestRelayManagerSendsRequestToAdvertisedRelay(t *testing.T) {
	advertised := net.IPv4(127, 0, 0, 2)

	fr := newFakeRelay(t, withAdvertisedAddress(advertised))
	t.Cleanup(fr.Close)
	discovery := fr.Addr()

	// Same port, different address: neither AMTRELAY nor the advertisement
	// carries a port, so it can only come from the discovery endpoint.
	advConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: advertised, Port: discovery.Port})
	if err != nil {
		// 127.0.0.2 is configured on Linux and not on a stock macOS; CI is Linux.
		t.Skipf("cannot listen on %s:%d: %v", advertised, discovery.Port, err)
	}
	t.Cleanup(func() { _ = advConn.Close() })

	cfg := DefaultRelayManagerConfig(discovery)
	cfg.EnableDRIAD = false
	cfg.TransportConfig.RelayAddr = discovery
	cfg.TransportConfig.Timeout = 2 * time.Second

	rm := NewRelayManager(cfg)
	t.Cleanup(func() { _ = rm.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- rm.Open(ctx) }()

	if err := advConn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := advConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no datagram reached the advertised relay %s: %v (relay saw %d Requests at the discovery address)",
			advertised, err, fr.requests.Load())
	}
	<-done

	if n < 1 || m.MessageType(buf[0]&0x0F) != m.RequestType {
		t.Fatalf("advertised relay received type %d from %s, want a Request (%d)", buf[0]&0x0F, from, m.RequestType)
	}
	if got := fr.requests.Load(); got != 0 {
		t.Fatalf("%d Requests went to the discovery address; after an advertisement none should", got)
	}
}

// A reconnect reuses the transport, so an adopted relay that has since died
// would otherwise capture every reconnect: the next Discovery would go to the
// dead relay instead of back to the discovery address, which in an anycast
// deployment is the only thing that can hand out a live one. Open is the
// generation boundary, so Open is where the destination resets.
func TestUDPTransportResetsToDiscoveryAddressOnOpen(t *testing.T) {
	discovery := net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2268}
	tr, err := NewUDPTransport(TransportConfig{RelayAddr: discovery, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	if got := tr.RelayAddr().String(); got != discovery.String() {
		t.Fatalf("RelayAddr() = %s before any advertisement, want the discovery address %s", got, discovery.String())
	}

	tr.AdoptAdvertisedRelay(mustAdvertisement(t, net.IPv4(127, 0, 0, 2)))
	if got, want := tr.RelayAddr().String(), "127.0.0.2:2268"; got != want {
		t.Fatalf("RelayAddr() = %s after a usable advertisement, want %s", got, want)
	}

	if err := tr.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := tr.RelayAddr().String(); got != discovery.String() {
		t.Fatalf("RelayAddr() = %s after reopening, want the discovery address %s back", got, discovery.String())
	}
}

// The sockets here are AF_INET. An advertisement carrying a global IPv6
// address passes every routability test -- 2000::/3 is not loopback, private,
// link-local or unspecified -- and is still unsendable, so taking it would
// black-hole everything after the Discovery. Before the advertised-relay
// change such an advertisement was inert; the guard is what keeps it inert.
//
// Checked at the transport seam as well as the Gateway one because the guard
// is shared and this lane also builds without cgo.
func TestUDPTransportRefusesAdvertisedRelayOfAnotherFamily(t *testing.T) {
	discovery := net.UDPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 2268}
	tr, err := NewUDPTransport(TransportConfig{RelayAddr: discovery})
	if err != nil {
		t.Fatalf("NewUDPTransport: %v", err)
	}

	v6 := net.ParseIP("2001:db8::9")
	adv := mustAdvertisement(t, v6)
	if len(adv) != 24 {
		t.Fatalf("advertisement is %d bytes, want the 24-byte IPv6 form; the test would prove nothing", len(adv))
	}

	tr.AdoptAdvertisedRelay(adv)
	if got := tr.RelayAddr().String(); got != discovery.String() {
		t.Fatalf("RelayAddr() = %s after an IPv6 advertisement on an IPv4 socket, want the discovery address %s", got, discovery.String())
	}
}

func mustAdvertisement(t *testing.T, relay net.IP) []byte {
	t.Helper()
	ip := relay.To4()
	if ip == nil {
		ip = relay.To16()
	}
	adv := m.RelayAdvertisementMessage{Nonce: [4]byte{1, 2, 3, 4}, RelayAddr: ip}
	data, err := adv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	return data
}

// The same guard, driven through a real relay rather than a hand-built
// advertisement: a relay reached over IPv4 that advertises a global IPv6
// address must be ignored and the tunnel must keep working against the
// discovery address. Without the family guard the Request is steered at an
// address the AF_INET socket cannot write to and the handshake never
// completes.
//
// This is also the test that needs withAdvertisedAddress to keep 16 bytes.
// While it took To4() unconditionally the fake emitted an 8-byte
// advertisement the decoder rejects outright, so the handshake survived for
// the wrong reason and the guard was never exercised.
func TestRelayManagerKeepsDiscoveryAddressWhenAdvertisementIsIPv6(t *testing.T) {
	fr := newFakeRelay(t, withAdvertisedAddress(net.ParseIP("2001:db8::9")))
	t.Cleanup(fr.Close)

	if got := len(fr.advertisedAddr); got != net.IPv6len {
		t.Fatalf("fake relay would advertise %d address bytes, want %d; "+
			"an 8-byte advertisement is rejected before the guard runs and this test would prove nothing", got, net.IPv6len)
	}

	rm := newTestManager(t, fr)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open failed against a relay advertising an unreachable IPv6 address: %v "+
			"(the discovery address answered and should have been kept)", err)
	}
	if rm.State() != RelayStateActive {
		t.Fatalf("state = %s, want Active", rm.State())
	}
	if got := fr.requests.Load(); got == 0 {
		t.Fatal("no Request reached the discovery address; the IPv6 advertisement was adopted")
	}
}
