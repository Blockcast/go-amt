//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"net"
	"testing"
	"time"
)

// openGateway runs Gateway.Open against fr, then releases the gateway.
func openGateway(t *testing.T, fr *fakeRelay) {
	t.Helper()
	addr := fr.Addr()
	gw := &Gateway{
		RelayAddr:  &addr,
		GroupAddr:  net.ParseIP("232.0.0.1"),
		SourceAddr: net.ParseIP("192.0.2.1"),
		MTU:        1500,
		Timeout:    5 * time.Second,
	}
	if err := gw.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	gw.abortOpen()
}

// Gateway.Open resends an unanswered Relay Discovery with the first copy's
// nonce (RFC 7450 sections 5.2.3.4.3 and 5.2.3.4.5). Before BLO-43016 it sent
// the Discovery once, so one lost datagram failed Open. The relay answers the
// first Discovery after 1.5s, after the 1s retransmission, and holds its
// answer to the second past the deadline. Open can only finish on the first
// answer, which a retransmission with a fresh nonce would have made stale.
func TestGatewayOpenResendsTheSameDiscovery(t *testing.T) {
	fr := newFakeRelay(t, withAdvertisementDelays(1500*time.Millisecond, time.Minute))
	openGateway(t, fr)
	if n := fr.discoveries.Load(); n != 2 {
		t.Errorf("Relay Discoveries the relay saw = %d, want 2: the first and its retransmission", n)
	}
}

// The Request half (RFC 7450 sections 5.2.3.5.3 and 5.2.3.5.6). The relay
// answers each Request after 1.5s, so the first Query arrives after the 1s
// retransmission and carries the first Request's nonce, which a fresh-nonce
// retransmission would have made stale.
func TestGatewayOpenResendsTheSameRequest(t *testing.T) {
	fr := newFakeRelay(t, withQueryDelay(1500*time.Millisecond))
	openGateway(t, fr)
	if n := fr.requests.Load(); n != 2 {
		t.Errorf("Requests the relay saw = %d, want 2: the first and its retransmission", n)
	}
}
