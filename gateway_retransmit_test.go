//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"math"
	"net"
	"strings"
	"sync"
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

// A Request leg that times out reports every retransmission, and doesn't blame
// the duplicate Advertisement. The relay answers the first Discovery after
// 1.5s, after the 1s retransmission, and the retransmission after 0.8s. Rust
// rejects that second answer as InvalidState. Every Request is dropped, so Open
// resends the Discovery once and the Request once (at 2.5s) before its 3s bound;
// the next resend is due at 3.5s at the earliest. Both timer races keep 500ms of
// slack: the Discovery resend at 1s against the first answer at 1.5s, and the
// Request resend at 2.5s against the 3s bound.
func TestGatewayOpenErrorAfterDuplicateAdvertisement(t *testing.T) {
	fr := newFakeRelay(t, withAdvertisementDelays(1500*time.Millisecond, 800*time.Millisecond), withLostRequests(1<<30))
	addr := fr.Addr()
	gw := &Gateway{
		RelayAddr:  &addr,
		GroupAddr:  net.ParseIP("232.0.0.1"),
		SourceAddr: net.ParseIP("192.0.2.1"),
		MTU:        1500,
		Timeout:    3 * time.Second,
	}
	err := gw.Open()
	gw.abortOpen()
	if err == nil {
		t.Fatal("Open succeeded against a relay that drops every Request")
	}
	if n := fr.advertised.Load(); n != 2 {
		t.Fatalf("relay advertisements sent = %d, want 2: the late answer and the duplicate", n)
	}
	if strings.Contains(err.Error(), "advertisement rejected") {
		t.Errorf("Open: %v; the rejected duplicate followed an accepted Advertisement, so it isn't why Open failed", err)
	}
	if !strings.Contains(err.Error(), "after 2 retransmissions") {
		t.Errorf("Open: %v; want 2 retransmissions, one per leg", err)
	}
}

// A Timeout longer than the keepalive's 10s seed interval must not let the
// keepalive tear down the handshake it exists to maintain.
//
// Before BLO-43640, Open started the keepalive goroutine immediately after the
// first Discovery, and that goroutine's first iteration destroyed the handshake
// deterministically. lastData is written by gateway.go's seed and by the two
// steady-state read loops in conn.go, and neither loop can run while Open is
// still handshaking — so after the goroutine's opening 10s sleep, idle always
// exceeded intervalTime. It took the stalled branch, called amt_gateway_reset
// on a gateway in the middle of its own handshake, and sent a second Discovery
// carrying a FRESH nonce, which Open's retransmission then resent as though it
// were its own. That breaks the same-nonce requirement of RFC 7450 sections
// 5.2.3.4.5 and 5.2.3.5.6 that TestGatewayOpenResendsTheSameDiscovery above
// exists to hold, and it does so only above 10s — which is why the default
// (DefaultOpenTimeout, exactly 10s) never showed it, and why #159 making
// RelayHandshakeTimeout reachable is what exposed it.
//
// The relay answers nothing, so Open can only end at its deadline. 12s is past
// the 10s mark where that first keepalive pass would have fired, with margin on
// both sides. Every Discovery the relay sees must carry one and the same nonce.
func TestGatewayOpenAboveTheKeepaliveIntervalSendsOneDiscoveryNonce(t *testing.T) {
	if testing.Short() {
		t.Skip("must outlast the keepalive's 10s seed interval to prove anything")
	}
	// Drop every Discovery: a silent relay, but one that still records what it
	// was sent. A bare ListenPacket black hole could not report the nonces.
	fr := newFakeRelay(t, withLostDiscoveries(math.MaxInt64))

	addr := fr.Addr()
	gw := &Gateway{
		RelayAddr:  &addr,
		GroupAddr:  net.ParseIP("232.0.0.1"),
		SourceAddr: net.ParseIP("192.0.2.1"),
		MTU:        1500,
		Timeout:    12 * time.Second,
	}
	if err := gw.Open(); err == nil {
		t.Fatal("Open succeeded against a relay that answered nothing")
	}
	gw.abortOpen()

	nonces := fr.seenDiscoveryNonces()
	// Positive control. With one Discovery and no retransmission the nonce
	// assertion below is vacuously true, which is also what a regression that
	// stopped Open retransmitting at all would look like.
	if len(nonces) < 2 {
		t.Fatalf("relay saw %d Relay Discoveries; Open did not retransmit, so this test asserts nothing", len(nonces))
	}
	distinct := make(map[uint32]struct{}, len(nonces))
	for _, n := range nonces {
		distinct[n] = struct{}{}
	}
	if len(distinct) != 1 {
		t.Errorf("distinct Discovery nonces = %d across %d Discoveries (%#x), want 1: "+
			"something other than Open's own retransmission started a discovery mid-handshake",
			len(distinct), len(nonces), nonces)
	}
}

// The other half of BLO-43640: moving the keepalive out of the handshake must
// not delete it. A successful Open still owes the tunnel a keepalive goroutine.
//
// The relay advertises a 200ms query interval (QQIC 0x02), which
// handleMembershipQuery adopts, so one keepalive pass costs 200ms rather than
// the 10s seed. Nothing reads the gateway socket here, so lastData is never
// refreshed and the pass takes its stalled branch — a reset and a rediscovery,
// which is the keepalive's own observable signature and the only one available
// without a MulticastConn read loop.
func TestGatewayOpenStartsTheKeepaliveOnSuccess(t *testing.T) {
	fr := newFakeRelay(t, withQueryIntervalCode(0x02))

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
	atHandshake := fr.discoveries.Load()

	deadline := time.Now().Add(2 * time.Second)
	for fr.discoveries.Load() == atHandshake && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := fr.discoveries.Load()

	// Stop the goroutine and let it observe that before abortOpen frees the
	// Rust handle it is still calling into. leave is read once per interval,
	// and an iteration already past that read finishes in microseconds, so one
	// second covers several intervals of slack.
	gw.stopKeepalive()
	time.Sleep(time.Second)
	gw.abortOpen()

	if got == atHandshake {
		t.Fatalf("relay saw no Relay Discovery in 2s after a successful Open (still %d): "+
			"the keepalive goroutine never started", got)
	}
}

// A keepalive Request that lands while handleMembershipQuery is between
// handle_query (Active to Querying) and send_update used to find the Rust
// gateway in Querying and fail with InvalidState, which the next read returned
// as "failed to request membership: 2" (BLO-47396). handleMu makes it wait for
// the Update, after which the Request goes out from Active.
func TestGatewayKeepaliveRequestWaitsForQueryHandling(t *testing.T) {
	fr := newFakeRelay(t, withQueryIntervalCode(0x01))
	addr := fr.Addr()
	gw := &Gateway{
		RelayAddr:  &addr,
		GroupAddr:  net.ParseIP("232.0.0.1"),
		SourceAddr: net.ParseIP("192.0.2.1"),
		MTU:        1500,
		Timeout:    5 * time.Second,
	}
	refreshed := make(chan error, 1)
	var once sync.Once
	betweenQueryAndUpdate = func(g *Gateway) {
		once.Do(func() {
			go func() { refreshed <- g.refreshMembership() }()
			// Give an unserialized Request ample time to reach the Rust
			// gateway while it is still in Querying.
			time.Sleep(50 * time.Millisecond)
		})
	}
	t.Cleanup(func() { betweenQueryAndUpdate = nil })

	if err := gw.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer gw.abortOpen()

	select {
	case err := <-refreshed:
		if err != nil {
			t.Fatalf("keepalive Request during Query handling: %v; want it to wait for the Update and succeed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive Request never completed")
	}
}
