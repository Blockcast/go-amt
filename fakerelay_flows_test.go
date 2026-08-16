package amt

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
)

var (
	testHarnessSource = netip.MustParseAddr("10.1.2.3")
	testHarnessGroup  = netip.MustParseAddr("232.1.2.3")
)

const testHarnessPort = 5004

// packetSourceIP unwraps the concrete address a delivered packet carries.
func packetSourceIP(t *testing.T, p *DataPacket) net.IP {
	t.Helper()
	ua, ok := p.Source.(*net.UDPAddr)
	if !ok {
		t.Fatalf("packet source is %T, want *net.UDPAddr", p.Source)
	}
	return ua.IP
}

// TestFakeRelayCompletesHandshake exercises the Relay Discovery -> Relay
// Advertisement -> Request -> Membership Query legs with no external relay.
func TestFakeRelayCompletesHandshake(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	if got := rm.State(); got != RelayStateActive {
		t.Fatalf("state after handshake = %v, want %v", got, RelayStateActive)
	}
	if n := fr.advertised.Load(); n != 1 {
		t.Errorf("relay advertisements sent = %d, want 1", n)
	}
	if n := fr.queried.Load(); n != 1 {
		t.Errorf("membership queries sent = %d, want 1", n)
	}
}

// TestFakeRelaySubscribeEmitsMembershipUpdate covers the Membership Update leg.
func TestFakeRelaySubscribeEmitsMembershipUpdate(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	key := SubscriptionKey{Source: testHarnessSource, Group: testHarnessGroup, Port: testHarnessPort}
	if _, err := rm.Subscribe(key, SubscriptionCallbacks{}); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	update, err := fr.WaitForUpdate(5 * time.Second)
	if err != nil {
		t.Fatalf("membership update: %v", err)
	}

	// [0]=V/Type [1]=rsvd [2..7]=response MAC [8..11]=nonce [12..]=IGMP report.
	if len(update) < 13 {
		t.Fatalf("membership update too short: %d bytes", len(update))
	}
	if update[0]&0x0F != 0x05 {
		t.Errorf("update message type = %#x, want 0x05", update[0]&0x0F)
	}
	if !bytes.Contains(update[12:], testHarnessGroup.AsSlice()) {
		t.Errorf("membership update does not carry group %s", testHarnessGroup)
	}
}

// TestFakeRelayDeliversMulticastData covers the Multicast Data leg end to end.
func TestFakeRelayDeliversMulticastData(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	key := SubscriptionKey{Source: testHarnessSource, Group: testHarnessGroup, Port: testHarnessPort}
	sub := subscribeActive(t, rm, key)

	want := []byte("shred-payload-0")
	fr.SendData(testHarnessSource, testHarnessGroup, 4321, testHarnessPort, want)

	select {
	case pkt := <-sub.dataChan:
		if !bytes.Equal(pkt.Data, want) {
			t.Errorf("payload = %q, want %q", pkt.Data, want)
		}
		if !packetSourceIP(t, pkt).Equal(net.IP(testHarnessSource.AsSlice())) {
			t.Errorf("source = %v, want %v", packetSourceIP(t, pkt), testHarnessSource)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for multicast data")
	}
}

// TestQueuedPacketsOwnPayloadAndSourceAddress is the payload-aliasing
// regression. The read loop reuses one buffer and parses with gopacket.NoCopy,
// so both the payload and the parsed IP header alias it. A packet sitting on
// dataChan must not change when the next packet is read -- including its source
// address, which is a slice into that same buffer.
func TestQueuedPacketsOwnPayloadAndSourceAddress(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	// Two sources feeding the same group, each with its own subscription. The
	// read loop services both through one shared buffer, which is what makes the
	// aliasing observable.
	srcA := netip.MustParseAddr("10.9.9.1")
	srcB := netip.MustParseAddr("10.9.9.2")

	subA := subscribeActive(t, rm, SubscriptionKey{Source: srcA, Group: testHarnessGroup, Port: testHarnessPort})
	subB := subscribeActive(t, rm, SubscriptionKey{Source: srcB, Group: testHarnessGroup, Port: testHarnessPort + 1})

	payloadA := bytes.Repeat([]byte("A"), 512)
	payloadB := bytes.Repeat([]byte("B"), 512)

	fr.SendData(srcA, testHarnessGroup, 1111, testHarnessPort, payloadA)

	// Take delivery of A, then let B overwrite the shared read buffer before
	// inspecting the bytes A handed us.
	var first *DataPacket
	select {
	case first = <-subA.dataChan:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first packet")
	}

	fr.SendData(srcB, testHarnessGroup, 2222, testHarnessPort+1, payloadB)
	select {
	case <-subB.dataChan:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for second packet")
	}

	if !bytes.Equal(first.Data, payloadA) {
		t.Errorf("first payload was overwritten by the second read: got %q...", first.Data[:16])
	}
	if !packetSourceIP(t, first).Equal(net.IP(srcA.AsSlice())) {
		t.Errorf("first source address was overwritten by the second read: got %v, want %v",
			packetSourceIP(t, first), srcA)
	}
}

// TestControlTrafficDoesNotRefreshDataLiveness pins defect 3 against the
// harness: a Membership Query must refresh control liveness but never the
// data-delivery timestamp, or a relay that has stopped forwarding data still
// reads as healthy.
func TestControlTrafficDoesNotRefreshDataLiveness(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	// Baseline taken after the handshake, which seeds both stamps.
	beforeData := rm.lastDataMessage.Load()
	time.Sleep(50 * time.Millisecond)

	// A bare Membership Query, i.e. pure control-plane traffic.
	gw := fr.conn.LocalAddr()
	_ = gw
	fr.mu.Lock()
	gwAddr := fr.gateway
	fr.mu.Unlock()
	if gwAddr == nil {
		t.Fatal("no gateway address recorded")
	}
	if _, err := fr.conn.WriteToUDP(fr.buildQuery([]byte{1, 2, 3, 4}), gwAddr); err != nil {
		t.Fatalf("send query: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		if rm.lastAnyMessage.Load().After(beforeData) {
			break
		}
		select {
		case <-deadline:
			t.Fatal("control message never refreshed lastAnyMessage")
		case <-time.After(20 * time.Millisecond):
		}
	}

	if got := rm.lastDataMessage.Load(); !got.Equal(beforeData) {
		t.Errorf("membership query refreshed the data-liveness stamp: %v -> %v", beforeData, got)
	}
}

// TestReconnectRunsOneLoopPairPerGeneration pins defect 2: a reconnect must
// leave exactly one reader and one keepalive running, never zero and never a
// duplicate pair per attempt.
func TestReconnectRunsOneLoopPairPerGeneration(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	rm.loopsMu.Lock()
	genBefore := rm.loopGeneration
	rm.loopsMu.Unlock()

	rm.reconnectWithBackoff()

	rm.loopsMu.Lock()
	genAfter := rm.loopGeneration
	cancelFn := rm.loopsCancel
	rm.loopsMu.Unlock()

	if genAfter == genBefore {
		t.Errorf("loop generation did not advance across reconnect: %d", genAfter)
	}
	if cancelFn == nil {
		t.Fatal("reconnect left no live loop generation")
	}
	if got := rm.State(); got != RelayStateActive {
		t.Errorf("state after reconnect = %v, want %v", got, RelayStateActive)
	}

	// The reader must still be delivering after a reconnect -- the failure mode
	// in defect 2 was a dead reader with the manager still reporting Active.
	key := SubscriptionKey{Source: testHarnessSource, Group: testHarnessGroup, Port: testHarnessPort}
	sub := subscribeActive(t, rm, key)

	want := []byte("post-reconnect")
	fr.SendData(testHarnessSource, testHarnessGroup, 4321, testHarnessPort, want)

	select {
	case pkt := <-sub.dataChan:
		if !bytes.Equal(pkt.Data, want) {
			t.Errorf("payload = %q, want %q", pkt.Data, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no data after reconnect: reader did not restart")
	}
}

// TestSubscribeRejectsNonIPv4Synchronously pins defect 7. The IGMPv3 report
// builder calls netip.Addr.As4, which panics on a v6 address, and it runs from
// a time.AfterFunc goroutine where no recover() can catch it -- so the
// rejection has to happen synchronously, in the caller's own goroutine.
func TestSubscribeRejectsNonIPv4Synchronously(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	cases := []struct {
		name string
		key  SubscriptionKey
	}{
		{
			name: "ipv6 group",
			key: SubscriptionKey{
				Source: testHarnessSource,
				Group:  netip.MustParseAddr("ff3e::4321:1234"),
				Port:   testHarnessPort,
			},
		},
		{
			name: "ipv6 source",
			key: SubscriptionKey{
				Source: netip.MustParseAddr("2001:db8::1"),
				Group:  testHarnessGroup,
				Port:   testHarnessPort,
			},
		},
		{
			name: "zero group",
			key: SubscriptionKey{
				Source: testHarnessSource,
				Group:  netip.Addr{},
				Port:   testHarnessPort,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rm.Subscribe(tc.key, SubscriptionCallbacks{}); err == nil {
				t.Fatal("Subscribe accepted a non-IPv4 subscription; the report builder will panic off-goroutine")
			}
		})
	}

	// A panic raised in the batched-membership timer would surface here rather
	// than in the assertions above, so give that timer a chance to fire.
	time.Sleep(200 * time.Millisecond)
}

// TestConcurrentSubscribeIsRaceFree gives the race detector something to chew
// on across the read loop, the keepalive loop and the subscription map.
func TestConcurrentSubscribeIsRaceFree(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := SubscriptionKey{
				Source: netip.MustParseAddr("10.20.30.40"),
				Group:  netip.AddrFrom4([4]byte{232, 4, 0, byte(i)}),
				Port:   uint16(6000 + i),
			}
			if _, err := rm.Subscribe(key, SubscriptionCallbacks{}); err != nil {
				t.Errorf("Subscribe(%d): %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	fr.SendData(testHarnessSource, testHarnessGroup, 1234, testHarnessPort, []byte("x"))
	time.Sleep(200 * time.Millisecond)
}

// TestUnsubscribeDuringPendingJoinPreservesOtherSource covers the review finding
// on relay_manager.go:479 (Ally, PR #33, head 36ce988).
//
// Unsubscribe decides between a group-wide CHANGE_TO_INCLUDE_MODE leave and a
// source-specific BLOCK_OLD_SOURCES leave by scanning for other subscribers of
// the same group -- but it scans only rm.subscriptions. Subscribe parks a new
// subscription in rm.pendingJoins, where it stays until the 50ms debounced batch
// promotes it. Unsubscribing (S1,G) inside that window therefore cannot see
// (S2,G), emits the group-wide leave, and withdraws S2's membership for G.
//
// The window is real but narrow, so this test deliberately does NOT let the
// debounce drain after subscribing S2.
func TestUnsubscribeDuringPendingJoinPreservesOtherSource(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	group := testHarnessGroup
	s1 := netip.MustParseAddr("10.7.7.1")
	s2 := netip.MustParseAddr("10.7.7.2")

	key1 := SubscriptionKey{Source: s1, Group: group, Port: testHarnessPort}
	key2 := SubscriptionKey{Source: s2, Group: group, Port: testHarnessPort + 1}

	// S1 fully joined; its batch has drained.
	subscribeActive(t, rm, key1)
	fr.DrainUpdates()

	// S2 queued but deliberately still in pendingJoins.
	if _, err := rm.Subscribe(key2, SubscriptionCallbacks{}); err != nil {
		t.Fatalf("Subscribe(s2): %v", err)
	}
	if err := rm.Unsubscribe(key1); err != nil {
		t.Fatalf("Unsubscribe(s1): %v", err)
	}

	rt, err := fr.WaitForLeaveRecord(3 * time.Second)
	if err != nil {
		t.Fatalf("leave record: %v", err)
	}

	if rt == m.IGMPv3ChangeToIncludeMode {
		t.Fatalf("Unsubscribe emitted a group-wide CHANGE_TO_INCLUDE_MODE leave while (%s,%s) "+
			"was still pending: this withdraws the other source's membership for the group",
			s2, group)
	}
	if rt != m.IGMPv3BlockOldSources {
		t.Fatalf("leave record type = %d, want BLOCK_OLD_SOURCES (%d)", rt, m.IGMPv3BlockOldSources)
	}
}

// TestV4MappedSubscriptionCompletesFullLifecycle covers the boundary the
// Subscribe guard actually draws (Ally, PR #33, head 937c12a, Important #2).
//
// The guard admits v4-mapped IPv6 (`::ffff:a.b.c.d`, Is4()==false but
// Is4In6()==true) while both leave builders require strictly Is4(). So such a
// subscription used to join and receive, and then on Unsubscribe the builder
// errored, the error was discarded, no leave was ever sent, and Unsubscribe
// still returned nil -- the caller believed it had detached while the relay kept
// forwarding for the life of the session.
//
// Subscribe now normalises with Unmap(), so the mapped form is accepted and
// works end to end, and a failed leave is surfaced rather than swallowed.
func TestV4MappedSubscriptionCompletesFullLifecycle(t *testing.T) {
	fr := newFakeRelay(t)
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	mappedSrc := netip.MustParseAddr("::ffff:10.6.6.1")
	mappedGrp := netip.MustParseAddr("::ffff:232.6.6.6")
	if mappedSrc.Is4() || !mappedSrc.Is4In6() {
		t.Fatalf("test premise broken: %s Is4=%v Is4In6=%v", mappedSrc, mappedSrc.Is4(), mappedSrc.Is4In6())
	}

	key := SubscriptionKey{Source: mappedSrc, Group: mappedGrp, Port: testHarnessPort}
	subscribeActive(t, rm, key)
	fr.DrainUpdates()

	// The leave must actually be emitted, and Unsubscribe must not report
	// success if it was not.
	if err := rm.Unsubscribe(key); err != nil {
		t.Fatalf("Unsubscribe(v4-mapped) reported an error: %v", err)
	}

	if _, err := fr.WaitForLeaveRecord(3 * time.Second); err != nil {
		t.Fatalf("no leave emitted for a v4-mapped subscription: %v — "+
			"the relay would keep forwarding this (S,G) for the session lifetime", err)
	}
}

// TestDataStarvationReconnectsDespiteControlTraffic pins the *read* side of
// defect 3. TestControlTrafficDoesNotRefreshDataLiveness proves a Membership
// Query cannot write the data-delivery stamp; this proves the keepalive health
// decision reads that stamp rather than the control-plane one.
//
// Both halves are needed. Splitting lastData into lastAnyMessage /
// lastDataMessage only fixes defect 3 if the starvation check at
// relay_manager.go:950 consults the data stamp. Point it at lastAnyMessage and
// every other test in this package still passes, while the original failure
// mode returns in full: reader and keepalive alive, state Active, liveness
// perpetually fresh, zero shreds, forever.
//
// The scenario makes that substitution fatal. The fake relay answers every
// keepalive Request with a Membership Query, so control traffic keeps arriving
// for the whole test while no Multicast Data ever does. lastAnyMessage is
// therefore refreshed on every tick and a health check reading it would never
// fire. Reading lastDataMessage, starvation is detected after intervalTime*2
// and reconnectWithBackoff runs, observable as a loop-generation bump.
func TestDataStarvationReconnectsDespiteControlTraffic(t *testing.T) {
	// QQIC is decoded in units of 100ms (gopacket igmpTimeDecode), so code 1 is
	// a 100ms keepalive interval and starvation is declared at >200ms.
	fr := newFakeRelay(t, withQueryIntervalCode(1))
	rm := newTestManager(t, fr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rm.Open(ctx); err != nil {
		t.Fatalf("Open against fake relay: %v", err)
	}

	// Safe to read for the same reason receive_serialization_test.go documents:
	// performHandshake wrote it on this goroutine inside Open.
	interval := rm.intervalTime
	if interval != 100*time.Millisecond {
		t.Fatalf("relay-advertised keepalive interval = %v, want 100ms: the test's "+
			"timing budget is derived from it", interval)
	}

	rm.loopsMu.Lock()
	genBefore := rm.loopGeneration
	rm.loopsMu.Unlock()
	queriesBefore := fr.queried.Load()

	// Sampled inside the poll below, while the generation is still unchanged.
	// Reading it after the bump instead would count the reconnect's *own*
	// handshake Request -- reconnectWithBackoff runs performHandshake
	// (relay_manager.go:1011), which sends a Request that fakeRelay.handleRequest
	// counts (fakerelay_test.go:179), and only then calls startLoops
	// (relay_manager.go:1039) to bump the generation. A post-bump count is
	// therefore unconditionally greater and the guard below could never fail.
	var queriesDuringStarvation int64

	// Never send data. Starvation is expected at ~3*interval (the tick at
	// 1*interval is within intervalTime*2); allow generous headroom for a
	// loaded runner.
	start := time.Now()
	waitFor(t, 100*interval, func() bool {
		rm.loopsMu.Lock()
		defer rm.loopsMu.Unlock()
		if rm.loopGeneration > genBefore {
			return true
		}
		queriesDuringStarvation = fr.queried.Load()
		return false
	}, "keepaliveLoop to detect data starvation and reconnect while control traffic flows")
	elapsed := time.Since(start)

	// Guards the premise rather than the conclusion: if no Membership Query
	// arrived between the handshake and the reconnect, lastAnyMessage was never
	// refreshed either, so the reconnect above would have happened even from a
	// control-plane liveness read and this run would prove nothing.
	//
	// Counting only keepalive-driven queries is what lets this fail. The
	// starvation branch (relay_manager.go:950) returns *without* sending a
	// keepalive Request, so if the ticker's first tick lands after intervalTime*2
	// has already elapsed on a loaded runner, no control traffic ever flows --
	// exactly the degenerate run this guards.
	if queriesDuringStarvation <= queriesBefore {
		t.Errorf("relay sent no Membership Query between the handshake and the "+
			"reconnect (%d -> %d): control traffic never flowed, so this run does "+
			"not distinguish a data-liveness read from a control-plane one",
			queriesBefore, queriesDuringStarvation)
	}

	// readLoop also reconnects on any transport.Receive error
	// (relay_manager.go:813), producing an identical generation bump, so a
	// spurious one would otherwise read as a pass. Starvation cannot be declared
	// until intervalTime*2 after the stamp Open seeded just before startLoops
	// (relay_manager.go:380 -- lastDataMessage; :379 is lastAnyMessage, and it is
	// the data stamp that governs here), so requiring a single interval is a
	// conservative floor that an early transport-error reconnect misses.
	//
	// The bound is not unconditional: elapsed runs from start (:518), taken
	// *after* Open seeded, so with skew d = start - seed the real guarantee is
	// elapsed > 2*interval - d. A loaded runner delaying the reconnect only makes
	// elapsed larger; the one direction that shrinks it is descheduling inside d.
	// Requiring interval therefore tolerates d < interval, i.e. 100ms of headroom
	// against the two field reads and one mutex pair that separate Open from
	// :518 -- microseconds of real work. Ample, but a margin, not a certainty.
	if elapsed < interval {
		t.Errorf("reconnect came %v after the generation was sampled, sooner than "+
			"data starvation can be declared (>%v after Open seeds "+
			"lastDataMessage): this bump is more likely a spurious transport-error "+
			"reconnect than the path under test", elapsed, 2*interval)
	}
}
