package amt

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
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
