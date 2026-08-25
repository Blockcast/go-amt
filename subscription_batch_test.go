package amt

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// tunnelConn returns a ManagedConn in the state Open leaves a successful relay
// handshake in: openDone closed so the data plane does not wait, usingTunnel
// set, no native socket, and a buffered readBuffer standing in for the
// subscription feed the RelayManager would be writing into.
//
// Constructing it directly rather than through Open is what makes these tests
// hermetic — the subscription read path is reachable without a relay, a socket,
// or root.
func tunnelConn(bufSize int) *ManagedConn {
	openDone := make(chan struct{})
	close(openDone)
	return &ManagedConn{
		openDone:    openDone,
		done:        make(chan struct{}),
		usingTunnel: true,
		readBuffer:  make(chan *DataPacket, bufSize),
	}
}

func testPacket(payload string) *DataPacket {
	return &DataPacket{
		Data:   []byte(payload),
		Source: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000},
	}
}

// sizedBatch returns n messages each with a real buffer, i.e. every slot has
// room. This is the shape both production consumers build
// (cmd/amt_bridge/main.go, cmd/amt_gw/main.go).
func sizedBatch(n, size int) []ipv4.Message {
	ms := make([]ipv4.Message, n)
	for i := range ms {
		ms[i] = ipv4.Message{Buffers: [][]byte{make([]byte, size)}}
	}
	return ms
}

// readBatchWithin runs ReadBatch under a deadline and fails the test if it does
// not return in time.
//
// Every read in this file goes through it, because the failure mode being
// guarded destroys packets: a reader that then asks for the data blocks forever
// on a channel nothing will ever fill again. Bounding the call turns that into a
// named assertion failure instead of a suite that hangs until the CI timeout and
// reports nothing about which invariant broke.
func readBatchWithin(t *testing.T, mc *ManagedConn, ms []ipv4.Message, what string) (int, error) {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := mc.ReadBatch(ms, 0)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked for 2s: it is waiting on a packet that was consumed and dropped by an earlier no-room read", what)
		return 0, nil
	}
}

func readFromWithin(t *testing.T, mc *ManagedConn, buf []byte, what string) (int, net.Addr, error) {
	t.Helper()
	type result struct {
		n    int
		addr net.Addr
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		n, addr, err := mc.ReadFrom(buf)
		ch <- result{n, addr, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.addr, r.err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked for 2s", what)
		return 0, nil, nil
	}
}

func readFromWithControlMessageWithin(t *testing.T, mc *ManagedConn, buf []byte, what string) (int, net.Addr, error) {
	t.Helper()
	type result struct {
		n    int
		addr net.Addr
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		n, _, addr, err := mc.ReadFromWithControlMessage(buf)
		ch <- result{n, addr, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.addr, r.err
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked for 2s", what)
		return 0, nil, nil
	}
}

func TestSinglePacketReadersKeepTunnelPacketForZeroLengthBuffer(t *testing.T) {
	readers := []struct {
		name string
		read func(*testing.T, *ManagedConn, []byte, string) (int, net.Addr, error)
	}{
		{"ReadFrom", readFromWithin},
		{"ReadFromWithControlMessage", readFromWithControlMessageWithin},
	}

	for _, tc := range readers {
		t.Run(tc.name, func(t *testing.T) {
			mc := tunnelConn(1)
			mc.readBuffer <- testPacket("alpha")

			n, addr, err := tc.read(t, mc, []byte{}, "zero-length "+tc.name)
			if err != nil {
				t.Fatalf("zero-length %s: unexpected error %v", tc.name, err)
			}
			if n != 0 || addr != nil {
				t.Fatalf("zero-length %s = (%d, %v, nil), want (0, nil, nil)", tc.name, n, addr)
			}

			buf := make([]byte, 1500)
			n, addr, err = tc.read(t, mc, buf, "follow-up "+tc.name)
			if err != nil {
				t.Fatalf("follow-up %s: unexpected error %v", tc.name, err)
			}
			if got := string(buf[:n]); got != "alpha" {
				t.Fatalf("follow-up %s payload = %q, want %q", tc.name, got, "alpha")
			}
			if addr == nil {
				t.Fatalf("follow-up %s returned nil source address", tc.name)
			}
		})
	}
}

// A no-room message must not consume a packet. On the subscription path the
// packet is taken off readBuffer and there is nowhere to put it back, so a room
// check that happens after the receive destroys the packet outright — this is
// the mirror image of the pending-path defect, and the guard mirrors
// TestReadBatchWithNoRoomKeepsPendingPacket.
//
// Each case asserts the packets survive by draining them through a following
// well-sized ReadBatch: "did not consume" is only meaningful if the data is
// still deliverable afterwards.
func TestReadBatchWithNoRoomKeepsSubscriptionPacket(t *testing.T) {
	noRoom := []struct {
		name string
		msg  ipv4.Message
	}{
		{"nil buffers", ipv4.Message{}},
		{"empty buffers slice", ipv4.Message{Buffers: [][]byte{}}},
		{"zero-length first buffer", ipv4.Message{Buffers: [][]byte{{}}}},
	}

	for _, tc := range noRoom {
		t.Run(tc.name, func(t *testing.T) {
			const npkts = 3
			mc := tunnelConn(npkts)
			payloads := []string{"alpha", "bravo", "charlie"}
			for _, p := range payloads {
				mc.readBuffer <- testPacket(p)
			}

			// Every slot is unusable, so the batch can accept nothing.
			ms := []ipv4.Message{tc.msg, tc.msg}
			n, err := readBatchWithin(t, mc, ms, "no-room ReadBatch")
			if err != nil {
				t.Fatalf("ReadBatch on no-room batch: unexpected error %v", err)
			}
			if n != 0 {
				t.Errorf("ReadBatch on no-room batch = %d, want 0", n)
			}
			if got := len(mc.readBuffer); got != npkts {
				t.Fatalf("readBuffer holds %d packets after a no-room ReadBatch, want %d — the no-room slot consumed and dropped %d", got, npkts, npkts-got)
			}

			// The packets must still be deliverable, in order, once given room.
			out := sizedBatch(npkts, 1500)
			n, err = readBatchWithin(t, mc, out, "follow-up ReadBatch")
			if err != nil {
				t.Fatalf("follow-up ReadBatch: unexpected error %v", err)
			}
			if n != npkts {
				t.Fatalf("follow-up ReadBatch = %d, want %d", n, npkts)
			}
			for i, want := range payloads {
				if got := string(out[i].Buffers[0][:out[i].N]); got != want {
					t.Errorf("packet %d = %q, want %q", i, got, want)
				}
			}
		})
	}
}

// The count must describe a contiguous filled prefix. A no-room slot in the
// middle of an otherwise usable batch is the case that separates "return short"
// from "skip the slot": skipping advances i while leaving ms[i] unfilled, so the
// slot stays inside ms[:count] and the caller reads a message that never
// received a packet. amt_bridge would re-emit a zero-length payload for it
// (cmd/amt_bridge/main.go:155), on top of losing the packet the slot ate.
func TestReadBatchReturnsShortRatherThanSkippingNoRoomSlot(t *testing.T) {
	mc := tunnelConn(3)
	for _, p := range []string{"alpha", "bravo", "charlie"} {
		mc.readBuffer <- testPacket(p)
	}

	ms := []ipv4.Message{
		{Buffers: [][]byte{make([]byte, 1500)}},
		{Buffers: [][]byte{{}}}, // no room: must end the batch here
		{Buffers: [][]byte{make([]byte, 1500)}},
	}

	n, err := readBatchWithin(t, mc, ms, "ReadBatch")
	if err != nil {
		t.Fatalf("ReadBatch: unexpected error %v", err)
	}
	if n != 1 {
		t.Fatalf("ReadBatch = %d, want 1 (short at the no-room slot); a count of 2 claims ms[1], which was never filled", n)
	}
	if got := string(ms[0].Buffers[0][:ms[0].N]); got != "alpha" {
		t.Errorf("ms[0] = %q, want %q", got, "alpha")
	}
	// The two packets past the short return must be untouched, not dropped.
	if got := len(mc.readBuffer); got != 2 {
		t.Errorf("readBuffer holds %d packets, want 2", got)
	}
}

// The blocking arm has the same obligation as the non-blocking one. It is
// reached only with an empty readBuffer and nothing filled yet, which is
// exactly where the old code blocked, consumed a packet, discarded it for want
// of room, and returned (0, nil) — a read that loses data while reporting no
// error.
//
// Post-fix the no-room slot short-circuits before the receive, so the call
// returns immediately and the packet that arrives during it is still queued.
func TestReadBatchNoRoomDoesNotConsumeFromEmptyBuffer(t *testing.T) {
	mc := tunnelConn(1)

	// Delivered while the call is in flight. The buffer has capacity, so this
	// send never blocks regardless of scheduling: pre-fix the blocking arm eats
	// it, post-fix it stays queued.
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		time.Sleep(10 * time.Millisecond)
		mc.readBuffer <- testPacket("alpha")
	}()

	// The no-room slot must short-circuit before the receive, so this returns
	// without waiting for a packet it could not store. readBatchWithin bounds it:
	// pre-fix this arm blocks until the goroutine's packet arrives, then eats it.
	n, err := readBatchWithin(t, mc, []ipv4.Message{{Buffers: [][]byte{{}}}}, "no-room ReadBatch on an empty buffer")
	if err != nil {
		t.Fatalf("ReadBatch: unexpected error %v", err)
	}
	if n != 0 {
		t.Errorf("ReadBatch = %d, want 0", n)
	}

	<-sent
	out := sizedBatch(1, 1500)
	n, err = readBatchWithin(t, mc, out, "follow-up ReadBatch")
	if err != nil {
		t.Fatalf("follow-up ReadBatch: unexpected error %v", err)
	}
	if n != 1 {
		t.Fatalf("follow-up ReadBatch = %d, want 1 — the no-room call consumed the packet and dropped it", n)
	}
	if got := string(out[0].Buffers[0][:out[0].N]); got != "alpha" {
		t.Errorf("payload = %q, want %q", got, "alpha")
	}
}

// Guard the ordinary path, so the room check cannot be "fixed" by refusing
// every batch.
func TestReadBatchFillsEverySlotWithRoom(t *testing.T) {
	mc := tunnelConn(2)
	mc.readBuffer <- testPacket("alpha")
	mc.readBuffer <- testPacket("bravo")

	ms := sizedBatch(2, 1500)
	n, err := readBatchWithin(t, mc, ms, "ReadBatch")
	if err != nil {
		t.Fatalf("ReadBatch: unexpected error %v", err)
	}
	if n != 2 {
		t.Fatalf("ReadBatch = %d, want 2", n)
	}
	for i, want := range []string{"alpha", "bravo"} {
		if got := string(ms[i].Buffers[0][:ms[i].N]); got != want {
			t.Errorf("ms[%d] = %q, want %q", i, got, want)
		}
		if ms[i].Addr == nil {
			t.Errorf("ms[%d].Addr not set", i)
		}
	}
}
