package amt

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// This file deliberately carries no build tags, for the same reason amtmode.go
// does not: MulticastConn and ManagedConn are selected by *different* tag sets
// (conn.go requires cgo, managed_conn_native.go only linux||darwin), so shared
// probe machinery has to compile under the union of both. Keeping it here is
// what lets the two paths run one implementation instead of two copies that
// drift — which is how ManagedConn kept the BLO-28640 defect after
// MulticastConn was fixed.

// nativeConn is the subset of methods shared by *ipv4.PacketConn and
// *ipv6.PacketConn that the non-data-plane bookkeeping (Close, deadlines,
// local address) needs, independent of the IP version's control-message type.
type nativeConn interface {
	Close() error
	LocalAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// errNativeProbeTimedOut reports that the probe window elapsed without native
// traffic. It is a decision, not a fault: the caller asked whether native
// multicast delivers here and this is the answer "no".
//
// probeNativeTraffic itself distinguishes this from a real error by its bool
// return; the sentinel exists for callers like ManagedConn.dialNativeMulticast
// whose signature can only report an error.
var errNativeProbeTimedOut = errors.New("native multicast produced no traffic inside the probe window")

// pendingPacket is a datagram that was consumed while establishing the delivery
// path, held until a caller read can be served with it.
//
// The probe has to actually receive a packet to know native multicast delivers
// here, so on the signalling channel the evidence IS an SLT the receiver wants.
// Discarding it cost one full signalling interval (>=5s, per
// multicast/lls/server.go:29-31) before the receiver saw a table it had already
// been handed.
//
// cm is only ever populated on the v4 native path: the v6 read path in
// MulticastConn.ReadFromWithControlMessage drops the control message anyway,
// because ipv6.ControlMessage is a different type, so there is nothing
// meaningful to carry for it.
type pendingPacket struct {
	buf []byte
	cm  *ipv4.ControlMessage
	src net.Addr
}

// pendingStore holds at most one pendingPacket.
//
// Swap is what makes this safe rather than a lock: two readers arriving together
// both call take, exactly one gets the packet, and the other falls through to
// the socket. That is precisely the property the net.PacketConn contract needs
// at a path handover — a buffered packet can be neither delivered twice nor
// dropped — and it holds without adding a mutex to the data plane, which
// MulticastConn deliberately does not have.
type pendingStore struct {
	p atomic.Pointer[pendingPacket]
}

func (s *pendingStore) put(pkt *pendingPacket) { s.p.Store(pkt) }

// take removes and returns the held packet, or nil when there is none. Safe from
// any number of goroutines; at most one ever sees a given packet.
func (s *pendingStore) take() *pendingPacket { return s.p.Swap(nil) }

// peek reports the held packet without removing it, for callers that must decide
// whether a packet is owed *before* they can commit to delivering it.
//
// This exists so no read path ever mutates the store on a branch that cannot
// deliver. take-then-put-back looks harmless but is not atomic: between the two,
// the store is empty, so a concurrent reader takes nil, falls through to the
// socket, and delivers a *later* packet first. That reorders the stream the
// pending-first check exists to keep ordered (Ally review on go-amt#58).
//
// A peek result is advisory — another reader may take the packet immediately
// after. That is safe for its only use: reporting "0 packets read, nothing lost"
// on a batch with no room, which claims nothing about who eventually delivers it.
func (s *pendingStore) peek() *pendingPacket { return s.p.Load() }

// probeNativeTraffic waits up to window for the native join to deliver a packet
// and reports whether it did.
//
// A timeout is not an error here: it is the answer the caller asked for. Any
// other error is real and is returned. The probe deadline is cleared on both
// outcomes so it can never bound a subsequent read.
//
// On success the packet that proved the path is RETURNED rather than discarded,
// so the caller can hand it to the next read (see pendingPacket). read reports
// the byte count so that a zero-length datagram — valid UDP — stays
// distinguishable from "nothing arrived"; that distinction is carried by the
// bool, never by len(buf).
//
// A non-nil error always comes with a nil packet and a false bool. The error
// return never carries a datagram the caller has to remember not to use.
func probeNativeTraffic(conn nativeConn, window time.Duration, mtu int, read func([]byte) (int, error)) ([]byte, bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		return nil, false, err
	}

	// Clamp rather than trust: an interface reporting MTU 0 (or a negative
	// value) would otherwise make a zero-length buffer and read into nothing.
	// The clamp lives here because probe.go is the single shared implementation,
	// so one guard covers all three call sites — both conn.go branches, which
	// pass mc.IFace.MTU straight through, and managed_conn_native.go, whose own
	// default only handles a nil IFace and not a present one reporting zero.
	if mtu <= 0 {
		mtu = 1500
	}
	buf := make([]byte, mtu)
	n, err := read(buf)
	if err == nil {
		// Clear the deadline first, and yield no packet if that clear fails.
		// Returning (buf[:n], true, err) would describe a state no caller can
		// act on: all three call sites — conn.go's v6 and v4 branches and
		// managed_conn_native.go — test the error and return before they ever
		// look at the bool, so the datagram would be consumed here and then
		// dropped there. That is the defect this file exists to close, and
		// leaving it expressible in the signature invites it back.
		//
		// Nothing is lost by dropping it: SetReadDeadline can only fail on a
		// socket that has gone away underneath the probe (a structurally
		// invalid conn already returned at the deadline set above), and there
		// is then no live connection left to deliver into.
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			return nil, false, clearErr
		}
		return buf[:n], true, nil
	}
	// errors.As rather than a bare err.(net.Error) assertion: every read closure
	// returns the ReadFrom error unwrapped today (conn.go:125, :174,
	// managed_conn_native.go:54), so the assertion happens to succeed — but the
	// promise this branch keeps ("a timeout is the answer, not a failure") must
	// not depend on that. Wrapping one closure for context is a one-line edit
	// that would otherwise send a timeout to the hard-error return below, and
	// Open would fail instead of handing the group to the tunnel: the BLO-28640
	// shape reached through error classification rather than the deadline.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		// Clear the expired deadline even though every caller today hands the
		// group to a tunnel on this path. A plan that probed without a fallback
		// would otherwise return a live socket carrying a deadline already in
		// the past, failing every subsequent read instantly — the exact shape of
		// the BLO-28640 outage, reintroduced one refactor later.
		return nil, false, conn.SetReadDeadline(time.Time{})
	}
	return nil, false, err
}
