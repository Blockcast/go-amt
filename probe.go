package amt

import (
	"errors"
	"net"
	"time"
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
// return; the sentinel exists for callers like ManagedConn.tryNativeMulticast
// whose signature can only report an error.
var errNativeProbeTimedOut = errors.New("native multicast produced no traffic inside the probe window")

// probeNativeTraffic waits up to window for the native join to deliver a packet
// and reports whether it did.
//
// A timeout is not an error here: it is the answer the caller asked for. Any
// other error is real and is returned. The probe deadline is cleared on both
// outcomes so it can never bound a subsequent read.
//
// The packet consumed by a successful probe is discarded. That costs one
// signalling interval of startup latency on the native path and is tracked
// separately; it is not new behaviour.
func probeNativeTraffic(conn nativeConn, window time.Duration, mtu int, read func([]byte) error) (bool, error) {
	if err := conn.SetReadDeadline(time.Now().Add(window)); err != nil {
		return false, err
	}

	discard := make([]byte, mtu)
	err := read(discard)
	if err == nil {
		return true, conn.SetReadDeadline(time.Time{})
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		// Clear the expired deadline even though every caller today hands the
		// group to a tunnel on this path. A plan that probed without a fallback
		// would otherwise return a live socket carrying a deadline already in
		// the past, failing every subsequent read instantly — the exact shape of
		// the BLO-28640 outage, reintroduced one refactor later.
		return false, conn.SetReadDeadline(time.Time{})
	}
	return false, err
}
