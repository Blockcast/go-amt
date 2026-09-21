//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Close-during-Open guards for MulticastConn's native publication site.
//
// WHY THIS FILE EXISTS AT ALL. conn.go is tagged `cgo && !purego`, and the only
// -race job runs `go test -race -tags purego ./...` (ci.yml), which deselects
// the file outright — so every line in conn.go had zero race coverage on CI.
// cgo-test is the one lane that compiles it, and its -race step runs an explicit
// -run list. A test here is therefore only race-covered if its name is ALSO
// added to that list; without the second half the test compiles, runs under
// `go test ./...` with no detector, and the guard has no teeth. That is the same
// two-part shape BLO-29064 needed for gateway_leave_race_test.go, and the same
// vacuous-pass mode the coverage table at the top of ci.yml warns about.
//
// WHAT IS ASSERTED, AND WHY IT IS NOT JUST THE RACE. Publishing conn4/conn6
// under pathMu removes the data race on the field, but a reported race is the
// weaker signal: fixing the field write alone silences the detector while
// leaving a real fd leak. Close snapshots conn4/conn6 under the lock and closes
// what it finds, so a Close that completes entirely between the bind and the
// publish closes nothing — and an unguarded publish then attaches a live bound
// socket to a conn nobody will ever close again, while Open returns nil and the
// caller believes it succeeded.
// TestMulticastConnOpenOntoAClosedConnDoesNotLeakTheNativeSocket
// asserts that semantic deterministically; the race test below covers the
// interleaving the detector is needed for. Both are required: the deterministic
// one would pass on a fix that used no lock at all, and the race one would pass
// on a fix that locked the write and still leaked the socket.
//
// BOTH FAMILIES ARE COVERED, AND BOTH HALVES EXIST FOR EACH (BLO-35057). conn.go
// carries the identical pathMu + mc.closed guard at its v4 and v6 publication
// sites, and each is asserted here by its own deterministic/race pair — four
// tests, all four named in ci.yml's cgo -race -run list. v6 was the residual gap
// until BLO-34983 added listen_seam6.go: before it, the v6 bind called
// ListenMulticastUDP6 directly with nothing to substitute, and a real v6 group
// join cannot succeed on a stock runner (no multicast route, no CAP_NET_ADMIN),
// so a regression reintroduced only on the v6 branch shipped green. The seam's
// tag union — `(linux && !android) || (darwin && !ios)` — is a superset of this
// file's, so it is available wherever this file builds.
//
// The two families are guarded separately rather than through one table-driven
// test because the mutation they exist to catch is per-branch: deleting the
// mc.closed check from the v6 site alone leaves the v4 site intact, and a shared
// test parameterised over both would have to fail for the right family to prove
// anything. Two named pairs make the -race -run list say which site ran.

// handOutLoopbackNativeConns substitutes the v4 bind seam with one that returns
// a real loopback UDP socket, and records every socket it hands out so a test
// can ask afterwards whether Open closed it.
//
// It returns real sockets rather than stubs because the assertion is about
// ownership of an fd: "was this socket closed" has to be answerable, and a
// second Close on an already-closed net.UDPConn is exactly the observation that
// answers it. The recorder is mutex-guarded because the race test calls the seam
// from a goroutine racing the test body — an unguarded slice append would make
// the detector report the harness rather than conn.go.
//
// The seam is package state, so a test using this must not call t.Parallel.
func handOutLoopbackNativeConns(t *testing.T) (handed *[]*net.UDPConn, mu *sync.Mutex) {
	t.Helper()

	var (
		lock    sync.Mutex
		sockets []*net.UDPConn
	)

	orig := listenMulticastUDP4
	listenMulticastUDP4 = func(network string, ifi *net.Interface, saddr netip.Addr,
		gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, ttl int,
		flags4 ipv4.ControlFlags, rcvBufBytes, sndBufBytes int) (*ipv4.PacketConn, error) {
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			return nil, err
		}
		lock.Lock()
		sockets = append(sockets, udp)
		lock.Unlock()
		return ipv4.NewPacketConn(udp), nil
	}
	t.Cleanup(func() {
		listenMulticastUDP4 = orig
		lock.Lock()
		for _, s := range sockets {
			_ = s.Close()
		}
		lock.Unlock()
	})

	return &sockets, &lock
}

// newNativeOnlyConn builds a MulticastConn that binds and returns immediately:
// no relay is configured and the mode is explicitly native, so planProbe yields
// the zero probePlan — attemptNative true, Probe false, TunnelOnFailure false.
// Open therefore binds, publishes, and returns without starting the probe or
// tunnel goroutines, which is what makes the tests below deterministic rather
// than dependent on a probe window elapsing.
func newNativeOnlyConn() *MulticastConn {
	return &MulticastConn{
		SrcAddr:   netip.MustParseAddr("10.9.9.1"),
		GroupAddr: netip.MustParseAddr("232.0.0.1"),
		GroupPort: 5005,
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
		Mode:      AMTModeNative,
		Timeout:   time.Second,
	}
}

// TestMulticastConnOpenOntoAClosedConnDoesNotLeakTheNativeSocket pins the
// close-safety half: Open must not publish a socket onto a conn Close has
// already finished with, and must not strand the socket it bound.
//
// Close-then-Open is the deterministic form of the interleaving. The bind
// happens before the guard either way, so the seam is genuinely exercised and
// the socket genuinely exists — this is the exact window a concurrent Close
// lands in, without needing to win a race to reach it.
func TestMulticastConnOpenOntoAClosedConnDoesNotLeakTheNativeSocket(t *testing.T) {
	handed, mu := handOutLoopbackNativeConns(t)

	mc := newNativeOnlyConn()
	if err := mc.Close(); err != nil {
		t.Fatalf("Close() on a fresh conn = %v, want nil", err)
	}

	err := mc.Open()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open() after Close() = %v, want net.ErrClosed", err)
	}

	mu.Lock()
	sockets := append([]*net.UDPConn(nil), *handed...)
	mu.Unlock()
	if len(sockets) != 1 {
		t.Fatalf("bind seam called %d times, want 1; the guard was reached without binding, so this test is vacuous", len(sockets))
	}

	// A second Close on a socket Open already closed reports an error. A nil
	// here means Open returned ErrClosed but left the fd and its group
	// membership behind, which is the leak this guard exists to prevent.
	if cerr := sockets[0].Close(); cerr == nil {
		t.Fatal("Open() refused to publish but leaked the native socket: it was still open after Open returned")
	}

	mc.pathMu.RLock()
	conn4, conn6 := mc.conn4, mc.conn6
	mc.pathMu.RUnlock()
	if conn4 != nil || conn6 != nil {
		t.Fatalf("Open() published onto a closed conn: conn4=%v conn6=%v, want both nil", conn4, conn6)
	}
}

// TestMulticastConnCloseDuringOpenDoesNotRaceOnTheNativeConns drives Open and
// Close on separate goroutines so the detector adjudicates the field access.
//
// This test's verdict comes from -race, not from its assertions: with conn4
// written outside pathMu while Close reads it under the lock, this is a textbook
// unsynchronised read/write pair. It must be named in ci.yml's cgo -race -run
// list or it proves nothing. The loop runs the interleaving repeatedly because
// which goroutine reaches the lock first is scheduler-dependent, and only the
// order where Close lands between the bind and the publish exercises the guard;
// the detector needs one such interleaving, not all of them.
//
// The only functional assertion is the one the race cannot express: whichever
// order wins, no socket may be left open once both calls have returned. Open
// either publishes (and Close closes it, or the trailing Close does) or refuses
// and closes it itself — there is no third outcome in which an fd survives.
func TestMulticastConnCloseDuringOpenDoesNotRaceOnTheNativeConns(t *testing.T) {
	handed, mu := handOutLoopbackNativeConns(t)

	const attempts = 50
	for i := 0; i < attempts; i++ {
		mc := newNativeOnlyConn()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Both outcomes are legitimate: nil if Open published before Close
			// took the lock, net.ErrClosed if it did not.
			_ = mc.Open()
		}()
		go func() {
			defer wg.Done()
			_ = mc.Close()
		}()
		wg.Wait()

		// Close may have completed before Open published. Idempotent by
		// construction, and it is what a real consumer's deferred Close does.
		_ = mc.Close()
	}

	mu.Lock()
	sockets := append([]*net.UDPConn(nil), *handed...)
	mu.Unlock()
	if len(sockets) == 0 {
		t.Fatal("bind seam was never called; this test is vacuous")
	}
	for i, s := range sockets {
		if cerr := s.Close(); cerr == nil {
			t.Fatalf("socket %d of %d survived Open+Close: neither path closed it", i, len(sockets))
		}
	}
}

// handOutLoopbackNativeConnsV6 is the v6 counterpart of
// handOutLoopbackNativeConns: it substitutes the listenMulticastUDP6 seam with
// one returning a real loopback UDP socket and records every socket handed out.
// The rationale is the v4 one verbatim — real sockets because the assertion is
// about ownership of an fd, and a second Close on an already-closed
// *net.UDPConn is the observation that answers it; mutex-guarded because the
// race test calls the seam from a goroutine racing the test body.
//
// It binds [::1]:0, not a v6 multicast group. The group join is precisely what a
// stock runner cannot do, and it is not what is under test: the guard runs after
// the bind regardless of what the bind joined.
//
// The seam is package state, so a test using this must not call t.Parallel.
func handOutLoopbackNativeConnsV6(t *testing.T) (handed *[]*net.UDPConn, mu *sync.Mutex) {
	t.Helper()

	var (
		lock    sync.Mutex
		sockets []*net.UDPConn
	)

	orig := listenMulticastUDP6
	listenMulticastUDP6 = func(network string, ifi *net.Interface, saddr netip.Addr,
		gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, hoplimit int,
		flags6 ipv6.ControlFlags, rcvBufBytes, sndBufBytes int) (*ipv6.PacketConn, error) {
		udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
		if err != nil {
			return nil, err
		}
		lock.Lock()
		sockets = append(sockets, udp)
		lock.Unlock()
		return ipv6.NewPacketConn(udp), nil
	}
	t.Cleanup(func() {
		listenMulticastUDP6 = orig
		lock.Lock()
		for _, s := range sockets {
			_ = s.Close()
		}
		lock.Unlock()
	})

	return &sockets, &lock
}

// newNativeOnlyConnV6 is newNativeOnlyConn with a v6 group, which is the only
// thing that selects conn.go's v6 branch: Open dispatches on GroupAddr.Is6().
// Everything else is identical and for the same reason — no relay plus an
// explicit native mode yields the zero probePlan, so Open binds, publishes and
// returns without starting the probe or tunnel goroutines.
func newNativeOnlyConnV6() *MulticastConn {
	return &MulticastConn{
		SrcAddr:   netip.MustParseAddr("2001:db8::1"),
		GroupAddr: netip.MustParseAddr("ff3e::8000:1"),
		GroupPort: 5005,
		IFace:     &net.Interface{Index: 0, Name: "gonotexist0", MTU: 1500},
		Mode:      AMTModeNative,
		Timeout:   time.Second,
	}
}

// TestMulticastConnOpenOntoAClosedConnDoesNotLeakTheNativeSocketV6 is the v6
// half of TestMulticastConnOpenOntoAClosedConnDoesNotLeakTheNativeSocket, and
// asserts the same semantic at conn.go's v6 publication site. See that test for
// why close-then-Open is the deterministic form of the interleaving.
func TestMulticastConnOpenOntoAClosedConnDoesNotLeakTheNativeSocketV6(t *testing.T) {
	handed, mu := handOutLoopbackNativeConnsV6(t)

	mc := newNativeOnlyConnV6()
	if err := mc.Close(); err != nil {
		t.Fatalf("Close() on a fresh conn = %v, want nil", err)
	}

	err := mc.Open()
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open() after Close() = %v, want net.ErrClosed", err)
	}

	mu.Lock()
	sockets := append([]*net.UDPConn(nil), *handed...)
	mu.Unlock()
	if len(sockets) != 1 {
		t.Fatalf("v6 bind seam called %d times, want 1; the guard was reached without binding, so this test is vacuous", len(sockets))
	}

	if cerr := sockets[0].Close(); cerr == nil {
		t.Fatal("Open() refused to publish but leaked the native v6 socket: it was still open after Open returned")
	}

	mc.pathMu.RLock()
	conn4, conn6 := mc.conn4, mc.conn6
	mc.pathMu.RUnlock()
	if conn4 != nil || conn6 != nil {
		t.Fatalf("Open() published onto a closed conn: conn4=%v conn6=%v, want both nil", conn4, conn6)
	}
}

// TestMulticastConnCloseDuringOpenDoesNotRaceOnTheNativeConnsV6 is the v6 half
// of TestMulticastConnCloseDuringOpenDoesNotRaceOnTheNativeConns. Its verdict
// comes from -race, so like its v4 twin it must be named in ci.yml's cgo -race
// -run list or it proves nothing; see that test for the full rationale.
func TestMulticastConnCloseDuringOpenDoesNotRaceOnTheNativeConnsV6(t *testing.T) {
	handed, mu := handOutLoopbackNativeConnsV6(t)

	const attempts = 50
	for i := 0; i < attempts; i++ {
		mc := newNativeOnlyConnV6()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = mc.Open()
		}()
		go func() {
			defer wg.Done()
			_ = mc.Close()
		}()
		wg.Wait()

		_ = mc.Close()
	}

	mu.Lock()
	sockets := append([]*net.UDPConn(nil), *handed...)
	mu.Unlock()
	if len(sockets) == 0 {
		t.Fatal("v6 bind seam was never called; this test is vacuous")
	}
	for i, s := range sockets {
		if cerr := s.Close(); cerr == nil {
			t.Fatalf("v6 socket %d of %d survived Open+Close: neither path closed it", i, len(sockets))
		}
	}
}
