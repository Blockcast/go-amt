//go:build linux || darwin

package amt

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

// fakeNativeSource is the native-multicast counterpart to fakeRelay: an
// in-process stand-in for a native multicast source, so a test can make a
// native join deliver or go silent ON DEMAND, per group, independently of
// whatever the relay is doing.
//
// WHY IT CANNOT JUST JOIN A GROUP. The real ListenMulticastUDP4 ends in
// IP_ADD_MEMBERSHIP against a named interface. A stock ubuntu-latest runner has
// no multicast route and no CAP_NET_ADMIN, so that join either fails outright or
// succeeds and then receives nothing there is no route for — and either way the
// test cannot decide when traffic starts and stops. So the fake substitutes the
// listenMulticastUDP4 seam and hands back a loopback UDP socket that it also
// sends to. What the code under test receives is a real *ipv4.PacketConn with
// real read-deadline semantics, which is what makes probeNativeTraffic genuinely
// exercised rather than mocked: the probe sets a deadline and blocks on a real
// socket, and whether that deadline expires is decided by whether this fake
// chose to send. Nothing about the delivery-path decision is stubbed — only the
// packet source is.
//
// Provenance is carried in the payload (see nativePayload / provenanceOf) rather
// than inferred from the socket, because that is the only thing that survives
// the AMT tunnel's re-encapsulation. It lets a switchover assertion distinguish
// "still receiving something" from "receiving via the path we expected", which
// is the distinction a fallback test exists to make.
//
// The seam is package state, so a test using this must not call t.Parallel.
type fakeNativeSource struct {
	t *testing.T

	// cadence is how often a packet is emitted to each enabled group. It stands
	// in for a source's send interval; it is deliberately far tighter than the
	// >=5s signalling cadence MinUsefulProbeWindow is sized against, so a test
	// that expects native to be chosen does not pay a real interval to see it.
	cadence time.Duration

	// binds counts seam calls, so a test can assert the fake was actually
	// reached. Without it a harness that silently failed to install would make
	// every "native delivered" assertion pass for the wrong reason.
	binds atomic.Int64
	sent  atomic.Int64

	mu sync.Mutex
	// enabled is the set of group IPs currently delivering, keyed by
	// net.IP.String(). Per-group rather than one global switch because a
	// switchover test has to be able to silence the group under test while
	// leaving anything else alone.
	enabled map[string]bool
	targets []nativeTarget
	closed  bool
	// cmErr is the first SetControlMessage refusal any listen saw, reported once
	// from the cleanup. See listen.
	cmErr error

	send *net.UDPConn
	stop chan struct{}
	wg   sync.WaitGroup
}

// nativeTarget is one join the code under test performed: the group it asked
// for, and the loopback address whose socket now stands in for it.
type nativeTarget struct {
	group string
	addr  *net.UDPAddr
}

const (
	// nativeProvenanceTag and tunnelProvenanceTag prefix a payload so a reader
	// can name the path a datagram actually travelled.
	nativeProvenanceTag = "native"
	tunnelProvenanceTag = "tunnel"

	// unknownProvenanceTag is what provenanceOf reports for bytes neither fake
	// emitted. It is a distinct answer from either path on purpose: a test that
	// treats "not native" as "tunnel" would call a corrupted or foreign packet a
	// successful switchover.
	unknownProvenanceTag = "unknown"
)

// nativePayload builds a datagram tagged as having come from the native source.
func nativePayload(seq int) []byte {
	return []byte(nativeProvenanceTag + "|" + strconv.Itoa(seq))
}

// tunnelPayload builds a datagram tagged as having come through the AMT tunnel,
// for a test to hand to fakeRelay.SendData.
func tunnelPayload(seq int) []byte {
	return []byte(tunnelProvenanceTag + "|" + strconv.Itoa(seq))
}

// provenanceOf names the delivery path a payload was emitted on, or
// unknownProvenanceTag if neither fake produced it.
func provenanceOf(payload []byte) string {
	tag, _, ok := strings.Cut(string(payload), "|")
	if !ok {
		return unknownProvenanceTag
	}
	switch tag {
	case nativeProvenanceTag, tunnelProvenanceTag:
		return tag
	default:
		return unknownProvenanceTag
	}
}

// installFakeNativeSource replaces the shared native-join seam for the duration
// of one test and returns the source now standing behind it.
//
// Delivery starts OFF for every group. A test must Enable the group it wants
// delivering, which is what keeps "native is silent" the default rather than
// something a test has to remember to arrange.
func installFakeNativeSource(t *testing.T) *fakeNativeSource {
	t.Helper()

	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake native source: open sender: %v", err)
	}

	fn := &fakeNativeSource{
		t:       t,
		cadence: 10 * time.Millisecond,
		enabled: map[string]bool{},
		send:    send,
		stop:    make(chan struct{}),
	}

	orig := listenMulticastUDP4
	listenMulticastUDP4 = fn.listen
	t.Cleanup(func() {
		listenMulticastUDP4 = orig
		if err := fn.controlMessageErr(); err != nil {
			t.Logf("fake native source: SetControlMessage refused (%v); the code under "+
				"test saw nil control messages, so a cm-dependent failure in this test is "+
				"the harness degrading, not the product", err)
		}
		fn.Close()
	})

	fn.wg.Add(1)
	go fn.run()

	return fn
}

// listen is the seam replacement. It ignores the interface, BPF program, TTL and
// buffer sizing — none of which a loopback stand-in can honour — and returns a
// socket the source can reach.
func (fn *fakeNativeSource) listen(network string, ifi *net.Interface, saddr netip.Addr,
	gaddr *net.UDPAddr, f []bpf.RawInstruction, timestamp bool, ttl int,
	flags4 ipv4.ControlFlags, rcvBufBytes, sndBufBytes int) (*ipv4.PacketConn, error) {

	if gaddr == nil || gaddr.IP.To4() == nil {
		// Mirror the real listener's rejection rather than accepting what it
		// would not, so a caller passing a bad group still fails here.
		return nil, fmt.Errorf("invalid ipv4 address")
	}

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	local := c.LocalAddr().(*net.UDPAddr)
	pc := ipv4.NewPacketConn(c)

	// The real listener enables these, and a caller's control message is only
	// ever non-nil because of it. Best-effort: a loopback socket in a restricted
	// container may refuse, and no assertion in this harness depends on cm, so
	// refusing is not worth failing the test over.
	//
	// The CODE UNDER TEST does read the control message, though, so a silent
	// refusal here resurfaces as a nil-cm fault inside production code and reads
	// as a product defect rather than a harness limitation. Record it and report
	// it from the cleanup — not with fn.t here, because listen runs on whatever
	// goroutine the code under test called Open from, and logging to an
	// already-completed test panics.
	cmErr := pc.SetControlMessage(flags4, true)

	fn.mu.Lock()
	defer fn.mu.Unlock()
	if cmErr != nil && fn.cmErr == nil {
		fn.cmErr = cmErr
	}
	if fn.closed {
		_ = pc.Close()
		return nil, fmt.Errorf("fake native source is closed")
	}
	fn.targets = append(fn.targets, nativeTarget{group: gaddr.IP.String(), addr: local})
	fn.binds.Add(1)
	return pc, nil
}

// Enable starts native delivery for a group. Idempotent.
func (fn *fakeNativeSource) Enable(group netip.Addr) {
	fn.mu.Lock()
	defer fn.mu.Unlock()
	fn.enabled[net.IP(group.AsSlice()).String()] = true
}

// Disable silences native delivery for a group without touching the socket, so
// the code under test sees exactly what a source going quiet looks like: a live
// join that stops producing. Tearing the socket down instead would surface as a
// read error, which is a different failure and not the one being tested.
func (fn *fakeNativeSource) Disable(group netip.Addr) {
	fn.mu.Lock()
	defer fn.mu.Unlock()
	delete(fn.enabled, net.IP(group.AsSlice()).String())
}

// Delivered reports how many datagrams the source has put on the wire, so a
// test can tell "native never sent" apart from "native sent and was ignored".
//
// The guarantee is one-directional, and that is deliberate — see run. If a
// payload has been read by the code under test, this CANNOT report 0. The
// converse does not hold: a write that failed is counted for the instant
// between the increment and its undo, so this can momentarily read high. Assert
// Delivered() > 0 to prove the source fed a test; assert Delivered() == 0 only
// in a test that never enables a group.
func (fn *fakeNativeSource) Delivered() int64 { return fn.sent.Load() }

// Binds reports how many joins went through the seam.
func (fn *fakeNativeSource) Binds() int64 { return fn.binds.Load() }

// controlMessageErr reports the first SetControlMessage refusal, if any.
func (fn *fakeNativeSource) controlMessageErr() error {
	fn.mu.Lock()
	defer fn.mu.Unlock()
	return fn.cmErr
}

func (fn *fakeNativeSource) Close() {
	fn.mu.Lock()
	if fn.closed {
		fn.mu.Unlock()
		return
	}
	fn.closed = true
	fn.mu.Unlock()

	close(fn.stop)
	_ = fn.send.Close()
	fn.wg.Wait()
}

// run emits one datagram per cadence tick to every enabled group.
func (fn *fakeNativeSource) run() {
	defer fn.wg.Done()

	tick := time.NewTicker(fn.cadence)
	defer tick.Stop()

	seq := 0
	for {
		select {
		case <-fn.stop:
			return
		case <-tick.C:
			seq++
			payload := nativePayload(seq)

			fn.mu.Lock()
			batch := make([]*net.UDPAddr, 0, len(fn.targets))
			for _, tgt := range fn.targets {
				if fn.enabled[tgt.group] {
					batch = append(batch, tgt.addr)
				}
			}
			fn.mu.Unlock()

			for _, addr := range batch {
				// COUNT BEFORE WRITING, and undo on failure. The ordering is
				// load-bearing, not stylistic.
				//
				// Once WriteToUDP returns, the datagram is already queued in the
				// kernel and readable by the code under test. Incrementing after
				// it — which this did until BLO-29741 — leaves a window in which a
				// payload has been read and verified while Delivered() still
				// reports 0, because the scheduler is free to preempt this
				// goroutine between the two statements. A precondition guard
				// asserting Delivered() > 0 then fails a test that genuinely
				// passed: CI run 32568421905 hit exactly that, and the guard at
				// fakenative_flows_test.go accused the assertion above it of
				// testing nothing when it had in fact tested everything it claims.
				//
				// Counting first inverts the error into the harmless direction. A
				// failed write is briefly over-counted before the decrement lands,
				// which can only ever make Delivered() read HIGH for a datagram
				// that was not delivered — never zero for one that was. Nothing
				// asserts an exact successful-write count; the guards are
				// Delivered() > 0 with a group enabled, and Delivered() == 0 in
				// tests that never enable a group at all. The latter attempt no
				// writes whatsoever, so the transient is unreachable from them.
				// Do not add a Delivered() == 0 assertion to a test that enables a
				// group — that is the one shape this ordering cannot serve.
				//
				// A closed target is expected: the code under test tears its join
				// down on handover to the tunnel. Ignore rather than fail the test
				// from a background goroutine.
				fn.sent.Add(1)
				if _, err := fn.send.WriteToUDP(payload, addr); err != nil {
					fn.sent.Add(-1)
				}
			}
		}
	}
}

// datagramReader is the read surface a provenance assertion needs, satisfied by
// both MulticastConn and ManagedConn.
type datagramReader interface {
	ReadFrom(p []byte) (int, net.Addr, error)
}

// nativeSocketReader adapts a raw *ipv4.PacketConn to datagramReader.
//
// The x/net conn returns a control message the two conn types absorb, so its
// ReadFrom is four-valued and does not satisfy net.PacketConn. This exists so a
// harness self-test can read the seam's socket DIRECTLY, under the same bounded
// helper the conn types are read through — a failure there is then
// unambiguously the harness rather than an arbiter reading it differently.
type nativeSocketReader struct{ pc *ipv4.PacketConn }

func (r nativeSocketReader) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, src, err := r.pc.ReadFrom(p)
	return n, src, err
}

// SetReadDeadline promotes nativeSocketReader to deadlineReader, which is what
// keeps readOne from abandoning a goroutine on this reader. See readOne.
func (r nativeSocketReader) SetReadDeadline(t time.Time) error {
	return r.pc.SetReadDeadline(t)
}

// deadlineReader is a datagramReader whose read can be bounded IN PLACE, so a
// timed-out read leaves nothing running behind it.
//
// Membership is by EXPLICIT OPT-IN — the unexported marker method — and not by
// method presence. An earlier revision of this interface required only
// datagramReader plus SetReadDeadline. Go interface satisfaction is structural,
// so that also captured *ManagedConn and *MulticastConn, the two types the
// comment here claimed it excluded: ManagedConn.SetReadDeadline is defined in
// managed_conn.go and MulticastConn.SetReadDeadline in conn.go.
//
// For *ManagedConn on the tunnel path the two halves do not line up:
//
//   - SetReadDeadline falls through to `return nil` — it reports success having
//     set nothing, because AMT deadline handling was never implemented.
//   - ReadFrom selects on readBuffer/done with NO timeout case.
//
// So readOneWithDeadline set a deadline that reached nothing and then parked on
// a channel forever, with none of the goroutine path's time.After backstop. The
// concrete site is the 16-packet tunnel burst in fakenative_flows_test.go, which
// calls readOne(silent, ...) after asserting IsUsingTunnel(): one dropped packet
// and that read never returns, so the t.Fatalf naming the defect is unreachable
// and the run dies on the test binary's global timeout with a goroutine dump
// instead. The bound was missing in exactly the failure mode it exists to
// report, and CI stayed green only because the relay does deliver.
//
// Hence the marker. Structural capture is silent and compiles; opting in is a
// deliberate claim that has to be written down next to the reader making it.
type deadlineReader interface {
	datagramReader
	SetReadDeadline(time.Time) error

	// canBoundReadInPlace has no behaviour. Implementing it asserts that
	// SetReadDeadline actually reaches the read ReadFrom performs. Do NOT
	// implement it on a reader whose read can park on a channel — that is the
	// defect described above.
	canBoundReadInPlace()
}

// The seam socket MUST keep satisfying deadlineReader: if it stopped, readOne
// would silently fall back to the goroutine path and
// TestReadOneTimeoutDoesNotStealTheNextDatagram's hazard would return.
var _ deadlineReader = nativeSocketReader{}

// canBoundReadInPlace: nativeSocketReader wraps a real *ipv4.PacketConn, so the
// deadline readOneWithDeadline sets does reach the ReadFrom underneath it.
//
// TestConnTypesDoNotClaimInPlaceReadBounds pins the negative direction, which is
// the half a compile-time assertion cannot express.
func (nativeSocketReader) canBoundReadInPlace() {}

// readOne reads a single datagram under a bound.
//
// Where the reader can bound its own read (the raw seam socket), use that: a
// timed-out deadline read leaves NOTHING parked on the socket. That matters more
// than tidiness. The goroutine fallback below abandons its reader on timeout,
// and an abandoned reader goes on to consume the next datagram to arrive and
// post it to a channel nobody reads — stealing it from the following readOne.
// Under a negative assertion ("nothing must arrive") that is fatal: the drain
// loop preceding it exits BY timing out, so a straggler — exactly the defect the
// assertion exists to catch — could be swallowed by the abandoned reader instead
// of failing the test. The bound would then be a coin flip.
//
// The goroutine path remains for the two conn types, where the tunnel path parks
// on a channel that no deadline reaches, so a bound indifferent to which path is
// live cannot be built from deadlines alone. Those readers are never the subject
// of a straggler assertion; the seam socket is.
//
// The channel is buffered so the reader goroutine can always finish and exit
// after a timeout instead of blocking forever on a send nobody will receive.
func readOne(r datagramReader, timeout time.Duration) ([]byte, error) {
	if dr, ok := r.(deadlineReader); ok {
		return readOneWithDeadline(dr, timeout)
	}

	type result struct {
		payload []byte
		err     error
	}
	ch := make(chan result, 1)

	go func() {
		buf := make([]byte, 2048)
		n, _, err := r.ReadFrom(buf)
		ch <- result{payload: append([]byte(nil), buf[:n]...), err: err}
	}()

	select {
	case res := <-ch:
		return res.payload, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("no datagram within %s", timeout)
	}
}

// readOneWithDeadline is readOne's in-place bound. The deadline is cleared again
// on the way out so this call's bound cannot leak into a later read of the same
// socket made through some other helper.
func readOneWithDeadline(r deadlineReader, timeout time.Duration) ([]byte, error) {
	if err := r.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	defer func() { _ = r.SetReadDeadline(time.Time{}) }()

	buf := make([]byte, 2048)
	n, _, err := r.ReadFrom(buf)
	if err != nil {
		// Report a timeout in readOne's words, so callers that only ever see the
		// bound cannot tell the two implementations apart.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, fmt.Errorf("no datagram within %s", timeout)
		}
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// reporter is the failure surface the shared assertions below report through.
//
// It exists so the SAME assertion body can be driven by a real *testing.T and by
// a recorder that captures failures instead of raising them. That is what makes
// the negative control below a genuine control: it runs the real assertion under
// a condition that must break it, rather than a paraphrase of it that might not.
//
// Errorf only, deliberately: t.Fatalf unwinds the calling goroutine, so a body
// shared with a recorder cannot use it and still be the same code on both paths.
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// failureRecorder is a reporter that remembers failures rather than raising them.
type failureRecorder struct {
	mu       sync.Mutex
	failures []string
}

func (fr *failureRecorder) Helper() {}

func (fr *failureRecorder) Errorf(format string, args ...any) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	fr.failures = append(fr.failures, fmt.Sprintf(format, args...))
}

func (fr *failureRecorder) failed() bool {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	return len(fr.failures) > 0
}

func (fr *failureRecorder) report() string {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if len(fr.failures) == 0 {
		return "(no failures recorded)"
	}
	return strings.Join(fr.failures, "; ")
}
