//go:build linux || darwin

package amt

import (
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
	_ = pc.SetControlMessage(flags4, true)

	fn.mu.Lock()
	defer fn.mu.Unlock()
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
func (fn *fakeNativeSource) Delivered() int64 { return fn.sent.Load() }

// Binds reports how many joins went through the seam.
func (fn *fakeNativeSource) Binds() int64 { return fn.binds.Load() }

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
				// A closed target is expected: the code under test tears its
				// join down on handover to the tunnel. Ignore rather than fail
				// the test from a background goroutine.
				if _, err := fn.send.WriteToUDP(payload, addr); err == nil {
					fn.sent.Add(1)
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

// readOne reads a single datagram under a bound.
//
// It runs the read on its own goroutine rather than using SetReadDeadline
// because the two delivery paths do not share a deadline mechanism: the native
// path is a socket, while the tunnel path parks on a channel that no deadline
// reaches. A bound that works on only one of them cannot be used by an
// assertion whose whole purpose is to be indifferent to which path is live.
//
// The channel is buffered so the reader goroutine can always finish and exit
// after a timeout instead of blocking forever on a send nobody will receive.
func readOne(r datagramReader, timeout time.Duration) ([]byte, error) {
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
