package amt

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// fakeRelay is an in-process AMT relay standing in for real relay infrastructure.
// It speaks enough of RFC 7450 for a RelayManager to complete a handshake and
// receive traffic: it answers Relay Discovery with a Relay Advertisement, answers
// a Request with a Membership Query, records Membership Updates, and pushes
// Multicast Data on demand.
//
// It exists so the defects this package has repeatedly regressed on
// (payload/address aliasing, reconnect loop duplication, data-liveness
// accounting) can be exercised deterministically, with no external relay and no
// network beyond loopback.
//
// Wire layouts below follow what this repository's decoders actually accept,
// which is not always what the matching MarshalBinary emits — see
// DecodeMembershipQueryMessage, whose flags field overlaps the message header.
type fakeRelay struct {
	t    *testing.T
	conn *net.UDPConn

	mu         sync.Mutex
	gateway    *net.UDPAddr
	updates    [][]byte
	closed     bool
	queryResp  time.Duration
	advertised atomic.Int64
	queried    atomic.Int64

	// queryIntervalCode is the QQIC byte of the Membership Query. The gateway
	// decodes it into RelayManager.intervalTime, which drives the keepalive
	// ticker and its data-liveness threshold -- so a test that must not race the
	// keepalive pins this rather than RelayManagerConfig.KeepaliveInterval, which
	// performHandshake overwrites. Immutable once serve starts; set it through
	// withQueryIntervalCode at construction, never afterwards.
	queryIntervalCode byte

	updateCh chan []byte
	done     chan struct{}
	wg       sync.WaitGroup
}

// fakeRelayOption customises a fakeRelay before its serve loop starts.
type fakeRelayOption func(*fakeRelay)

// withQueryIntervalCode overrides the QQIC byte the relay advertises in its
// Membership Query. gopacket decodes byte 9 with igmpTimeDecode, so a code
// below 0x80 means code*100ms: 0x0a is 1s (the default), 0x7f is 12.7s.
func withQueryIntervalCode(code byte) fakeRelayOption {
	return func(fr *fakeRelay) { fr.queryIntervalCode = code }
}

// newFakeRelay starts a relay bound to an ephemeral loopback port.
func newFakeRelay(t *testing.T, opts ...fakeRelayOption) *fakeRelay {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("fake relay listen: %v", err)
	}

	fr := &fakeRelay{
		t:                 t,
		conn:              conn,
		queryResp:         100 * time.Millisecond,
		queryIntervalCode: 0x0a,
		updateCh:          make(chan []byte, 16),
		done:              make(chan struct{}),
	}
	// Apply options before the serve goroutine exists: starting a goroutine is a
	// happens-before edge, so the fields it reads need no further synchronisation.
	// Mutating them after serve starts would be a genuine race.
	for _, opt := range opts {
		opt(fr)
	}

	fr.wg.Add(1)
	go fr.serve()

	t.Cleanup(fr.Close)
	return fr
}

// Addr is the address a RelayManager should be pointed at.
func (fr *fakeRelay) Addr() net.UDPAddr {
	a := fr.conn.LocalAddr().(*net.UDPAddr)
	return net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: a.Port}
}

func (fr *fakeRelay) Close() {
	fr.mu.Lock()
	if fr.closed {
		fr.mu.Unlock()
		return
	}
	fr.closed = true
	fr.mu.Unlock()

	close(fr.done)
	_ = fr.conn.Close()
	fr.wg.Wait()
}

func (fr *fakeRelay) serve() {
	defer fr.wg.Done()

	buf := make([]byte, 2048)
	for {
		select {
		case <-fr.done:
			return
		default:
		}

		_ = fr.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, addr, err := fr.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return // socket closed
		}
		if n < 1 {
			continue
		}

		fr.mu.Lock()
		fr.gateway = addr
		fr.mu.Unlock()

		msg := append([]byte(nil), buf[:n]...)
		switch m.MessageType(msg[0] & 0x0F) {
		case m.RelayDiscoveryType:
			fr.handleDiscovery(msg, addr)
		case m.RequestType:
			fr.handleRequest(msg, addr)
		case m.MembershipUpdateType:
			fr.handleUpdate(msg)
		}
	}
}

// handleDiscovery answers a Relay Discovery with a Relay Advertisement echoing
// the gateway's nonce. A mismatched nonce is rejected by HandleAdvertisement.
func (fr *fakeRelay) handleDiscovery(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 8 {
		return
	}
	// [0]=V/Type [1..3]=reserved [4..7]=nonce
	adv := []byte{0x02, 0, 0, 0}
	adv = append(adv, msg[4:8]...)
	adv = append(adv, 127, 0, 0, 1) // relay address

	// Counted before the reply is sent, not after. The client observes the
	// packet, so a counter bumped afterwards can still read stale to a test that
	// asserts on it once the handshake has completed -- the relay goroutine may
	// not have run yet. Race instrumentation widens that window enough to fail.
	fr.advertised.Add(1)
	_, _ = fr.conn.WriteToUDP(adv, addr)
}

// handleRequest answers a Request with a Membership Query.
func (fr *fakeRelay) handleRequest(msg []byte, addr *net.UDPAddr) {
	if len(msg) < 8 {
		return
	}
	nonce := msg[4:8]
	// Counted before the reply is sent; see handleAdvertisement.
	fr.queried.Add(1)
	_, _ = fr.conn.WriteToUDP(fr.buildQuery(nonce), addr)
}

func (fr *fakeRelay) handleUpdate(msg []byte) {
	fr.mu.Lock()
	fr.updates = append(fr.updates, msg)
	fr.mu.Unlock()

	select {
	case fr.updateCh <- msg:
	default:
	}
}

// buildQuery lays out a Membership Query the way DecodeMembershipQueryMessage
// reads it: a 2-byte field it treats as flags (and which carries the header),
// a 6-byte response MAC, a 4-byte nonce, then the encapsulated IGMPv3 query.
// Bit 0x2 of the flags word must stay clear or the decoder reserves 18 trailing
// bytes for a gateway address that is not there.
func (fr *fakeRelay) buildQuery(nonce []byte) []byte {
	out := []byte{0x04, 0x00}                             // header, doubles as flags
	out = append(out, 0x02, 0x00, 0x5e, 0x01, 0x02, 0x03) // response MAC
	out = append(out, nonce...)
	out = append(out, fr.encapsulatedIGMPQuery()...)
	return out
}

// encapsulatedIGMPQuery builds an IPv4-encapsulated IGMPv3 General Query.
func (fr *fakeRelay) encapsulatedIGMPQuery() []byte {
	// IGMPv3 Membership Query, RFC 3376 section 4.1.
	maxResp := byte(fr.queryResp / (100 * time.Millisecond))
	if maxResp == 0 {
		maxResp = 1
	}
	igmp := make([]byte, 12)
	igmp[0] = 0x11 // Membership Query
	igmp[1] = maxResp
	// igmp[2:4] checksum, filled below
	// igmp[4:8] group address: zero for a General Query
	igmp[8] = 0x02                             // QRV
	igmp[9] = fr.queryIntervalCode             // QQIC
	binary.BigEndian.PutUint16(igmp[10:12], 0) // no sources
	binary.BigEndian.PutUint16(igmp[2:4], onesComplementChecksum(igmp))

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      1,
		Protocol: layers.IPProtocolIGMP,
		SrcIP:    net.IPv4(127, 0, 0, 1),
		DstIP:    net.IPv4(224, 0, 0, 1),
	}

	sbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(sbuf, opts, ip, gopacket.Payload(igmp)); err != nil {
		fr.t.Fatalf("serialize IGMP query: %v", err)
	}
	return sbuf.Bytes()
}

// SendData pushes one Multicast Data message carrying a UDP datagram from
// (src:sport) to (group:dport).
func (fr *fakeRelay) SendData(src, group netip.Addr, sport, dport uint16, payload []byte) {
	fr.t.Helper()

	fr.mu.Lock()
	gw := fr.gateway
	fr.mu.Unlock()
	if gw == nil {
		fr.t.Fatal("fake relay: no gateway seen yet; complete the handshake first")
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP(src.AsSlice()),
		DstIP:    net.IP(group.AsSlice()),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(sport),
		DstPort: layers.UDPPort(dport),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		fr.t.Fatalf("udp checksum setup: %v", err)
	}

	sbuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(sbuf, opts, ip, udp, gopacket.Payload(payload)); err != nil {
		fr.t.Fatalf("serialize multicast data: %v", err)
	}

	// Multicast Data: 2-byte header (m.DataMsgHdrLen) then the IP packet.
	out := make([]byte, 0, m.DataMsgHdrLen+len(sbuf.Bytes()))
	out = append(out, 0x06, 0x00)
	out = append(out, sbuf.Bytes()...)

	if _, err := fr.conn.WriteToUDP(out, gw); err != nil {
		fr.t.Fatalf("fake relay send data: %v", err)
	}
}

// WaitForUpdate blocks until the relay observes a Membership Update.
func (fr *fakeRelay) WaitForUpdate(timeout time.Duration) ([]byte, error) {
	select {
	case u := <-fr.updateCh:
		return u, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out after %s waiting for a membership update", timeout)
	}
}

// DrainUpdates discards any Membership Updates recorded so far, so a test can
// assert on the next one without matching earlier joins.
func (fr *fakeRelay) DrainUpdates() {
	for {
		select {
		case <-fr.updateCh:
		default:
			return
		}
	}
}

// WaitForLeaveRecord returns the IGMPv3 record type of the next Membership
// Update carrying a leave, i.e. CHANGE_TO_INCLUDE_MODE (group-wide) or
// BLOCK_OLD_SOURCES (source-specific).
//
// Update layout is 12 bytes (header, response MAC, nonce) followed by the
// encapsulated IGMPv3 report, whose record type sits at report offset 28.
func (fr *fakeRelay) WaitForLeaveRecord(timeout time.Duration) (byte, error) {
	const recordTypeOffset = 12 + 28

	deadline := time.After(timeout)
	for {
		select {
		case u := <-fr.updateCh:
			if len(u) <= recordTypeOffset {
				continue
			}
			switch rt := u[recordTypeOffset]; rt {
			case m.IGMPv3ChangeToIncludeMode, m.IGMPv3BlockOldSources:
				return rt, nil
			default:
				continue // a join, keep looking
			}
		case <-deadline:
			return 0, fmt.Errorf("timed out after %s waiting for a leave record", timeout)
		}
	}
}

func onesComplementChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// subscribeActive subscribes and waits for the manager's own join path to
// promote the subscription to Active. Subscribe() only queues into pendingJoins;
// the debounced batch timer sends the Membership Update and promotes it. Forcing
// the state instead races that timer, which then resets it to Joining.
func subscribeActive(t *testing.T, rm *RelayManager, key SubscriptionKey) *Subscription {
	t.Helper()

	sub, err := rm.Subscribe(key, SubscriptionCallbacks{})
	if err != nil {
		t.Fatalf("Subscribe(%s): %v", key.String(), err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sub.State() == SubscriptionStateActive {
			return sub
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscription %s never became active (state %v)", key.String(), sub.State())
	return nil
}

// newTestManager wires a RelayManager to a fake relay with test-scale timings.
func newTestManager(t *testing.T, fr *fakeRelay) *RelayManager {
	t.Helper()

	cfg := DefaultRelayManagerConfig(fr.Addr())
	cfg.EnableDRIAD = false
	cfg.TransportConfig.RelayAddr = fr.Addr()
	cfg.TransportConfig.Timeout = 2 * time.Second

	rm := NewRelayManager(cfg)
	t.Cleanup(func() { _ = rm.Close() })
	return rm
}
