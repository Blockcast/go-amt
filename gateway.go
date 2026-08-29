//go:build (linux || darwin) && !ios && !android && cgo && !purego

package amt

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -lamt_protocol -ldl -lm -lpthread

#include <stdlib.h>
#include <string.h>
#include "amt_protocol.h"
*/
import "C"
import (
	"fmt"
	m "github.com/blockcast/go-amt/messages"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/atomic"
	"golang.org/x/net/ipv4"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Gateway implements AMT (RFC 7450) using Rust-backed protocol logic.
// Public fields maintain compatibility with conn.go.
type Gateway struct {
	// Public fields for conn.go compatibility
	conn       *ipv4.PacketConn
	RelayAddr  net.Addr
	SourceAddr net.IP
	GroupAddr  net.IP
	MTU        int
	// RcvBufBytes and SndBufBytes are forwarded to the AMT relay UDP socket;
	// see MulticastConn for semantics.
	RcvBufBytes int
	SndBufBytes int
	// Timeout bounds the relay handshake in Open: discovery is sent, then the
	// relay advertisement and membership query must arrive within it. Zero
	// selects DefaultOpenTimeout. Without a bound, a relay that never answers
	// blocks Open forever — the caller has no way to recover, because the
	// blocking read is internal to it.
	Timeout  time.Duration
	lastData atomic.Time
	loopErr  atomic.Error

	// Internal fields
	handle C.amt_gateway_handle_t
	cm     *ipv4.ControlMessage
	// leave signals the keepalive goroutine to exit and switches
	// handleMembershipQuery from renewing the membership to tearing it down.
	//
	// Atomic because it is genuinely cross-goroutine in both directions: the
	// keepalive goroutine started by Open reads it every interval while
	// stopKeepalive writes it from Open's failure paths, and
	// handleMembershipQuery reads it from the read loop while Close writes it.
	// As a plain bool that was a data race — and worse than the detector
	// complaining, because the read sits in a bare for loop with no
	// synchronisation, so nothing obliges the goroutine to ever observe the
	// write. stopKeepalive exists to prevent a leaked goroutine reconnecting to
	// a relay nobody is listening to, and unsynchronised it could fail to do
	// exactly that.
	leave atomic.Bool
	// intervalTime is atomic for the same reason leave is, and between the same
	// two goroutines: handleMembershipQuery writes it from the read loop and from
	// Close's goroutine, while the keepalive goroutine reads it every iteration to
	// decide staleness and to size its sleep. As a plain time.Duration that was the
	// identical race, two lines below the one this change set out to fix.
	intervalTime atomic.Duration
	responseMac  [6]byte
	requestNonce uint32
}

// Version returns the Rust library version.
func Version() string {
	return C.GoString(C.amt_version())
}

func (g *Gateway) setupSocket() (*ipv4.PacketConn, error) {
	if len(g.SourceAddr) == 0 {
		g.SourceAddr = net.IPv4zero
	}
	// Create socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("could not get socket: %w", err)
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
		return nil, fmt.Errorf("could not set socket timestamp: %w", err)
	}

	if err := applyForcedBuffers(sock, g.RcvBufBytes, g.SndBufBytes); err != nil {
		_ = syscall.Close(sock)
		return nil, err
	}

	// Turn the socket file descriptor into an *os.File
	file := os.NewFile(uintptr(sock), "")

	// Turn it into a net.PacketConn
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, err
	}

	// We no longer need the file
	if err = file.Close(); err != nil {
		return nil, err
	}

	return ipv4.NewPacketConn(conn), nil
}

// createRustGateway initializes the Rust AMT gateway handle.
func (g *Gateway) createRustGateway() error {
	relayUDP, ok := g.RelayAddr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("RelayAddr must be *net.UDPAddr")
	}

	cAddr := C.CString(relayUDP.IP.String())
	defer C.free(unsafe.Pointer(cAddr))

	var handle C.amt_gateway_handle_t
	result := C.amt_gateway_new(cAddr, C.uint16_t(relayUDP.Port), false, &handle)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to create AMT gateway: %d", result)
	}

	g.handle = handle
	return nil
}

// sendDiscovery sends AMT Relay Discovery message using Rust library.
func (g *Gateway) sendDiscovery() error {
	var outMsg C.amt_buffer_t
	result := C.amt_gateway_start_discovery(g.handle, &outMsg)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to start discovery: %d", result)
	}
	defer C.amt_buffer_free(outMsg)

	data := C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len))
	_, err := g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

// sendRequest sends AMT Request message using Rust library.
func (g *Gateway) sendRequest() error {
	var outMsg C.amt_buffer_t
	result := C.amt_gateway_request_membership(g.handle, false, &outMsg)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to request membership: %d", result)
	}
	defer C.amt_buffer_free(outMsg)

	data := C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len))
	_, err := g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

// createIGMPReport creates an IGMPv3 SSM join report using Rust library.
func (g *Gateway) createIGMPReport() ([]byte, error) {
	source := g.SourceAddr.To4()
	group := g.GroupAddr.To4()

	if source == nil || group == nil {
		return nil, fmt.Errorf("IPv4 addresses required")
	}

	cSource := C.CString(source.String())
	defer C.free(unsafe.Pointer(cSource))

	cGroup := C.CString(group.String())
	defer C.free(unsafe.Pointer(cGroup))

	var outReport C.amt_buffer_t
	result := C.amt_igmp_ssm_join(cSource, cGroup, &outReport)
	if result != C.AMT_RESULT_OK {
		return nil, fmt.Errorf("failed to create IGMP report: %d", result)
	}
	defer C.amt_buffer_free(outReport)

	return C.GoBytes(unsafe.Pointer(outReport.data), C.int(outReport.len)), nil
}

// sendMembershipUpdate sends AMT Membership Update message.
func (g *Gateway) sendMembershipUpdate(membershipQuery m.MembershipQueryMessage) error {
	// Create IGMP report using Rust library
	igmpReport, err := g.createIGMPReport()
	if err != nil {
		return fmt.Errorf("failed to create IGMP report: %w", err)
	}

	// Send update using Rust library
	var outMsg C.amt_buffer_t
	result := C.amt_gateway_send_update(
		g.handle,
		(*C.uint8_t)(unsafe.Pointer(&igmpReport[0])),
		C.size_t(len(igmpReport)),
		&outMsg,
	)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to send update: %d", result)
	}
	defer C.amt_buffer_free(outMsg)

	data := C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len))
	_, err = g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

// sendMembershipLeave sends a leave report (CHANGE_TO_INCLUDE with empty sources).
func (g *Gateway) sendMembershipLeave(membershipQuery m.MembershipQueryMessage) error {
	// For leave, we send CHANGE_TO_INCLUDE_MODE with no sources
	// This is handled by the existing sendMembershipUpdate logic in Rust
	// For now, we just don't send anything as teardown handles the leave
	return nil
}

// sendTeardown sends AMT Teardown message.
func (g *Gateway) sendTeardown(membershipQuery m.MembershipQueryMessage) error {
	var outMsg C.amt_buffer_t
	result := C.amt_gateway_send_teardown(g.handle, &outMsg)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to send teardown: %d", result)
	}
	defer C.amt_buffer_free(outMsg)

	data := C.GoBytes(unsafe.Pointer(outMsg.data), C.int(outMsg.len))
	_, err := g.conn.WriteTo(data, g.cm, g.RelayAddr)
	return err
}

// Open initializes the AMT gateway and performs the handshake.
func (g *Gateway) Open() (err error) {
	relay := relayAddrString(g.RelayAddr)
	started := time.Now()

	// Report every failure path from one place. Open's error used to be
	// invisible in two different ways: against a silent relay it never returned
	// at all, and when it did return, the caller was the only thing that logged
	// it. An operator had no way to tell "AMT was never attempted" from "AMT is
	// wedged mid-handshake" — both looked like a healthy process. See BLO-28641.
	defer func() {
		if err != nil {
			slog.Warn("amt: relay handshake failed",
				"relay", relay, "elapsed", time.Since(started), "error", err)
		}
	}()

	g.cm = &ipv4.ControlMessage{}
	g.conn, err = g.setupSocket()
	if err != nil {
		return fmt.Errorf("error setting up socket: %w", err)
	}

	// Create Rust gateway handle
	if err = g.createRustGateway(); err != nil {
		return fmt.Errorf("error creating Rust gateway: %w", err)
	}

	g.intervalTime.Store(time.Second * 10)
	g.lastData.Store(time.Now())

	openTimeout := g.Timeout
	if openTimeout <= 0 {
		openTimeout = DefaultOpenTimeout
	}

	// Announce the attempt before blocking on it. Until this line existed,
	// tcpdump was the only way to observe that AMT was being tried at all: the
	// discovery datagram left the socket with nothing written to the log.
	slog.Info("amt: starting relay handshake",
		"relay", relay,
		"group", g.GroupAddr.String(),
		"source", g.SourceAddr.String(),
		"timeout", openTimeout)

	// Send discovery
	if err = g.sendDiscovery(); err != nil {
		return err
	}

	// Start keepalive goroutine. `loopErr` is deliberately local: the outer
	// `err` is written concurrently by the read loop below, so assigning to it
	// from here is a data race.
	go func() {
		// stalled tracks whether the previous iteration already saw the relay as
		// silent, so entering and leaving that state logs once each rather than
		// every interval. A permanently unreachable relay would otherwise emit a
		// line every intervalTime forever, which is the kind of noise that gets
		// logging filtered out precisely when it is needed.
		var stalled bool
		for {
			// SLEEP FIRST. This loop used to run its body immediately, before
			// the handshake it is meant to maintain had any chance to complete.
			// At that instant the Rust gateway is in Discovering (set by
			// start_discovery, gateway.rs:155) and request_membership requires
			// Idle (gateway.rs:195), so the very first keepalive reliably
			// returned InvalidState and stored it in loopErr — where the next
			// ReadBatch picks it up via `loopErr.Swap(nil)` (conn.go) and
			// returns it to the caller. A successful Open was therefore
			// followed by a spurious error on the first read of the tunnel.
			//
			// Sleeping first is also what the loop already means: nothing can
			// be stale at t=0, because lastData was stored moments earlier, so
			// the idle branch below could never fire on that first pass either.
			// Shutdown latency is unchanged — leave is still observed within
			// one interval, it is just checked after the sleep instead of
			// before it.
			time.Sleep(g.intervalTime.Load())
			if g.leave.Load() {
				return
			}
			var loopErr error
			if idle := time.Since(g.lastData.Load()); idle > g.intervalTime.Load() {
				if !stalled {
					stalled = true
					slog.Warn("amt: no data from relay, re-sending discovery",
						"relay", relay, "idle", idle)
				}
				// Reset and rediscover
				C.amt_gateway_reset(g.handle)
				loopErr = g.sendDiscovery()
			} else {
				if stalled {
					stalled = false
					slog.Info("amt: relay data resumed", "relay", relay)
				}
				loopErr = g.sendRequest()
			}
			if loopErr != nil {
				slog.Warn("amt: keepalive send failed", "relay", relay, "error", loopErr)
				g.loopErr.Store(loopErr)
			}
		}
	}()

	// Bound the handshake. Without this the read below blocks forever against a
	// relay that never answers, and the keepalive goroutine spins behind it.
	if err = g.conn.SetReadDeadline(time.Now().Add(openTimeout)); err != nil {
		g.stopKeepalive()
		return fmt.Errorf("error setting handshake deadline: %w", err)
	}

	// Wait for advertisement and query
	buffer := make([]byte, g.MTU)
	var lastAdvErr error
	for {
		// SLICE TO WHAT WAS ACTUALLY RECEIVED. This used to discard n and hand
		// the decoders `buffer[:]` — the whole MTU-sized array, of which only
		// the first n bytes were the message and the rest was zero padding.
		//
		// For every message type but one that is merely wasteful, because the
		// Rust decoders bound-check with `<` (a minimum length) and the Go ones
		// read relative offsets. Relay Advertisement is the exception, and it is
		// decoded by EXACT length: amt-protocol/src/messages.rs:213-224 selects
		// IPv4 on `buf.len() == 12` and IPv6 on `== 24`, and errors on anything
		// else. A 1500-byte buffer is neither, so the advertisement failed to
		// decode on every single handshake — the Rust gateway stayed in
		// Discovering, no Request was ever sent, and Open sat until its deadline
		// and surfaced an i/o timeout that named nothing. That is BLO-29437, and
		// it made the whole cgo AMT path unable to complete a handshake against
		// any relay, real or fake.
		//
		// Close() already sliced its read correctly (`buffer[:n]` below), so the
		// two halves of this file disagreed with each other; this makes Open
		// match the half that was right.
		var n int
		n, _, _, err = g.conn.ReadFrom(buffer)
		if err != nil {
			g.stopKeepalive()
			if lastAdvErr != nil {
				return fmt.Errorf(
					"error reading from connection: %w (last advertisement rejected: %v)",
					err, lastAdvErr,
				)
			}
			return fmt.Errorf("error reading from connection: %w", err)
		}
		// A zero-length UDP datagram is legal and carries no type byte;
		// determineAMTmessageType would index past the end of it.
		if n == 0 {
			continue
		}
		msg := buffer[:n]
		amtMessageType := determineAMTmessageType(msg)
		switch amtMessageType {
		case m.RelayAdvertisementType:
			slog.Debug("amt: relay advertisement received", "relay", relay, "bytes", n)
			// Report rather than discard. The result of this call used to be
			// assigned to `err` and then overwritten by the next iteration's
			// ReadFrom, so a rejected advertisement was indistinguishable from
			// never having received one: both ended as the same bare i/o
			// timeout, which is precisely what made the length bug above take a
			// full CI run to localise.
			//
			// Logged and retried rather than fatal, deliberately. A relay is
			// free to retransmit an advertisement, and a duplicate arriving
			// after the gateway has left Discovering is rejected by
			// gateway.rs:167 as InvalidState — benign protocol noise that must
			// not fail an otherwise healthy Open. A genuinely undecodable
			// advertisement still ends at the deadline, but now says why.
			if advErr := g.handleRelayAdvertisement(msg); advErr != nil {
				lastAdvErr = advErr
				slog.Warn("amt: relay advertisement rejected",
					"relay", relay, "bytes", n, "error", advErr)
			}
		case m.MembershipQueryType:
			// Handshake done: clear the deadline so steady-state reads are not
			// bounded by the Open timeout.
			if deadlineErr := g.conn.SetReadDeadline(time.Time{}); deadlineErr != nil {
				g.stopKeepalive()
				return fmt.Errorf("error clearing handshake deadline: %w", deadlineErr)
			}
			if queryErr := g.handleMembershipQuery(msg); queryErr != nil {
				g.stopKeepalive()
				return queryErr
			}
			slog.Info("amt: relay handshake complete",
				"relay", relay, "elapsed", time.Since(started))
			return nil
		default:
			g.stopKeepalive()
			return fmt.Errorf("invalid response: %d", amtMessageType)
		}
	}
}

// relayAddrString renders the relay endpoint for log output. RelayAddr is an
// interface and may be unset on a misconfigured gateway, so this tolerates nil
// rather than letting a log line panic a path that is already failing.
func relayAddrString(a net.Addr) string {
	if a == nil {
		return "<unset>"
	}
	return a.String()
}

// DefaultOpenTimeout bounds the relay handshake when Gateway.Timeout is unset.
const DefaultOpenTimeout = 10 * time.Second

// stopKeepalive signals the keepalive goroutine to exit. Called on every Open
// failure path so a failed Open does not leak a goroutine that reconnects to a
// relay nobody is listening to.
func (g *Gateway) stopKeepalive() {
	g.leave.Store(true)
}

// abortOpen releases only resources that Open managed to initialize. It is
// intentionally separate from Close: a failed setup may not have a socket or
// Rust handle yet, so graceful teardown would try to exchange protocol
// messages through a partially initialized gateway.
func (g *Gateway) abortOpen() {
	g.stopKeepalive()
	if g.handle != nil {
		C.amt_gateway_free(g.handle)
		g.handle = nil
	}
	if g.conn != nil {
		_ = g.conn.Close()
		g.conn = nil
	}
}

// handleRelayAdvertisement processes AMT Relay Advertisement.
func (g *Gateway) handleRelayAdvertisement(data []byte) error {
	// Pass to Rust library
	result := C.amt_gateway_handle_advertisement(
		g.handle,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
	)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to handle advertisement: %d", result)
	}

	// Send request after advertisement
	return g.sendRequest()
}

// handleMembershipQuery processes AMT Membership Query.
func (g *Gateway) handleMembershipQuery(data []byte) error {
	// Pass to Rust library to extract query data
	var outQueryData C.amt_buffer_t
	result := C.amt_gateway_handle_query(
		g.handle,
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		&outQueryData,
	)
	if result != C.AMT_RESULT_OK {
		return fmt.Errorf("failed to handle query: %d", result)
	}
	defer C.amt_buffer_free(outQueryData)

	queryData := C.GoBytes(unsafe.Pointer(outQueryData.data), C.int(outQueryData.len))

	// Parse IGMP query to get interval time
	if len(queryData) > 0 && queryData[0]>>4 == 4 {
		p := gopacket.NewPacket(queryData, layers.LayerTypeIPv4, gopacket.NoCopy)
		igmp, ok := p.Layer(layers.LayerTypeIGMP).(*layers.IGMP)
		if ok && igmp.Type == layers.IGMPMembershipQuery {
			if igmp.IntervalTime > 0 {
				g.intervalTime.Store(igmp.IntervalTime)
			}
		}
	}

	// Decode the membership query for response MAC (needed for leave/teardown)
	membershipQuery, err := m.DecodeMembershipQueryMessage(data)
	if err != nil {
		return fmt.Errorf("error decoding membership query: %w", err)
	}

	if g.leave.Load() {
		if err = g.sendTeardown(*membershipQuery); err != nil {
			return fmt.Errorf("error in sendTeardown: %w", err)
		}
		if err = g.sendMembershipLeave(*membershipQuery); err != nil {
			return fmt.Errorf("error in sendMembershipLeave: %w", err)
		}
		return g.conn.Close()
	}

	// Send membership update
	if err = g.sendMembershipUpdate(*membershipQuery); err != nil {
		return fmt.Errorf("error in sendMembershipUpdate: %w", err)
	}

	return nil
}

// Close gracefully closes the AMT gateway.
func (g *Gateway) Close() error {
	g.leave.Store(true)
	buffer := make([]byte, g.MTU)
	errc := make(chan error, 1)

	go func() {
		defer close(errc)
		for {
			if err := g.sendRequest(); err != nil {
				errc <- fmt.Errorf("failed to send request: %w", err)
				return
			}
			n, _, _, err := g.conn.ReadFrom(buffer)
			if err != nil {
				errc <- fmt.Errorf("error reading from connection: %w", err)
				return
			}
			amtMessageType := determineAMTmessageType(buffer[:])
			if amtMessageType == m.MembershipQueryType {
				errc <- g.handleMembershipQuery(buffer[:n])
				return
			}
		}
	}()

	var err error
	select {
	case <-time.After(5 * time.Second):
	case err = <-errc:
	}

	// Free Rust handle
	if g.handle != nil {
		C.amt_gateway_free(g.handle)
		g.handle = nil
	}

	errClose := g.conn.Close()
	if err == nil {
		err = errClose
	}
	return err
}

// determineAMTmessageType extracts AMT message type from data.
func determineAMTmessageType(data []byte) m.MessageType {
	return m.MessageType(data[0])
}
