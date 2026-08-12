//go:build (linux || darwin) && !ios && !android && cgo

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
	handle       C.amt_gateway_handle_t
	cm           *ipv4.ControlMessage
	leave        bool
	intervalTime time.Duration
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
	g.cm = &ipv4.ControlMessage{}
	g.conn, err = g.setupSocket()
	if err != nil {
		return fmt.Errorf("error setting up socket: %w", err)
	}

	// Create Rust gateway handle
	if err = g.createRustGateway(); err != nil {
		return fmt.Errorf("error creating Rust gateway: %w", err)
	}

	g.intervalTime = time.Second * 10
	g.lastData.Store(time.Now())

	openTimeout := g.Timeout
	if openTimeout <= 0 {
		openTimeout = DefaultOpenTimeout
	}

	// Send discovery
	if err = g.sendDiscovery(); err != nil {
		return err
	}

	// Start keepalive goroutine. `loopErr` is deliberately local: the outer
	// `err` is written concurrently by the read loop below, so assigning to it
	// from here is a data race.
	go func() {
		for {
			if g.leave {
				return
			}
			var loopErr error
			if time.Since(g.lastData.Load()) > g.intervalTime {
				// Reset and rediscover
				C.amt_gateway_reset(g.handle)
				loopErr = g.sendDiscovery()
			} else {
				loopErr = g.sendRequest()
			}
			if loopErr != nil {
				g.loopErr.Store(loopErr)
			}
			time.Sleep(g.intervalTime)
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
	for {
		_, _, _, err = g.conn.ReadFrom(buffer)
		if err != nil {
			g.stopKeepalive()
			return fmt.Errorf("error reading from connection: %w", err)
		}
		amtMessageType := determineAMTmessageType(buffer[:])
		switch amtMessageType {
		case m.RelayAdvertisementType:
			err = g.handleRelayAdvertisement(buffer[:])
		case m.MembershipQueryType:
			// Handshake done: clear the deadline so steady-state reads are not
			// bounded by the Open timeout.
			if deadlineErr := g.conn.SetReadDeadline(time.Time{}); deadlineErr != nil {
				g.stopKeepalive()
				return fmt.Errorf("error clearing handshake deadline: %w", deadlineErr)
			}
			if queryErr := g.handleMembershipQuery(buffer[:]); queryErr != nil {
				g.stopKeepalive()
				return queryErr
			}
			return nil
		default:
			g.stopKeepalive()
			return fmt.Errorf("invalid response: %d", amtMessageType)
		}
	}
}

// DefaultOpenTimeout bounds the relay handshake when Gateway.Timeout is unset.
const DefaultOpenTimeout = 10 * time.Second

// stopKeepalive signals the keepalive goroutine to exit. Called on every Open
// failure path so a failed Open does not leak a goroutine that reconnects to a
// relay nobody is listening to.
func (g *Gateway) stopKeepalive() {
	g.leave = true
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
				g.intervalTime = igmp.IntervalTime
			}
		}
	}

	// Decode the membership query for response MAC (needed for leave/teardown)
	membershipQuery, err := m.DecodeMembershipQueryMessage(data)
	if err != nil {
		return fmt.Errorf("error decoding membership query: %w", err)
	}

	if g.leave {
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
	g.leave = true
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
