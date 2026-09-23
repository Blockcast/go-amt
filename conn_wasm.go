//go:build js && wasm

package amt

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// MulticastConnWASM is a WASM-compatible multicast connection over AMT
type MulticastConnWASM struct {
	RelayAddr net.UDPAddr
	SrcAddr   netip.Addr
	GroupAddr netip.Addr
	GroupPort uint16

	conn   *ChromeUDPConn
	AmtGw  *GatewayWASM // Exported so joinGroup can update addresses
	isOpen bool
}

// Open establishes the AMT connection
func (mc *MulticastConnWASM) Open() error {
	// Create Chrome UDP connection
	mc.conn = NewChromeUDPConn()

	// Create AMT gateway
	var sourceIP net.IP
	if mc.SrcAddr.IsValid() && !mc.SrcAddr.IsUnspecified() {
		sourceIP = mc.SrcAddr.AsSlice()
	}

	mc.AmtGw = NewGatewayWASM(
		mc.conn,
		&mc.RelayAddr,
		sourceIP,
		mc.GroupAddr.AsSlice(),
	)

	// Send Discovery to find relay
	if err := mc.AmtGw.SendDiscovery(); err != nil {
		return fmt.Errorf("send discovery: %w", err)
	}

	// Wait for Advertisement (handled in ReadFrom loop)
	// Then send Request
	// Wait for Query
	// Then send Membership Update (join)

	mc.isOpen = true
	return nil
}

// IsUsingTunnel returns true (WASM always uses AMT tunnel)
func (mc *MulticastConnWASM) IsUsingTunnel() bool {
	return true
}

// ReadFrom reads a multicast packet
// Returns the raw UDP payload from the multicast stream
func (mc *MulticastConnWASM) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if !mc.isOpen {
		return 0, nil, fmt.Errorf("connection not open")
	}

	for {
		payload, sourceIP, err := mc.AmtGw.ReadPacket(p)
		if err != nil {
			return 0, nil, err
		}

		if payload != nil {
			// Got multicast data
			n = len(payload)
			addr = &net.UDPAddr{
				IP:   sourceIP,
				Port: int(mc.GroupPort),
			}
			return n, addr, nil
		}

		// Control message (Advertisement, Query), continue reading
	}
}

// WriteTo is not supported for AMT gateway
func (mc *MulticastConnWASM) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, fmt.Errorf("write not supported for AMT gateway")
}

// Close closes the AMT connection
func (mc *MulticastConnWASM) Close() error {
	if !mc.isOpen {
		return nil
	}

	mc.isOpen = false

	if mc.AmtGw != nil {
		return mc.AmtGw.Close()
	}

	if mc.conn != nil {
		return mc.conn.Close()
	}

	return nil
}

// LocalAddr returns the local address
func (mc *MulticastConnWASM) LocalAddr() net.Addr {
	if mc.conn != nil {
		return mc.conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

// SetDeadline sets read/write deadlines
func (mc *MulticastConnWASM) SetDeadline(t time.Time) error {
	if mc.conn != nil {
		return mc.conn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline sets read deadline
func (mc *MulticastConnWASM) SetReadDeadline(t time.Time) error {
	if mc.conn != nil {
		return mc.conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline sets write deadline
func (mc *MulticastConnWASM) SetWriteDeadline(t time.Time) error {
	if mc.conn != nil {
		return mc.conn.SetWriteDeadline(t)
	}
	return nil
}

// Join sends an IGMP join for the configured group
func (mc *MulticastConnWASM) Join() error {
	if !mc.isOpen || mc.AmtGw == nil {
		return fmt.Errorf("connection not open")
	}

	return mc.AmtGw.SendMembershipUpdate(true)
}

// Leave sends an IGMP leave for the configured group
func (mc *MulticastConnWASM) Leave() error {
	if !mc.isOpen || mc.AmtGw == nil {
		return fmt.Errorf("connection not open")
	}

	return mc.AmtGw.SendMembershipUpdate(false)
}

// SendRequest sends an AMT Request message
func (mc *MulticastConnWASM) SendRequest() error {
	if !mc.isOpen || mc.AmtGw == nil {
		return fmt.Errorf("connection not open")
	}

	return mc.AmtGw.SendRequest()
}
