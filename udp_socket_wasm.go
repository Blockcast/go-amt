//go:build js && wasm

package amt

import (
	"fmt"
	"net"
	"syscall/js"
	"time"
)

// ChromeUDPConn implements net.PacketConn using Chrome Extension's chrome.sockets.udp API
// This allows Go WASM code to send/receive UDP packets via JavaScript interop
type ChromeUDPConn struct {
	socketID      int
	localAddr     *net.UDPAddr
	readChan      chan *udpPacket
	writeChan     chan *udpPacket
	closeChan     chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
	closed        bool
}

type udpPacket struct {
	data []byte
	addr *net.UDPAddr
	err  error
}

// NewChromeUDPConn creates a new Chrome UDP connection
// The actual socket creation happens via JavaScript
func NewChromeUDPConn() *ChromeUDPConn {
	conn := &ChromeUDPConn{
		socketID:  -1, // Will be set by JavaScript
		localAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		readChan:  make(chan *udpPacket, 100),
		writeChan: make(chan *udpPacket, 100),
		closeChan: make(chan struct{}),
	}

	// Register callbacks with JavaScript
	conn.registerCallbacks()

	return conn
}

// registerCallbacks sets up JavaScript callbacks for UDP operations
func (c *ChromeUDPConn) registerCallbacks() {
	// Callback for receiving data from JavaScript
	onReceiveCallback := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) < 3 {
			return nil
		}

		// args[0] = data (Uint8Array)
		// args[1] = remote address (string)
		// args[2] = remote port (number)

		dataJS := args[0]
		dataLen := dataJS.Get("length").Int()
		data := make([]byte, dataLen)
		js.CopyBytesToGo(data, dataJS)

		remoteAddr := args[1].String()
		remotePort := args[2].Int()

		packet := &udpPacket{
			data: data,
			addr: &net.UDPAddr{
				IP:   net.ParseIP(remoteAddr),
				Port: remotePort,
			},
		}

		select {
		case c.readChan <- packet:
		case <-c.closeChan:
			return nil
		default:
			// Buffer full, drop packet
		}

		return nil
	})

	// Callback for socket ID assignment
	onSocketCreated := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) > 0 {
			c.socketID = args[0].Int()
		}
		return nil
	})

	// Callback for local address update
	onLocalAddr := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) >= 2 {
			ip := args[0].String()
			port := args[1].Int()
			c.localAddr = &net.UDPAddr{
				IP:   net.ParseIP(ip),
				Port: port,
			}
		}
		return nil
	})

	// Register callbacks with JavaScript global object
	js.Global().Set("_goUDPOnReceive", onReceiveCallback)
	js.Global().Set("_goUDPOnSocketCreated", onSocketCreated)
	js.Global().Set("_goUDPOnLocalAddr", onLocalAddr)
}

// ReadFrom reads a packet from the connection
// Implements net.PacketConn
func (c *ChromeUDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if c.closed {
		return 0, nil, net.ErrClosed
	}

	var packet *udpPacket

	if c.readDeadline.IsZero() {
		// No deadline, block until packet arrives
		select {
		case packet = <-c.readChan:
		case <-c.closeChan:
			return 0, nil, net.ErrClosed
		}
	} else {
		// Has deadline, use timer
		timer := time.NewTimer(time.Until(c.readDeadline))
		defer timer.Stop()

		select {
		case packet = <-c.readChan:
		case <-timer.C:
			return 0, nil, &net.OpError{
				Op:   "read",
				Net:  "udp",
				Addr: c.localAddr,
				Err:  &timeoutError{},
			}
		case <-c.closeChan:
			return 0, nil, net.ErrClosed
		}
	}

	if packet.err != nil {
		return 0, nil, packet.err
	}

	n = copy(p, packet.data)
	return n, packet.addr, nil
}

// WriteTo writes a packet to the connection
// Implements net.PacketConn
func (c *ChromeUDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed {
		return 0, net.ErrClosed
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("address must be *net.UDPAddr, got %T", addr)
	}

	// Copy data to avoid races
	data := make([]byte, len(p))
	copy(data, p)

	// Call JavaScript to send via chrome.sockets.udp
	jsData := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(jsData, data)

	destIP := udpAddr.IP.String()
	destPort := udpAddr.Port

	// Call JavaScript function: sendUDPPacket(socketId, data, ip, port)
	result := js.Global().Call("_goUDPSend", c.socketID, jsData, destIP, destPort)

	// Check result
	resultCode := result.Int()
	if resultCode < 0 {
		return 0, &net.OpError{
			Op:   "write",
			Net:  "udp",
			Addr: addr,
			Err:  fmt.Errorf("chrome.sockets.udp.send failed with code %d", resultCode),
		}
	}

	return len(p), nil
}

// Close closes the connection
// Implements net.PacketConn
func (c *ChromeUDPConn) Close() error {
	if c.closed {
		return nil
	}

	c.closed = true
	close(c.closeChan)

	// Call JavaScript to close socket
	if c.socketID >= 0 {
		js.Global().Call("_goUDPClose", c.socketID)
	}

	return nil
}

// LocalAddr returns the local network address
// Implements net.PacketConn
func (c *ChromeUDPConn) LocalAddr() net.Addr {
	return c.localAddr
}

// SetDeadline sets the read and write deadlines
// Implements net.PacketConn
func (c *ChromeUDPConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline
// Implements net.PacketConn
func (c *ChromeUDPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline
// Implements net.PacketConn
func (c *ChromeUDPConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// timeoutError implements net.Error for timeout conditions
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
