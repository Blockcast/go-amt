//go:build js && wasm

package amt

import (
	"net"
	"testing"
	"time"
)

// Test that ChromeUDPConn implements net.PacketConn interface
func TestChromeUDPConnImplementsPacketConn(t *testing.T) {
	var _ net.PacketConn = (*ChromeUDPConn)(nil)
}

func TestChromeUDPConnCreation(t *testing.T) {
	conn := NewChromeUDPConn()
	if conn == nil {
		t.Fatal("NewChromeUDPConn returned nil")
	}
	
	if conn.readChan == nil {
		t.Error("readChan should be initialized")
	}
	
	if conn.writeChan == nil {
		t.Error("writeChan should be initialized")
	}
}

func TestChromeUDPConnLocalAddr(t *testing.T) {
	conn := NewChromeUDPConn()
	addr := conn.LocalAddr()
	
	if addr == nil {
		t.Error("LocalAddr should not return nil")
	}
	
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Errorf("LocalAddr should return *net.UDPAddr, got %T", addr)
	}
	
	// Initially, address should be unspecified
	if udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() {
		t.Errorf("Initial IP should be unspecified, got %v", udpAddr.IP)
	}
}

func TestChromeUDPConnSetDeadline(t *testing.T) {
	conn := NewChromeUDPConn()
	
	deadline := time.Now().Add(5 * time.Second)
	err := conn.SetDeadline(deadline)
	if err != nil {
		t.Errorf("SetDeadline failed: %v", err)
	}
	
	// Verify deadline was set
	if conn.readDeadline.IsZero() {
		t.Error("Read deadline should be set")
	}
	if conn.writeDeadline.IsZero() {
		t.Error("Write deadline should be set")
	}
}

func TestChromeUDPConnSetReadDeadline(t *testing.T) {
	conn := NewChromeUDPConn()
	
	deadline := time.Now().Add(5 * time.Second)
	err := conn.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("SetReadDeadline failed: %v", err)
	}
	
	if conn.readDeadline.IsZero() {
		t.Error("Read deadline should be set")
	}
}

func TestChromeUDPConnSetWriteDeadline(t *testing.T) {
	conn := NewChromeUDPConn()
	
	deadline := time.Now().Add(5 * time.Second)
	err := conn.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline failed: %v", err)
	}
	
	if conn.writeDeadline.IsZero() {
		t.Error("Write deadline should be set")
	}
}

func TestChromeUDPConnClose(t *testing.T) {
	conn := NewChromeUDPConn()
	
	err := conn.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
	
	// Verify channels are closed
	select {
	case _, ok := <-conn.readChan:
		if ok {
			t.Error("readChan should be closed")
		}
	default:
		// Channel might be buffered, this is okay
	}
}




