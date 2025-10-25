//go:build js && wasm

package amt

import (
	"net"
	"testing"
	
	m "github.com/blockcast/go-amt/messages"
)

func TestGatewayWASMCreation(t *testing.T) {
	conn := NewChromeUDPConn()
	gw := &GatewayWASM{
		conn:      conn,
		RelayAddr: &net.UDPAddr{IP: net.ParseIP("162.250.137.254"), Port: 2268},
		GroupAddr: net.ParseIP("232.1.2.3"),
		MTU:       1500,
	}
	
	if gw.conn == nil {
		t.Error("Gateway connection should not be nil")
	}
	
	if gw.MTU != 1500 {
		t.Errorf("Expected MTU 1500, got %d", gw.MTU)
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce := generateNonce()
	
	if len(nonce) != 4 {
		t.Errorf("Nonce should be 4 bytes, got %d", len(nonce))
	}
	
	// Check it's not all zeros
	allZero := true
	for _, b := range nonce {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Nonce should not be all zeros")
	}
	
	// Generate multiple nonces and check they're different
	nonce2 := generateNonce()
	if string(nonce) == string(nonce2) {
		t.Error("Sequential nonces should be different (very unlikely to match)")
	}
}

func TestCreateDiscoveryMessage(t *testing.T) {
	nonce := []byte{0x12, 0x34, 0x56, 0x78}
	msg := createDiscoveryMessage(nonce)
	
	if msg.Version != m.Version {
		t.Errorf("Expected version %d, got %d", m.Version, msg.Version)
	}
	
	if msg.Type != m.RelayDiscoveryType {
		t.Errorf("Expected type %d, got %d", m.RelayDiscoveryType, msg.Type)
	}
	
	discoveryBody, ok := msg.Body.(*m.DiscoveryMessage)
	if !ok {
		t.Fatalf("Message body should be *DiscoveryMessage, got %T", msg.Body)
	}
	
	if discoveryBody.Nonce != [4]byte{0x12, 0x34, 0x56, 0x78} {
		t.Errorf("Nonce mismatch: expected %v, got %v", nonce, discoveryBody.Nonce)
	}
}

func TestCreateRequestMessage(t *testing.T) {
	nonce := []byte{0xAB, 0xCD, 0xEF, 0x12}
	msg := createRequestMessage(nonce)
	
	if msg.Version != m.Version {
		t.Errorf("Expected version %d, got %d", m.Version, msg.Version)
	}
	
	if msg.Type != m.RequestType {
		t.Errorf("Expected type %d, got %d", m.RequestType, msg.Type)
	}
	
	requestBody, ok := msg.Body.(*m.RequestMessage)
	if !ok {
		t.Fatalf("Message body should be *RequestMessage, got %T", msg.Body)
	}
	
	if requestBody.Nonce != [4]byte{0xAB, 0xCD, 0xEF, 0x12} {
		t.Errorf("Nonce mismatch")
	}
	
	if requestBody.Reserved != 0 {
		t.Errorf("Reserved field should be 0, got %d", requestBody.Reserved)
	}
}

func TestCreateMembershipUpdateJoin(t *testing.T) {
	groupIP := net.ParseIP("232.1.2.3")
	sourceIP := net.ParseIP("83.97.94.146")
	
	msg := createMembershipUpdate(
		groupIP,
		sourceIP,
		true, // join
		[]byte{0x11, 0x22, 0x33, 0x44}, // nonce
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}, // MAC
	)
	
	if msg.Type != m.MembershipUpdateType {
		t.Errorf("Expected type %d, got %d", m.MembershipUpdateType, msg.Type)
	}
	
	updateBody, ok := msg.Body.(*m.MembershipUpdateMessage)
	if !ok {
		t.Fatalf("Message body should be *MembershipUpdateMessage, got %T", msg.Body)
	}
	
	if len(updateBody.Encapsulated) == 0 {
		t.Error("Encapsulated IGMP message should not be empty")
	}
}

func TestCreateMembershipUpdateLeave(t *testing.T) {
	groupIP := net.ParseIP("232.1.2.3")
	sourceIP := net.ParseIP("83.97.94.146")
	
	msg := createMembershipUpdate(
		groupIP,
		sourceIP,
		false, // leave
		[]byte{0x11, 0x22, 0x33, 0x44},
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	)
	
	if msg.Type != m.MembershipUpdateType {
		t.Errorf("Expected type %d, got %d", m.MembershipUpdateType, msg.Type)
	}
	
	// Verify it's a leave message (CHANGE_TO_INCLUDE_MODE with empty sources)
	updateBody, ok := msg.Body.(*m.MembershipUpdateMessage)
	if !ok {
		t.Fatal("Message body should be *MembershipUpdateMessage")
	}
	
	if len(updateBody.Encapsulated) == 0 {
		t.Error("Encapsulated IGMPv3 leave should not be empty")
	}
}

func TestCreateTeardownMessage(t *testing.T) {
	nonce := []byte{0x11, 0x22, 0x33, 0x44}
	mac := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	gatewayIP := net.ParseIP("203.0.113.10")
	gatewayPort := uint16(54321)
	
	msg := createTeardownMessage(nonce, mac, gatewayIP, gatewayPort)
	
	if msg.Type != m.TeardownType {
		t.Errorf("Expected type %d, got %d", m.TeardownType, msg.Type)
	}
	
	teardownBody, ok := msg.Body.(*m.MembershipTeardownMessage)
	if !ok {
		t.Fatalf("Message body should be *MembershipTeardownMessage, got %T", msg.Body)
	}
	
	if teardownBody.Nonce != [4]byte{0x11, 0x22, 0x33, 0x44} {
		t.Error("Nonce mismatch")
	}
	
	if teardownBody.GWPortNum != gatewayPort {
		t.Errorf("Gateway port mismatch: expected %d, got %d", gatewayPort, teardownBody.GWPortNum)
	}
}




