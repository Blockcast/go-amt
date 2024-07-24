package amt

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	m "github.com/blockcast/go-amt/messages"
)

func setupSocket(relay string) (*net.UDPConn, error) {
	addr := net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	_, err := net.ListenUDP("udp", &addr)

	relayAddr := net.UDPAddr{IP: net.ParseIP(relay), Port: m.DefaultPort}
	conn, err := net.ListenUDP("udp", &relayAddr)

	if err != nil {
		return nil, err
	}
	// relayAddr := net.UDPAddr{IP: net.ParseIP(relay), Port: m.DefaultPort}
	// conn.Connect(&relayAddr)
	// conn, err = net.DialUDP("udp", nil, &relayAddr)

	return conn, nil
}

func sendDiscovery(conn *net.UDPConn, nonce []byte) error {
	discovery := m.DiscoveryMessage{
		Header: m.Header{Version: m.Version, Type: m.RelayDiscoveryType},
		Nonce:  [4]byte(nonce),
	}
	// data, err := discovery.Encode()
	data, err := discovery.Header.MarshalBinary()
	conn.Write(data)
	return err
}

func readRelayAdvertisement(conn *net.UDPConn, nonce []byte) error {
	buffer := make([]byte, 1024)

	// n, err := conn.Read(buffer)
	_, err := conn.Read(buffer)
	fmt.Println("paso")

	if err != nil {
		// return nil, err
		return err

	}
	// return DecodeRelayAdvertisement(buffer[:n])
	aux := m.RelayAdvertisementMessage{}
	return aux.UnmarshalBinary(buffer)
}

func sendMembershipUpdate(conn *net.UDPConn, query *m.MembershipQueryMessage) {
	update := m.MembershipUpdateMessage{
		Header:      m.Header{Version: m.Version, Type: m.MembershipUpdateType},
		ResponseMAC: query.ResponseMAC,
		Nonce:       query.Nonce,
	}
	data, _ := update.Encode()
	conn.Write(data)
}

func receiveAndForwardData(conn *net.UDPConn, dataChannel chan []byte) {
	for {

		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			close(dataChannel)
			break
		}
		dataChannel <- buffer[:n]
	}
}

func sendTeardown(conn *net.UDPConn, nonce []byte) {
	teardown := m.MembershipTeardownMessage{
		Header: m.Header{Version: m.Version, Type: m.TeardownType},
		Nonce:  [4]byte(nonce), // Example nonce, should match the one used in DiscoveryMessage
	}
	data, _ := teardown.Encode()
	conn.Write(data)
}

func StartGateway(relay, source, group string, dataChannel chan []byte) {
	// relayAddr := net.UDPAddr{IP: net.ParseIP(relay), Port: m.DefaultPort}

	conn, err := setupSocket(relay)
	if err != nil {
		fmt.Println("Error setting up socket:", err)
		return
	}

	defer conn.Close()

	nonce := make([]byte, 4)
	rand.Read(nonce)
	err = sendDiscovery(conn, nonce)
	if err != nil {
		fmt.Println("Error sending discovery:", err)
		return
	}

	// adv, err := readRelayAdvertisement(conn, nonce)
	err = readRelayAdvertisement(conn, nonce)
	if err != nil {
		fmt.Sprint("Error", err.Error())
	}

	// fmt.Println("Received Relay Advertisement from", adv.RelayAddr)
	fmt.Println("Received Relay Advertisement from")

	// Placeholder for receiving a membership query and sending a membership update
	// This part is simplified for demonstration purposes
	time.Sleep(2 * time.Second)          // Simulate waiting for a query
	query := &m.MembershipQueryMessage{} // Simulate receiving a query
	sendMembershipUpdate(conn, query)

	go receiveAndForwardData(conn, dataChannel)

	// Placeholder for teardown logic
	// In a real application, you might wait for a signal or a specific condition before tearing down
	time.Sleep(10 * time.Second) // Simulate operation
	sendTeardown(conn, nonce)
}
