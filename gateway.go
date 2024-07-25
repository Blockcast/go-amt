package amt

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	m "github.com/blockcast/go-amt/messages"
)

func setupSocket(relay string) (*net.UDPConn, error) {
	relayIP := relay
	relayPort := m.DefaultPort

	relayAddr := &net.UDPAddr{
		IP:   net.ParseIP(relayIP),
		Port: relayPort,
	}

	conn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		fmt.Println("Error connecting to relay:", err)
		return nil, nil
	}
	return conn, nil
}

func sendDiscovery(conn *net.UDPConn, nonce []byte) error {
	discovery := m.DiscoveryMessage{
		Header: m.Header{Version: m.Version, Type: m.RelayDiscoveryType},
		Nonce:  [4]byte(nonce),
	}
	// data, err := discovery.Encode()
	data, err := discovery.Header.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = conn.Write(data)
	return err
}

func sendAdvertisement(conn *net.UDPConn, query *m.MembershipQueryMessage, relayIP string) error {
	relayAdvertisement := m.RelayAdvertisementMessage{
		Header:    m.Header{Version: m.Version, Type: m.RelayAdvertisementType},
		Nonce:     query.Nonce,
		RelayAddr: net.ParseIP(relayIP),
	}
	data, err := relayAdvertisement.MarshalBinary()
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = conn.Write(data)
	return err
}

func sendMembershipUpdate(conn *net.UDPConn, query *m.MembershipQueryMessage) {
	update := m.MembershipUpdateMessage{
		Header:      m.Header{Version: m.Version, Type: m.MembershipUpdateType},
		ResponseMAC: query.ResponseMAC,
		Nonce:       query.Nonce,
	}
	data, err := update.Encode()
	if err != nil {
		fmt.Println(err.Error())
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println(err.Error())
	}

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

func receiveAndForwardData(conn *net.UDPConn, dataChannel chan []byte) {
	fmt.Sprintln("en receiveAndForwardData")

	buffer := make([]byte, 1024)
	timeout := 10 * time.Second
	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buffer)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Read timeout, no data received")
			break
		} else if err != nil {
			fmt.Println("Error reading from connection:", err)
			break
		}
		fmt.Println("Received data:", buffer[:n])
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

	query := &m.MembershipQueryMessage{} // Simulate receiving a query
	err = sendAdvertisement(conn, query, relay)
	if err != nil {
		fmt.Println("Error sending advertisement:", err)
		return
	}

	// Placeholder for receiving a membership query and sending a membership update
	// This part is simplified for demonstration purposes
	fmt.Sprintln("Waiting for 2 seconds")
	time.Sleep(2 * time.Second) // Simulate waiting for a query
	// query := &m.MembershipQueryMessage{} // Simulate receiving a query
	sendMembershipUpdate(conn, query)

	go receiveAndForwardData(conn, dataChannel)

	// Placeholder for teardown logic
	// In a real application, you might wait for a signal or a specific condition before tearing down
	fmt.Sprintln("Waiting for 10 seconds")
	time.Sleep(10 * time.Second) // Simulate operation
	sendTeardown(conn, nonce)

	// os.Exit(1)
}
