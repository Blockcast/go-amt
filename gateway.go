package amt

//
//import (
//	"fmt"
//	"math/rand"
//	"net"
//	"time"
//)
//
//func setupSocket(relay string) (*net.UDPConn, error) {
//	addr := net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
//	conn, err := net.ListenUDP("udp", &addr)
//	if err != nil {
//		return nil, err
//	}
//	relayAddr := net.UDPAddr{IP: net.ParseIP(relay), Port: DefaultPort}
//	conn.Connect(&relayAddr)
//	return conn, nil
//}
//
//func sendDiscovery(conn *net.UDPConn, nonce []byte) error {
//	discovery := DiscoveryMessage{
//		Header: Header{Version: Version, Type: RelayDiscoveryType},
//		Nonce:  [4]byte(nonce),
//	}
//	data, err := discovery.Encode()
//	conn.Write(data)
//	return err
//}
//
//func readRelayAdvertisement(conn *net.UDPConn, nonce []byte) (*RelayAdvertisementMessage, error) {
//	buffer := make([]byte, 1024)
//	n, err := conn.Read(buffer)
//	if err != nil {
//		return nil, err
//	}
//	return DecodeRelayAdvertisement(buffer[:n])
//}
//
//func sendMembershipUpdate(conn *net.UDPConn, query *MembershipQueryMessage) {
//	update := MembershipUpdateMessage{
//		Header:      Header{Version: Version, Type: MembershipUpdateType},
//		ResponseMAC: query.ResponseMAC,
//		Nonce:       query.Nonce,
//	}
//	data, _ := update.Encode()
//	conn.Write(data)
//}
//
//func receiveAndForwardData(conn *net.UDPConn, dataChannel chan []byte) {
//	for {
//		buffer := make([]byte, 4096)
//		n, err := conn.Read(buffer)
//		if err != nil {
//			close(dataChannel)
//			break
//		}
//		dataChannel <- buffer[:n]
//	}
//}
//
//func sendTeardown(conn *net.UDPConn, nonce []byte) {
//	teardown := MembershipTeardownMessage{
//		Header: Header{Version: Version, Type: TeardownType},
//		Nonce:  [4]byte(nonce), // Example nonce, should match the one used in DiscoveryMessage
//	}
//	data, _ := teardown.Encode()
//	conn.Write(data)
//}
//
//func StartGateway(relay, source, group string, dataChannel chan []byte) {
//	conn, err := setupSocket(relay)
//	if err != nil {
//		fmt.Println("Error setting up socket:", err)
//		return
//	}
//	defer conn.Close()
//
//	nonce := make([]byte, 4)
//	rand.Read(nonce)
//
//	err = sendDiscovery(conn, nonce)
//	if err != nil {
//		fmt.Println("Error sending discovery:", err)
//		return
//	}
//	adv, err := readRelayAdvertisement(conn, nonce)
//	fmt.Println("Received Relay Advertisement from", adv.RelayAddr)
//
//	// Placeholder for receiving a membership query and sending a membership update
//	// This part is simplified for demonstration purposes
//	time.Sleep(2 * time.Second)        // Simulate waiting for a query
//	query := &MembershipQueryMessage{} // Simulate receiving a query
//	sendMembershipUpdate(conn, query)
//
//	go receiveAndForwardData(conn, dataChannel)
//
//	// Placeholder for teardown logic
//	// In a real application, you might wait for a signal or a specific condition before tearing down
//	time.Sleep(10 * time.Second) // Simulate operation
//	sendTeardown(conn, nonce)
//}
