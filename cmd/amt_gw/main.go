package main

import (
	"fmt"
	"net"

	"github.com/blockcast/go-amt"
)

func main() {
	// relay := "162.250.137.254"
	// relay := "162.250.136.101"
	// source := "83.97.94.146"
	// group := "232.1.2.3"

	relay := "162.250.137.254"
	multicast := "232.162.250.140" // group
	source := "162.250.138.201"

	fmt.Println(relay, "is", checkIPVersion(relay))
	fmt.Println(multicast, "is", checkIPVersion(multicast))
	fmt.Println(source, "is", checkIPVersion(source))

	dataChannel := make(chan []byte)
	amt.StartGateway(relay, source, multicast, dataChannel)

	for data := range dataChannel {
		fmt.Println("Received data:", data)
	}

}

func checkIPVersion(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "an invalid IP"
	}
	if ip.To4() != nil {
		return "an IPv4 address"
	}
	if ip.To16() != nil {
		return "an IPv6 address"
	}
	return "an unknown IP"
}
