package main

import (
	"fmt"

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

	dataChannel := make(chan []byte)
	amt.StartGateway(relay, source, multicast, dataChannel)

	for data := range dataChannel {
		fmt.Println("Received data:", data)
	}

}
