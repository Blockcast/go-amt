package main

import (
	"fmt"

	"github.com/blockcast/go-amt"
)

func main() {
	relay := "162.250.137.254"
	multicast := "232.162.250.140"
	source := "162.250.138.201"

	dataChannel := make(chan []byte)
	amt.StartGateway(relay, source, multicast, dataChannel)
	for data := range dataChannel {
		fmt.Println("!!!!!")
		fmt.Println("Received data:", data)
	}
}
