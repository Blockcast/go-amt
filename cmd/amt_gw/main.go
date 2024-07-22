package main

import (
	"fmt"
	"github.com/blockcast/go-amt"
)

func main() {
	relay := "162.250.137.254"
	source := "83.97.94.146"
	group := "232.1.2.3"
	dataChannel := make(chan []byte)

	go amt.StartGateway(relay, source, group, dataChannel)

	for data := range dataChannel {
		fmt.Println("Received data:", data)
	}
}
