package main

import (
	"fmt"
	"github.com/blockcast/go-amt"
	m "github.com/blockcast/go-amt/messages"
	"net"
	"net/netip"
	"os"
	"time"
)

func main() {
	ifi, err := net.InterfaceByName("en0")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	g := amt.MutlicastConn{
		RelayAddr: net.UDPAddr{
			IP:   net.ParseIP("162.250.137.254"),
			Port: m.DefaultPort,
		},
		//SrcAddr:   netip.MustParseAddr("162.250.138.201"),
		GroupAddr: netip.MustParseAddr("232.162.250.140"),
		GroupPort: 1234,
		IFace:     ifi,
		Timeout:   time.Second * 5,
	}
	if err := g.Open(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	//discard := make([]byte, ifi.MTU)
	//n, src, err := g.ReadFrom(discard)
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}
	//fmt.Printf("read n=%d, src=%s\n", n, src)

	//ms := []ipv4.Message{
	//	{
	//		Buffers: [][]byte{make([]byte, 1500)},
	//		OOB:     make([]byte, 1500),
	//	},
	//	{
	//		Buffers: [][]byte{make([]byte, 1500)},
	//		OOB:     make([]byte, 1500),
	//	},
	//}

	//count := 0
	//for count < 1000 {
	//	N, err := g.ReadBatch(ms, 0)
	//	if err != nil {
	//		fmt.Println(err)
	//		os.Exit(1)
	//	}
	//	for i := range N {
	//		fmt.Printf("%d: read n=%d, src=%s\n", count, ms[i].N, ms[i].Addr)
	//		count++
	//	}
	//}

	err = g.Close()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
