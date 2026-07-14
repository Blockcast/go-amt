//go:build (linux || darwin) && cgo

// Command amt_bridge joins one SSM (S,G) group through an AMT relay and
// re-emits each received datagram's payload to a local UDP address. It is the
// AMT last-mile receiver for the shred-race measurement rig (Blockcast
// BLO-15940 / BLO-16070): the go-amt MulticastConn is exactly the delivery
// mechanism a real subscriber on a non-multicast network uses, so pointing
// shred-race's `udp` input at this bridge measures our true delivery path.
//
// On a host with no native route to the source, MulticastConn.Open falls back
// to the AMT tunnel after Timeout; the re-emit to loopback adds only
// sub-microsecond localhost latency, equal for every captured packet.
//
// Example (Tokyo box, shred stream):
//
//	amt_bridge -relay 69.25.95.128:2268 -source 69.25.95.102 \
//	    -group 232.0.0.1 -port 5001 -iface enp1s0 -out 127.0.0.1:20001
package main

import (
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	amt "github.com/blockcast/go-amt"
	"golang.org/x/net/ipv4"
)

func main() {
	relay := flag.String("relay", "", "AMT relay address host:port (required)")
	source := flag.String("source", "", "SSM source IPv4 (required)")
	group := flag.String("group", "", "SSM group IPv4 (required)")
	port := flag.Uint("port", 0, "group UDP port (required)")
	ifaceName := flag.String("iface", "", "interface name for the join (required)")
	out := flag.String("out", "127.0.0.1:20001", "local UDP target for re-emitted payloads")
	rcvbuf := flag.Int("rcvbuf", 16<<20, "receive buffer bytes (SO_RCVBUFFORCE; needs CAP_NET_ADMIN)")
	timeout := flag.Duration("timeout", 5*time.Second, "native-join wait before AMT fallback")
	statEvery := flag.Duration("stats", 10*time.Second, "stats log interval")
	flag.Parse()

	for name, v := range map[string]string{"relay": *relay, "source": *source, "group": *group, "iface": *ifaceName} {
		if v == "" {
			log.Fatalf("-%s is required", name)
		}
	}
	if *port == 0 || *port > 65535 {
		log.Fatalf("-port must be 1..65535")
	}

	relayHost, relayPortStr, err := net.SplitHostPort(*relay)
	if err != nil {
		log.Fatalf("-relay: %v", err)
	}
	relayPort, err := strconv.Atoi(relayPortStr)
	if err != nil {
		log.Fatalf("-relay port: %v", err)
	}
	ifi, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("-iface %q: %v", *ifaceName, err)
	}
	srcAddr, err := netip.ParseAddr(*source)
	if err != nil {
		log.Fatalf("-source: %v", err)
	}
	grpAddr, err := netip.ParseAddr(*group)
	if err != nil {
		log.Fatalf("-group: %v", err)
	}

	outConn, err := net.Dial("udp", *out)
	if err != nil {
		log.Fatalf("-out %q: %v", *out, err)
	}
	defer outConn.Close()

	mc := amt.MulticastConn{
		RelayAddr:   net.UDPAddr{IP: net.ParseIP(relayHost), Port: relayPort},
		SrcAddr:     srcAddr,
		GroupAddr:   grpAddr,
		GroupPort:   uint16(*port),
		IFace:       ifi,
		Timeout:     *timeout,
		RcvBufBytes: *rcvbuf,
	}
	log.Printf("joining (%s,%s):%d via relay %s on %s -> %s",
		*source, *group, *port, *relay, *ifaceName, *out)
	if err := mc.Open(); err != nil {
		log.Fatalf("open: %v", err)
	}
	defer mc.Close()
	log.Printf("open ok; tunnel=%v", mc.IsUsingTunnel())

	var pkts, bytesN, sendErr atomic.Uint64
	go func() {
		t := time.NewTicker(*statEvery)
		defer t.Stop()
		var lastP, lastB uint64
		for range t.C {
			p, b := pkts.Load(), bytesN.Load()
			log.Printf("pkts=%d (+%d) bytes=%d (+%d) send_err=%d tunnel=%v",
				p, p-lastP, b, b-lastB, sendErr.Load(), mc.IsUsingTunnel())
			lastP, lastB = p, b
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("signal; closing")
		mc.Close()
		os.Exit(0)
	}()

	// Batch receive for throughput; re-emit each payload to the local target.
	const batch = 64
	bufs := make([][]byte, batch)
	oobs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, ifi.MTU)
		oobs[i] = make([]byte, 512)
	}
	for {
		ms := make([]ipv4.Message, batch)
		for i := range ms {
			ms[i] = ipv4.Message{Buffers: [][]byte{bufs[i]}, OOB: oobs[i]}
		}
		n, err := mc.ReadBatch(ms, 0)
		if err != nil {
			if isClosed(err) {
				return
			}
			log.Printf("readbatch: %v", err)
			continue
		}
		for i := 0; i < n; i++ {
			payload := ms[i].Buffers[0][:ms[i].N]
			if _, err := outConn.Write(payload); err != nil {
				sendErr.Add(1)
				continue
			}
			pkts.Add(1)
			bytesN.Add(uint64(ms[i].N))
		}
	}
}

func isClosed(err error) bool {
	// Close() during a blocked ReadBatch surfaces either net.ErrClosed or a
	// wrapped "use of closed network connection" — both mean clean shutdown.
	return err != nil && (err == net.ErrClosed || strings.Contains(err.Error(), "use of closed"))
}
