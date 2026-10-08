//go:build linux

// shred-merger merges two independent Solana turbine shred streams into one
// deduplicated SSM multicast channel, the union feed (BLO-22812).
//
// Ingest A: SSM join (prod-src, group):port. This is the production forwarder's
// stream.
// Ingest B: unicast UDP on 127.0.0.1:<local-port>. This is the second
// listener's stream.
// Egress: SSM emit to (egress-group):port from -iface-ip, which makes a NEW
// (S,G) channel whose source is this host.
// v3 egress (optional, -v3-egress-group): the same deduplicated stream as
// forwarder wire version 3, for consumers that cannot take version 4. The
// browser player is one: its MoQ datagram budget fits a version-3 frame and
// not a full shred. Version-4 frames are reduced to the erasure shard the
// forwarder sends as version 3 (shred.FrameV3); version-3 frames pass through
// unchanged.
//
// The dedup key is (slot, fec_set_index, local_index). local_index is a
// UNIFIED data||coding coordinate produced by shred-forwarder's parse_shred:
//
//	data   shreds -> index - fec_set_index        (0 .. num_data-1)
//	coding shreds -> num_data + position          (num_data .. num_data+num_coding-1)
//
// so data and coding never collide and no is_coding component is required.
// Keying on (slot, local_index) alone would be WRONG: local_index is local to
// the FEC set (0..63), so it would collapse distinct shreds across FEC sets in
// the slot. The key ignores the wire version, so a shred both inputs deliver
// is emitted once even while the inputs are on different versions.
//
// Frames go out on -egress-group verbatim (28-byte header + body). The emitted
// stream is therefore byte-identical to what a single forwarder would have
// produced, and it keeps the original send_ts_us of whichever listener saw the
// shred first.
//
// Deployed on CT 140 (pve1, 69.25.95.57) as shred-merger.service. See that
// address in onprem-k8s network/registry.yaml.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/blockcast/go-amt/shred"
)

const (
	hdrLen      = shred.WireHeaderSize
	maxDatagram = 2048
)

type frame struct {
	buf []byte
	n   int
	src uint8 // 0 = production SSM, 1 = second listener
}

func mustIP4(s string) [4]byte {
	var a [4]byte
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		log.Fatalf("not an IPv4 address: %q", s)
	}
	copy(a[:], ip.To4())
	return a
}

// listenUDP4 binds a UDP socket with SO_REUSEADDR and a large receive buffer.
// mcast=true also clears IP_MULTICAST_ALL. Linux defaults it to 1, which
// delivers every multicast group arriving on the bound port to this socket,
// whatever (S,G) it joined. At the default the merger would ingest unrelated
// groups on port 5001. If the union were ever emitted on the SAME group it
// ingests, it would also ingest its own output.
func listenUDP4(bindAddr string, rcvbuf int, mcast bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
					return
				}
				if mcast {
					if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0); serr != nil {
						return
					}
				}
				// Best effort: capped by net.core.rmem_max.
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", bindAddr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func joinSSM(c *net.UDPConn, group, source, iface string) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	g, s, i := mustIP4(group), mustIP4(source), mustIP4(iface)
	// struct ip_mreq_source { __be32 imr_multiaddr; __be32 imr_interface;
	//                         __be32 imr_sourceaddr; }  -- 12 bytes. The
	// in_addr bytes go in verbatim; they are already in network order.
	var mreq [12]byte
	copy(mreq[0:4], g[:])
	copy(mreq[4:8], i[:])
	copy(mreq[8:12], s[:])
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_ADD_SOURCE_MEMBERSHIP, string(mreq[:]))
	}); err != nil {
		return err
	}
	return serr
}

// emitSocket returns a UDP socket pinned to egress multicast on ifaceIP.
func emitSocket(ifaceIP string, ttl int) (*net.UDPConn, error) {
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	ifa := mustIP4(ifaceIP)
	var serr error
	if err := rc.Control(func(fd uintptr) {
		// IP_MULTICAST_IF pins egress to the shared-L2 interface; without it the
		// kernel would pick the default route.
		if serr = unix.SetsockoptInet4Addr(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_IF, ifa); serr != nil {
			return
		}
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, ttl); serr != nil {
			return
		}
		// Our own emissions must never loop back into the SSM ingest socket.
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, 0); serr != nil {
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
	}); err != nil {
		return nil, err
	}
	return uc, serr
}

func reader(c *net.UDPConn, src uint8, out chan<- frame, dropped *atomic.Uint64) {
	for {
		b := make([]byte, maxDatagram)
		n, _, err := c.ReadFromUDP(b)
		if err != nil {
			log.Printf("read error (src=%d): %v", src, err)
			return
		}
		if n < hdrLen {
			continue
		}
		select {
		case out <- frame{buf: b, n: n, src: src}:
		default:
			dropped.Add(1) // the processor is backlogged: count the frame rather than block the reader
		}
	}
}

type verdict int

const (
	emit      verdict = iota // first sighting: forward it
	duplicate                // the union already carries this shred
	skip                     // slot 0, or older than the dedup window
)

// dedup remembers, per slot, which shreds the union has already emitted.
type dedup struct {
	window  uint64
	maxSlot uint64
	seen    map[uint64]map[uint64]struct{} // slot -> fec_set_index<<32 | local_index
}

func newDedup(window uint64) *dedup {
	return &dedup{window: window, seen: make(map[uint64]map[uint64]struct{}, 256)}
}

func (d *dedup) observe(slot uint64, fec, idx uint32) verdict {
	if slot == 0 {
		return skip
	}
	if slot > d.maxSlot {
		d.maxSlot = slot
		// Evict slots that have fallen out of the dedup window.
		if d.maxSlot > d.window {
			cutoff := d.maxSlot - d.window
			for s := range d.seen {
				if s < cutoff {
					delete(d.seen, s)
				}
			}
		}
	}
	// A shred older than the window is dropped, not emitted: its history is
	// gone, so it could be a repeat. At 64 slots (~25s) of history against
	// sub-second skew between the listeners, this should not fire in practice.
	if d.maxSlot > d.window && slot < d.maxSlot-d.window {
		return skip
	}
	set, ok := d.seen[slot]
	if !ok {
		set = make(map[uint64]struct{}, 4096)
		d.seen[slot] = set
	}
	k := uint64(fec)<<32 | uint64(idx)
	if _, dup := set[k]; dup {
		return duplicate
	}
	set[k] = struct{}{}
	return emit
}

// asV3 returns b as a forwarder wire-version-3 frame.
func asV3(b []byte) ([]byte, bool) {
	switch b[0] {
	case 3:
		return b, true
	case 4:
		return shred.FrameV3(b)
	}
	return nil, false
}

func main() {
	var (
		prodSrc   = flag.String("prod-src", "69.25.95.197", "source IP of the production SSM stream to ingest")
		group     = flag.String("group", "232.0.0.1", "SSM group to INGEST (production channel)")
		egress    = flag.String("egress-group", "", "SSM group to EMIT the union on, frames verbatim (default: same as -group)")
		v3Egress  = flag.String("v3-egress-group", "", "SSM group to ALSO emit the union on as wire version 3 (default: none)")
		port      = flag.Int("port", 5001, "SSM UDP port (ingest and egress)")
		ifaceIP   = flag.String("iface-ip", "69.25.95.57", "local IP on the shared L2 segment; SSM egress source")
		localPort = flag.Int("local-port", 5002, "loopback UDP port the second listener feeds")
		ttl       = flag.Int("ttl", 16, "IP_MULTICAST_TTL for the emitted union streams")
		window    = flag.Uint64("slot-window", 64, "slots of dedup history to retain (~400ms per slot)")
		statsSec  = flag.Int("stats-interval", 10, "seconds between stats lines")
		rcvbuf    = flag.Int("rcvbuf", 4<<20, "SO_RCVBUF for ingest sockets")
	)
	flag.Parse()

	if *egress == "" {
		*egress = *group
	}
	if *v3Egress != "" && (*v3Egress == *egress || *v3Egress == *group) {
		log.Fatalf("-v3-egress-group %s must differ from -egress-group and -group", *v3Egress)
	}

	log.SetFlags(log.LstdFlags | log.LUTC)

	// Ingest A: the production SSM stream. The socket binds the group address
	// so the kernel also filters on destination group.
	inA, err := listenUDP4(fmt.Sprintf("%s:%d", *group, *port), *rcvbuf, true)
	if err != nil {
		log.Fatalf("bind ingest A: %v", err)
	}
	if err := joinSSM(inA, *group, *prodSrc, *ifaceIP); err != nil {
		log.Fatalf("SSM join (%s, %s) on %s: %v", *prodSrc, *group, *ifaceIP, err)
	}
	log.Printf("ingest A: SSM join (S=%s, G=%s):%d via %s", *prodSrc, *group, *port, *ifaceIP)

	// Ingest B: the second listener, over loopback unicast.
	inB, err := listenUDP4(fmt.Sprintf("127.0.0.1:%d", *localPort), *rcvbuf, false)
	if err != nil {
		log.Fatalf("bind ingest B: %v", err)
	}
	log.Printf("ingest B: unicast 127.0.0.1:%d", *localPort)

	out, err := emitSocket(*ifaceIP, *ttl)
	if err != nil {
		log.Fatalf("emit socket: %v", err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP(*egress), Port: *port}
	log.Printf("egress: (S=%s, G=%s):%d ttl=%d", *ifaceIP, *egress, *port, *ttl)
	var v3dst *net.UDPAddr
	if *v3Egress != "" {
		v3dst = &net.UDPAddr{IP: net.ParseIP(*v3Egress), Port: *port}
		log.Printf("v3 egress: (S=%s, G=%s):%d ttl=%d", *ifaceIP, *v3Egress, *port, *ttl)
	}

	ch := make(chan frame, 1<<16)
	var qdrop atomic.Uint64
	go reader(inA, 0, ch, &qdrop)
	go reader(inB, 1, ch, &qdrop)

	seen := newDedup(*window)
	var rxA, rxB, emitted, dupA, dupB, firstFromB, emitErr uint64
	var v3Emitted, v3Unconvertible, v3EmitErr uint64

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(time.Duration(*statsSec) * time.Second)
	defer tick.Stop()

	for {
		select {
		case f := <-ch:
			b := f.buf[:f.n]
			if f.src == 0 {
				rxA++
			} else {
				rxB++
			}
			switch seen.observe(binary.LittleEndian.Uint64(b[1:9]), binary.LittleEndian.Uint32(b[9:13]), binary.LittleEndian.Uint32(b[13:17])) {
			case skip:
				continue
			case duplicate:
				if f.src == 0 {
					dupA++
				} else {
					dupB++
				}
				continue
			}
			if f.src == 1 {
				firstFromB++ // a marginal shred the second listener contributed
			}
			if _, err := out.WriteToUDP(b, dst); err != nil {
				emitErr++
			} else {
				emitted++
			}
			if v3dst != nil {
				if v3, ok := asV3(b); !ok {
					v3Unconvertible++
				} else if _, err := out.WriteToUDP(v3, v3dst); err != nil {
					v3EmitErr++
				} else {
					v3Emitted++
				}
			}

		case <-tick.C:
			// The original fields keep their order; new fields are appended.
			log.Printf("rx_prod=%d rx_listener2=%d emitted=%d dup_prod=%d dup_listener2=%d first_from_listener2=%d emit_err=%d qdrop=%d slots=%d max_slot=%d v3_emitted=%d v3_unconvertible=%d v3_emit_err=%d",
				rxA, rxB, emitted, dupA, dupB, firstFromB, emitErr, qdrop.Load(), len(seen.seen), seen.maxSlot, v3Emitted, v3Unconvertible, v3EmitErr)

		case s := <-sig:
			log.Printf("signal %v; final: rx_prod=%d rx_listener2=%d emitted=%d first_from_listener2=%d v3_emitted=%d", s, rxA, rxB, emitted, firstFromB, v3Emitted)
			return
		}
	}
}
