//go:build linux

// shred-merger merges two independent Solana turbine shred streams into one
// deduplicated stream, the union feed (BLO-22812), and emits it on one or
// more outputs.
//
// Ingest A: SSM join (prod-src, group):port. This is the production forwarder's
// stream. A datagram on the port from any other source is dropped, and counted
// as foreign.
// Ingest B: unicast UDP on 127.0.0.1:<local-port>. This is the second
// listener's stream.
//
// Outputs (-out ADDR[:PORT]=KIND, repeatable; PORT defaults to -port). A
// multicast ADDR makes a NEW SSM channel whose source is this host: -iface-ip
// for IPv4, -src6 for IPv6. A unicast ADDR, such as 127.0.0.1:5003 for a
// local consumer, gets the same frames by unicast. KIND selects the frames
// and their wire version:
//
//	all          every frame, verbatim
//	v3           every frame as forwarder wire version 3, for consumers that
//	             cannot take version 4. The browser player is one: its MoQ
//	             datagram budget fits a version-3 frame and not a full shred.
//	             Version-4 frames are reduced to the erasure shard the forwarder
//	             sends as version 3 (shred.FrameV3); version-3 frames pass
//	             through unchanged.
//	data         data shreds only, verbatim
//	coding-even  coding shreds at an even FEC-set position, verbatim
//	coding-odd   coding shreds at an odd FEC-set position, verbatim
//
// data, coding-even and coding-odd partition the stream into layers. A
// receiver joins the data layer, then adds coding layers as its loss requires.
// With 32:32 FEC sets, data alone needs every data shred of a set, data plus
// one coding layer survives 16 losses in each set of 48, and all three layers
// survive 32 in each set of 64. Reed-Solomon recovery needs any 32 shreds of
// the set, so a missing coding layer counts as losses.
//
// -egress-group G is shorthand for -out G=all. At least one output is
// required, and none may be the ingest group and port.
//
// Outputs share -port, the ingest port, unless given another. A receiver
// that binds the wildcard address gets every group the host has joined on its
// port: Linux defaults IP_MULTICAST_ALL to 1. The layers are disjoint, so one
// such socket can take several layers, but it must not also take the v3
// output, or it gets most shreds twice in two versions. Bind each group
// address, or clear IP_MULTICAST_ALL as listenUDP4 does.
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
// History of a slot lasts -dedup-keep past its latest shred: an arrival
// clock, not a slot window, because the forwarders do not authenticate slots
// (see dedup).
//
// Verbatim frames (28-byte header + body) are byte-identical to what a single
// forwarder would have produced. They keep the original send_ts_us of
// whichever listener saw the shred first. That copy also fixes the version:
// while one input is on version 3 and the other on version 4, every verbatim
// output carries a per-shred mix of both, and only the version-4 frames carry
// the producer's signature. emitted_v3 and emitted_v4 in the stats line show
// the mix.
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
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

// emitSocket6 returns a UDP socket that sends from src and pins multicast to
// the interface holding src. Binding src fixes the SSM source address, so the
// channel is (src, G) whatever other addresses the interface carries.
func emitSocket6(src net.IP, hops int) (*net.UDPConn, error) {
	ifindex, err := interfaceWith(src)
	if err != nil {
		return nil, err
	}
	uc, err := net.ListenUDP("udp6", &net.UDPAddr{IP: src})
	if err != nil {
		return nil, err
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, ifindex); serr != nil {
			return
		}
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, hops); serr != nil {
			return
		}
		if serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, 0); serr != nil {
			return
		}
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4<<20)
	}); err != nil {
		return nil, err
	}
	return uc, serr
}

// interfaceWith returns the index of the interface that holds ip.
func interfaceWith(ip net.IP) (int, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return ifi.Index, nil
			}
		}
	}
	return 0, fmt.Errorf("no interface holds %s", ip)
}

// reader passes c's datagrams to out. A valid from admits only datagrams sent
// from that address and counts the rest in foreign. Ingest A needs it: its
// socket binds the wildcard on its port, so unicast from any host reaches it,
// and a forged shred that arrives before the real one wins dedup (BLO-43063).
func reader(c *net.UDPConn, src uint8, from netip.Addr, out chan<- frame, dropped, foreign *atomic.Uint64) {
	b := make([]byte, maxDatagram)
	for {
		n, ap, err := c.ReadFromUDPAddrPort(b)
		if err != nil {
			// The union needs both ingests: exit so systemd restarts the
			// merger, rather than run on half of them with healthy stats.
			log.Fatalf("read error (src=%d): %v", src, err)
		}
		if from.IsValid() && ap.Addr().Unmap() != from {
			foreign.Add(1)
			continue
		}
		if n < hdrLen {
			continue
		}
		select {
		case out <- frame{buf: b, n: n, src: src}:
			b = make([]byte, maxDatagram) // out owns the old buffer now
		default:
			dropped.Add(1) // the processor is backlogged: count the frame rather than block the reader
		}
	}
}

type verdict int

const (
	emit      verdict = iota // first sighting: forward it
	duplicate                // the union already carries this shred
	skip                     // slot 0: no real shred has it
)

// dedup remembers, per slot, which shreds the union has already emitted. It
// forgets a slot once keep passes with no shred of it.
//
// History is bounded by arrival time, not by distance from the highest slot
// seen, for the reason shred/retention.go gives: the slot is whatever the
// sender wrote. The forwarders take shreds on a TVU port open to any host and
// check no signature. When history was a window below the highest slot, one
// forged far-future slot moved the window past every real slot, and the union
// emitted nothing more until a restart. Now a forged slot only costs one entry
// that ages out, and real shreds are never refused.
type dedup struct {
	keep      time.Duration
	maxSlot   uint64 // the highest slot seen, for the stats line only
	seen      map[uint64]*slotSeen
	ids       int       // shreds remembered across every slot
	forgotten uint64    // slots forgotten or reset at a cap rather than for idling
	sweep     time.Time // when the next eviction pass runs
}

type slotSeen struct {
	last time.Time           // arrival of its latest shred
	ids  map[uint64]struct{} // fec_set_index<<32 | local_index
}

// maxDedupSlots bounds history under a flood of distinct forged slots. Real
// traffic holds keep times the slot rate, about 140 slots at the default.
// Past the cap, the slot idle longest goes first, and a slot still being
// received is never the idlest.
const maxDedupSlots = 256

// maxSlotIDs bounds one slot's history. A flood of distinct (fec_set_index,
// local_index) pairs on one slot number keeps that slot fresh, so neither the
// sweep nor maxDedupSlots ever forgets it. A real slot carries at most 32768
// data shreds and as many coding. A new id past the cap starts the slot over;
// a duplicate never does, so a full real slot is not reset by a repeat.
const maxSlotIDs = 1 << 16

// maxDedupIDs bounds history across slots. The two caps above allow 16.8M ids,
// about 577 MiB at 36 B an id (Ally, go-amt#144 review 5464391246), and a flood
// could hold that forever with one duplicate per slot per keep (Ally,
// go-amt#147 review 5468443886). Past this cap a new id first forgets the
// idlest other slot. That bounds memory, not the hold: a flood can still hold
// up to the cap, and one that refreshes its slots faster than live slots go
// idle makes the live slots the idlest, so their history shortens instead.
// 2M ids is about 72 MiB, ten times the 130k-190k ids live traffic holds across
// 100-140 slots (CT 140, 2026-10-09). A dedup_ids pinned near it is a flood of
// full slots, and slots pinned at 256 one of distinct slots. A one-slot flood
// leaves both at live levels and shows only as forgotten climbing, one per
// 65536 new ids.
const maxDedupIDs = 1 << 21

func newDedup(keep time.Duration) *dedup {
	return &dedup{keep: keep, seen: map[uint64]*slotSeen{}}
}

func (d *dedup) observe(now time.Time, slot uint64, fec, idx uint32) verdict {
	if slot == 0 {
		return skip
	}
	d.maxSlot = max(d.maxSlot, slot)
	if !now.Before(d.sweep) {
		// One pass per keep/2 rather than per shred, so a slot can outlive
		// keep by up to half of it.
		for s, ss := range d.seen {
			if now.Sub(ss.last) > d.keep {
				d.drop(s)
			}
		}
		d.sweep = now.Add(d.keep / 2)
	}
	ss := d.seen[slot]
	if ss == nil {
		if len(d.seen) >= maxDedupSlots {
			d.forgetIdlest(slot)
		}
		ss = &slotSeen{ids: map[uint64]struct{}{}}
		d.seen[slot] = ss
	}
	ss.last = now
	// A shred of a slot already forgotten is emitted again. After keep with
	// no shred of its slot, a repeat is rarer than the harm of refusing a
	// slot on its number alone.
	k := uint64(fec)<<32 | uint64(idx)
	if _, dup := ss.ids[k]; dup {
		return duplicate
	}
	if len(ss.ids) >= maxSlotIDs {
		// More shreds than a real slot has: start it over.
		d.ids -= len(ss.ids)
		ss.ids = map[uint64]struct{}{}
		d.forgotten++
	}
	for d.ids >= maxDedupIDs && len(d.seen) > 1 {
		d.forgetIdlest(slot)
	}
	ss.ids[k] = struct{}{}
	d.ids++
	return emit
}

// drop forgets slot s.
func (d *dedup) drop(s uint64) {
	d.ids -= len(d.seen[s].ids)
	delete(d.seen, s)
}

// forgetIdlest forgets the slot, other than except, whose latest shred arrived
// longest ago.
func (d *dedup) forgetIdlest(except uint64) {
	var idlest uint64
	var at time.Time
	for s, ss := range d.seen {
		if s != except && (at.IsZero() || ss.last.Before(at)) {
			idlest, at = s, ss.last
		}
	}
	d.drop(idlest)
	d.forgotten++
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

// kind selects which frames an output carries, and in which wire version.
type kind int

const (
	kindAll kind = iota
	kindV3
	kindData
	kindCodingEven
	kindCodingOdd
)

var kindNames = []string{"all", "v3", "data", "coding-even", "coding-odd"}

func (k kind) String() string { return kindNames[k] }

// carries reports whether an output of kind k carries the frame b.
func (k kind) carries(b []byte) bool {
	coding := b[17]&0x02 != 0 // flags bit1: IS_CODING_SHRED
	switch k {
	case kindData:
		return !coding
	case kindCodingEven, kindCodingOdd:
		// A coding shred's local_index is num_data + its position in the set.
		pos := binary.LittleEndian.Uint32(b[13:17]) - uint32(b[18])
		return coding && pos%2 == uint32(k-kindCodingEven)
	}
	return true
}

// output is one destination of the union. Each has its own socket, queue and
// sender goroutine. On CT 140 a write costs tens of microseconds, a veth into a
// bridge that floods multicast to every port, and one loop writing every frame
// to every output fell behind when a fourth output was added (BLO-41705). Now
// the processor only queues, the outputs write in parallel, and an output that
// falls behind drops its own frames instead of delaying the rest.
type output struct {
	dst             *net.UDPAddr
	kind            kind
	conn            *net.UDPConn
	q               chan []byte
	sent, err, drop atomic.Uint64
}

// outQueue is each output's backlog in frames. At 5.5k shreds/s that is about
// 1.5 s for an all or v3 output, 3 s for data and 6 s for a coding layer. The
// stats line shows each queue's depth, so a backlog shows before it drops.
const outQueue = 1 << 13

// start makes the output's queue and starts its sender, which writes the
// queued frames to dst in order.
func (o *output) start() {
	o.q = make(chan []byte, outQueue)
	go func() {
		for p := range o.q {
			if _, err := o.conn.WriteToUDP(p, o.dst); err != nil {
				o.err.Add(1)
			} else {
				o.sent.Add(1)
			}
		}
	}()
}

// parseOutput parses an -out value, ADDR[:PORT]=KIND. An IPv6 ADDR with a
// PORT is written [ADDR]:PORT.
func parseOutput(spec string, defaultPort int) (*output, error) {
	addr, name, ok := strings.Cut(spec, "=")
	if !ok {
		return nil, fmt.Errorf("-out %q: want ADDR[:PORT]=KIND", spec)
	}
	k := -1
	for i, n := range kindNames {
		if n == name {
			k = i
		}
	}
	if k < 0 {
		return nil, fmt.Errorf("-out %q: unknown kind %q, want one of %s", spec, name, strings.Join(kindNames, ", "))
	}
	host, port := addr, defaultPort
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host = h
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("-out %q: bad port %q", spec, p)
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("-out %q: %q is not an IP address", spec, host)
	}
	return &output{dst: &net.UDPAddr{IP: ip, Port: port}, kind: kind(k)}, nil
}

// parseOutputs parses the -out values. It refuses an empty list, a repeated
// destination, and a destination that is one of the ingests.
func parseOutputs(specs []string, defaultPort int, ingests ...*net.UDPAddr) ([]*output, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("no output: give -out ADDR[:PORT]=KIND or -egress-group")
	}
	var outs []*output
	for _, s := range specs {
		o, err := parseOutput(s, defaultPort)
		if err != nil {
			return nil, err
		}
		// One destination carrying two kinds would hand its receivers each
		// shred twice, or in two versions.
		for _, prev := range outs {
			if o.dst.IP.Equal(prev.dst.IP) && o.dst.Port == prev.dst.Port {
				return nil, fmt.Errorf("-out %q: %s is already an output", s, o.dst)
			}
		}
		// On the second listener's port the merger would ingest its own output.
		// On the ingest group it would not, being a different source, but a
		// wildcard receiver of the production channel would get the union too.
		for _, in := range ingests {
			if o.dst.IP.Equal(in.IP) && o.dst.Port == in.Port {
				return nil, fmt.Errorf("-out %q: %s is an ingest", s, in)
			}
		}
		outs = append(outs, o)
	}
	return outs, nil
}

// send queues the frame b on every output that carries it, without waiting:
// an output whose queue is full loses the frame and counts it in drop. It
// reports false when a version-3 output needed the frame and b cannot be
// converted. Queued frames are shared and never written to: each frame a reader
// passes on has its own buffer, and asV3 copies.
func send(outs []*output, b []byte) (convertible bool) {
	var v3 []byte
	converted := false
	convertible = true
	for _, o := range outs {
		if !o.kind.carries(b) {
			continue
		}
		p := b
		if o.kind == kindV3 {
			if !converted {
				v3, convertible = asV3(b)
				converted = true
			}
			if !convertible {
				continue
			}
			p = v3
		}
		select {
		case o.q <- p:
		default:
			o.drop.Add(1)
		}
	}
	return convertible
}

type outFlags []string

func (f *outFlags) String() string     { return strings.Join(*f, " ") }
func (f *outFlags) Set(s string) error { *f = append(*f, s); return nil }

func main() {
	var specs outFlags
	flag.Var(&specs, "out", "ADDR[:PORT]=KIND to emit the union on; repeatable. KIND is all, v3, data, coding-even or coding-odd (see the package doc)")
	var (
		prodSrc   = flag.String("prod-src", "69.25.95.197", "source IP of the production SSM stream to ingest")
		group     = flag.String("group", "232.0.0.1", "SSM group to INGEST (production channel)")
		egress    = flag.String("egress-group", "", "shorthand for -out GROUP=all")
		port      = flag.Int("port", 5001, "SSM UDP port to ingest, and the default -out port")
		ifaceIP   = flag.String("iface-ip", "69.25.95.57", "local IP on the shared L2 segment; SSM source of the IPv4 outputs")
		src6      = flag.String("src6", "", "local IPv6 address; SSM source of the IPv6 outputs (required by any)")
		localPort = flag.Int("local-port", 5002, "loopback UDP port the second listener feeds")
		ttl       = flag.Int("ttl", 16, "IP_MULTICAST_TTL and IPV6_MULTICAST_HOPS for the outputs")
		keep      = flag.Duration("dedup-keep", 25*time.Second, "how long a slot's dedup history outlives its latest shred")
		statsSec  = flag.Int("stats-interval", 10, "seconds between stats lines")
		rcvbuf    = flag.Int("rcvbuf", 4<<20, "SO_RCVBUF for ingest sockets")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if *keep <= 0 {
		log.Fatalf("-dedup-keep %v: want a positive duration", *keep)
	}
	if *egress != "" {
		specs = append(specs, *egress+"=all")
	}
	ingestB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: *localPort}
	outs, err := parseOutputs(specs, *port, &net.UDPAddr{IP: net.ParseIP(*group), Port: *port}, ingestB)
	if err != nil {
		log.Fatal(err)
	}
	var src net.IP // the IPv6 outputs' source, when there are any
	for _, o := range outs {
		if o.dst.IP.To4() == nil && src == nil {
			if src = net.ParseIP(*src6); src == nil || src.To4() != nil {
				log.Fatalf("an IPv6 -out needs -src6, a local IPv6 address; got %q", *src6)
			}
		}
	}

	// Ingest A: the production SSM stream. Go binds the wildcard for a multicast
	// address, so what keeps the socket to this channel's multicast is its own
	// join, with IP_MULTICAST_ALL cleared. Unicast to the port still reaches it,
	// so its reader admits only -prod-src.
	inA, err := listenUDP4(fmt.Sprintf("%s:%d", *group, *port), *rcvbuf, true)
	if err != nil {
		log.Fatalf("bind ingest A: %v", err)
	}
	if err := joinSSM(inA, *group, *prodSrc, *ifaceIP); err != nil {
		log.Fatalf("SSM join (%s, %s) on %s: %v", *prodSrc, *group, *ifaceIP, err)
	}
	log.Printf("ingest A: SSM join (S=%s, G=%s):%d via %s", *prodSrc, *group, *port, *ifaceIP)

	// Ingest B: the second listener, over loopback unicast.
	inB, err := listenUDP4(ingestB.String(), *rcvbuf, false)
	if err != nil {
		log.Fatalf("bind ingest B: %v", err)
	}
	log.Printf("ingest B: unicast %s", ingestB)

	// One socket per output: writes on a shared socket serialize on its lock.
	for _, o := range outs {
		from := *ifaceIP
		if o.dst.IP.To4() == nil {
			if o.conn, err = emitSocket6(src, *ttl); err != nil {
				log.Fatalf("IPv6 emit socket from %s for %s: %v", src, o.dst, err)
			}
			from = *src6
		} else if o.conn, err = emitSocket(*ifaceIP, *ttl); err != nil {
			log.Fatalf("emit socket for %s: %v", o.dst, err)
		}
		o.start()
		log.Printf("out: %s (S=%s, D=%s) ttl=%d", o.kind, from, o.dst, *ttl)
	}

	ch := make(chan frame, 1<<16)
	var qdrop, foreign atomic.Uint64
	go reader(inA, 0, netip.AddrFrom4(mustIP4(*prodSrc)), ch, &qdrop, &foreign)
	go reader(inB, 1, netip.Addr{}, ch, &qdrop, &foreign) // bound to 127.0.0.1

	seen := newDedup(*keep)
	var rxA, rxB, emitted, emittedV3, emittedV4, dupA, dupB, firstFromB, v3Unconvertible, skipped uint64

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
			switch seen.observe(time.Now(), binary.LittleEndian.Uint64(b[1:9]), binary.LittleEndian.Uint32(b[9:13]), binary.LittleEndian.Uint32(b[13:17])) {
			case skip:
				skipped++
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
			emitted++
			switch b[0] {
			case 3:
				emittedV3++
			case 4:
				emittedV4++
			}
			if !send(outs, b) {
				v3Unconvertible++
			}

		case <-tick.C:
			// emitted counts the shreds the union carries. Each output follows
			// as KIND@DST=SENT/ERR/DROP/QUEUED: frames written, failed, dropped
			// with its queue full, and still queued; for an all output they add
			// up to emitted. A unicast output with no listener still counts its
			// frames as SENT: its socket is unconnected, so it never sees the
			// ICMP port unreachable. emit_err and out_drop sum ERR and DROP.
			// queue is the input backlog, which qdrop counts once it is full.
			// foreign counts datagrams to ingest A from a host other than
			// -prod-src, dropped unread.
			var emitErr, outDrop uint64
			var per strings.Builder
			for _, o := range outs {
				sent, e, d := o.sent.Load(), o.err.Load(), o.drop.Load()
				emitErr += e
				outDrop += d
				fmt.Fprintf(&per, " %s@%s=%d/%d/%d/%d", o.kind, o.dst, sent, e, d, len(o.q))
			}
			log.Printf("rx_prod=%d rx_listener2=%d emitted=%d dup_prod=%d dup_listener2=%d first_from_listener2=%d emit_err=%d out_drop=%d qdrop=%d foreign=%d queue=%d slots=%d max_slot=%d emitted_v3=%d emitted_v4=%d v3_unconvertible=%d skipped=%d dedup_ids=%d forgotten=%d%s",
				rxA, rxB, emitted, dupA, dupB, firstFromB, emitErr, outDrop, qdrop.Load(), foreign.Load(), len(ch), len(seen.seen), seen.maxSlot, emittedV3, emittedV4, v3Unconvertible, skipped, seen.ids, seen.forgotten, per.String())

		case s := <-sig:
			log.Printf("signal %v; final: rx_prod=%d rx_listener2=%d emitted=%d first_from_listener2=%d", s, rxA, rxB, emitted, firstFromB)
			return
		}
	}
}
