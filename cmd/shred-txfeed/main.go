//go:build linux

// shred-txfeed decodes the shred union into Solana transactions and emits
// them on partition groups (BLO-41705), one per datagram, or in chunks when a
// transaction would not fit in txfeed.MaxDatagram, so that no datagram is
// IP-fragmented.
//
// Ingest is union frames, forwarder wire version 3 or 4: unicast on -listen,
// such as the merger's -out 127.0.0.1:5003=all, or an SSM join with -ssm.
// txfeed.Assembler assembles FEC sets, recovers missing data shreds with
// Reed-Solomon and deshreds complete entry batches. Each transaction is
// parsed, classified, and sent as txframes (txfeed/frame.go) to every
// partition group it belongs to, at these offsets from the group base:
//
//	1          non-vote transactions
//	2          simple votes
//	16+i       transactions invoking named program i: -program, or
//	           txfeed.DefaultPrograms
//	64+b       transactions invoking a program in bucket b (txfeed.Bucket),
//	           except the compute budget program
//
// A non-vote transaction belongs to several groups, so a subscriber to more
// than one can receive it more than once. The groups are SSM channels whose
// source is this host: -iface-ip under -group-base, -src6 under
// -group-base6. They use their own -port: 5001 carries shreds.
//
// -channel6 KIND:BASE58 adds a filter channel (W9, txfeed/channel.go). Each
// transaction that invokes the program (KIND program; top-level instructions
// only, as a program called by CPI is not visible in shreds) or lists the
// account among its message's static account keys (KIND account; not an
// account loaded from an address lookup table) is also sent, once, to the
// channel's own IPv6 SSM group, txfeed.ChannelGroup, from -src6 on -port. Its
// datagrams are cut to txfeed.MaxChannelDatagram, 1182 bytes, which cross a
// 1280-byte IPv6 path whole through the IPv6 AMT relay. Only configured
// channels are sent, at most -channel-max of them, and never one on the vote
// or compute budget program, which nearly every transaction carries.
//
// -ttl 0 with -loop keeps the feed on this host, for a subscriber on it.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

const (
	maxDatagram = 2048
)

// output is one address family's partition groups and, for IPv6, the filter
// channels.
type output struct {
	conn interface { // a *net.UDPConn; tests record the datagrams
		WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	}
	dst   []netip.AddrPort                  // by partition; nil for -channel6 without -group-base6
	chans map[txfeed.Channel]netip.AddrPort // each -channel6 channel's group
}

// publish sends tx, transaction i of batch, to each of its partition groups
// on every output, then to the group of each filter channel it matches: as
// one txframe, or as its chunks when it would not fit in txfeed.MaxDatagram,
// or in txfeed.MaxChannelDatagram on a channel. Each group gets every
// datagram of tx in order before the next group gets any. It returns the
// datagrams sent, the sends that failed, and the datagrams tx took on a
// partition group.
func publish(outs []*output, ids []txfeed.Pubkey, batch txfeed.Batch, i int, tx txfeed.Tx) (sent, failed uint64, n int) {
	f := txfeed.Frame{
		Vote: tx.Vote, Slot: batch.Slot, BatchStart: batch.StartIndex,
		Index: uint16(i), ShredTs: batch.ShredTs, Tx: tx.Raw,
	}
	dgs := txfeed.Datagrams(f)
	send := func(o *output, dst netip.AddrPort, ds [][]byte) {
		for _, d := range ds {
			if _, err := o.conn.WriteToUDPAddrPort(d, dst); err != nil {
				failed++
			} else {
				sent++
			}
		}
	}
	for _, p := range txfeed.Partitions(tx, ids) {
		for _, o := range outs {
			if o.dst != nil {
				send(o, o.dst[p], dgs)
			}
		}
	}
	// Only the configured channels, never a group derived from a program or
	// account seen in tx. Traffic to an (S,G) the MX holds no state for makes
	// it punt a resolve to its routing engine, so a group per key seen would
	// be a self-inflicted control-plane DoS; -channel-max caps the set.
	var chanDgs [][]byte // cut at the first match: most transactions match none
	for _, o := range outs {
		for _, c := range txfeed.MatchChannels(tx, o.chans) {
			if chanDgs == nil {
				chanDgs = txfeed.DatagramsWithin(f, txfeed.MaxChannelDatagram)
			}
			send(o, o.chans[c], chanDgs)
		}
	}
	return sent, failed, len(dgs)
}

// newOutput opens a socket that sends from src, to the partition groups under
// base, or to none when base is empty.
func newOutput(base string, src netip.Addr, port, ttl int, loop bool) (*output, error) {
	o := &output{}
	if base != "" {
		b, err := netip.ParseAddr(base)
		if err != nil {
			return nil, err
		}
		if b.Is4() != src.Is4() {
			return nil, fmt.Errorf("group base %s and source %s are different address families", b, src)
		}
		o.dst = make([]netip.AddrPort, txfeed.PartBucketBase+txfeed.NumBuckets)
		for p := range o.dst {
			g, err := txfeed.Group(b, p)
			if err != nil {
				return nil, err
			}
			o.dst[p] = netip.AddrPortFrom(g, uint16(port))
		}
	}
	var err error
	if o.conn, err = txfeed.EmitSocket(src, ttl, loop); err != nil {
		return nil, fmt.Errorf("emit socket from %s: %w", src, err)
	}
	return o, nil
}

// parsePrograms parses the -program values, NAME=BASE58. None means
// txfeed.DefaultPrograms.
func parsePrograms(specs []string) ([]txfeed.Named, error) {
	if len(specs) == 0 {
		return txfeed.DefaultPrograms, nil
	}
	if len(specs) > txfeed.NumNamed {
		return nil, fmt.Errorf("%d -program values, at most %d", len(specs), txfeed.NumNamed)
	}
	var named []txfeed.Named
	for _, s := range specs {
		name, id, ok := strings.Cut(s, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("-program %q: want NAME=BASE58", s)
		}
		p, err := txfeed.ParsePubkey(id)
		if err != nil {
			return nil, fmt.Errorf("-program %q: %w", s, err)
		}
		named = append(named, txfeed.Named{Name: name, ID: p})
	}
	return named, nil
}

// parseChannels parses the -channel6 values, KIND:BASE58, into at most limit
// channels, none on a txfeed.RefusedKeys key. A channel given twice is one
// channel.
func parseChannels(specs []string, limit int) ([]txfeed.Channel, error) {
	var chans []txfeed.Channel
	for _, s := range specs {
		c, err := txfeed.ParseChannel(s)
		if err != nil {
			return nil, fmt.Errorf("-channel6: %w", err)
		}
		if i := slices.IndexFunc(txfeed.RefusedKeys, func(n txfeed.Named) bool { return n.ID == c.Key }); i >= 0 {
			return nil, fmt.Errorf("-channel6 %s: the %s program is in nearly every transaction, so its channel would carry the whole feed", c, txfeed.RefusedKeys[i].Name)
		}
		if !slices.Contains(chans, c) {
			chans = append(chans, c)
		}
	}
	if len(chans) > limit {
		return nil, fmt.Errorf("%d -channel6 channels, over -channel-max %d", len(chans), limit)
	}
	return chans, nil
}

// source6 parses src6, -src6: the source of the IPv6 partition groups and the
// filter channels, so either needs it. Without either it returns the zero
// Addr.
func source6(src6, base6 string, channels int) (netip.Addr, error) {
	if base6 == "" && channels == 0 {
		return netip.Addr{}, nil
	}
	src, err := netip.ParseAddr(src6)
	if err != nil || src.Is4() {
		return netip.Addr{}, fmt.Errorf("-group-base6 and -channel6 need -src6, a local IPv6 address; got %q", src6)
	}
	return src, nil
}

func reader(c *net.UDPConn, out chan<- []byte, qdrop *atomic.Uint64) {
	buf := make([]byte, maxDatagram)
	for {
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			log.Fatalf("read error: %v", err) // exit rather than run on with no ingest
		}
		select {
		case out <- bytes.Clone(buf[:n]): // the assembler keeps the frame
		default:
			qdrop.Add(1) // the processor is backlogged: count the frame rather than block the reader
		}
	}
}

type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, " ") }
func (f *multiFlag) Set(s string) error { *f = append(*f, s); return nil }

func main() {
	var programs, channels multiFlag
	flag.Var(&programs, "program", "NAME=BASE58 named program partition; repeatable, at most 16; replaces the defaults")
	flag.Var(&channels, "channel6", "KIND:BASE58 filter channel, KIND program (top-level instructions) or account (static account keys), sent from -src6 to its own IPv6 group; repeatable; not the vote or compute budget program")
	var (
		listen     = flag.String("listen", "", "unicast ingest ADDR:PORT, e.g. 127.0.0.1:5003 from the merger's -out 127.0.0.1:5003=all")
		ssm        = flag.String("ssm", "", "SSM ingest SOURCE@GROUP:PORT; exactly one of -listen and -ssm")
		ifaceIP    = flag.String("iface-ip", "", "local IPv4 address: the SSM join interface and the source of the IPv4 groups")
		base4      = flag.String("group-base", "232.0.3.0", "IPv4 partition group base; empty disables IPv4 output")
		base6      = flag.String("group-base6", "", "IPv6 partition group base, e.g. ff3e::232:300; requires -src6")
		src6       = flag.String("src6", "", "local IPv6 address: the source of the IPv6 groups and the filter channels")
		channelMax = flag.Int("channel-max", 256, "most -channel6 channels; more refuses to start")
		port       = flag.Int("port", 5003, "partition group and filter channel port; 5001 carries shreds")
		ttl        = flag.Int("ttl", 16, "IP_MULTICAST_TTL and IPV6_MULTICAST_HOPS; 0 keeps the feed on this host")
		loop       = flag.Bool("loop", false, "IP_MULTICAST_LOOP, for subscribers on this host")
		keep       = flag.Duration("keep", 10*time.Second, "how long a slot's FEC-set and batch state outlives its latest frame")
		statsSec   = flag.Int("stats-interval", 10, "seconds between stats lines")
		rcvbuf     = flag.Int("rcvbuf", 8<<20, "SO_RCVBUF for the ingest socket")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if *keep <= 0 {
		log.Fatalf("-keep %v: want a positive duration", *keep)
	}
	if *statsSec <= 0 {
		log.Fatalf("-stats-interval %d: want a positive number of seconds", *statsSec)
	}
	named, err := parsePrograms(programs)
	if err != nil {
		log.Fatal(err)
	}
	ids := make([]txfeed.Pubkey, len(named))
	for i, n := range named {
		ids[i] = n.ID
	}
	chans, err := parseChannels(channels, *channelMax)
	if err != nil {
		log.Fatal(err)
	}
	source, err := source6(*src6, *base6, len(chans))
	if err != nil {
		log.Fatal(err)
	}
	var iface netip.Addr
	if *ssm != "" || *base4 != "" {
		if iface, err = netip.ParseAddr(*ifaceIP); err != nil || !iface.Is4() {
			log.Fatalf("-ssm and -group-base need -iface-ip, a local IPv4 address; got %q", *ifaceIP)
		}
	}

	var outs []*output
	if *base4 != "" {
		o, err := newOutput(*base4, iface, *port, *ttl, *loop)
		if err != nil {
			log.Fatalf("-group-base: %v", err)
		}
		outs = append(outs, o)
		log.Printf("out: %s + partition, port %d (S=%s) ttl=%d loop=%t", *base4, *port, iface, *ttl, *loop)
	}
	if source.IsValid() {
		o, err := newOutput(*base6, source, *port, *ttl, *loop)
		if err != nil {
			log.Fatalf("IPv6 output: %v", err)
		}
		if *base6 != "" {
			log.Printf("out: %s + partition, port %d (S=%s) hops=%d loop=%t", *base6, *port, source, *ttl, *loop)
		}
		o.chans = make(map[txfeed.Channel]netip.AddrPort, len(chans))
		for _, c := range chans {
			o.chans[c] = netip.AddrPortFrom(txfeed.ChannelGroup(c.Kind, c.Key), uint16(*port))
			log.Printf("channel %s: (S=%s, G=%s) hops=%d loop=%t", c, source, o.chans[c], *ttl, *loop)
		}
		outs = append(outs, o)
	}
	if len(outs) == 0 {
		log.Fatal("no output: give -group-base, -group-base6 or -channel6")
	}
	for i, n := range named {
		log.Printf("program %s %s on offset %d", n.Name, n.ID, txfeed.PartNamedBase+i)
	}

	var in *net.UDPConn
	switch {
	case (*listen == "") == (*ssm == ""):
		log.Fatal("give exactly one of -listen and -ssm")
	case *listen != "":
		ap, err := netip.ParseAddrPort(*listen)
		if err != nil {
			log.Fatalf("-listen: %v", err)
		}
		if in, err = net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap)); err != nil {
			log.Fatalf("-listen: %v", err)
		}
		_ = in.SetReadBuffer(*rcvbuf) // best effort: capped by net.core.rmem_max
		log.Printf("ingest: unicast %s", ap)
	default:
		src, grp, err := txfeed.ParseSSM(*ssm)
		if err != nil {
			log.Fatal(err)
		}
		if in, err = txfeed.ListenSSM(src, grp.Addr(), int(grp.Port()), iface, *rcvbuf); err != nil {
			log.Fatalf("-ssm: %v", err)
		}
		log.Printf("ingest: SSM join (S=%s, G=%s) via %s", src, grp, iface)
	}

	ch := make(chan []byte, 1<<16)
	var qdrop atomic.Uint64
	go reader(in, ch, &qdrop)

	asm := txfeed.NewAssembler(*keep)
	var batchErr, txs, votes, oversize, overflow, chunked, sent, sendErr uint64
	stats := func() string {
		s := asm.Stats()
		return fmt.Sprintf("frames=%d dups=%d bad=%d sets_recovered=%d shards_recovered=%d recovered_bad=%d parity_checked=%d parity_mismatch=%d batches=%d batch_err=%d txs=%d votes=%d oversize=%d index_overflow=%d chunked=%d sent=%d send_err=%d queue=%d qdrop=%d slots=%d held=%d evicted=%d max_slot=%d",
			s.Frames, s.Dups, s.Bad, s.SetsRecovered, s.ShardsRecovered, s.RecoveredBad, s.ParityChecked, s.ParityMismatch, s.Batches, batchErr, txs, votes, oversize, overflow, chunked, sent, sendErr, len(ch), qdrop.Load(), s.Slots, s.Held, s.Evicted, s.MaxSlot)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(time.Duration(*statsSec) * time.Second)
	defer tick.Stop()

	for {
		select {
		case b := <-ch:
			for _, batch := range asm.Add(b) {
				parsed, err := txfeed.ParseEntries(batch.Payload)
				if err != nil {
					if batchErr++; batchErr == 1 { // the first is enough to find a parser bug
						log.Printf("batch error: slot=%d start=%d len=%d: %v; first bytes %x",
							batch.Slot, batch.StartIndex, len(batch.Payload), err, batch.Payload[:min(64, len(batch.Payload))])
					}
					continue
				}
				for i, tx := range parsed {
					txs++
					if len(tx.Raw) > txfeed.MaxTxSize {
						oversize++ // its frame would overrun a subscriber's MaxFrameSize buffer
						continue
					}
					if i > math.MaxUint16 {
						overflow++ // past a txframe's u16 index; only a forged batch holds that many
						continue
					}
					if tx.Vote {
						votes++
					}
					s, e, n := publish(outs, ids, batch, i, tx)
					sent, sendErr = sent+s, sendErr+e
					if n > 1 {
						chunked++
					}
				}
			}

		case <-tick.C:
			log.Print(stats())

		case s := <-sig:
			log.Printf("signal %v; final: %s", s, stats())
			return
		}
	}
}
