//go:build linux

// shred-txfeed decodes the shred union into Solana transactions and emits
// them, one per datagram, on partition groups (BLO-41705).
//
// Ingest is union frames, forwarder wire version 3 or 4: unicast on -listen,
// such as the merger's -out 127.0.0.1:5003=all, or an SSM join with -ssm.
// txfeed.Assembler assembles FEC sets, recovers missing data shreds with
// Reed-Solomon and deshreds complete entry batches. Each transaction is
// parsed, classified, and sent as a txframe (txfeed/frame.go) to every
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
// -ttl 0 with -loop keeps the feed on this host, for a subscriber on it.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

const (
	maxDatagram = 2048
	maxNamed    = 16 // named partitions occupy offsets 16..31
)

// output is one address family's partition groups.
type output struct {
	conn *net.UDPConn
	dst  []netip.AddrPort // by partition
}

func newOutput(base string, src netip.Addr, port, ttl int, loop bool) (*output, error) {
	b, err := netip.ParseAddr(base)
	if err != nil {
		return nil, err
	}
	if b.Is4() != src.Is4() {
		return nil, fmt.Errorf("group base %s and source %s are different address families", b, src)
	}
	o := &output{dst: make([]netip.AddrPort, txfeed.PartBucketBase+txfeed.NumBuckets)}
	for p := range o.dst {
		g, err := txfeed.Group(b, p)
		if err != nil {
			return nil, err
		}
		o.dst[p] = netip.AddrPortFrom(g, uint16(port))
	}
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
	if len(specs) > maxNamed {
		return nil, fmt.Errorf("%d -program values, at most %d", len(specs), maxNamed)
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

func reader(c *net.UDPConn, out chan<- []byte, qdrop *atomic.Uint64) {
	buf := make([]byte, maxDatagram)
	for {
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			return
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
	var programs multiFlag
	flag.Var(&programs, "program", "NAME=BASE58 named program partition; repeatable, at most 16; replaces the defaults")
	var (
		listen   = flag.String("listen", "", "unicast ingest ADDR:PORT, e.g. 127.0.0.1:5003 from the merger's -out 127.0.0.1:5003=all")
		ssm      = flag.String("ssm", "", "SSM ingest SOURCE@GROUP:PORT; exactly one of -listen and -ssm")
		ifaceIP  = flag.String("iface-ip", "", "local IPv4 address: the SSM join interface and the source of the IPv4 groups")
		base4    = flag.String("group-base", "232.0.3.0", "IPv4 partition group base; empty disables IPv4 output")
		base6    = flag.String("group-base6", "", "IPv6 partition group base, e.g. ff3e::232:300; requires -src6")
		src6     = flag.String("src6", "", "local IPv6 address: the source of the IPv6 groups")
		port     = flag.Int("port", 5003, "partition group port; 5001 carries shreds")
		ttl      = flag.Int("ttl", 16, "IP_MULTICAST_TTL and IPV6_MULTICAST_HOPS; 0 keeps the feed on this host")
		loop     = flag.Bool("loop", false, "IP_MULTICAST_LOOP, for subscribers on this host")
		window   = flag.Uint64("slot-window", 64, "slots of FEC-set and batch state to retain (~400ms per slot)")
		statsSec = flag.Int("stats-interval", 10, "seconds between stats lines")
		rcvbuf   = flag.Int("rcvbuf", 8<<20, "SO_RCVBUF for the ingest socket")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	named, err := parsePrograms(programs)
	if err != nil {
		log.Fatal(err)
	}
	ids := make([]txfeed.Pubkey, len(named))
	for i, n := range named {
		ids[i] = n.ID
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
	if *base6 != "" {
		src, err := netip.ParseAddr(*src6)
		if err != nil || src.Is4() {
			log.Fatalf("-group-base6 needs -src6, a local IPv6 address; got %q", *src6)
		}
		o, err := newOutput(*base6, src, *port, *ttl, *loop)
		if err != nil {
			log.Fatalf("-group-base6: %v", err)
		}
		outs = append(outs, o)
		log.Printf("out: %s + partition, port %d (S=%s) hops=%d loop=%t", *base6, *port, src, *ttl, *loop)
	}
	if len(outs) == 0 {
		log.Fatal("no output: give -group-base or -group-base6")
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

	asm := txfeed.NewAssembler(*window)
	var batchErr, txs, votes, oversize, sent, sendErr uint64
	stats := func() string {
		s := asm.Stats()
		return fmt.Sprintf("frames=%d dups=%d bad=%d sets_recovered=%d shards_recovered=%d recovered_bad=%d parity_checked=%d parity_mismatch=%d batches=%d batch_err=%d txs=%d votes=%d oversize=%d sent=%d send_err=%d queue=%d qdrop=%d slots=%d max_slot=%d",
			s.Frames, s.Dups, s.Bad, s.SetsRecovered, s.ShardsRecovered, s.RecoveredBad, s.ParityChecked, s.ParityMismatch, s.Batches, batchErr, txs, votes, oversize, sent, sendErr, len(ch), qdrop.Load(), s.Slots, s.MaxSlot)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(time.Duration(*statsSec) * time.Second)
	defer tick.Stop()

	var buf []byte
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
					if tx.Vote {
						votes++
					}
					buf = txfeed.AppendFrame(buf[:0], txfeed.Frame{
						Vote: tx.Vote, Slot: batch.Slot, BatchStart: batch.StartIndex,
						Index: uint16(i), ShredTs: batch.ShredTs, Tx: tx.Raw,
					})
					for _, p := range txfeed.Partitions(tx, ids) {
						for _, o := range outs {
							if _, err := o.conn.WriteToUDPAddrPort(buf, o.dst[p]); err != nil {
								sendErr++
							} else {
								sent++
							}
						}
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
