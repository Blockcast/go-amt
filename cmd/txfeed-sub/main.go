//go:build linux

// txfeed-sub subscribes to shred-txfeed partition groups and prints the
// transactions it receives, a demo of the feed (BLO-41705).
//
// Selectors join groups under -group-base, from -source, and combine:
//
//	-vote          simple votes
//	-nonvote       every other transaction
//	-named NAME    transactions invoking a txfeed.DefaultPrograms program
//	-program B58   transactions invoking that program. Its bucket group is
//	               shared with other programs, so frames from it are
//	               filtered to the ones that invoke it.
//	-ssm S@G:P     a raw SSM join, unfiltered
//
// A transaction can arrive on several of the joined groups; it is printed
// once, with its latency from the shred's send time. -verify checks its
// ed25519 signatures.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

const (
	maxDatagram = txfeed.MaxFrameSize
	rcvbuf      = 4 << 20
	slotWindow  = 64 // slots of dedup history
)

// sub is one joined group.
type sub struct {
	label  string
	source netip.Addr
	group  netip.AddrPort
	all    bool            // some selector takes every frame of the group
	filter []txfeed.Pubkey // otherwise, keep transactions invoking one of these
	frames uint64
}

func (s *sub) keeps(tx txfeed.Tx) bool {
	return s.all || slices.ContainsFunc(tx.Programs, func(p txfeed.Pubkey) bool { return slices.Contains(s.filter, p) })
}

// join adds a group to subs, or widens the one already joined. A nil prog
// takes every frame.
func join(subs []*sub, label string, source netip.Addr, group netip.AddrPort, prog *txfeed.Pubkey) []*sub {
	i := slices.IndexFunc(subs, func(s *sub) bool { return s.source == source && s.group == group })
	if i < 0 {
		i = len(subs)
		subs = append(subs, &sub{label: label, source: source, group: group})
	}
	if prog == nil {
		subs[i].all = true
	} else {
		subs[i].filter = append(subs[i].filter, *prog)
	}
	return subs
}

// percentile returns the p-th percentile of sorted, by nearest rank.
func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, len(sorted)*p/100)]
}

// line is one printed transaction.
type line struct {
	Slot      uint64   `json:"slot"`
	Batch     uint32   `json:"batch"`
	Index     uint16   `json:"index"`
	Vote      bool     `json:"vote"`
	Sig       string   `json:"sig"`
	Programs  []string `json:"programs"`
	LatencyMs float64  `json:"latency_ms"`
	Verify    string   `json:"verify,omitempty"`
}

type packet struct {
	s  *sub
	b  []byte
	at time.Time
}

type multiFlag []string

func (f *multiFlag) String() string     { return strings.Join(*f, " ") }
func (f *multiFlag) Set(s string) error { *f = append(*f, s); return nil }

func main() {
	var named, programs, raw multiFlag
	flag.Var(&named, "named", "NAME of a default named program to subscribe to; repeatable")
	flag.Var(&programs, "program", "BASE58 program to subscribe to, through its bucket group; repeatable")
	flag.Var(&raw, "ssm", "SOURCE@GROUP:PORT to join unfiltered; repeatable")
	var (
		source   = flag.String("source", "69.25.95.57", "source of the partition groups: the shred-txfeed host")
		base     = flag.String("group-base", "232.0.3.0", "partition group base")
		port     = flag.Int("port", 5003, "partition group port")
		ifaceIP  = flag.String("iface-ip", "", "local IP address on the interface to join on")
		vote     = flag.Bool("vote", false, "subscribe to simple votes")
		nonvote  = flag.Bool("nonvote", false, "subscribe to non-vote transactions")
		verify   = flag.Bool("verify", false, "verify each transaction's ed25519 signatures")
		asJSON   = flag.Bool("json", false, "print JSON lines")
		limit    = flag.Uint64("n", 0, "exit after this many transactions; 0 for no limit")
		duration = flag.Duration("duration", 0, "exit after this long; 0 for no limit")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	iface, err := netip.ParseAddr(*ifaceIP)
	if err != nil {
		log.Fatalf("-iface-ip: want a local IP address; got %q", *ifaceIP)
	}
	src, err := netip.ParseAddr(*source)
	if err != nil {
		log.Fatalf("-source: %v", err)
	}
	b, err := netip.ParseAddr(*base)
	if err != nil {
		log.Fatalf("-group-base: %v", err)
	}
	group := func(off int) netip.AddrPort {
		g, err := txfeed.Group(b, off)
		if err != nil {
			log.Fatalf("-group-base: %v", err)
		}
		return netip.AddrPortFrom(g, uint16(*port))
	}

	var subs []*sub
	if *vote {
		subs = join(subs, "vote", src, group(txfeed.PartVote), nil)
	}
	if *nonvote {
		subs = join(subs, "nonvote", src, group(txfeed.PartNonVote), nil)
	}
	names := map[txfeed.Pubkey]string{}
	for _, n := range txfeed.DefaultPrograms {
		names[n.ID] = n.Name
	}
	for _, name := range named {
		i := slices.IndexFunc(txfeed.DefaultPrograms, func(n txfeed.Named) bool { return n.Name == name })
		if i < 0 {
			log.Fatalf("-named %q: not a default program", name)
		}
		subs = join(subs, name, src, group(txfeed.PartNamedBase+i), nil)
	}
	for _, s := range programs {
		p, err := txfeed.ParsePubkey(s)
		if err != nil {
			log.Fatalf("-program: %v", err)
		}
		b := txfeed.Bucket(p)
		subs = join(subs, fmt.Sprintf("bucket-%d", b), src, group(txfeed.PartBucketBase+b), &p)
	}
	for _, s := range raw {
		rs, rg, err := txfeed.ParseSSM(s)
		if err != nil {
			log.Fatal(err)
		}
		subs = join(subs, "ssm", rs, rg, nil)
	}
	if len(subs) == 0 {
		log.Fatal("nothing to subscribe to: give -vote, -nonvote, -named, -program or -ssm")
	}

	ch := make(chan packet, 1<<14)
	for _, s := range subs {
		c, err := txfeed.ListenSSM(s.source, s.group.Addr(), int(s.group.Port()), iface, rcvbuf)
		if err != nil {
			log.Fatalf("%s: %v", s.label, err)
		}
		log.Printf("joined %s: (S=%s, G=%s) via %s", s.label, s.source, s.group, iface)
		go func(s *sub, c *net.UDPConn) {
			buf := make([]byte, maxDatagram)
			for {
				n, _, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					log.Printf("%s: read error: %v", s.label, err)
					return
				}
				ch <- packet{s: s, b: bytes.Clone(buf[:n]), at: time.Now()}
			}
		}(s, c)
	}

	var printed, dups, filtered, bad, verOK, verBad uint64
	var lat []float64 // ponytail: keeps every latency for the percentiles; a histogram if runs get long
	var maxSlot uint64
	seen := map[uint64]map[uint64]bool{} // slot -> batch start<<16 | index
	enc := json.NewEncoder(os.Stdout)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	var deadline <-chan time.Time
	if *duration > 0 {
		deadline = time.After(*duration)
	}

	defer func() {
		slices.Sort(lat)
		for _, s := range subs {
			log.Printf("group %s %s: frames=%d", s.label, s.group, s.frames)
		}
		log.Printf("printed=%d dups=%d filtered=%d bad=%d verify_ok=%d verify_bad=%d latency_ms p50=%.1f p90=%.1f p99=%.1f",
			printed, dups, filtered, bad, verOK, verBad, percentile(lat, 50), percentile(lat, 90), percentile(lat, 99))
	}()
	for *limit == 0 || printed < *limit {
		var p packet
		select {
		case p = <-ch:
		case <-deadline:
			return
		case <-sig:
			return
		}
		p.s.frames++
		f, err := txfeed.ParseFrame(p.b)
		if err != nil {
			bad++
			continue
		}
		tx, _, err := txfeed.ParseTx(f.Tx)
		if err != nil || tx.NumSigs == 0 {
			bad++
			continue
		}
		if !p.s.keeps(tx) {
			filtered++
			continue
		}

		if f.Slot > maxSlot {
			maxSlot = f.Slot
			for s := range seen {
				if s+slotWindow < maxSlot {
					delete(seen, s)
				}
			}
		}
		k := uint64(f.BatchStart)<<16 | uint64(f.Index)
		if seen[f.Slot][k] {
			dups++
			continue
		}
		if seen[f.Slot] == nil {
			seen[f.Slot] = map[uint64]bool{}
		}
		seen[f.Slot][k] = true

		l := line{Slot: f.Slot, Batch: f.BatchStart, Index: f.Index, Vote: f.Vote, Sig: txfeed.Base58Encode(tx.Sig),
			LatencyMs: float64(p.at.UnixMicro()-int64(f.ShredTs)) / 1000}
		for _, id := range tx.Programs {
			name, ok := names[id]
			if !ok {
				name = id.String()[:8]
			}
			l.Programs = append(l.Programs, name)
		}
		lat = append(lat, l.LatencyMs)
		if *verify {
			if ok, err := txfeed.VerifyTx(f.Tx); ok && err == nil {
				l.Verify, verOK = "ok", verOK+1
			} else {
				l.Verify, verBad = "bad", verBad+1
			}
		}
		printed++
		if *asJSON {
			_ = enc.Encode(l)
			continue
		}
		v := ""
		if *verify {
			v = " verify=" + l.Verify
		}
		fmt.Printf("slot=%d batch=%d:%d vote=%t sig=%s programs=%s latency_ms=%.1f%s\n",
			l.Slot, l.Batch, l.Index, l.Vote, l.Sig, strings.Join(l.Programs, ","), l.LatencyMs, v)
	}
}
