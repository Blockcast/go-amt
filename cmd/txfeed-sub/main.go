// txfeed-sub subscribes to shred-txfeed partition groups and prints the
// transactions it receives, a demo of the feed (BLO-41705).
//
// Selectors join groups under -group-base, from -source, and combine:
//
//	-nonvote       every transaction but a simple vote
//	-named NAME    transactions invoking a txfeed.DefaultPrograms program
//	-program B58   transactions invoking that program. Its bucket group is
//	               shared with other programs, so frames from it are
//	               filtered to the ones that invoke it.
//	-ssm S@G:P     a raw SSM join, unfiltered
//
// A transaction can arrive on several of the joined groups; it is printed
// once, with its latency from the shred's send time. -verify checks its
// ed25519 signatures.
//
// Without -relay, each group is a native SSM join on the interface holding
// -iface-ip. That needs Linux and a network that routes the feed's multicast.
// -relay IP[:PORT] (port 2268 by default) opens each group the way
// blockcast-shreds opens an ssm:// feed with ?relay=: natively first, then, if
// no native traffic arrives within the probe window (amt.MinUsefulProbeWindow),
// through an AMT tunnel to that relay. All the groups share one tunnel.
// -iface-ip is optional then, and the command runs on macOS and Windows as
// well. Off Blockcast's network:
//
//	txfeed-sub -relay 69.25.95.128 -named jupiter-v6 -json
//
// -listen ADDR:PORT joins nothing: it reads frames from a loopback socket, the
// hand-off from amt-verify --forward (amt-protocol), which receives an IPv6
// filter channel (W9, txfeed.ChannelGroup) through the IPv6 AMT relay.
// -channel KIND:BASE58 checks that every transaction matches that channel. One
// that does not is counted as nonmatching, not printed, and makes the exit
// status 1. For the Jupiter v6 program channel:
//
//	txfeed-sub -listen 127.0.0.1:15003 -channel program:JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 -json &
//	amt-verify --family v6 --relay 2602:f74d:1::128 --source 2602:f74d:1:5::57 \
//		--group ff3e:0:5931:b9e6:ea21:cfec:b94a:e197 --forward 127.0.0.1:15003
//
// -footers times Alpenglow block footers on the shred union instead
// (txfeed.FooterTimes, BLO-49345): join the union with -ssm, natively or
// through -relay, or read it from -listen. It prints a JSON line a block: the
// footer's producer time, its receive time, and latency_ms between them with no
// clock correction. It requires -clock-source, this host's time source, and
// -clock-offset, this host's clock minus that source's, and records both on
// each line: latency_ms minus clock_offset_us/1000 is corrected for this host's
// clock, not the leader's. timedatectl timesync-status prints the opposite
// sign, so its Offset of -190us is -clock-offset=190us. The exit summary's
// percentiles take the latency at index n*p/100, rounded down: up to 100
// footers, p99 is the slowest. On sfo12:
//
//	txfeed-sub -footers -ssm 69.25.95.57@232.0.0.2:5001 -iface-ip 69.25.95.32 -duration 10m \
//		-clock-source 'systemd-timesyncd time.cloudflare.com' -clock-offset=190us
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	amt "github.com/blockcast/go-amt"
	"github.com/blockcast/go-amt/internal/amtrelay"
	"github.com/blockcast/go-amt/txfeed"
)

const (
	maxDatagram = txfeed.MaxFrameSize
	rcvbuf      = 4 << 20
	// dedupKeep is how long a slot's dedup history outlives its latest frame.
	// History goes by arrival time, as in txfeed.Assembler: a slot number from
	// the wire cannot measure age.
	dedupKeep = 10 * time.Second
	// A transaction too large for one datagram arrives as chunks sent back to
	// back; one still incomplete after chunkTimeout lost a chunk.
	chunkTimeout = time.Second
	// maxChunked caps the chunked transactions each group holds at once. The non-vote
	// group carried 245 a second on 2026-10-13, each held up to 1.5 s.
	maxChunked = 4096
)

// sub is one joined group.
type sub struct {
	label  string
	source netip.Addr
	group  netip.AddrPort
	all    bool            // some selector takes every frame of the group
	filter []txfeed.Pubkey // otherwise, keep transactions invoking one of these
	frames uint64
	// chunks is this group's own: a reassembler shared across groups would
	// complete a transaction on one group, filter it out there, and then
	// discard its chunks from a group whose filter keeps it.
	chunks *txfeed.Reassembler
}

// frame parses one datagram from s. whole is false for a chunk of a
// transaction not yet complete.
func (s *sub) frame(b []byte, at time.Time) (f txfeed.Frame, whole bool, err error) {
	if f, err = txfeed.ParseFrame(b); err != nil {
		return f, false, err
	}
	f, whole = s.chunks.Add(f, at)
	return f, whole, nil
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
		subs = append(subs, &sub{label: label, source: source, group: group, chunks: txfeed.NewReassembler(chunkTimeout, maxChunked)})
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

// footerLine is one timed block footer (-footers).
type footerLine struct {
	Slot          uint64  `json:"slot"`
	BankHash      string  `json:"bank_hash"`
	Agent         string  `json:"agent"`
	ProducerNs    uint64  `json:"producer_ns"`
	RecvNs        int64   `json:"recv_ns"`
	LatencyMs     float64 `json:"latency_ms"` // recv_ns minus producer_ns
	Recovered     bool    `json:"recovered"`
	SendTsUs      uint64  `json:"send_ts_us"` // of the frame that completed the footer
	ClockSource   string  `json:"clock_source"`
	ClockOffsetUs float64 `json:"clock_offset_us"` // this host's clock minus clock_source's
}

// footerLine is ft's line, with this host's clock as -clock-source and
// -clock-offset give it.
func (c *config) footerLine(ft txfeed.FooterTime) footerLine {
	return footerLine{Slot: ft.Slot, BankHash: txfeed.Base58Encode(ft.BankHash[:]), Agent: ft.UserAgent,
		ProducerNs: ft.ProducerTimeNanos, RecvNs: ft.At.UnixNano(), LatencyMs: float64(ft.Latency()) / 1e6,
		Recovered: ft.Recovered, SendTsUs: ft.ShredTs, ClockSource: c.clockSource, ClockOffsetUs: float64(c.clockOffset) / 1e3}
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

// config is a parsed command line.
type config struct {
	subs           []*sub
	iface          netip.Addr              // -iface-ip; unset with -relay and no -iface-ip
	ifi            *net.Interface          // the interface holding iface, for a relayed join
	relay          *net.UDPAddr            // -relay; nil for native joins only
	listen         netip.AddrPort          // -listen; unset when joining groups
	channel        map[txfeed.Channel]bool // -channel, the one channel every transaction must match; nil for no check
	verify, asJSON bool
	limit          uint64
	duration       time.Duration
	footers        bool          // -footers: time block footers instead of printing transactions
	clockSource    string        // -clock-source, recorded on each footer line
	clockOffset    time.Duration // -clock-offset, this host's clock minus clockSource's: recorded on each footer line, not applied

	mu       sync.Mutex
	conns    []*amt.ManagedConn // relayed joins, left at exit
	stopping atomic.Bool        // set by leave, so a closed join's read error is not fatal
}

func parse(fs *flag.FlagSet, args []string) (*config, error) {
	c := &config{}
	var named, programs, raw multiFlag
	fs.Var(&named, "named", "NAME of a default named program to subscribe to; repeatable")
	fs.Var(&programs, "program", "BASE58 program to subscribe to, through its bucket group; repeatable")
	fs.Var(&raw, "ssm", "SOURCE@GROUP:PORT to join unfiltered; repeatable")
	fs.Func("relay", "AMT relay IP[:PORT], port 2268 by default: join each group natively first, then through an AMT tunnel to the relay "+
		"if no native traffic arrives within the probe window ("+amt.MinUsefulProbeWindow.String()+"); makes -iface-ip optional", func(s string) error {
		if c.relay != nil {
			return errors.New("given twice")
		}
		a, err := amtrelay.Parse(s)
		if err != nil {
			return err
		}
		c.relay = &a
		return nil
	})
	fs.Func("listen", "loopback ADDR:PORT to read frames from instead of joining any group: the hand-off from amt-verify --forward", func(s string) error {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return err
		}
		// Loopback only, like --forward: the socket is a hand-off on this host,
		// not a port open to the network.
		if !ap.Addr().IsLoopback() {
			return fmt.Errorf("%s is not a loopback address", ap.Addr())
		}
		c.listen = ap
		return nil
	})
	fs.Func("channel", "KIND:BASE58 channel, KIND program or account, that every transaction must match; one that does not is "+
		"counted as nonmatching, not printed, and makes the exit status 1", func(s string) error {
		if c.channel != nil {
			return errors.New("given twice")
		}
		ch, err := txfeed.ParseChannel(s)
		if err != nil {
			return err
		}
		c.channel = map[txfeed.Channel]bool{ch: true}
		return nil
	})
	var (
		source   = fs.String("source", "69.25.95.57", "source of the partition groups: the shred-txfeed host")
		base     = fs.String("group-base", "232.0.3.0", "partition group base")
		port     = fs.Int("port", 5003, "partition group port")
		ifaceIP  = fs.String("iface-ip", "", "local IP address on the interface to join on; optional with -relay")
		nonvote  = fs.Bool("nonvote", false, "subscribe to non-vote transactions")
		verify   = fs.Bool("verify", false, "verify each transaction's ed25519 signatures")
		asJSON   = fs.Bool("json", false, "print JSON lines")
		limit    = fs.Uint64("n", 0, "exit after this many transactions, or footers with -footers; 0 for no limit")
		duration = fs.Duration("duration", 0, "exit after this long; 0 for no limit")
		footers  = fs.Bool("footers", false, "time Alpenglow block footers on the shred union, joined with -ssm or read from -listen, "+
			"and print a JSON line a block instead of transactions")
		clockSrc = fs.String("clock-source", "", "required with -footers: this host's time source, such as 'systemd-timesyncd time.cloudflare.com'; "+
			"recorded on each line")
		clockOff = fs.Duration("clock-offset", 0, "required with -footers: this host's clock minus -clock-source's, positive when this host is ahead: "+
			"timedatectl timesync-status's Offset negated, so its -190us is 190us. Recorded on each line as clock_offset_us, not applied")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage of txfeed-sub:

  txfeed-sub -iface-ip 10.0.0.5 -nonvote                  native joins: Linux, on a network carrying the feed
  txfeed-sub -relay 69.25.95.128 -named jupiter-v6 -json  anywhere: native first, else through the AMT relay
  txfeed-sub -listen 127.0.0.1:15003 -channel program:B58  frames handed off by amt-verify --forward 127.0.0.1:15003
  txfeed-sub -footers -relay 69.25.95.128 -ssm 69.25.95.57@232.0.0.2:5001 -clock-source SRC -clock-offset D
                                                          block footer latency on the shred union

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	c.verify, c.asJSON, c.limit, c.duration = *verify, *asJSON, *limit, *duration
	c.footers, c.clockSource, c.clockOffset = *footers, *clockSrc, *clockOff
	if c.footers && (*nonvote || len(named)+len(programs) > 0 || c.channel != nil || c.verify) {
		return nil, errors.New("-footers reads the shred union from -ssm or -listen: give no -nonvote, -named, -program, -channel or -verify with it")
	}
	offset := false // -clock-offset given: a zero then is measured, not a default
	fs.Visit(func(f *flag.Flag) { offset = offset || f.Name == "clock-offset" })
	if c.footers && (strings.TrimSpace(c.clockSource) == "" || !offset) {
		return nil, errors.New("-footers needs -clock-source and -clock-offset, so that no line reads as a measured zero offset")
	}

	if c.listen.IsValid() {
		if c.relay != nil || *ifaceIP != "" || *nonvote || len(named)+len(programs)+len(raw) > 0 {
			return nil, errors.New("-listen joins nothing: give no -relay, -iface-ip or group selector with it")
		}
		c.subs = []*sub{{label: "listen", group: c.listen, all: true, chunks: txfeed.NewReassembler(chunkTimeout, maxChunked)}}
		return c, nil
	}

	if c.relay == nil && runtime.GOOS != "linux" {
		return nil, errors.New("give -relay: a native join needs Linux")
	}
	if c.relay == nil || *ifaceIP != "" {
		iface, err := netip.ParseAddr(*ifaceIP)
		if err != nil {
			return nil, fmt.Errorf("-iface-ip: want a local IP address; got %q", *ifaceIP)
		}
		c.iface = iface
	}
	if c.relay != nil && c.iface.IsValid() {
		ifi, err := txfeed.InterfaceWith(c.iface)
		if err != nil {
			return nil, fmt.Errorf("-iface-ip: %v", err)
		}
		c.ifi = ifi
	}
	src, err := netip.ParseAddr(*source)
	if err != nil {
		return nil, fmt.Errorf("-source: %v", err)
	}
	b, err := netip.ParseAddr(*base)
	if err != nil {
		return nil, fmt.Errorf("-group-base: %v", err)
	}
	// Every partition offset is in range, so a group fails only on its base.
	if _, err := txfeed.Group(b, 0); err != nil && (*nonvote || len(named) > 0 || len(programs) > 0) {
		return nil, fmt.Errorf("-group-base: %v", err)
	}
	group := func(off int) netip.AddrPort {
		g, _ := txfeed.Group(b, off)
		return netip.AddrPortFrom(g, uint16(*port))
	}

	if *nonvote {
		c.subs = join(c.subs, "nonvote", src, group(txfeed.PartNonVote), nil)
	}
	for _, name := range named {
		i := slices.IndexFunc(txfeed.DefaultPrograms, func(n txfeed.Named) bool { return n.Name == name })
		if i < 0 {
			return nil, fmt.Errorf("-named %q: not a default program", name)
		}
		c.subs = join(c.subs, name, src, group(txfeed.PartNamedBase+i), nil)
	}
	for _, s := range programs {
		p, err := txfeed.ParsePubkey(s)
		if err != nil {
			return nil, fmt.Errorf("-program: %v", err)
		}
		b := txfeed.Bucket(p)
		c.subs = join(c.subs, fmt.Sprintf("bucket-%d", b), src, group(txfeed.PartBucketBase+b), &p)
	}
	for _, s := range raw {
		rs, rg, err := txfeed.ParseSSM(s)
		if err != nil {
			return nil, err
		}
		c.subs = join(c.subs, "ssm", rs, rg, nil)
	}
	if len(c.subs) == 0 {
		return nil, errors.New("nothing to subscribe to: give -nonvote, -named, -program, -ssm or -listen")
	}
	return c, nil
}

// matches reports whether tx passes the -channel check: it matches the channel,
// or no -channel was given.
func (c *config) matches(tx txfeed.Tx) bool {
	return c.channel == nil || len(txfeed.MatchChannels(tx, c.channel)) > 0
}

// openRelayed opens a relayed join. It and listenNative, the native join, are
// the two ways to join a group; a test swaps them.
var openRelayed = (*amt.ManagedConn).Open

// open joins s and returns a function that reads its next datagram, and how it
// joined. With -listen it reads the loopback socket and joins nothing. Without
// -relay it is the native txfeed.ListenSSM join. With -relay it
// is an amt.ManagedConn, the opener behind blockcast-shreds' ssm:// feeds.
// ManagedConns to one relay share its RelayManager, so every group rides one
// AMT tunnel.
func (c *config) open(s *sub) (read func([]byte) (int, error), via string, err error) {
	if c.listen.IsValid() {
		uc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(c.listen))
		if err != nil {
			return nil, "", err
		}
		_ = uc.SetReadBuffer(rcvbuf)
		return func(b []byte) (int, error) { n, _, err := uc.ReadFromUDPAddrPort(b); return n, err }, "on " + uc.LocalAddr().String(), nil
	}
	if c.relay == nil {
		uc, err := listenNative(s.source, s.group.Addr(), int(s.group.Port()), c.iface, rcvbuf)
		if err != nil {
			return nil, "", err
		}
		return func(b []byte) (int, error) { n, _, err := uc.ReadFromUDPAddrPort(b); return n, err }, "via " + c.iface.String(), nil
	}
	mc := &amt.ManagedConn{SrcAddr: s.source, GroupAddr: s.group.Addr(), GroupPort: s.group.Port(),
		RelayAddr: *c.relay, Mode: amt.AMTModeAuto, IFace: c.ifi, RcvBufBytes: rcvbuf}
	if err := openRelayed(mc); err != nil {
		_ = mc.Close()
		return nil, "", err
	}
	c.mu.Lock()
	c.conns = append(c.conns, mc)
	c.mu.Unlock()
	via = "natively"
	if mc.IsUsingTunnel() {
		via = "through AMT relay " + c.relay.String()
	}
	return func(b []byte) (int, error) { n, _, err := mc.ReadFrom(b); return n, err }, via, nil
}

// leave closes the relayed joins, which sends each its leave, and waits out
// the leave retransmissions: a lost leave keeps the relay streaming to this
// host for minutes after it exits (BLO-45585).
//
// ponytail: a join still opening at exit, inside its probe window or the relay
// handshake, sends no leave and the relay times it out. Wait for in-flight
// opens, as blockcast-shreds does, if that matters.
func (c *config) leave() {
	c.stopping.Store(true)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.conns) == 0 {
		return
	}
	for _, mc := range c.conns {
		_ = mc.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = amt.WaitRelayLeaves(ctx)
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := parse(flag.CommandLine, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	names := map[txfeed.Pubkey]string{}
	for _, n := range txfeed.DefaultPrograms {
		names[n.ID] = n.Name
	}

	ch := make(chan packet, 1<<14)
	start := func(s *sub) {
		read, via, err := cfg.open(s)
		if err != nil {
			log.Fatalf("%s: %v", s.label, err)
		}
		if cfg.listen.IsValid() {
			log.Printf("listening %s", via)
		} else {
			log.Printf("joined %s: (S=%s, G=%s) %s", s.label, s.source, s.group, via)
		}
		go func() {
			buf := make([]byte, maxDatagram)
			for {
				n, err := read(buf)
				if err != nil {
					if cfg.stopping.Load() {
						return
					}
					log.Fatalf("%s: read error: %v", s.label, err) // exit rather than drop a group silently
				}
				ch <- packet{s: s, b: bytes.Clone(buf[:n]), at: time.Now()}
			}
		}()
	}
	var nonmatching uint64 // transactions failing the -channel check
	defer func() {
		if nonmatching > 0 {
			os.Exit(1) // last, after the summary and the leaves
		}
	}()
	for ch := range cfg.channel {
		log.Printf("checking every transaction against channel %s, group %s", ch, txfeed.ChannelGroup(ch.Kind, ch.Key))
	}
	defer cfg.leave() // after the summary below: it can wait 2s on the relay
	for _, s := range cfg.subs {
		if cfg.relay != nil {
			// Relayed joins open at once: each can spend a probe window on its
			// native join before it tunnels, and in turn the windows would add.
			go start(s)
		} else {
			start(s)
		}
	}

	var footers *txfeed.FooterTimes
	if cfg.footers {
		footers = txfeed.NewFooterTimes()
	}
	var printed, dups, filtered, bad, verOK, verBad uint64
	var lat []float64 // ponytail: keeps every latency for the percentiles; a histogram if runs get long
	type slotSeen struct {
		last time.Time
		keys map[uint64]bool // batch start<<16 | index
	}
	seen := map[uint64]*slotSeen{}
	var sweep time.Time // when the next eviction pass runs
	enc := json.NewEncoder(os.Stdout)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	var deadline <-chan time.Time
	if cfg.duration > 0 {
		deadline = time.After(cfg.duration)
	}

	defer func() {
		slices.Sort(lat)
		for _, s := range cfg.subs {
			log.Printf("group %s %s: frames=%d", s.label, s.group, s.frames)
		}
		if footers != nil {
			s := footers.Stats()
			log.Printf("footers=%d frames=%d dups=%d bad=%d sets_recovered=%d latency_ms p50=%.1f p95=%.1f p99=%.1f",
				printed, s.Frames, s.Dups, s.Bad, s.SetsRecovered, percentile(lat, 50), percentile(lat, 95), percentile(lat, 99))
			return
		}
		log.Printf("printed=%d dups=%d filtered=%d bad=%d verify_ok=%d verify_bad=%d latency_ms p50=%.1f p90=%.1f p99=%.1f",
			printed, dups, filtered, bad, verOK, verBad, percentile(lat, 50), percentile(lat, 90), percentile(lat, 99))
		if cfg.channel != nil {
			log.Printf("channel check: matched=%d nonmatching=%d", printed, nonmatching)
		}
		var c txfeed.ReassemblyStats
		for _, s := range cfg.subs {
			g := s.chunks.Stats()
			c.Chunks += g.Chunks
			c.Txs += g.Txs
			c.Dups += g.Dups
			c.Inconsistent += g.Inconsistent
			c.Timeouts += g.Timeouts
			c.Overflow += g.Overflow
		}
		log.Printf("chunks=%d reassembled=%d chunk_dups=%d inconsistent=%d timeouts=%d overflow=%d",
			c.Chunks, c.Txs, c.Dups, c.Inconsistent, c.Timeouts, c.Overflow)
	}()
	for cfg.limit == 0 || printed < cfg.limit {
		var p packet
		select {
		case p = <-ch:
		case <-deadline:
			return
		case <-sig:
			return
		}
		p.s.frames++
		if footers != nil {
			for _, ft := range footers.Add(p.b, p.at) {
				if printed == cfg.limit && cfg.limit > 0 {
					break // -n: one frame can complete two footers
				}
				l := cfg.footerLine(ft)
				lat = append(lat, l.LatencyMs)
				printed++
				_ = enc.Encode(l)
			}
			continue
		}
		f, whole, err := p.s.frame(p.b, p.at)
		if err != nil {
			bad++
			continue
		}
		if !whole {
			continue // a chunk of a transaction not yet complete
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

		if !p.at.Before(sweep) {
			for s, ss := range seen {
				if p.at.Sub(ss.last) > dedupKeep {
					delete(seen, s)
				}
			}
			sweep = p.at.Add(dedupKeep / 2)
		}
		ss := seen[f.Slot]
		if ss == nil {
			// ponytail: no cap on slots; a flood of forged slots holds its rate
			// times dedupKeep entries. Cap it as txfeed.Assembler does if the
			// subscriber outgrows a demo.
			ss = &slotSeen{keys: map[uint64]bool{}}
			seen[f.Slot] = ss
		}
		ss.last = p.at
		k := uint64(f.BatchStart)<<16 | uint64(f.Index)
		if ss.keys[k] {
			dups++
			continue
		}
		ss.keys[k] = true
		if !cfg.matches(tx) {
			if nonmatching++; nonmatching == 1 { // the first only: a wrong channel would flood the log
				log.Printf("nonmatching transaction: slot=%d sig=%s", f.Slot, txfeed.Base58Encode(tx.Sig))
			}
			continue
		}

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
		if cfg.verify {
			if ok, err := txfeed.VerifyTx(f.Tx); ok && err == nil {
				l.Verify, verOK = "ok", verOK+1
			} else {
				l.Verify, verBad = "bad", verBad+1
			}
		}
		printed++
		if cfg.asJSON {
			_ = enc.Encode(l)
			continue
		}
		v := ""
		if cfg.verify {
			v = " verify=" + l.Verify
		}
		fmt.Printf("slot=%d batch=%d:%d vote=%t sig=%s programs=%s latency_ms=%.1f%s\n",
			l.Slot, l.Batch, l.Index, l.Vote, l.Sig, strings.Join(l.Programs, ","), l.LatencyMs, v)
	}
}
