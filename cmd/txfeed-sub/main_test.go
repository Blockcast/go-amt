package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	amt "github.com/blockcast/go-amt"
	"github.com/blockcast/go-amt/txfeed"
)

// No test here joins multicast or contacts a relay: listenNative and
// openRelayed are swapped for fakes. TestListenReadsLoopback binds a loopback
// socket, as -listen does.

func parseArgs(args ...string) (*config, error) {
	fs := flag.NewFlagSet("txfeed-sub", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return parse(fs, args)
}

// swapOpeners replaces both join paths for the test.
func swapOpeners(t *testing.T, native func(netip.Addr, netip.Addr, int, netip.Addr, int) (*net.UDPConn, error), relayed func(*amt.ManagedConn) error) {
	n, r := listenNative, openRelayed
	listenNative, openRelayed = native, relayed
	t.Cleanup(func() { listenNative, openRelayed = n, r })
}

func TestRelayFlag(t *testing.T) {
	for args, want := range map[string]string{
		"-relay 69.25.95.128 -nonvote":      "69.25.95.128:2268",
		"-relay 69.25.95.128:4000 -nonvote": "69.25.95.128:4000",
	} {
		c, err := parseArgs(strings.Fields(args)...)
		if err != nil || c.relay == nil || c.relay.String() != want {
			t.Errorf("parse(%q): relay %v, %v; want %s", args, c.relay, err, want)
			continue
		}
		if c.iface.IsValid() || c.ifi != nil {
			t.Errorf("parse(%q): -relay without -iface-ip must join on the default interface", args)
		}
	}
	if c, err := parseArgs("-relay", "69.25.95.128", "-iface-ip", "127.0.0.1", "-nonvote"); err != nil || c.ifi == nil {
		t.Errorf("-relay with -iface-ip must join on the interface holding it: %v", err)
	}

	// Each must fail loudly, not quietly drop the AMT fallback.
	for _, args := range [][]string{
		{"-nonvote", "-relay"},                                 // no value
		{"-relay=", "-nonvote"},                                // an unset ${RELAY}
		{"-relay", ":2268", "-nonvote"},                        // no host, which ManagedConn reads as no relay
		{"-relay", "69.25.95.128:", "-nonvote"},                // empty port
		{"-relay", "69.25.95.128:0", "-nonvote"},               // port 0
		{"-relay", "69.25.95.128:x", "-nonvote"},               // not a port
		{"-relay", "[::1]:2268", "-nonvote"},                   // not IPv4
		{"-relay", "1.1.1.1", "-relay", "2.2.2.2", "-nonvote"}, // two relays
	} {
		if c, err := parseArgs(args...); err == nil {
			t.Errorf("parse(%q) accepted, relay %v", args, c.relay)
		}
	}

	want := "-iface-ip"
	if runtime.GOOS != "linux" {
		want = "-relay"
	}
	if _, err := parseArgs("-nonvote"); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("parse(-nonvote) = %v; without -relay it must ask for %s", err, want)
	}
	// The vote group 232.0.3.2 is retired (BLO-22812): -vote selects nothing.
	if _, err := parseArgs("-relay", "69.25.95.128", "-vote"); err == nil {
		t.Error("-vote accepted")
	}
	// The relay example in the docs names jupiter-v6; plain jupiter is not a
	// default program.
	if _, err := parseArgs("-relay", "69.25.95.128", "-named", "jupiter"); err == nil {
		t.Error("-named jupiter accepted")
	}
}

// TestRelayRoutesEveryGroup: with -relay, every selector's group goes through
// the native-first ManagedConn, and none through the native-only join.
func TestRelayRoutesEveryGroup(t *testing.T) {
	jup := txfeed.DefaultPrograms[5]
	c, err := parseArgs("-relay", "69.25.95.128", "-nonvote", "-named", jup.Name,
		"-program", jup.ID.String(), "-ssm", "69.25.95.57@232.0.3.200:5003")
	if err != nil {
		t.Fatal(err)
	}
	var opened []*amt.ManagedConn
	swapOpeners(t, func(netip.Addr, netip.Addr, int, netip.Addr, int) (*net.UDPConn, error) {
		t.Error("a relayed group went to the native-only join")
		return nil, errors.New("native")
	}, func(mc *amt.ManagedConn) error {
		opened = append(opened, mc)
		return nil
	})
	for _, s := range c.subs {
		if _, _, err := c.open(s); err != nil {
			t.Fatalf("%s: %v", s.label, err)
		}
	}

	want := []string{"232.0.3.1:5003", "232.0.3.21:5003",
		fmt.Sprintf("232.0.3.%d:5003", txfeed.PartBucketBase+txfeed.Bucket(jup.ID)), "232.0.3.200:5003"}
	if len(opened) != len(want) {
		t.Fatalf("opened %d relayed joins, want %d", len(opened), len(want))
	}
	for i, mc := range opened {
		if g := netip.AddrPortFrom(mc.GroupAddr, mc.GroupPort).String(); g != want[i] || mc.SrcAddr.String() != "69.25.95.57" {
			t.Errorf("join %d: (S=%s, G=%s), want (S=69.25.95.57, G=%s)", i, mc.SrcAddr, g, want[i])
		}
		// AMTModeNative would never tunnel; AMTModeTunnel would skip the
		// native join that works on Blockcast's network.
		if mc.Mode != amt.AMTModeAuto || mc.RelayAddr.String() != "69.25.95.128:2268" || mc.RcvBufBytes != rcvbuf {
			t.Errorf("join %d: mode %v relay %v rcvbuf %d, want auto via 69.25.95.128:2268 with %d", i, mc.Mode, &mc.RelayAddr, mc.RcvBufBytes, rcvbuf)
		}
	}
	if len(c.conns) != len(want) {
		t.Errorf("%d of %d relayed joins kept to leave at exit", len(c.conns), len(want))
	}
	c.leave() // closes unopened conns; no relay manager exists, so nothing is sent
}

// TestNoRelayStaysNative: without -relay a group is the txfeed.ListenSSM join,
// with the 4 MiB buffer, as before -relay existed.
func TestNoRelayStaysNative(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native joins are Linux-only")
	}
	c, err := parseArgs("-iface-ip", "127.0.0.1", "-nonvote")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	stop := errors.New("stop")
	swapOpeners(t, func(source, group netip.Addr, port int, iface netip.Addr, buf int) (*net.UDPConn, error) {
		got = fmt.Sprint(source, group, port, iface, buf)
		return nil, stop
	}, func(*amt.ManagedConn) error {
		t.Error("a native-only group went to the relayed join")
		return nil
	})
	if _, _, err := c.open(c.subs[0]); !errors.Is(err, stop) {
		t.Fatalf("open = %v", err)
	}
	if want := "69.25.95.57 232.0.3.1 5003 127.0.0.1 4194304"; got != want {
		t.Errorf("native join (S G port iface rcvbuf) = %s, want %s", got, want)
	}
}

func TestJoinFiltersOnlyProgramBuckets(t *testing.T) {
	src := netip.MustParseAddr("69.25.95.57")
	bucket := netip.MustParseAddrPort("232.0.3.72:5003")
	jup, token := txfeed.DefaultPrograms[5].ID, txfeed.DefaultPrograms[0].ID
	subs := join(nil, "bucket", src, bucket, &jup)
	subs = join(subs, "nonvote", src, netip.MustParseAddrPort("232.0.3.1:5003"), nil)
	if len(subs) != 2 || !subs[0].keeps(txfeed.Tx{Programs: []txfeed.Pubkey{token, jup}}) || subs[0].keeps(txfeed.Tx{Programs: []txfeed.Pubkey{token}}) {
		t.Fatal("a -program group must keep only transactions invoking the program")
	}
	if !subs[1].keeps(txfeed.Tx{}) {
		t.Error("a -nonvote group must keep every transaction")
	}
	// A raw join of the same channel takes every frame of it.
	if subs = join(subs, "ssm", src, bucket, nil); len(subs) != 2 || !subs[0].keeps(txfeed.Tx{Programs: []txfeed.Pubkey{token}}) {
		t.Error("joining a filtered group unfiltered must widen it, not join it twice")
	}
}

// A chunked transaction reaches every group that carries it, each with its own
// filter: completing it on one group must not mark it done for another
// (Ally on go-amt#179).
func TestGroupsReassembleIndependently(t *testing.T) {
	src := netip.MustParseAddr("69.25.95.57")
	jup := txfeed.DefaultPrograms[5].ID
	subs := join(nil, "nonvote", src, netip.MustParseAddrPort("232.0.3.1:5003"), &jup)
	subs = join(subs, "jupiter", src, netip.MustParseAddrPort("232.0.3.21:5003"), nil)
	f := txfeed.Frame{Slot: 456620543, BatchStart: 7, Index: 3, Tx: make([]byte, 3000)}
	at := time.Unix(1785000000, 0)
	for _, s := range subs { // publish sends every chunk to the non-vote group first
		var got int
		for _, d := range txfeed.Datagrams(f) {
			g, whole, err := s.frame(d, at)
			if err != nil {
				t.Fatalf("%s: %v", s.label, err)
			}
			if whole {
				got++
				if len(g.Tx) != len(f.Tx) {
					t.Errorf("%s: reassembled %d bytes, want %d", s.label, len(g.Tx), len(f.Tx))
				}
			}
		}
		if got != 1 {
			t.Errorf("%s: %d whole transactions, want 1", s.label, got)
		}
	}
}

func TestPercentile(t *testing.T) {
	l := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for p, want := range map[int]float64{0: 1, 50: 6, 90: 10, 99: 10} {
		if got := percentile(l, p); got != want {
			t.Errorf("percentile(1..10, %d) = %v, want %v", p, got, want)
		}
	}
	if percentile(nil, 50) != 0 {
		t.Error("the percentile of nothing is 0")
	}
}

func TestListenFlag(t *testing.T) {
	jup := txfeed.DefaultPrograms[5].ID
	c, err := parseArgs("-listen", "127.0.0.1:15003", "-channel", "program:"+jup.String())
	if err != nil {
		t.Fatal(err)
	}
	if c.listen.String() != "127.0.0.1:15003" || len(c.subs) != 1 || !c.subs[0].all || !c.channel[txfeed.Channel{Kind: txfeed.ChannelProgram, Key: jup}] {
		t.Errorf("parse: listen %v, %d subs, channel %v; want one unfiltered sub on 127.0.0.1:15003 checked against Jupiter v6", c.listen, len(c.subs), c.channel)
	}
	// -listen alone needs no -iface-ip, which a native join does, and no -relay.
	if _, err := parseArgs("-listen", "[::1]:15003"); err != nil {
		t.Errorf("-listen [::1]:15003: %v", err)
	}

	for _, args := range [][]string{
		{"-listen", "10.0.0.5:15003"},              // not loopback: the hand-off never leaves the host
		{"-listen", "127.0.0.1"},                   // no port
		{"-listen", "127.0.0.1:15003", "-nonvote"}, // -listen joins nothing
		{"-listen", "127.0.0.1:15003", "-relay", "69.25.95.128"},
		{"-listen", "127.0.0.1:15003", "-iface-ip", "127.0.0.1"},
		{"-listen", "127.0.0.1:15003", "-channel", "vote:" + jup.String()}, // not a kind
		{"-listen", "127.0.0.1:15003", "-channel", "program:x"},            // not a key
		{"-listen", "127.0.0.1:15003", "-channel", "program:" + jup.String(), "-channel", "account:" + jup.String()},
	} {
		if c, err := parseArgs(args...); err == nil {
			t.Errorf("parse(%q) accepted, listen %v", args, c.listen)
		}
	}
}

func TestListenReadsLoopback(t *testing.T) {
	c, err := parseArgs("-listen", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	swapOpeners(t, func(netip.Addr, netip.Addr, int, netip.Addr, int) (*net.UDPConn, error) {
		t.Error("-listen joined a group natively")
		return nil, errors.New("native")
	}, func(*amt.ManagedConn) error {
		t.Error("-listen joined a group through a relay")
		return nil
	})
	read, via, err := c.open(c.subs[0])
	if err != nil {
		t.Fatal(err)
	}
	to, err := netip.ParseAddrPort(strings.TrimPrefix(via, "on "))
	if err != nil {
		t.Fatalf("via %q: %v", via, err)
	}
	uc, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if _, err := uc.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, maxDatagram)
	if n, err := read(b); err != nil || string(b[:n]) != "frame" {
		t.Errorf("read %q, %v; want the datagram sent to %s", b[:n], err, to)
	}
}

// The -channel check passes only transactions matching the channel; without
// -channel it passes all.
func TestChannelCheck(t *testing.T) {
	jup, token := txfeed.DefaultPrograms[5].ID, txfeed.DefaultPrograms[0].ID
	c, err := parseArgs("-listen", "127.0.0.1:15003", "-channel", "program:"+jup.String())
	if err != nil {
		t.Fatal(err)
	}
	if !c.matches(txfeed.Tx{Programs: []txfeed.Pubkey{token, jup}}) || c.matches(txfeed.Tx{Programs: []txfeed.Pubkey{token}}) {
		t.Error("a program channel must pass exactly the transactions invoking the program")
	}
	// Jupiter's key as a static account, not an invoked program, is an account
	// channel's match, never a program channel's.
	if c.matches(txfeed.Tx{Programs: []txfeed.Pubkey{token}, Keys: jup[:]}) {
		t.Error("a program channel passed a transaction that only lists the program as an account")
	}
	if c.channel = nil; !c.matches(txfeed.Tx{}) {
		t.Error("without -channel every transaction must pass")
	}
}

// -footers takes the shred union from -ssm or -listen, this host's clock as
// -clock-source and -clock-offset, and no selector or check made for
// transactions.
func TestFootersFlag(t *testing.T) {
	for _, args := range []string{
		"-footers -ssm 69.25.95.57@232.0.0.2:5001 -relay 69.25.95.128 -clock-source chrony -clock-offset=0s",
		"-footers -listen 127.0.0.1:15001 -clock-source systemd-timesyncd -clock-offset=190us",
	} {
		if c, err := parseArgs(strings.Fields(args)...); err != nil || !c.footers {
			t.Errorf("parse(%q): %v", args, err)
		}
	}
	c, err := parseArgs("-footers", "-listen", "127.0.0.1:15001", "-clock-source", "systemd-timesyncd 162.159.200.1", "-clock-offset=190us")
	if err != nil {
		t.Fatal(err)
	}
	if c.clockSource != "systemd-timesyncd 162.159.200.1" || c.clockOffset != 190*time.Microsecond {
		t.Errorf("clock %q %v; want the source and offset as given", c.clockSource, c.clockOffset)
	}
	jup := txfeed.DefaultPrograms[5]
	for _, args := range [][]string{
		{"-footers", "-relay", "69.25.95.128", "-nonvote"},
		{"-footers", "-relay", "69.25.95.128", "-named", jup.Name},
		{"-footers", "-relay", "69.25.95.128", "-program", jup.ID.String()},
		{"-footers", "-listen", "127.0.0.1:15001", "-channel", "program:" + jup.ID.String()},
		{"-footers", "-listen", "127.0.0.1:15001", "-verify"},
	} {
		if _, err := parseArgs(append(args, "-clock-source", "chrony", "-clock-offset=0s")...); err == nil {
			t.Errorf("parse(%q) accepted", args)
		}
	}
	// Unset, the clock would read as a measured zero offset.
	for _, args := range [][]string{
		{"-footers", "-listen", "127.0.0.1:15001"},
		{"-footers", "-listen", "127.0.0.1:15001", "-clock-offset=190us"},
		{"-footers", "-listen", "127.0.0.1:15001", "-clock-source", "chrony"},
		{"-footers", "-listen", "127.0.0.1:15001", "-clock-source=", "-clock-offset=190us"},
		{"-footers", "-listen", "127.0.0.1:15001", "-clock-source", " \t", "-clock-offset=190us"}, // blank: names no source
	} {
		if _, err := parseArgs(args...); err == nil {
			t.Errorf("parse(%q) accepted", args)
		}
	}
}

// A footer's line: latency_ms from the nanosecond clocks, this host's clock as
// given, under the names the lines are read by.
func TestFooterLine(t *testing.T) {
	c, err := parseArgs("-footers", "-listen", "127.0.0.1:15001", "-clock-source", "systemd-timesyncd time.cloudflare.com", "-clock-offset=190us")
	if err != nil {
		t.Fatal(err)
	}
	// Slot 460191482's footer in the 10-22 capture of txfeed's tests, read from
	// its own data shred, whose send_ts_us is ShredTs, and received here
	// 1.253567ms after that.
	hash, err := txfeed.ParsePubkey("2BLWnrUPqLvMHp3oqq9Y8xBpobR4tFqTwR41rb8DLzh4")
	if err != nil {
		t.Fatal(err)
	}
	ft := txfeed.FooterTime{Slot: 460191482, BankHash: hash, UserAgent: "agave/4.3.2 (src:013a4306; feat:c9ad34d2, client:JitoLabs)",
		ProducerTimeNanos: 1792705262401095514, At: time.Unix(0, 1792705262496234567), ShredTs: 1792705262494981}
	b, err := json.Marshal(c.footerLine(ft))
	want := `{"slot":460191482,"bank_hash":"2BLWnrUPqLvMHp3oqq9Y8xBpobR4tFqTwR41rb8DLzh4",` +
		`"agent":"agave/4.3.2 (src:013a4306; feat:c9ad34d2, client:JitoLabs)","producer_ns":1792705262401095514,` +
		`"recv_ns":1792705262496234567,"latency_ms":95.139053,"recovered":false,"send_ts_us":1792705262494981,` +
		`"clock_source":"systemd-timesyncd time.cloudflare.com","clock_offset_us":190}`
	if err != nil || string(b) != want {
		t.Errorf("line %s, %v; want %s", b, err, want)
	}
	if ft.Recovered = true; !c.footerLine(ft).Recovered {
		t.Error("a recovered footer's line reads recovered false")
	}
}
