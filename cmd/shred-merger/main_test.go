//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var t0 = time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

func TestDedupKeysOnFECSetAndLocalIndex(t *testing.T) {
	d := newDedup(25 * time.Second)
	for _, step := range []struct {
		name     string
		slot     uint64
		fec, idx uint32
		want     verdict
	}{
		{"first sighting", 100, 0, 5, emit},
		{"the same shred from the other listener", 100, 0, 5, duplicate},
		{"same local index, next FEC set: a different shred", 100, 32, 5, emit},
		{"same coordinates, next slot: a different shred", 101, 0, 5, emit},
		{"slot 0 is never emitted", 0, 0, 5, skip},
	} {
		if got := d.observe(t0, step.slot, step.fec, step.idx, 0); got != step.want {
			t.Errorf("%s: observe = %d, want %d", step.name, got, step.want)
		}
	}
}

func TestDedupForgetsASlotIdleForKeep(t *testing.T) {
	d := newDedup(25 * time.Second)
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }
	d.observe(at(0), 100, 0, 1, 0)
	if got := d.observe(at(20), 100, 0, 1, 0); got != duplicate {
		t.Fatalf("slot 100 inside keep: observe = %d, want duplicate", got)
	}
	// History runs from a slot's latest shred, not its first: 24s after the
	// latest, a sweep keeps it.
	d.observe(at(44), 300, 0, 1, 0)
	if _, kept := d.seen[100]; !kept {
		t.Fatal("slot 100 was swept 24s after its latest shred, inside keep")
	}
	// Sweeps run every keep/2. The next one, 37s after the latest shred,
	// forgets the slot, and its shreds are emitted again.
	d.observe(at(57), 300, 0, 2, 0)
	if _, kept := d.seen[100]; kept {
		t.Error("slot 100 sat idle past keep but its history was not swept")
	}
	if got := d.observe(at(57), 100, 0, 1, 0); got != emit {
		t.Errorf("slot 100 after its history was swept: observe = %d, want emit", got)
	}
	checkIDs(t, d)
}

// checkIDs checks the stats line's dedup_ids against the history held, each
// version of a shred counted.
func checkIDs(t *testing.T, d *dedup) {
	t.Helper()
	n := 0
	for _, ss := range d.seen {
		n += len(ss.ids) + len(ss.alt)
	}
	if d.ids != n {
		t.Errorf("dedup_ids = %d, but the slots hold %d", d.ids, n)
	}
}

// A slot can come in two versions, as at the Alpenglow switch. Each version of
// a shred is emitted once, so the union carries every shred of each version it
// received, and a TVU fed from it is not left with a set mixing the two.
func TestDedupKeepsEachVersionOfAShred(t *testing.T) {
	d := newDedup(25 * time.Second)
	for _, step := range []struct {
		name string
		ver  uint64
		want verdict
	}{
		{"first version", 0xa, emit},
		{"the first version from the other listener", 0xa, duplicate},
		{"a second version", 0xb, emitOther},
		{"the second version again", 0xb, duplicate},
		{"a third version", 0xc, emitOther},
		{"a version-3 frame, which has no signature", 0, duplicate},
	} {
		if got := d.observe(t0, 100, 0, 5, step.ver); got != step.want {
			t.Errorf("%s: observe = %d, want %d", step.name, got, step.want)
		}
	}
	checkIDs(t, d)
}

// A version-3 frame has no signature, so it matches every version: a shred is
// emitted once while one input is on wire version 3 and the other on 4.
func TestDedupV3FrameMatchesAnyVersion(t *testing.T) {
	d := newDedup(25 * time.Second)
	if got := d.observe(t0, 100, 0, 5, 0); got != emit {
		t.Errorf("version-3 frame first: observe = %d, want emit", got)
	}
	for _, ver := range []uint64{0, 0xa, 0xb} {
		if got := d.observe(t0, 100, 0, 5, ver); got != duplicate {
			t.Errorf("version %#x after a version-3 frame: observe = %d, want duplicate", ver, got)
		}
	}
	checkIDs(t, d)
}

// The forwarders check no signature, so forged versions of one shred cost
// nothing and keep its slot fresh. Unless the slot's cap counts them, they pass
// it, and past maxDedupIDs every new id forgets a real slot instead.
func TestDedupBoundsVersionsOfOneShred(t *testing.T) {
	d := newDedup(25 * time.Second)
	for v := range uint64(maxSlotIDs + 10) {
		d.observe(t0, 100, 0, 0, v+1)
	}
	if ss := d.seen[100]; len(ss.ids)+len(ss.alt) > maxSlotIDs || d.ids > maxSlotIDs {
		t.Errorf("slot 100 holds %d ids, %d in all; want at most %d", len(ss.ids)+len(ss.alt), d.ids, maxSlotIDs)
	}
	if d.forgotten != 1 {
		t.Errorf("forgotten = %d, want 1: the slot started over once", d.forgotten)
	}
	checkIDs(t, d)
}

// A later version that starts its slot over becomes that shred's first
// version, since the reset forgot the version it followed. Its copy from the
// other listener is then a duplicate, not a second emit of the same version.
func TestDedupSlotResetByALaterVersion(t *testing.T) {
	d := newDedup(25 * time.Second)
	for v := uint64(1); v <= maxSlotIDs; v++ {
		d.observe(t0, 100, 0, 0, v)
	}
	if v := d.observe(t0, 100, 0, 0, maxSlotIDs+1); v != emit || d.forgotten != 1 {
		t.Errorf("version past the cap: %v, forgotten=%d; want emit, 1", v, d.forgotten)
	}
	if v := d.observe(t0, 100, 0, 0, maxSlotIDs+1); v != duplicate {
		t.Errorf("that version again: %v; want duplicate", v)
	}
	checkIDs(t, d)
}

// A slot forgotten for idling gives back its later versions too, or dedup_ids
// climbs with every slot that had one.
func TestDedupDropCountsLaterVersions(t *testing.T) {
	d := newDedup(25 * time.Second)
	d.observe(t0, 100, 0, 5, 0xa)
	d.observe(t0, 100, 0, 5, 0xb)
	d.observe(t0.Add(time.Minute), 101, 0, 5, 0xa) // sweeps slot 100, idle past keep
	if _, kept := d.seen[100]; kept || d.ids != 1 {
		t.Errorf("after slot 100 was swept: kept=%v, dedup_ids=%d; want false, 1", kept, d.ids)
	}
	checkIDs(t, d)
}

func TestFrameVersionReadsTheLeaderSignature(t *testing.T) {
	f := v4Frame(7, 3, false)
	binary.LittleEndian.PutUint64(f[hdrLen:], 0x0123456789abcdef) // the signature's first 8 bytes
	for name, b := range map[string][]byte{"a version-4 frame": f, "a version-4 frame cut after those 8 bytes": f[:hdrLen+8]} {
		if got := frameVersion(b); got != 0x0123456789abcdef {
			t.Errorf("frameVersion(%s) = %#x, want 0x0123456789abcdef", name, got)
		}
	}
	v3, _ := asV3(f) // its body starts with the variant byte, not 0
	for name, b := range map[string][]byte{"a version-3 frame": v3, "a bodyless version-4 frame": f[:hdrLen]} {
		if got := frameVersion(b); got != 0 {
			t.Errorf("frameVersion(%s) = %#x, want 0", name, got)
		}
	}
}

// One forged far-future slot used to move a slot window past every real slot
// and stop the union for good (Ally, go-amt#144 comment 6066225989). History
// by arrival time has no window to move.
func TestDedupIgnoresTheSlotNumberOfAForgedShred(t *testing.T) {
	d := newDedup(25 * time.Second)
	d.observe(t0, 100, 0, 1, 0)
	for _, forged := range []uint64{1 << 62, 1<<64 - 1, 1} {
		if got := d.observe(t0, forged, 0, 1, 0); got != emit {
			t.Errorf("forged slot %d: observe = %d, want emit (the merger does not authenticate)", forged, got)
		}
	}
	for i := uint32(2); i < 52; i++ {
		if got := d.observe(t0.Add(time.Duration(i)*time.Millisecond), 100, 0, i, 0); got != emit {
			t.Fatalf("real shred %d after forged slots: observe = %d, want emit", i, got)
		}
	}
	if got := d.observe(t0.Add(time.Second), 100, 0, 1, 0); got != duplicate {
		t.Errorf("real slot's history after forged slots: observe = %d, want duplicate", got)
	}
}

func TestDedupBoundsHistoryUnderAFloodOfSlots(t *testing.T) {
	d := newDedup(25 * time.Second)
	at := t0
	d.observe(at, 100, 0, 1, 0)
	for s := uint64(1 << 40); s < 1<<40+3*maxDedupSlots; s++ {
		at = at.Add(time.Microsecond)
		d.observe(at, s, 0, 1, 0)
		d.observe(at, 100, 0, uint32(s), 0) // the real slot keeps receiving
	}
	if len(d.seen) > maxDedupSlots {
		t.Errorf("dedup holds %d slots, want at most %d", len(d.seen), maxDedupSlots)
	}
	if got := d.observe(at, 100, 0, 1, 0); got != duplicate {
		t.Errorf("the slot being received lost its history in the flood: observe = %d, want duplicate", got)
	}
	// Slot 100 and the first 255 forged slots fill the cap; each later forged
	// slot forgets one.
	if want := uint64(3*maxDedupSlots - (maxDedupSlots - 1)); d.forgotten != want {
		t.Errorf("forgotten = %d, want %d", d.forgotten, want)
	}
	checkIDs(t, d)
}

// A flood of distinct (fec_set_index, local_index) pairs on one slot number
// keeps that slot fresh, so only a cap on the slot's own history bounds it
// (Ally, go-amt#144 review 5464269530).
func TestDedupBoundsTheHistoryOfOneSlot(t *testing.T) {
	d := newDedup(25 * time.Second)
	for i := range uint64(maxSlotIDs + 10) {
		d.observe(t0, 100, uint32(i>>6), uint32(i&63), 0)
	}
	if n := len(d.seen[100].ids); n > maxSlotIDs || d.ids > maxSlotIDs {
		t.Errorf("slot 100 holds %d ids, %d in all; want at most %d", n, d.ids, maxSlotIDs)
	}
	if d.forgotten != 1 {
		t.Errorf("forgotten = %d, want 1: the slot started over once", d.forgotten)
	}
	checkIDs(t, d)
}

// A slot holding every id a real slot can have is not reset by a repeat,
// which a union receives continuously; only a new id past the cap resets it
// (Ally, go-amt#144 review 5464391246).
func TestDedupDoesNotResetAFullSlotOnADuplicate(t *testing.T) {
	d := newDedup(25 * time.Second)
	for i := range uint64(maxSlotIDs) {
		d.observe(t0, 100, uint32(i>>6), uint32(i&63), 0)
	}
	if v := d.observe(t0, 100, 0, 0, 0); v != duplicate || d.forgotten != 0 || d.ids != maxSlotIDs {
		t.Errorf("repeat into a full slot: %v, forgotten=%d ids=%d; want duplicate, 0, %d", v, d.forgotten, d.ids, maxSlotIDs)
	}
	if v := d.observe(t0, 100, 1<<20, 0, 0); v != emit || d.forgotten != 1 || d.ids != 1 {
		t.Errorf("new id past the cap: %v, forgotten=%d ids=%d; want emit, 1, 1", v, d.forgotten, d.ids)
	}
	checkIDs(t, d)
}

// Full slots kept fresh by one duplicate each cannot hold more than
// maxDedupIDs between them: past it, a new id forgets the idlest other slot
// (Ally, go-amt#147 review 5468443886).
func TestDedupBoundsIDsAcrossSlots(t *testing.T) {
	d := newDedup(25 * time.Second)
	at := t0
	const full = maxDedupIDs/maxSlotIDs + 1 // one full slot more than the cap holds
	for s := uint64(1); s <= full; s++ {
		for r := uint64(1); r < s; r++ { // one duplicate keeps each earlier slot fresh
			at = at.Add(time.Nanosecond)
			d.observe(at, r, 0, 0, 0)
		}
		for i := range uint64(maxSlotIDs) {
			at = at.Add(time.Nanosecond)
			d.observe(at, s, uint32(i>>6), uint32(i&63), 0)
			if d.ids > maxDedupIDs {
				t.Fatalf("dedup holds %d ids filling slot %d, want at most %d", d.ids, s, maxDedupIDs)
			}
		}
	}
	if ss := d.seen[full]; ss == nil || len(ss.ids) != maxSlotIDs || d.forgotten != 1 || d.seen[1] != nil {
		t.Errorf("slot %d kept=%v, forgotten=%d, slot 1 kept=%v; want all %d ids, 1, false: the idlest other slot gives way",
			full, ss != nil, d.forgotten, d.seen[1] != nil, maxSlotIDs)
	}
	// A slot is not forgotten for its own new id, even stamped earliest of all.
	if v := d.observe(t0, full+1, 0, 0, 0); v != emit || d.seen[full+1] == nil {
		t.Errorf("new slot at the cap: %v, kept=%v; want emit, true", v, d.seen[full+1] != nil)
	}
	checkIDs(t, d)
}

// The cap across slots counts later versions too. Here later versions alone
// take the total to it: each slot's first version came while the total was low.
func TestDedupBoundsVersionsAcrossSlots(t *testing.T) {
	d := newDedup(25 * time.Second)
	at := t0
	const slots, per = 2 * maxDedupIDs / maxSlotIDs, maxSlotIDs / 2 // half-full slots, the cap between them
	for s := uint64(1); s <= slots; s++ {
		d.observe(at, s, 0, 0, 1)
	}
	for s := uint64(1); s <= slots; s++ {
		for v := uint64(2); v <= per; v++ {
			at = at.Add(time.Nanosecond)
			d.observe(at, s, 0, 0, v)
		}
	}
	if v := d.observe(at.Add(time.Nanosecond), 1, 0, 0, per+1); v != emitOther || d.ids > maxDedupIDs || d.seen[2] != nil {
		t.Errorf("a later version past the cap: %v, dedup_ids=%d, slot 2 kept=%v; want emitOther, at most %d, false: the idlest other slot gives way",
			v, d.ids, d.seen[2] != nil, maxDedupIDs)
	}
	checkIDs(t, d)
}

func TestAsV3(t *testing.T) {
	// A version-4 frame: forwarder header, then a 32:32 chained data shred
	// (variant 0x96: chained Merkle data, proof 6).
	v4 := make([]byte, 28+1203)
	v4[0] = 4
	v4[1] = 7 // slot 7
	body := v4[28:]
	for i := range body {
		body[i] = byte(i)
	}
	body[64] = 0x96

	v3, ok := asV3(v4)
	if !ok {
		t.Fatal("asV3 refused a well-formed version-4 frame")
	}
	// The shard runs from after the signature (64) to before the 32-byte
	// root and six 20-byte proof entries.
	if v3[0] != 3 || v3[1] != 7 || !bytes.Equal(v3[28:], body[64:1203-32-6*20]) {
		t.Errorf("asV3(v4) = version %d, slot byte %d, %d-byte body; want 3, 7, %d", v3[0], v3[1], len(v3)-28, 1203-32-6*20-64)
	}

	passthrough := append([]byte{3}, v4[1:28]...)
	if got, ok := asV3(passthrough); !ok || &got[0] != &passthrough[0] {
		t.Error("a version-3 frame must pass through unchanged")
	}
	if _, ok := asV3(append([]byte{5}, v4[1:]...)); ok {
		t.Error("an unknown version must not reach the version-3 group")
	}
}

// v4Frame builds a version-4 frame for a 32:32 chained Merkle FEC set.
// local is the unified local index: data 0..31, coding 32+position.
func v4Frame(slot uint64, local uint32, coding bool) []byte {
	size, variant := 1203, byte(0x96) // chained Merkle data, proof 6
	if coding {
		size, variant = 1228, 0x66 // chained Merkle code, proof 6
	}
	b := make([]byte, 28+size)
	b[0] = 4
	binary.LittleEndian.PutUint64(b[1:9], slot)
	binary.LittleEndian.PutUint32(b[13:17], local)
	if coding {
		b[17], b[18], b[19] = 0x02, 32, 32
	}
	b[28+64] = variant
	return b
}

func TestParseOutput(t *testing.T) {
	for _, c := range []struct {
		spec, dst string
		kind      kind
	}{
		{"232.0.2.1=data", "232.0.2.1:5001", kindData},
		{"127.0.0.1:5003=all", "127.0.0.1:5003", kindAll},
		{"232.0.0.2=v3", "232.0.0.2:5001", kindV3},
		{"ff3e::232:202=coding-even", "[ff3e::232:202]:5001", kindCodingEven},
		{"[ff3e::232:203]:6000=coding-odd", "[ff3e::232:203]:6000", kindCodingOdd},
	} {
		o, err := parseOutput(c.spec, 5001)
		if err != nil {
			t.Errorf("parseOutput(%q): %v", c.spec, err)
			continue
		}
		if o.dst.String() != c.dst || o.kind != c.kind {
			t.Errorf("parseOutput(%q) = %s %s, want %s %s", c.spec, o.dst, o.kind, c.dst, c.kind)
		}
	}
	for _, spec := range []string{"232.0.2.1", "232.0.2.1=coding", "relay.example=all", "232.0.2.1:0=all", "232.0.2.1:x=all", "[ff3e::1]=all"} {
		if _, err := parseOutput(spec, 5001); err == nil {
			t.Errorf("parseOutput(%q) accepted a malformed -out", spec)
		}
	}
}

func TestParseOutputsRefusesAmbiguousConfigs(t *testing.T) {
	ingestA := &net.UDPAddr{IP: net.ParseIP("232.0.0.1"), Port: 5001}
	ingestB := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5002}
	for _, c := range []struct {
		name  string
		specs []string
	}{
		{"no output", nil},
		{"one group twice", []string{"232.0.2.1=data", "232.0.2.1:5001=v3"}},
		{"the ingest channel", []string{"232.0.0.1=v3"}},
		{"the second listener's port", []string{"127.0.0.1:5002=all"}},
		{"a malformed group", []string{"232.0.0.9x=v3"}},
	} {
		if outs, err := parseOutputs(c.specs, 5001, ingestA, ingestB); err == nil {
			t.Errorf("%s: parseOutputs accepted %d outputs; want a refusal", c.name, len(outs))
		}
	}
	outs, err := parseOutputs([]string{"232.0.2.1=data", "232.0.2.1:5011=coding-even", "232.0.0.1:5003=all", "127.0.0.1:5003=all"}, 5001, ingestA, ingestB)
	if err != nil || len(outs) != 4 {
		t.Errorf("distinct destinations off the ingests: %d outputs, %v; want all 4", len(outs), err)
	}
}

func TestLayersPartitionEveryFECSet(t *testing.T) {
	layers := []kind{kindData, kindCodingEven, kindCodingOdd}
	for local := uint32(0); local < 64; local++ {
		coding := local >= 32
		b := v4Frame(9, local, coding)
		var in []kind
		for _, k := range layers {
			if k.carries(b) {
				in = append(in, k)
			}
		}
		want := kindData
		if coding {
			want = kindCodingEven + kind((local-32)%2)
		}
		if len(in) != 1 || in[0] != want {
			t.Errorf("local index %d is in layers %v, want only %s", local, in, want)
		}
		if !kindAll.carries(b) || !kindV3.carries(b) {
			t.Errorf("local index %d: all and v3 must carry every frame", local)
		}
	}
}

func TestSendRoutesEachFrameToItsOutputs(t *testing.T) {
	conn4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn4.Close()
	recv := func(network string, ip net.IP) *net.UDPConn {
		c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	sinks := map[kind]*net.UDPConn{}
	var outs []*output
	for _, k := range []kind{kindData, kindCodingEven, kindCodingOdd, kindV3} {
		sinks[k] = recv("udp4", net.IPv4(127, 0, 0, 1))
		outs = append(outs, &output{dst: sinks[k].LocalAddr().(*net.UDPAddr), kind: k, conn: conn4})
	}
	// The IPv6 path: emitSocket6 from ::1 to an IPv6 receiver.
	var sink6 *net.UDPConn
	if conn6, err := emitSocket6(net.IPv6loopback, 1); err != nil {
		t.Logf("no IPv6 loopback, skipping the IPv6 output: %v", err)
	} else {
		defer conn6.Close()
		sink6 = recv("udp6", net.IPv6loopback)
		outs = append(outs, &output{dst: sink6.LocalAddr().(*net.UDPAddr), kind: kindAll, conn: conn6})
	}

	for _, o := range outs {
		o.start()
		t.Cleanup(func() { close(o.q) })
	}

	data, even, odd := v4Frame(7, 3, false), v4Frame(7, 32+4, true), v4Frame(7, 32+5, true)
	unknown := append([]byte{5}, data[1:]...)
	for _, f := range [][]byte{data, even, odd} {
		if !send(outs, f, false) {
			t.Fatalf("send reported a well-formed version-4 frame unconvertible")
		}
	}
	if send(outs, unknown, false) {
		t.Error("send must report a frame the version-3 output cannot take")
	}

	read := func(c *net.UDPConn) [][]byte {
		var got [][]byte
		for {
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			b := make([]byte, maxDatagram)
			n, err := c.Read(b)
			if err != nil {
				return got
			}
			got = append(got, b[:n])
		}
	}
	// Verbatim outputs select on the header alone, whatever the version: the
	// unknown-version frame is a data shred, so the data layer carries it.
	for k, want := range map[kind][][]byte{
		kindData:       {data, unknown},
		kindCodingEven: {even},
		kindCodingOdd:  {odd},
	} {
		got := read(sinks[k])
		ok := len(got) == len(want)
		for i := 0; ok && i < len(got); i++ {
			ok = bytes.Equal(got[i], want[i])
		}
		if !ok {
			t.Errorf("%s output received %d frames, want these %d verbatim", k, len(got), len(want))
		}
	}
	// The version-3 output takes every convertible frame, converted, and
	// drops the unknown version.
	if got := read(sinks[kindV3]); len(got) != 3 {
		t.Errorf("v3 output received %d frames, want 3", len(got))
	} else {
		for i, f := range got {
			if f[0] != 3 || len(f) != 1015 {
				t.Errorf("v3 frame %d: version %d, %d bytes; want 3, 1015", i, f[0], len(f))
			}
		}
	}
	if sink6 != nil {
		if got := read(sink6); len(got) != 4 || !bytes.Equal(got[3], unknown) {
			t.Errorf("IPv6 all output received %d frames, want all 4 verbatim", len(got))
		}
	}
	for _, o := range outs {
		if e, d := o.err.Load(), o.drop.Load(); e != 0 || d != 0 {
			t.Errorf("%s output counted %d write errors and %d drops", o.kind, e, d)
		}
	}
}

// An output whose queue is full loses frames. It holds up neither send, which
// runs on the merger's only processing loop, nor the other outputs, which still
// get every frame in order.
func TestSendDoesNotWaitForAFullOutput(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	// stuck has room for one frame and no sender, so it is full from then on.
	stuck := &output{dst: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, kind: kindAll, conn: conn, q: make(chan []byte, 1)}
	live := &output{dst: sink.LocalAddr().(*net.UDPAddr), kind: kindAll, conn: conn}
	live.start()
	t.Cleanup(func() { close(live.q) })

	// Headers only, one slot each, to check the order. send and an all output
	// read nothing past the header, and 100 full frames would overflow the
	// sink's default receive buffer before the test reads it.
	const n, more = 100, 10000
	frames := make([][]byte, n)
	for i := range frames {
		frames[i] = v4Frame(uint64(i+1), 3, false)[:hdrLen]
	}
	took := make(chan time.Duration)
	go func() {
		start := time.Now()
		for _, f := range frames {
			send([]*output{stuck, live}, f, false)
		}
		// Then many to the full output alone: waiting even 0.1 ms a frame
		// would take a second.
		for range more {
			send([]*output{stuck}, frames[0], false)
		}
		took <- time.Since(start)
	}()
	select {
	case d := <-took:
		if d > time.Second {
			t.Errorf("send took %v for %d frames: it waits on a full output", d, n+more)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send waited on a full output")
	}

	var slots []uint64
	for b := make([]byte, maxDatagram); len(slots) < n; {
		sink.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := sink.Read(b); err != nil {
			break
		}
		slots = append(slots, binary.LittleEndian.Uint64(b[1:9]))
	}
	if len(slots) != n {
		t.Errorf("the live output delivered %d of %d frames", len(slots), n)
	}
	for i, s := range slots {
		if s != uint64(i+1) {
			t.Errorf("the live output's frame %d carries slot %d, want %d", i, s, i+1)
			break
		}
	}
	if d := stuck.drop.Load(); d != n-1+more {
		t.Errorf("the full output counted %d drops, want %d", d, n-1+more)
	}
	if d := live.drop.Load(); d != 0 {
		t.Errorf("the live output counted %d drops, want 0", d)
	}
}

// A later version of a shred goes to every verbatim output and not to v3, whose
// frames have no signature to tell versions apart by: that output keeps one
// version of each shred, the first.
func TestSendKeepsLaterVersionsOffTheV3Output(t *testing.T) {
	var outs []*output
	for _, k := range []kind{kindAll, kindV3, kindData, kindCodingEven, kindCodingOdd} {
		outs = append(outs, &output{kind: k, q: make(chan []byte, 4)}) // no sender: the queue keeps what send gave it
	}
	for _, f := range [][]byte{v4Frame(7, 3, false), v4Frame(7, 32+4, true)} {
		if !send(outs, f, true) {
			t.Error("send counted a later version as v3_unconvertible")
		}
	}
	for _, o := range outs {
		if want := map[kind]int{kindAll: 2, kindData: 1, kindCodingEven: 1}[o.kind]; len(o.q) != want {
			t.Errorf("%s output queued %d later versions, want %d", o.kind, len(o.q), want)
		}
	}
}

// Ingest A takes only the production source's datagrams. Its socket binds the
// wildcard on its port, so any host can reach it by unicast, and a forged
// shred that arrived first would win dedup over the real one (BLO-43063).
func TestReaderDropsDatagramsFromOtherSources(t *testing.T) {
	// reader exits the process on a read error, so this socket and its reader
	// stay open until the test binary exits.
	in, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan frame, 2)
	var ctr counters
	go reader(in, 0, netip.MustParseAddr("127.0.0.2"), ch, &ctr)

	sendFrom := func(ip string, slot uint64) {
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)}, in.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(v4Frame(slot, 3, false)[:hdrLen]); err != nil {
			t.Fatal(err)
		}
	}
	sendFrom("127.0.0.3", 1) // a forger
	for deadline := time.Now().Add(2 * time.Second); ctr.foreign[0].Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if n := ctr.foreign[0].Load(); n != 1 {
		t.Fatalf("foreign = %d after a datagram from 127.0.0.3, want 1; %d frame(s) passed", n, len(ch))
	}
	sendFrom("127.0.0.2", 2) // the production source
	select {
	case f := <-ch:
		if slot := binary.LittleEndian.Uint64(f.buf[1:9]); slot != 2 {
			t.Fatalf("reader passed slot %d, want only the production source's slot 2", slot)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader passed nothing from the production source")
	}
}

// Each frame a reader passes on must own its buffer. reader reuses its read
// buffer for a datagram it drops, so it has to replace the buffer once out owns
// one: otherwise the next read overwrites a frame still queued on an output
// (BLO-43063).
func TestReaderGivesEachPassedFrameItsOwnBuffer(t *testing.T) {
	in := loopbackUDP(t)
	ch := make(chan frame, 2)
	var ctr counters
	go reader(in, 0, netip.Addr{}, ch, &ctr) // unfiltered: this is about buffers

	c, err := net.DialUDP("udp4", nil, in.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Take delivery of one slot before sending the next, so a reader that reuses
	// the buffer overwrites a frame this test is already holding.
	recv := func(slot uint64) frame {
		t.Helper()
		if _, err := c.Write(v4Frame(slot, 3, false)[:hdrLen]); err != nil {
			t.Fatal(err)
		}
		select {
		case f := <-ch:
			return f
		case <-time.After(2 * time.Second):
			t.Fatalf("reader passed nothing for slot %d", slot)
		}
		return frame{}
	}
	first, second := recv(1), recv(2)

	if &first.buf[0] == &second.buf[0] {
		t.Error("two passed frames share a buffer: the next read overwrites a frame still in flight")
	}
	if slot := binary.LittleEndian.Uint64(first.buf[1:9]); slot != 1 {
		t.Errorf("the first frame now reads slot %d, want 1: a later read wrote over it", slot)
	}
}

// loopbackUDP returns a UDP socket on an ephemeral loopback port. reader exits
// the process on a read error, so a socket handed to one stays open until the
// test binary exits and is deliberately not closed.
func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// scrape returns the exposition text of r.
func scrape(t *testing.T, r *prometheus.Registry) string {
	t.Helper()
	srv := httptest.NewServer(promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	return string(b)
}

func wantExposition(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		found := false
		for _, got := range strings.Split(out, "\n") {
			if strings.TrimRight(got, "\r") == l {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("/metrics missing line %q\n--- exposition ---\n%s", l, out)
		}
	}
}

// The alert BLO-43479 unblocks reads foreign off /metrics rather than off the
// journal. Ingest A must count a forged datagram; ingest B must publish the 0
// it can never leave, so "nothing touched ingest B" is a series and not a gap.
func TestMetricsExportForeignPerIngest(t *testing.T) {
	inA, inB := loopbackUDP(t), loopbackUDP(t)
	var c counters
	ch := make(chan frame, 4)
	go reader(inA, 0, netip.MustParseAddr("127.0.0.2"), ch, &c)
	go reader(inB, 1, netip.Addr{}, ch, &c)

	reg := prometheus.NewRegistry()
	if err := registerMerger(reg, &c, nil); err != nil {
		t.Fatal(err)
	}

	sendFrom := func(from string, to *net.UDPConn, slot uint64) {
		t.Helper()
		conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(from)}, to.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write(v4Frame(slot, 3, false)[:hdrLen]); err != nil {
			t.Fatal(err)
		}
	}
	sendFrom("127.0.0.3", inA, 1) // a forger
	sendFrom("127.0.0.2", inA, 2) // the production source
	sendFrom("127.0.0.1", inB, 3) // the second listener, which admits anyone

	// Both passed datagrams land on ch; the forged one lands on foreign[0].
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if c.foreign[0].Load() == 1 && len(ch) == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	out := scrape(t, reg)
	wantExposition(t, out,
		`# TYPE shred_merger_foreign_datagrams_total counter`,
		`shred_merger_foreign_datagrams_total{ingest="a"} 1`,
		`shred_merger_foreign_datagrams_total{ingest="b"} 0`,
	)
}

// Each exported series must read the counter the stats line prints under that
// name, so distinct values rather than a shared 0: reading rx_listener2 off
// emitted, say, is invisible when every counter is 0.
func TestMetricsExportReadsEachStatsLineCounter(t *testing.T) {
	var c counters
	c.rx[0].Store(11)
	c.rx[1].Store(22)
	c.emitted.Store(33)
	c.otherVersions.Store(88)
	c.qdrop.Store(44)
	c.foreign[0].Store(55)
	c.foreign[1].Store(66) // not reachable in production; distinct here to pin the label

	// One output per counter, so a sum that reads the wrong field is visible.
	outs := []*output{{}, {}}
	outs[0].err.Store(7)
	outs[1].err.Store(70)
	outs[0].drop.Store(5)
	outs[1].drop.Store(50)

	reg := prometheus.NewRegistry()
	if err := registerMerger(reg, &c, outs); err != nil {
		t.Fatal(err)
	}
	wantExposition(t, scrape(t, reg),
		`shred_merger_received_total{ingest="a"} 11`,
		`shred_merger_received_total{ingest="b"} 22`,
		`shred_merger_emitted_total 33`,
		`shred_merger_other_versions_total 88`,
		`shred_merger_queue_drops_total 44`,
		`shred_merger_foreign_datagrams_total{ingest="a"} 55`,
		`shred_merger_foreign_datagrams_total{ingest="b"} 66`,
		`shred_merger_emit_errors_total 77`,
		`shred_merger_output_drops_total 55`,
	)
}

// out_drop is summed over every output at scrape time, so a full output has to
// show up on /metrics without anything republishing it.
func TestMetricsExportOutputDropsAcrossOutputs(t *testing.T) {
	// Queues of one with no sender, so both are full after one frame each.
	stuck := []*output{
		{dst: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, kind: kindAll, q: make(chan []byte, 1)},
		{dst: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10}, kind: kindAll, q: make(chan []byte, 1)},
	}
	var c counters
	reg := prometheus.NewRegistry()
	if err := registerMerger(reg, &c, stuck); err != nil {
		t.Fatal(err)
	}
	f := v4Frame(1, 3, false)[:hdrLen]
	for range 4 {
		send(stuck, f, false)
	}
	// 4 frames to each output, 1 queued, 3 dropped.
	wantExposition(t, scrape(t, reg), `shred_merger_output_drops_total 6`)
}

// qdrop counts a datagram the reader could not hand on. Nothing receives on
// this channel, so the select's default branch takes the first datagram the
// admitted source sends.
func TestMetricsExportQueueDrops(t *testing.T) {
	in := loopbackUDP(t)
	var c counters
	go reader(in, 0, netip.MustParseAddr("127.0.0.2"), make(chan frame), &c)

	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")}, in.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(v4Frame(1, 3, false)[:hdrLen]); err != nil {
		t.Fatal(err)
	}

	reg := prometheus.NewRegistry()
	if err := registerMerger(reg, &c, nil); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); c.qdrop.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	wantExposition(t, scrape(t, reg), `shred_merger_queue_drops_total 1`)
}

// -metrics-addr is the whole listener: empty opens none, which is the default
// on a host whose exposed ingest port is this row's subject, and a given
// address serves the exposition over real HTTP.
func TestServeMetricsOpensNoListenerByDefault(t *testing.T) {
	var c counters
	for _, addr := range []string{"", "  "} {
		got, err := serveMetrics(addr, &c, nil)
		if err != nil {
			t.Fatalf("serveMetrics(%q): %v", addr, err)
		}
		if got != nil {
			t.Errorf("serveMetrics(%q) listened on %s, want no listener", addr, got)
		}
	}

	c.foreign[0].Store(3)
	addr, err := serveMetrics("127.0.0.1:0", &c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil {
		t.Fatal("serveMetrics with an address opened no listener")
	}
	resp, err := http.Get("http://" + addr.String() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics: %v", err)
	}
	wantExposition(t, string(body), `shred_merger_foreign_datagrams_total{ingest="a"} 3`)
}
