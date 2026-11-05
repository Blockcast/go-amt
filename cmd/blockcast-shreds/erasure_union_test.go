package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/blockcast/go-amt/broker"
	"github.com/blockcast/go-amt/broker/gwclient"
	"github.com/blockcast/go-amt/receiver"
	"github.com/blockcast/go-amt/shred"
	"github.com/prometheus/client_golang/prometheus"
)

// codingShred builds one forwarder-framed coding shred at local index
// 32..63, the shape the coding-even/coding-odd layers carry.
func codingShred(slot uint64, fecSet uint32, localIndex uint8) []byte {
	packet := dataShred(slot, fecSet, localIndex)
	packet[17] = 0x02 // IS_CODING_SHRED
	packet[18] = 32
	packet[19] = 32
	return packet
}

// layeredCapture is one slot whose single FEC set has exactly 32 of its 64
// shreds, spread so no layer alone holds 32: data 0..15 on d, even coding
// shreds 32..46 on ce, odd coding 33..47 on co. A shred of the next slot on
// every layer gives the first slot its boundary.
type arrival struct {
	feed   string
	packet []byte
}

func layeredCapture() []arrival {
	var capture []arrival
	for i := uint8(0); i < 16; i++ {
		capture = append(capture, arrival{"d", dataShred(10, 0, i)})
	}
	for i := uint8(32); i < 48; i++ {
		feed := "ce"
		if i%2 == 1 {
			feed = "co"
		}
		capture = append(capture, arrival{feed, codingShred(10, 0, i)})
	}
	return append(capture,
		arrival{"d", dataShred(11, 0, 0)},
		arrival{"ce", codingShred(11, 0, 32)},
		arrival{"co", codingShred(11, 0, 33)})
}

// scoreLayers runs capture through processPacket the way the read loop does
// and returns the heartbeat snapshot after one drain, plus the feed labels on
// /metrics' erasure_fraction series.
func scoreLayers(t *testing.T, names []string, unionID string, capture []arrival) ([]receiver.FeedSnapshot, []string) {
	t.Helper()
	start := time.Unix(1_800_000_000, 0)
	const grace = 10 * time.Millisecond
	registry := prometheus.NewRegistry()
	metrics, err := receiver.NewUnionReceiverMetrics(registry, names, receiver.ReportsWindows, unionID)
	if err != nil {
		t.Fatal(err)
	}
	reported, byFeed, err := newErasureTrackers(names, unionID, grace, start)
	if err != nil {
		t.Fatal(err)
	}
	scorer := shred.NewFeedScorerWithRetention(shred.FormatForwarder, names, shred.DefaultRetention)
	at := start
	for _, a := range capture {
		at = at.Add(time.Millisecond)
		if err := metrics.ObserveIngress(a.feed, len(a.packet), at); err != nil {
			t.Fatal(err)
		}
		processPacket(a.feed, a.packet, at, scorer, nil, metrics, byFeed[a.feed])
	}
	publishWindows(reported, metrics, at.Add(grace+time.Millisecond))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var labelled []string
	for _, family := range families {
		if !strings.HasSuffix(family.GetName(), "erasure_fraction") {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "feed" {
					labelled = append(labelled, label.GetValue())
				}
			}
		}
	}
	return metrics.Snapshot(), labelled
}

var layers = []string{"d", "ce", "co"}

// TestPerFeedTrackersScoreCodingLayersErased is the failure BLO-53098 exists
// for: today's per-feed trackers call every set erased on every layer, though
// the validator holds 32 of 64 shreds and can recover the set.
func TestPerFeedTrackersScoreCodingLayersErased(t *testing.T) {
	snapshot, _ := scoreLayers(t, layers, "", layeredCapture())
	for _, feed := range snapshot {
		if feed.Window.SetsTotal != 1 || feed.Window.SetsErased != 1 {
			t.Fatalf("feed %s: sets %d erased %d, want 1 of 1 erased per layer",
				feed.FeedID, feed.Window.SetsTotal, feed.Window.SetsErased)
		}
	}
}

func TestErasureUnionScoresTheSetAcrossLayers(t *testing.T) {
	unionID := unionFeedID([]string{"d", "ce", "co"})
	if unionID != "union:ce+co+d" {
		t.Fatalf("unionFeedID = %q", unionID)
	}
	snapshot, labelled := scoreLayers(t, layers, unionID, layeredCapture())
	if len(labelled) != 1 || labelled[0] != unionID {
		t.Fatalf("/metrics erasure_fraction feeds = %v, want only %q: a layer's own window is false evidence", labelled, unionID)
	}
	if len(snapshot) != 1 || snapshot[0].FeedID != unionID {
		t.Fatalf("snapshot = %+v, want the single union entry", snapshot)
	}
	union := snapshot[0]
	if union.Window.SetsTotal != 1 || union.Window.SetsErased != 0 {
		t.Fatalf("union: sets %d erased %d, want 1 complete set", union.Window.SetsTotal, union.Window.SetsErased)
	}
	if want := uint64(len(layeredCapture())); union.Liveness.Packets != want {
		t.Fatalf("union packets = %d, want the %d summed over layers", union.Liveness.Packets, want)
	}

	// The union entry is a valid erasure-schema-2 heartbeat feed.
	producer, err := gwclient.NewProducer("123e4567-e89b-42d3-a456-426614174000", "https://broker.invalid",
		staticSource(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	beat, err := producer.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(beat.Feeds) != 1 || beat.Feeds[0].Erasure.Schema != 2 {
		t.Fatalf("heartbeat feeds = %+v, want one schema-2 union report", beat.Feeds)
	}
	if err := broker.ValidateHeartbeat(beat); err != nil {
		t.Fatal(err)
	}
}

type staticSource []receiver.FeedSnapshot

func (s staticSource) Snapshot() []receiver.FeedSnapshot { return s }

// TestErasureUnionKeepsTwoSignedVersionsApart: two versions of one slot
// deliver 20 shreds of a set each, 40 in all. Keyed on position alone the union reads one complete
// set that no validator could rebuild; keyed on the leader signature it reads
// two erased ones. An unsigned (v3) shred still joins either.
func TestErasureUnionKeepsTwoSignedVersionsApart(t *testing.T) {
	signed := func(i uint8, sig uint64) []byte {
		p := dataShred(10, 0, i)
		if i >= 32 {
			p = codingShred(10, 0, i)
		}
		p = append(p, make([]byte, 64)...)
		binary.LittleEndian.PutUint64(p[shred.WireHeaderSize:], sig)
		return p
	}
	var capture []arrival
	for i := uint8(0); i < 40; i++ {
		capture = append(capture, arrival{[]string{"a", "b"}[i%2], signed(i, 1+uint64(i/20))}) // version 1 on 0..19, 2 on 20..39
	}
	capture = append(capture, arrival{"a", dataShred(11, 0, 0)}, arrival{"b", dataShred(11, 0, 1)})
	snapshot, _ := scoreLayers(t, []string{"a", "b"}, "union:a+b", capture)
	if w := snapshot[0].Window; w.SetsTotal != 2 || w.SetsErased != 2 {
		t.Fatalf("sets %d erased %d, want two versions scored apart, both erased", w.SetsTotal, w.SetsErased)
	}
}

func TestErasureGraceInSlots(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"slots without slot time", []string{"--erasure-grace-slots", "2"}, "--erasure-grace-slots requires --slot-time"},
		{"slot time without slots", []string{"--slot-time", "212ms"}, "--slot-time only scales --erasure-grace-slots"},
		{"both grace forms", []string{"--erasure-grace-slots", "2", "--slot-time", "212ms", "--erasure-grace-ms", "400"}, "both set the grace"},
		{"negative slots", []string{"--erasure-grace-slots", "-1", "--slot-time", "212ms"}, "must not be negative"},
		{"union in generic mode", []string{"--mode", "generic", "--source-label", "s", "--rights-basis", "r", "--erasure-union"}, "--erasure-union requires --mode shred"},
		{"slots in generic mode", []string{"--mode", "generic", "--source-label", "s", "--rights-basis", "r", "--erasure-grace-slots", "2", "--slot-time", "212ms"}, "--erasure-grace-slots requires --mode shred"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := run(append(tc.args, "--http-addr", ""))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run(%v) = %v, want %q", tc.args, err, tc.want)
			}
		})
	}
	grace, err := erasureGrace(400, 2, 212*time.Millisecond, map[string]bool{"erasure-grace-slots": true, "slot-time": true})
	if err != nil || grace != 424*time.Millisecond {
		t.Fatalf("erasureGrace(2 x 212ms) = %v, %v; want 424ms", grace, err)
	}
	grace, err = erasureGrace(400, 0, 0, map[string]bool{})
	if err != nil || grace != 400*time.Millisecond {
		t.Fatalf("erasureGrace default = %v, %v; want the 400ms v1 default", grace, err)
	}
}
