//go:build linux && !android && cgo && !purego

package amt

import (
	"bytes"
	"net"
	"testing"

	"golang.org/x/net/ipv4"
)

// TestWriteSegmentsCMAllocatesNothingOnceWarm pins BLO-47267: a segmented send
// with a channel's hoisted control message costs no allocation once its pooled
// state is warm. Each one used to cost nine (sockaddr, RawConn, cmsg buffer,
// marshalled cm, the write closure and its captured results).
//
// sync.Pool drops a Put one time in four under -race by design, so the bound
// there is an average, not zero.
func TestWriteSegmentsCMAllocatesNothingOnceWarm(t *testing.T) {
	_, pc, dst := loopbackPair(t)
	cm := &ipv4.ControlMessage{Src: net.IPv4(127, 0, 0, 1)}
	payload := make([]byte, 4*400)
	const runs = 200
	send := func() {
		if _, err := writeSegmentsCM(pc, payload, 400, cm, dst); err != nil {
			t.Fatalf("writeSegmentsCM: %v", err)
		}
	}
	send()
	allocs := testing.AllocsPerRun(runs, send)
	limit := 0.0
	if raceEnabled {
		limit = 4
	}
	if allocs > limit {
		t.Fatalf("writeSegmentsCM allocated %v per send, want <= %v", allocs, limit)
	}
}

// TestSegSendMarshalCMTracksItsInput: the cache must re-marshal whenever any
// field Marshal reads changes, and return exactly cm.Marshal()'s bytes.
func TestSegSendMarshalCMTracksItsInput(t *testing.T) {
	s := takeSegSend()
	defer s.put()
	for i, cm := range []*ipv4.ControlMessage{
		{},
		{Src: net.IPv4(10, 0, 0, 1)},
		{Src: net.IPv4(10, 0, 0, 1)},
		{Src: net.IPv4(10, 0, 0, 2)},
		{Src: net.IPv4(10, 0, 0, 2), IfIndex: 3},
		{Src: net.IPv4(10, 0, 0, 2), IfIndex: 3, TTL: 5},
		{Src: net.IPv4(10, 0, 0, 2), IfIndex: 3, Dst: net.IPv4(224, 0, 0, 1)},
		{},
	} {
		if got, want := s.marshalCM(cm), cm.Marshal(); !bytes.Equal(got, want) {
			t.Fatalf("message %d (%+v): cached %x, Marshal %x", i, cm, got, want)
		}
	}
}
