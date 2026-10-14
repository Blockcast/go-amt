//go:build linux

package main

import (
	"log"
	"time"

	"github.com/blockcast/go-amt/txfeed"
)

// channelCaps caps the bytes each filter channel sends, and all of them
// together, with token buckets that hold one second's worth. A channel on a
// key that nearly every transaction lists, such as a sysvar, would otherwise
// carry most of the feed. A transaction over a cap is not sent on that
// channel, whole, never in part, and is counted.
type channelCaps struct {
	perChan, total float64 // bytes per second; 0 is no cap
	now            func() time.Time
	buckets        map[txfeed.Channel]*bucket
	all            bucket
	capped         uint64                  // channel sends refused
	over           map[txfeed.Channel]bool // channels already logged as over a cap
}

func newChannelCaps(perChanMbps, totalMbps float64) *channelCaps {
	return &channelCaps{
		perChan: perChanMbps * 1e6 / 8, total: totalMbps * 1e6 / 8, now: time.Now,
		buckets: map[txfeed.Channel]*bucket{}, over: map[txfeed.Channel]bool{},
	}
}

type bucket struct {
	tokens float64
	last   time.Time
}

// fill tops b up for the time since it was last filled, to at most one
// second at rate.
func (b *bucket) fill(rate float64, now time.Time) {
	if b.last.IsZero() {
		b.tokens = rate
	} else {
		b.tokens = min(rate, b.tokens+rate*now.Sub(b.last).Seconds())
	}
	b.last = now
}

// take reports whether channel c may send n bytes now, and if so spends them
// from its bucket and from the total.
func (cc *channelCaps) take(c txfeed.Channel, n int) bool {
	now := cc.now()
	b := cc.buckets[c]
	if b == nil {
		b = &bucket{}
		cc.buckets[c] = b
	}
	if cc.perChan > 0 {
		b.fill(cc.perChan, now)
	}
	if cc.total > 0 {
		cc.all.fill(cc.total, now)
	}
	if cc.perChan > 0 && float64(n) > b.tokens || cc.total > 0 && float64(n) > cc.all.tokens {
		cc.capped++
		if !cc.over[c] {
			cc.over[c] = true
			log.Printf("channel %s: over -channel-cap or -channel-total-cap; transactions above the cap are not sent on it", c)
		}
		return false
	}
	if cc.perChan > 0 {
		b.tokens -= float64(n)
	}
	if cc.total > 0 {
		cc.all.tokens -= float64(n)
	}
	return true
}

// forget drops the state of a channel that stopped.
func (cc *channelCaps) forget(c txfeed.Channel) {
	delete(cc.buckets, c)
	delete(cc.over, c)
}
