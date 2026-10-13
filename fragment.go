package amt

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// tunnelReadBuffer sizes the RelayManager read loop's buffer. The relay sends
// an AMT data message larger than the path MTU as IP fragments, and the kernel
// hands the reassembled UDP datagram over whole: W5.6 saw such datagrams over
// 1,500 B from Tokyo and London. The largest UDP payload an IPv4 datagram can
// carry is 65,507 B, so a 64 KiB buffer holds any of them and a read can never
// be truncated.
const tunnelReadBuffer = 64 << 10

// Inner IPv4 reassembly bounds (RFC 791 §3.2, with a shorter timer than its 15
// s: the fragments of a datagram arrive back to back through one tunnel, so 2 s
// without the rest means they are lost).
const (
	maxReassemblies   = 64 // datagrams in flight; with maxIPv4Payload, caps held bytes at 4 MiB
	reassemblyTimeout = 2 * time.Second
	maxIPv4Payload    = 65535 - 20
)

// DecapStats counts the inner packets of AMT Multicast Data messages that the
// data path reassembled or could not deliver as they arrived.
type DecapStats struct {
	// Fragments is the inner IPv4 fragments received. The relay sends each
	// fragment of a datagram larger than the path MTU as its own data message.
	Fragments uint64
	// Reassembled is the UDP datagrams rebuilt from them.
	Reassembled uint64
	// ReassemblyExpired is the datagrams dropped incomplete: a fragment did not
	// arrive within reassemblyTimeout, or the datagram was evicted to stay under
	// maxReassemblies.
	ReassemblyExpired uint64
	// ReassemblyInvalid is the datagrams dropped whole for overlapping,
	// inconsistent or oversized fragments.
	ReassemblyInvalid uint64
	// Truncated is the inner packets cut short of, or inconsistent with, the
	// lengths their IPv4 and UDP headers give. None is delivered.
	Truncated uint64
	// Unsupported is the inner packets that are not IPv4 UDP. Subscriptions
	// are IPv4-only, so an IPv6 packet, fragmented or not, is counted here
	// rather than parsed.
	Unsupported uint64
}

// udp4 is one whole UDP datagram from the inner packet of a data message.
type udp4 struct {
	src, dst     netip.Addr
	sport, dport uint16
	payload      []byte // aliases the read buffer unless it was reassembled
}

// fragKey is RFC 791's reassembly key less the protocol: only UDP is
// reassembled, so it is always 17.
type fragKey struct {
	src, dst netip.Addr
	id       uint16
}

type fragment struct {
	off int
	b   []byte
}

type reassembly struct {
	start  time.Time
	frags  []fragment
	held   int  // bytes in frags
	maxEnd int  // the furthest byte any fragment reaches
	end    int  // the payload length, once the last fragment is in; -1 until
	dead   bool // dropped as invalid; absorbs the rest until it expires
}

// decapsulator turns the inner packets of AMT Multicast Data messages into UDP
// datagrams, reassembling IPv4 fragments. The zero value is ready to use, and
// it is safe for concurrent use.
type decapsulator struct {
	mu      sync.Mutex
	pending map[fragKey]*reassembly

	fragments, reassembled, expired, invalid, truncated, unsupported atomic.Uint64
}

func (d *decapsulator) stats() DecapStats {
	return DecapStats{
		Fragments:         d.fragments.Load(),
		Reassembled:       d.reassembled.Load(),
		ReassemblyExpired: d.expired.Load(),
		ReassemblyInvalid: d.invalid.Load(),
		Truncated:         d.truncated.Load(),
		Unsupported:       d.unsupported.Load(),
	}
}

// decap parses ip, the inner packet of a data message, received at now. It
// returns the UDP datagram ip carries or, for a fragment, the datagram it
// completes. A fragment that completes nothing, and a packet that is not a
// whole IPv4 UDP datagram, return false.
func (d *decapsulator) decap(ip []byte, now time.Time) (udp4, bool) {
	if len(ip) == 0 || ip[0]>>4 != 4 {
		d.unsupported.Add(1)
		return udp4{}, false
	}
	if len(ip) < 20 {
		d.truncated.Add(1)
		return udp4{}, false
	}
	hlen, total := int(ip[0]&0x0f)*4, int(binary.BigEndian.Uint16(ip[2:4]))
	if hlen < 20 || total < hlen || total > len(ip) {
		// total > len(ip) is a datagram cut short on the way here. Before the
		// read buffer was sized for the largest one, this is how a datagram
		// over 1,500 B arrived, and its payload was delivered truncated.
		d.truncated.Add(1)
		return udp4{}, false
	}
	if ip[9] != 17 { // UDP
		d.unsupported.Add(1)
		return udp4{}, false
	}
	ip = ip[:total] // drop any trailing padding
	src, dst := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
	payload := ip[hlen:]
	if ff := binary.BigEndian.Uint16(ip[6:8]); ff&0x3fff != 0 { // MF, or a fragment offset
		d.fragments.Add(1)
		k := fragKey{src: src, dst: dst, id: binary.BigEndian.Uint16(ip[4:6])}
		if payload = d.reassemble(k, int(ff&0x1fff)*8, ff&0x2000 != 0, payload, now); payload == nil {
			return udp4{}, false
		}
		d.reassembled.Add(1)
	}
	if len(payload) < 8 {
		d.truncated.Add(1)
		return udp4{}, false
	}
	ulen := int(binary.BigEndian.Uint16(payload[4:6]))
	if ulen < 8 || ulen > len(payload) {
		d.truncated.Add(1)
		return udp4{}, false
	}
	return udp4{
		src: src, dst: dst,
		sport:   binary.BigEndian.Uint16(payload[0:2]),
		dport:   binary.BigEndian.Uint16(payload[2:4]),
		payload: payload[8:ulen],
	}, true
}

// reassemble adds the fragment b, at byte offset off of datagram k's IP
// payload, and returns the whole payload once it is complete. Overlapping or
// inconsistent fragments drop the whole datagram (RFC 5722 makes that the rule
// for IPv6; a forged overlap must not splice bytes into an IPv4 one either).
// A byte-identical duplicate is ignored.
func (d *decapsulator) reassemble(k fragKey, off int, more bool, b []byte, now time.Time) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		d.pending = map[fragKey]*reassembly{}
	}
	a := d.pending[k]
	if a != nil && now.Sub(a.start) > reassemblyTimeout {
		d.drop(k, a)
		a = nil
	}
	if a == nil {
		// ponytail: expiry runs only when a datagram starts, so a burst's last
		// lost fragments hold their reassemblies (at most 4 MiB) until the next
		// fragmented datagram. A timer if a silent tunnel must free them sooner.
		var oldest fragKey
		for key, p := range d.pending {
			if now.Sub(p.start) > reassemblyTimeout {
				d.drop(key, p)
			} else if q := d.pending[oldest]; q == nil || p.start.Before(q.start) {
				oldest = key
			}
		}
		if len(d.pending) >= maxReassemblies {
			d.drop(oldest, d.pending[oldest])
		}
		a = &reassembly{start: now, end: -1}
		d.pending[k] = a
	}
	if a.dead {
		return nil
	}
	end := off + len(b)
	if more && (len(b) == 0 || len(b)%8 != 0) || // only the last fragment may end off an 8-byte boundary
		end > maxIPv4Payload ||
		!more && (a.end >= 0 && a.end != end || a.maxEnd > end) || // a second, different last fragment, or bytes past the end
		more && a.end >= 0 && end > a.end {
		return d.kill(a)
	}
	for _, f := range a.frags {
		if off < f.off+len(f.b) && f.off < end {
			if f.off == off && bytes.Equal(f.b, b) {
				return nil
			}
			return d.kill(a)
		}
	}
	a.frags = append(a.frags, fragment{off: off, b: bytes.Clone(b)})
	a.held += len(b)
	a.maxEnd = max(a.maxEnd, end)
	if !more {
		a.end = end
	}
	if a.end < 0 || a.held != a.end {
		return nil
	}
	// No two fragments overlap and none reaches past end, so held == end
	// means they tile [0, end).
	out := make([]byte, a.end)
	for _, f := range a.frags {
		copy(out[f.off:], f.b)
	}
	delete(d.pending, k)
	return out
}

// kill drops a datagram as invalid and keeps its entry, so the fragments still
// to come are absorbed rather than starting a datagram that can never finish.
func (d *decapsulator) kill(a *reassembly) []byte {
	a.dead, a.frags = true, nil
	d.invalid.Add(1)
	return nil
}

// drop removes a reassembly, counting it expired unless it was already counted
// invalid.
func (d *decapsulator) drop(k fragKey, a *reassembly) {
	if !a.dead {
		d.expired.Add(1)
	}
	delete(d.pending, k)
}
