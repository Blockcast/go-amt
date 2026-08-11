package receiver

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/blockcast/go-amt/erasure"
	"github.com/blockcast/go-amt/shred"
)

// ProcessorStats is a point-in-time snapshot of packet processing counters.
type ProcessorStats struct {
	IngressPackets uint64
	ShredsUnparsed uint64
}

// ProcessResult describes the independent delivery and scoring outcomes for a
// packet. A packet can be delivered even when its shred header is malformed.
type ProcessResult struct {
	Enqueued bool
	Parsed   bool
	Counted  bool
}

// Processor connects ingress packets to the bounded fan-out and erasure
// tracker without coupling either path to the broker transport.
type Processor struct {
	fanout  *Fanout
	tracker *erasure.Tracker

	ingressPackets atomic.Uint64
	shredsUnparsed atomic.Uint64
}

// NewProcessor constructs a receiver packet processor.
func NewProcessor(fanout *Fanout, tracker *erasure.Tracker) (*Processor, error) {
	if fanout == nil {
		return nil, errors.New("processor fan-out must be set")
	}
	if tracker == nil {
		return nil, errors.New("processor erasure tracker must be set")
	}
	return &Processor{fanout: fanout, tracker: tracker}, nil
}

// Process copies packet into the delivery ring before parsing its header for
// scoring. Parse failures therefore never suppress byte-identical delivery.
func (p *Processor) Process(packet []byte, receivedAt time.Time) ProcessResult {
	p.ingressPackets.Add(1)
	result := ProcessResult{Enqueued: p.fanout.Enqueue(packet)}

	header, err := shred.ParseHeader(packet)
	if err != nil {
		p.shredsUnparsed.Add(1)
		return result
	}
	result.Parsed = true
	result.Counted = p.tracker.Observe(header, receivedAt)
	return result
}

// Stats returns a lock-free snapshot of packet processing counters.
func (p *Processor) Stats() ProcessorStats {
	return ProcessorStats{
		IngressPackets: p.ingressPackets.Load(),
		ShredsUnparsed: p.shredsUnparsed.Load(),
	}
}
