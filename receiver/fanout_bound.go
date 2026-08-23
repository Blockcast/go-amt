package receiver

// The fan-out is designed to a BOUNDED number of unicast destinations, not to
// "unicast forever". These two constants are that bound, in code, so the
// decision has an enforcement point rather than only a paragraph.
//
// Source: the W2c AC6 design record on BLO-25708, document `n65-revisit-trigger`
// §6. GATE 0 (BLO-23032) ratified unicast for the shred class because
// (k-1)/k = 0 at k = 1 on every tunnelled path — a per-subscriber tunnel gives
// multicast no fan-out to amortise, independent of subscriber count. That
// argument is about the TUNNEL, not about N, so it does not hold as N grows on a
// path where native multicast is actually available: past the crossover, N-way
// unicast egress costs more than one multicast tree.
//
// Both numbers are deliberately exported. The threshold is not an internal
// detail of one warning: an operator sizing a deployment, an alert on the gauge,
// and this package's own guard all have to agree on the same figure, and three
// copies of "55" would not stay equal.
const (
	// MulticastCrossoverDestinations is the modelled N at which one multicast
	// tree becomes cheaper than N unicast streams.
	//
	// Treat it as a SHAPE, not a measured constant. It comes from the fan-out
	// harness on a dummy netdev with zero real egress; §5 of the design record
	// makes the real-NIC measurement an explicit prerequisite to trusting the
	// absolute value, and notes the figure already moved 3.7x once it was
	// measured rather than modelled. Changing it is out of scope for the guard
	// and needs that measurement first.
	MulticastCrossoverDestinations = 65

	// RevisitThresholdDestinations is where we start warning: far enough below
	// the crossover to leave room to act, close enough that it is not noise.
	//
	// The gap is the entire point. A guard that fired AT the crossover would
	// announce a decision that had already expired — re-architecting a delivery
	// path is weeks of work, not something to discover on the day the economics
	// invert. Ten destinations of headroom is the warning's whole value; do not
	// "tidy" this to equal MulticastCrossoverDestinations.
	RevisitThresholdDestinations = 55
)
