package broker

import (
	"fmt"
	"net/netip"
	"net/url"
	"unicode/utf8"
)

// This file is the *sender*-to-broker transport contract: how the unicast
// fan-out sender learns which destinations are entitled to a feed, and at what
// address. It is a different surface from transport.go, which is the
// gateway-to-broker contract, and the two are versioned independently.
//
// # Why this is not a fourth route in transport.go
//
// transport.go freezes three route patterns, and the reason it freezes them is
// specific: bcast-shred-gw is customer-installed and cannot be force-upgraded,
// so the side that cannot move in lockstep publishes the contract and the side
// that redeploys at will adopts it as a compile-time dependency.
//
// That rationale does not reach this surface. The fan-out sender and the broker
// are both Blockcast-operated and both redeploy at will, so this contract *can*
// evolve in lockstep and does not need the same freeze. Filing it under
// TransportSchema would have coupled a contract that may move to one that must
// not, and would have made every sender-side revision look like a breaking
// change to a customer-installed binary. Hence a separate schema constant.
//
// It still lives in go-amt, and still uses the route-pair mechanism described
// at the top of transport.go: the broker registers PatternDeliveryTargets on
// its mux and the sender builds its path with DeliveryTargetsPath, so a route
// rename is a compile-time event on the server rather than a 404 in production.
// Sharing a package with the gateway contract is also what lets both surfaces
// share one error taxonomy and one Retry vocabulary.
//
// # What is deliberately absent
//
// There is no admission handshake anywhere in this contract, and no per-request
// error taxonomy of its own. Both absences are load-bearing and are documented
// at DeliveryTarget and at DeliveryTargetsRead respectively. See BLO-29787 for
// the ratification.

const (
	// SenderTransportSchema versions the route, envelope, and read semantics in
	// this file, independently of TransportSchema.
	//
	// Like TransportSchema it is not carried on the wire — the route is
	// versioned by its /v1/ prefix — and exists so both sides can assert at
	// build time that they were compiled against the same revision.
	SenderTransportSchema = "sender.transport.v1"
)

// PatternDeliveryTargets is the per-feed delivery-target read, in the exact
// spelling the broker registers on a net/http.ServeMux.
//
// It is a GET, and it is the only route in this package that is not a POST.
// transport.go's three are POST because each mutates broker state and none is
// safely repeatable by an intermediary. This one mutates nothing and *is*
// safely repeatable, which is the whole point: it is polled.
//
// The producer behind it is Broker.ActiveDeliveryTargets in the portal's
// internal/sessionbroker package. Its FeedTargets doc comment is the normative
// description of the semantics mirrored below; this type is the wire form.
const PatternDeliveryTargets = "GET /v1/feeds/{feed_id}/delivery-targets"

// DeliveryTargetsFeedIDParam is the wildcard name inside
// PatternDeliveryTargets. The broker reads the feed with
// r.PathValue(broker.DeliveryTargetsFeedIDParam) rather than re-spelling
// "feed_id", so the wildcard cannot drift from the pattern.
const DeliveryTargetsFeedIDParam = "feed_id"

// DeliveryTargetsPath returns the request path for reading feedID's targets.
//
// The feed is path-escaped for the same reason RenewPath escapes a ticket id:
// a feed_id needing escaping is already a bug, and escaping makes that bug
// surface as a 404 rather than as a silently different path.
func DeliveryTargetsPath(feedID string) string {
	return "/v1/feeds/" + url.PathEscape(feedID) + "/delivery-targets"
}

// DeliveryTarget is one entitled destination: an opaque billing identity and
// the address to send to.
//
// # There is no admission handshake, and that is the design
//
// The sender never receives anything from a subscriber and never decides
// whether to admit a flow. It sends to Addr and bills TargetID. Everything that
// would otherwise be an admission decision has already happened on the broker's
// mTLS listener at mint, and is re-asserted at every renew.
//
// In particular the IP half of Addr is the *authenticated peer address*: Mint
// records it only after rejecting any mint whose asserted destination disagrees
// with the connection it arrived on. So the sender cannot be aimed at a third
// party — a destination that never proved possession of a client certificate is
// unrepresentable here. The port half is client-asserted and only range-checked,
// which is safe precisely because the address half is proven: a lying client can
// only redirect its own traffic to its own other port.
//
// A signed bearer ticket presented in-band was considered and rejected on
// BLO-29787: it would be a second, weaker copy of an authentication that already
// happened on a stronger channel.
type DeliveryTarget struct {
	// TargetID is a canonical, non-nil, lowercase UUID — the same spelling rule
	// as ticket_id, because it *is* the ticket id.
	//
	// It is the ticket id rather than the subscriber id for two independent
	// reasons. One subscriber may hold several concurrent tickets on one feed,
	// so a subscriber id collides and cannot key a target set. And a ticket id
	// is fresh per mint, which makes an ABA reuse of a departed target's
	// identity unrepresentable rather than merely unlikely.
	TargetID string `json:"target_id"`

	// Addr is the destination in "ip:port" form, exactly as
	// netip.ParseAddrPort and net.ResolveUDPAddr accept it.
	//
	// Two targets in one set may legitimately share an Addr — several seats
	// behind one NAT — which is why TargetID and not Addr is the key.
	Addr string `json:"addr"`
}

// DeliveryTargetsRead is the response body of a successful read: the entitled
// target set for one feed, evaluated at an instant.
//
// # An empty set is an answer, not a failure
//
// This is the distinction the type exists to carry across the wire, and losing
// it is the expensive failure mode. Fanout.ReconcileDestinations deliberately
// *refuses* an empty target set, on the grounds that a broker returning nothing
// is more often a broker fault than a genuinely idle feed. So a caller that
// cannot tell "authoritatively zero subscribers" from "the read failed" makes a
// legitimately idle feed look like a permanent error forever.
//
// On a 200, Targets is therefore non-nil, and len(Targets) == 0 means
// authoritatively zero entitled subscribers — a fact. The correct response is
// to hold the previous table and stop sending, which is a different action from
// erroring. It must not be forwarded to ReconcileDestinations.
//
// See ValidateDeliveryTargetsRead for why "non-nil" needs enforcing rather than
// documenting.
//
// # There is no error taxonomy for this read
//
// transport.go models seven error codes because a gateway branches on them: a
// capped account backs off differently from a denied entitlement. A sender does
// not branch. Its action on *every* non-2xx is identical — hold the
// last-known-good table, keep serving the destinations already in it, do not
// call ReconcileDestinations, and retry per RetryTransportFailure.
//
// Modelling codes it would not read would invite a client to branch on them,
// and the first client that did would have a failure mode where some read
// errors drop destinations and others do not. The existing codes still appear
// in ErrorResponse bodies for operators and logs; they are simply not a
// client-visible fork. Do not add a code here to make this route look like the
// others.
//
// This is also why "broker unreachable ⇒ no new subscribers" is the intended
// posture rather than a defect: existing subscribers keep flowing on the last
// good table, and no unentitled destination is ever added. It fails closed in
// both directions.
type DeliveryTargetsRead struct {
	// FeedID is the canonical feed the read was evaluated for. Echoed so a
	// misrouted or misattributed response is detectable rather than silently
	// reconciled against the wrong feed.
	FeedID string `json:"feed_id"`

	// Targets is every active, addressable ticket for FeedID at EvaluatedAt.
	// Non-nil on any 200 — see the type doc and ValidateDeliveryTargetsRead.
	Targets []DeliveryTarget `json:"targets"`

	// EvaluatedAt is when the set was evaluated, as a canonical UTC timestamp
	// in the exact spelling described on HeartbeatSchema.
	//
	// The set is a snapshot, not a subscription: it is already stale when the
	// sender reads it, and that staleness is bounded by the sender's poll
	// interval rather than by TicketTTL. A ticket can be revoked microseconds
	// after this instant, which is why revocation is driven synchronously
	// broker-side instead of waiting for a poll to notice.
	EvaluatedAt string `json:"evaluated_at"`

	// SkippedUnaddressable counts active, entitled tickets omitted from Targets
	// because they carry no usable destination port.
	//
	// It is a real delivery hole and is reported rather than hidden. It is not
	// an error: the omitted rows are self-healing, because a port is mandatory
	// at mint and every pre-existing ticket either renews or expires within one
	// TicketTTL. A sender should surface a sustained non-zero value as an
	// operator signal and must not respond by guessing a port.
	SkippedUnaddressable int `json:"skipped_unaddressable"`
}

// ValidateDeliveryTargetsRead checks a delivery-target response.
//
// The sender calls it on every read, before reconciling. The broker calls it
// before responding, for the reason ValidateMintRequest is called on both
// sides: the client call turns a bad reconcile into a local error, and the
// server call is the one that enforces.
//
// # Why a nil Targets is rejected rather than treated as empty
//
// encoding/json marshals a nil slice as "null" and an empty one as "[]", and
// unmarshals both back into a []DeliveryTarget that len() reports as 0. So the
// one distinction this contract exists to carry — authoritatively zero versus
// no answer — is exactly the distinction a serialization accident erases, and
// it erases it in the unsafe direction: a broker bug that produced "null" would
// be read as "this feed has no subscribers" and would tear down every
// destination on the feed.
//
// Rejecting a nil Targets on an otherwise-successful read closes that. The
// broker must emit "[]"; a sender that receives "null" must treat it as a
// malformed envelope, which routes it into the read-failure path where it holds
// its table rather than acting on it.
func ValidateDeliveryTargetsRead(read DeliveryTargetsRead) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidTransport, fmt.Sprintf(format, args...))
	}
	if read.FeedID == "" || !utf8.ValidString(read.FeedID) || len(read.FeedID) > MaxFeedIDBytes {
		return invalid("feed_id must be non-empty, valid UTF-8, and at most %d bytes", MaxFeedIDBytes)
	}
	if read.Targets == nil {
		return invalid(`targets must be [] rather than null: an empty set is an authoritative "no entitled subscribers" and must be distinguishable from an absent one`)
	}
	if _, err := parseCanonicalUTCTimestamp(read.EvaluatedAt); err != nil {
		return invalid("evaluated_at must be a canonical UTC timestamp: %s", canonicalTimestampRule)
	}
	if read.SkippedUnaddressable < 0 {
		return invalid("skipped_unaddressable must not be negative")
	}
	seen := make(map[string]struct{}, len(read.Targets))
	for i, target := range read.Targets {
		if err := validateCanonicalUUID(target.TargetID); err != nil {
			return invalid("targets[%d].target_id must be a canonical, non-nil, lowercase UUID: %s", i, err)
		}
		if _, dup := seen[target.TargetID]; dup {
			return invalid("targets[%d].target_id %q is repeated: Target.ID must be unique within a set", i, target.TargetID)
		}
		seen[target.TargetID] = struct{}{}
		addr, err := netip.ParseAddrPort(target.Addr)
		if err != nil {
			return invalid(`targets[%d].addr must be "ip:port": %s`, i, err)
		}
		if addr.Port() == 0 {
			return invalid("targets[%d].addr port must be non-zero", i)
		}
		if !addr.Addr().IsValid() || addr.Addr().IsUnspecified() {
			return invalid("targets[%d].addr must carry a specific destination address", i)
		}
	}
	return nil
}
