# AMT delivery-path selection: from a startup guess to a reversible decision

Status: **phase 2 implemented**. Item 2 (deliver the probe packet) and the
non-blocking two-path arbiter are implemented; conditional standby teardown is
still deliberately deferred until telemetry exists.

Tracking: [BLO-28740]. Background: [BLO-28640] (the 2026-08-18 outage),
go-amt#49 (the window-sizing fix this builds on).

## The problem this closes

`MulticastConn.Open` currently decides, once, at startup, whether native
multicast works — and that decision is permanent. `probeNativeTraffic` waits
`MinUsefulProbeWindow` (10s) for a packet. If none arrives, `conn4` is closed and
the process runs on the AMT tunnel until it is restarted.

Three things are wrong with that shape, and only the first was an outage:

1. **It is a guess.** The window is now long enough to be evidence (that was
   go-amt#49), but a sender restarting, a switch converging, or one missed IGMP
   query still produces a silent 10s and condemns the process.
2. **It is one-way.** Nothing re-examines the decision. Native multicast can come
   back a second later and the receiver will not notice for its lifetime.
3. **It is serial and blocking.** A genuinely-dead native path costs the full
   window *per channel*, paid one channel at a time across every content-group
   join. That is dead startup latency in exactly the deployment that can least
   afford it.

## What "both paths" actually costs

The tempting fix — keep native and AMT both up forever, take whichever delivers —
has a cost that is easy to state and easy to get wrong, because it is
**asymmetric**. This is the part worth being precise about.

| State | Native join cost | AMT tunnel cost |
|---|---|---|
| Native joined, **group is flowing** | Full group bitrate arrives on the NIC, plus IGMP/MLD membership reports on query (IGMPv3 general query, typically ~125s) | — |
| Native joined, **group is silent** | Membership reports only. Effectively free: by definition no data is arriving | — |
| AMT up, **group is flowing** | — | Full group bitrate inside the unicast tunnel, plus Membership Update refresh at the relay's advertised interval (QQIC, decoded into `RelayManager.intervalTime`) |
| AMT up, **group is silent** | — | Refresh traffic only |
| AMT up, **unsubscribed from group** | — | Keepalive/refresh only. No group data at any bitrate, and re-subscribing costs one Membership Update rather than a cold DRIAD + discovery + handshake |

The consequence: **keeping both joined while both deliver doubles ingress
bandwidth per channel.** On a Tier-1 multicast video path with many content
groups that is not a rounding error — it is the thing that makes "just leave both
up" unshippable as a steady state.

The last row is the one the decision below turns on, and it is why "tear down the
standby" is the wrong primitive: membership is what costs bandwidth, path state is
what costs latency to rebuild, and they can be dropped independently.

The asymmetry does not by itself rescue the design, though the first version of
this doc claimed it did. It is true that when *native is dead and we are on AMT*
the native join costs membership reports and nothing else — that is precisely
what "native is dead" means, and reversibility in that direction is nearly free.
But that is the cheap direction and also the non-urgent one; traffic is already
flowing. The direction that actually hurts is the reverse — native was carrying
the channel and dies — and there the standby we need is the AMT one, whose
useful and expensive states *are* the same state. Only separating membership from
path state makes both directions cheap at once.

## Decision

**Keep the loser joined only when the loser is silent; tear it down once it is
demonstrably carrying the same traffic as the winner.**

Concretely:

- `Open` binds native **and** brings AMT up, concurrently, and returns without
  waiting for either to prove itself. This removes the per-channel probe window
  from startup (AC 2).
- Exactly one path is **active** at a time. The data plane reads from the active
  path only. This is what makes "no duplicates" true by construction rather than
  by deduplication (AC 4).
- The **standby** path is watched by a cheap liveness sampler, not read by the
  data plane. Anything it does deliver is discarded — those packets are
  duplicates of the active path's, or the active path is dead and we are about to
  switch. "Watched" means its socket counters are sampled, not that it is drained
  at line rate; see *Why not multiplex the data plane* for why that distinction
  is load-bearing.
- Native is preferred on a tie: it is the cheaper path and the one the AMT tunnel
  exists to substitute for.
- **Teardown drops the standby's group membership, never its path state.** Once
  the standby has been observed carrying traffic for a settling period, it is
  *unsubscribed* from the group — that is the doubled-bandwidth state and it must
  not persist. What it is not is deconstructed: an AMT standby keeps its relay,
  its gateway handle and its keepalive, so re-activating it costs one membership
  update rather than a cold handshake. If the standby is *silent*, even the
  membership stays, because a silent standby carries no traffic to save and its
  membership is the only thing that makes recovery possible without a restart
  (AC 1).

That last bullet is the whole decision in one line, and it is why this is not
simply "option 2 as described". Option 2 — both paths up for the process
lifetime — is right about reversibility and wrong about cost. But the naive
repair of it is wrong in a way worth writing down, because it was the first
version of this section and a review caught it (Ally on go-amt#58).

**Why teardown cannot key on observed delivery alone.** An AMT standby is joined
to the same group through a relay that unicasts it to us, so it is *by
construction* always delivering — it can only fall silent if the tunnel breaks.
Native, meanwhile, is preferred on a tie (above), so it is the active path
whenever it works. Compose those two and "tear down the standby that is
delivering" reduces on the real topology to *always tear down AMT, always keep
native* — which removes reversibility in precisely the direction we need it. The
steady state becomes native-active with no AMT standby at all; then native dies,
the BLO-28640 direction, and there is nothing to fail over to.

That direction is also the expensive one to rebuild. A cold AMT re-establish pays
DRIAD (`driad.go`, RFC 8777) plus relay discovery, advertisement, membership
query and update — bounded by `DefaultOpenTimeout`, which is **10s**
(`gateway.go`). That is the same 10s as `MinUsefulProbeWindow`, i.e. exactly the
latency AC 2 exists to delete from startup, silently reintroduced and now paid
*during an outage* instead of at boot. Recovering the other way — back to native
— is a single IGMP join and is not urgent, because traffic is already flowing
over AMT.

So the asymmetry is real, but it is an asymmetry in **what silence means**, not
in which path is cheap to keep: native-silent is evidence the path is dead, while
AMT-silent is evidence the tunnel is broken. Neither maps onto "cheap to keep".
Splitting membership from path state is what dissolves it — `sendMembershipLeave`
and `sendTeardown` are already separate operations (`gateway.go`), so dropping a
subscription while retaining the tunnel needs no new protocol work. The bandwidth
cost goes away, the reversibility does not, and no path is ever abandoned on the
strength of a decision that only looked correct in the direction that never
fails.

Making teardown conditional on *observed duplicate delivery*, and scoping it to
the membership rather than the path, keeps the reversibility everywhere and drops
only the bandwidth.

### Why not multiplex the data plane

The obvious implementation — a reader goroutine per path feeding a shared channel
— must be rejected explicitly, because it will be the first thing anyone
proposes.

`ReadBatch` hands the caller's own buffers to the kernel. A goroutine that reads
ahead of the caller cannot read *into* those buffers, so it must allocate and
then copy on delivery. That adds an allocation, a copy, and a channel hop to
**every packet on the hottest path in the receiver**, to solve a problem that
occurs at most twice in a process lifetime.

Arbitration avoids all of it: the active path is read directly, exactly as today,
with no copy and no channel. Only the standby — whose packets are thrown away —
pays anything, and it can be sampled cheaply rather than drained at line rate.

Sampling and draining are not the same claim, and the difference has to be named
or the design contradicts itself. A standby delivering at line rate but read only
occasionally will overrun its socket buffer continuously — which is fine for the
liveness question and misleading for everything else, because the kernel drop
counters it produces are indistinguishable from an incident, and the
pre-activation drain below becomes unbounded.

So the liveness signal is **not** "did we read a packet". It is the socket's own
counters: `SO_RXQ_OVFL` (overflow count) together with the byte/packet counters,
which move whether or not userspace reads. A standby whose counters advance is
delivering, at a cost of one `recvmsg` with `MSG_DONTWAIT` per interval rather
than per packet. Two consequences follow and are deliberate: standby overflow is
expected and must be excluded from the drop alerting that watches the active
path, and the pre-activation drain is bounded by the socket buffer, not by the
silence duration — it is a fixed-size discard, which is what makes "drop
seconds-old packets" below a bounded operation.

### Switchover mechanics

The hazard is a read already parked on the old active path when the arbiter
switches. Blocking reads do not observe a field change.

- The arbiter unblocks a parked reader with `SetReadDeadline(now)` on the
  outgoing path, then restores the caller's deadline on the incoming one.
- The reader treats *that specific* timeout as a retry against the new active
  path, not as an error to return. A caller-set deadline must still surface as a
  timeout, so the two cannot be conflated — the retry is keyed on a generation
  counter the arbiter bumps, not on the timeout alone.
- Before a path becomes active, its socket buffer is drained. A standby that has
  been silent may hold a burst that arrived just before the switch, and
  delivering seconds-old packets as current is worse than dropping them.
- The outgoing socket is not closed at switchover, only deactivated — so no read
  is ever served from a closed socket (AC 4), and a switch back does not need a
  fresh IGMP join.

### `IsUsingTunnel()` becomes a sample, not a fact

Today it is `mc.amtGw != nil` — a property fixed at `Open`. Under this design the
active path can change, so every caller has to be re-read as asking "which path
is active *right now*", and the answer can be stale before it is used.

`ReadBatch` and `ReadFromWithControlMessage` branch on it today. They must
instead take the active path as a single snapshot and use that one value for the
whole call, never re-testing mid-read — otherwise a switch between the branch and
the read sends the AMT decoder a native packet, or vice versa.

The method stays, because operators and metrics legitimately want the sample, but
it stops being load-bearing for correctness inside the package.

## Phasing

1. **Item 2 — deliver the probe packet.** Done. Small, independent of everything
   above, and it retires roughly one signalling interval (>=5s) of startup
   latency on the signalling channel. The `pendingStore` seam it introduces is
   reused by the switchover drain in item 1.

2. **Arbiter, native-vs-AMT, no teardown.** Both paths up, one active, standby
   watched. Ship with the conditional teardown disabled so the steady state is
   observable before it is optimised. Note what that configuration *is*: both
   paths subscribed and both delivering — the doubled-ingress state *What "both
   paths" actually costs* calls unshippable as a steady state. So phase 2 is **lab and
   canary only**, bounded to a named set of groups, and is not a fleet rollout
   step. Its purpose is to produce the telemetry phase 3 needs, not to run.
3. **Conditional teardown after the settling period.** Only once step 2's
   telemetry shows how often both paths genuinely deliver at once.

Steps 2 and 3 need the `fakerelay` harness to drive `MulticastConn`, which it
does not do today — it exercises `RelayManager`/`ManagedConn`. That harness gap
is real work and is called out here so it is not discovered mid-implementation.

## Open questions

- **Re-subscribe cadence for an unsubscribed standby.** Step 3 drops the group
  membership of a standby that was observed delivering. While it is
  unsubscribed it carries no traffic, so its counters cannot report liveness —
  and if the active path then goes silent, the arbiter is choosing blind. A
  periodic re-subscribe is the fallback; its cadence trades a membership
  update (IGMP join/leave, or an AMT membership update on the tunnel) against
  detection latency and is not yet chosen. Retaining the path state makes each
  probe cheap, which is what makes a short cadence affordable at all.
- **Per-group or per-process arbitration.** Every group on a host almost always
  shares a verdict. Arbitrating per process would collapse N probe windows into
  one, but couples unrelated channels — a decision worth making deliberately
  rather than by omission.
- **v6.** `Open`'s v6 branch still returns "v6 AMT tunnel fallback not yet
  supported". Dual-path does not change that; it makes it more visible, because
  the v6 native join now has no fallback to arbitrate against.

[BLO-28740]: https://paperclip.blockcast.net/BLO/issues/BLO-28740
[BLO-28640]: https://paperclip.blockcast.net/BLO/issues/BLO-28640
