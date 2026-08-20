# AMT delivery-path selection: from a startup guess to a reversible decision

Status: **proposed**. Item 2 (deliver the probe packet) is implemented in
go-amt#49's follow-up; item 1 (reversible path selection) is specified here and
not yet built.

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

The consequence: **keeping both joined while both deliver doubles ingress
bandwidth per channel.** On a Tier-1 multicast video path with many content
groups that is not a rounding error — it is the thing that makes "just leave both
up" unshippable as a steady state.

But the asymmetry rescues the design. The case we actually need reversibility for
is *native is dead, we are on AMT*. In that state the native join costs
**membership reports and nothing else**, because no data is flowing on it — that
is precisely what "native is dead" means. So the expensive combination and the
useful combination are not the same combination.

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
- The **standby** path is drained by a cheap liveness watcher, not by the data
  plane. Its packets are discarded — they are duplicates of the active path's, or
  the active path is dead and we are about to switch.
- Native is preferred on a tie: it is the cheaper path and the one the AMT tunnel
  exists to substitute for.
- **Teardown is conditional on both paths delivering.** Once the standby has been
  observed carrying traffic for a settling period, it is torn down — that is the
  doubled-bandwidth state and it must not persist. If the standby is *silent*, it
  stays joined indefinitely, because it costs almost nothing and it is the only
  thing that makes recovery possible without a restart (AC 1).

That last bullet is the whole decision in one line, and it is why this is not
simply "option 2 as described". Option 2 — both paths up for the process
lifetime — is right about reversibility and wrong about cost. Making teardown
conditional on *observed duplicate delivery* keeps the reversibility where it is
free and drops it where it is expensive.

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
   observable before it is optimised.
3. **Conditional teardown after the settling period.** Only once step 2's
   telemetry shows how often both paths genuinely deliver at once.

Steps 2 and 3 need the `fakerelay` harness to drive `MulticastConn`, which it
does not do today — it exercises `RelayManager`/`ManagedConn`. That harness gap
is real work and is called out here so it is not discovered mid-implementation.

## Open questions

- **Re-probe cadence when native is torn down.** Step 3 tears down a native join
  that was observed delivering. If it later goes silent *and* AMT is also silent,
  there is nothing left to detect recovery with. A periodic re-join is the
  fallback; its cadence trades an IGMP join/leave pair against detection latency
  and is not yet chosen.
- **Per-group or per-process arbitration.** Every group on a host almost always
  shares a verdict. Arbitrating per process would collapse N probe windows into
  one, but couples unrelated channels — a decision worth making deliberately
  rather than by omission.
- **v6.** `Open`'s v6 branch still returns "v6 AMT tunnel fallback not yet
  supported". Dual-path does not change that; it makes it more visible, because
  the v6 native join now has no fallback to arbitrate against.

[BLO-28740]: https://paperclip.blockcast.net/BLO/issues/BLO-28740
[BLO-28640]: https://paperclip.blockcast.net/BLO/issues/BLO-28640
