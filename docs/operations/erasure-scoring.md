# Receiver-observed erasure scoring

The receiver publishes a delivery score the customer can audit from its own
machine, on `/metrics` and (once the broker lane lands) in the 30-second
heartbeat. This note states what that number means, because two different
delivery numbers come out of the same process and they are not interchangeable.

## The scored definition

A shred belongs to an FEC set identified by `(slot, fec_set_index)`. Each set
holds up to 64 shreds, 32 data and 32 coding. A set is **complete** at 32
distinct shreds and **erased** if it is still below 32 when it is scored.

A set is scored at `slot_boundary + erasure_grace`, where:

* `slot_boundary` is when the receiver first saw a **later** slot. A slot is not
  scored until a later slot proves it ended, so the newest slot in flight is
  never scored.
* `erasure_grace` is `--erasure-grace-ms`, default 400 ms, published as
  `bcast_shred_gw_erasure_grace_milliseconds`.

Duplicates count once. State is retained until it is scored, then reclaimed.
Retention is therefore a **rate**, not a constant: every slot observed within the
last `erasure_grace` is still unscorable, so retained slot state is about
`(observed-slot arrival rate x erasure_grace) + 1`. At steady capture rates that
is a handful of slots; during a burst or catch-up replay it rises with the
arrival rate for the duration. `--report-interval` is bounded above for the same
reason — the tracker holds one arrival timestamp per shred until the window
drains, so the interval sets resident memory as well as reporting cadence.

This is a **receiver-observed, comparable v1 score. It is not the validator's
true replay deadline** and must not be quoted as one.

## Two numbers, deliberately

| | `/metrics` + heartbeat | the stdout receipt |
|---|---|---|
| source | `erasure.Tracker` | `shred.FeedScorer` |
| question | was this set complete **at its deadline**? | did this set **ever** complete, over the whole run? |
| window | the last drained reporting window | the entire process lifetime |
| authoritative for the SLA | **yes** | no |

They disagree, and the disagreement is the point. On the bundled 401-shred
capture the receipt reports `sets_total 7, sets_erased 2, fraction 0.2857` while
`/metrics` reports `total 4, erased 0`. Neither is wrong:

* Two of the receipt's sets are single shreds for slots `438757867` and
  `438758026` that arrive **90 to 120 seconds late**, roughly 500 slots behind
  the newest slot at the time. Their scoring deadline passed long before, so the
  tracker declines them; the receipt, having no deadline, counts them as sets
  that never completed.
* One more set belongs to the newest slot, which no later slot has ended.

**The tracker is authoritative for the delivery SLA.** The receipt is a
whole-run summary for demo and debugging. Do not reconcile them by loosening the
deadline: a score that counts a shred arriving two minutes late is not a score
of timely delivery.

## Reading the metrics

`erasure_sets`, `erasure_fraction`, `shreds_per_second` and `gap_events` are all
**windowed gauges**, drained together every `--report-interval` (default 30s, to
match the heartbeat) and published from one snapshot so a scrape can never mix
two windows.

Because they are windowed, they fall back to zero when a window carries no
traffic. **`erasure_fraction 0` therefore means "no erasure in the last window"
OR "no traffic in the last window".** Do not alert on it alone:

* `bcast_shred_gw_ingress_packets_total` is a monotonic counter — a flat counter
  is a dead feed, whatever the fraction says.
* `/healthz` fails on last-packet freshness.

Alert on feed liveness first and the erasure fraction second. An erasure gauge
read on its own reports a stopped feed as a perfect one.

### Slot-guard counters

Slot arrives from the wire unvalidated, so the tracker refuses observations whose
slot is implausible relative to the frontier. Those refusals are **cumulative
counters**, not windowed gauges — they survive a window drain, because a frontier
resync is a discontinuity you must still be able to see afterwards.

* `bcast_shred_gw_erasure_slot_rejections_total{direction="ahead"}` — refused for
  jumping further forward than the frontier bound allows.
* `bcast_shred_gw_erasure_slot_rejections_total{direction="behind"}` — refused for
  sitting too far behind the frontier. **Sustained growth here means the frontier
  itself is suspect**: real traffic is being refused because an earlier advance
  moved it too far. The tracker self-heals after a sustained coherent run, and
  each recovery shows up as a resync.
* `bcast_shred_gw_erasure_frontier_resyncs_total` — the frontier was abandoned and
  re-adopted. Sets in flight were dropped unscored, so treat every increment as a
  gap in the erasure series rather than as a data point in it.

A resync is rare on a healthy feed. `increase(...frontier_resyncs_total[1h]) > 0`
alongside a flat erasure fraction is the signature of a feed whose SLA series is
being interrupted rather than one that is clean.
