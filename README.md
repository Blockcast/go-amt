Automatic Multicast Tunneling (AMT)
====================================

A Golang implementation of the Automatic Multicast Tunneling (AMT) protocol, as defined in [RFC 7450](https://tools.ietf.org/html/rfc7450).

## Installation

```bash
go get github.com/blockcast/go-amt
```

## Usage

The library has a pure-Go protocol path, but the legacy `amt_gw` and
`amt_bridge` example commands require CGO. The `blockcast-shreds` demo command
is pure Go and builds as a static binary with `CGO_ENABLED=0`.

### With CGO (optional, for Rust library performance)

To use the optimized Rust-based implementation via CGO:

1. **Build the Rust library** from [pim-multicast-gateway](https://github.com/Blockcast/pim-multicast-gateway):

```bash
cd pim-multicast-gateway/packages/amt-protocol
make ffi
```

2. **Install to system paths** or provide library location:

```bash
# Option A: Install to system (requires sudo)
sudo cp target/release/libamt_protocol.so /usr/local/lib/
sudo cp include/amt_protocol.h /usr/local/include/
sudo ldconfig

# Option B: Provide paths via environment variables
export CGO_CFLAGS="-I/path/to/amt-protocol/include"
export CGO_LDFLAGS="-L/path/to/amt-protocol/target/release -lamt_protocol"
```

3. **Build with CGO enabled**:

```bash
CGO_ENABLED=1 go build
```

### Build Constraints

| Build                  | Implementation | Requirements                  |
|------------------------|----------------|-------------------------------|
| `CGO_ENABLED=0`        | Pure Go        | None                          |
| `CGO_ENABLED=1` (no lib) | Pure Go      | None (CGO files won't compile without library) |
| `CGO_ENABLED=1` + lib  | Rust FFI       | libamt_protocol installed     |

### Shred delivery demo

```bash
CGO_ENABLED=0 go build -o blockcast-shreds ./cmd/blockcast-shreds
./blockcast-shreds selftest --fixture
```

Run `./blockcast-shreds --help` for demo-mode unicast listen, repeatable feed,
and Jito-proxy-compatible `--dest-ip-ports` forwarding flags.

To measure the value of a second feed, bind one socket per named input:

```bash
./blockcast-shreds \
  --feed blockcast=0.0.0.0:20000 \
  --feed existing=0.0.0.0:20001
```

The receipt is the **measured worth of a second feed**: each feed's own
unrecoverable (erasure) fraction and mean distinct shreds per FEC set, the
first-arrival-wins union's fraction, the FEC sets the extra feeds rescued
(`second_feed_measured_worth ... rescued_sets= gap_closed_fraction=`), and what
share of unique shreds arrived first on each feed. Pass `--json` (also accepted
by `selftest --fixture`) for the same numbers as a machine-readable document.

Honesty caveat: the union numbers quantify what the observed second input added
during this run — nothing more. They do not prove the feeds are independently
operated or path-decorrelated, and if both inputs ultimately share one tap the
tool cannot detect it. Do not present the union figure as evidence of
decorrelated infrastructure; state each input's actual origin, and prefer a
second feed the viewer already operates as the genuinely independent input.

The `gap_ms` line ends with `reordered=`, which counts arrivals whose timestamp
did not advance the frontier and from which no inter-arrival gap could be
derived. Arrival timestamps are captured at the socket read, before any
per-packet work, so with more than one `--feed` two goroutines can capture
`t1 < t2` and reach the scorer as `t2, t1`. Those arrivals are counted here
rather than bucketed, because the alternative — a negative gap — falls through
the bucket ladder into `<1` and silently inflates the sub-millisecond count.
The buckets plus `reordered` account for every non-first shred, so a non-zero
`reordered` means the histogram is a sample of arrivals rather than all of
them. The histogram itself is derived from the first-*processed* copy of each
shred: a duplicate that turns out to be older does not retroactively re-derive
the gap already recorded against it, so with more than one `--feed` the gap
buckets keep the processing-order dependence that `unique_first` no longer has.
Completion latency is repaired rather than merely unaffected: an earlier
duplicate lowers its FEC set's arrival floor, so `time_to_32nd_shred` measures
the set's arrival extent and not the timestamp of whichever copy was processed
first. The repair reaches only sets that are still incomplete — a set's latency
is frozen when its 32nd distinct shred lands — and it lowers the floor only, so
a set whose newest counted shred was itself raced keeps a slightly wide extent.

### Retention: what the receipt is exact about

The receiver is a long-running process, so the scorer cannot keep per-shred state
for the life of the run — at mainnet shred rates that is hundreds of megabytes
per hour and no steady state. It keeps that state for a **window** past each
arrival (`--retain`, default `2s`) and folds anything older into counters.

What the window bounds is not what the receipt *counts* but what can still be
recognised as a *repeat*:

- **Exact for the whole run**, however long it runs: `sets_total`, `sets_erased`,
  `erasure_fraction`, `mean_shreds_per_set`, `unique_shreds_total`,
  `unique_first`, `first_arrival_fraction`, `rescued_sets`, and the `gap_ms`
  histogram. These are counters; reclamation advances them, it does not reset
  them. `sum(unique_first) == unique_shreds_total` holds exactly, always.
- **Exact within the window**: which feed gets first-arrival credit for a given
  shred. A copy arriving on a second feed with an earlier timestamp moves the
  credit — that is what makes `first_arrival_fraction` a function of the arrivals
  rather than of goroutine scheduling — but only while the shred's identity is
  still retained.
- **Given up beyond the window**: a second copy of a shred arriving more than
  `--retain` after the first has no surviving identity to match against, so it is
  counted as a new unique shred rather than as a duplicate. The duplicates this
  exists to recognise are the same shred on a second feed, milliseconds apart, so
  the default clears that by three orders of magnitude. Widen `--retain` if your
  inputs can be seconds apart; it costs memory, and it does not affect the
  completion-percentile ceiling below in either direction.

The window is measured on the **arrival clock**, not in slots.
`erasure/tracker.go` bounds comparable state by slot distance (two slots behind
its frontier), which is correct for the dense live feed it scores. It is not
correct here: in the bundled capture the observed slots are 438757867, 438758026,
438758296, 438758365, 438758729 and 438758936 — gaps of 69 to 364 — and two of
them arrive with slot numbers several hundred *below* their neighbours' while
their timestamps are the newest yet seen. Scoring that capture with a
slot-distance window discards both and moves `erasure_fraction` from 0.286 to
0.000. A slot number is a property of the shred; "how long ago did this arrive"
is a property of the arrival.

Completion percentiles (`time_to_32nd_shred`) are the one approximation. Exact
quantiles cannot be computed in bounded memory over an unbounded stream, so
completions go into a fixed-size log-linear histogram and the reported value is
the upper edge of the bucket the true value fell in: **never below the truth, and
over by at most 0.78%** — for completions below the ladder's ceiling of
**4.194304s**. At or above the ceiling a completion lands in a single overflow
bucket that has no upper edge and reports its floor, so it understates instead,
by an unbounded amount.

**`--retain` does not bound this, and no window setting makes it impossible.**
The window ages a set on its *newest* arrival, so a set that keeps receiving
shreds is never evicted, and its first-to-32nd span is limited only by the
inter-arrival gap staying inside the window — not by the window itself. 32
shreds arriving 200ms apart span 6.2s at the 2s default, with every gap well
inside it. Measured, not hypothetical.

So the receipt reports the condition instead of predicting it:
`completions_above_ceiling` counts completions that landed in the overflow
bucket, out of `completions_total`. Any nonzero value means a percentile that
fell among them understates and the 0.78% figure does not apply to it — the
count and its denominator are both reported because one overflow in a million is
a different run from half of them. The human table prints the same warning
inline. Check it before quoting a percentile in a dispute.

Every other figure on the receipt is an exact counter rather than an
approximation — `selftest --fixture` reports the same sets, erasures, means and
gap buckets it did before the bound existed. That is not the same as saying they
are independent of `--retain`: as the third bullet above says, a duplicate
arriving beyond the window is counted as a new unique shred, so the window
decides what *counts* as a repeat even though nothing about the counting is
approximate.

`unique_first` and `first_arrival_fraction` are decided by the same arrival
timestamps, not by which feed's goroutine reached the scorer first. When a shred
already counted for one feed shows up on another with an earlier timestamp, the
credit moves to the earlier arrival. The recorded first arrival is therefore the
running minimum over every copy seen, and the totals are a function of the
arrivals alone: replaying one capture always yields the same split, and so does
any interleaving of it. Copies arriving within the same clock tick keep the
credit on whichever was processed first — with a coarse clock that tie-break,
not the concurrency, is the remaining ambiguity. Re-attribution only moves
credit between feeds, so `unique_first` still sums to `unique_shreds_total`.

Shreds are deduplicated on `(slot, fec_set_index, local_index)` — never on
`(slot, shred_index)` alone, which collapses distinct shreds because the in-set
index repeats across the FEC sets of a slot (the 31x distinct-shred undercount
found in BLO-26535). The local index already unifies data (`0..num_data-1`) and
coding (`num_data+position`) shreds.

### Generic mode — a payload that isn't shreds

The same client scores generic framed records: the same delivery receipt, on a
payload that isn't shreds. It reports window completeness, arrival percentiles
and arrival gaps, and reports no FEC erasure, because this mode does no erasure
coding.

```bash
./blockcast-shreds selftest --generic
```

Generic mode requires the provenance of its input to be stated, and refuses to
start otherwise — a receipt whose input provenance is unstated is exactly what
the rights guardrail exists to prevent:

```bash
./blockcast-shreds --mode generic --listen 127.0.0.1:7201 \
  --source-label synthetic \
  --rights-basis synthetic-generated-no-third-party-content
```

`gensend` emits the same synthetic feed as real datagrams so the receipt can be
driven end to end through the demo tap. See
[docs/demo/d5-payload-agnostic-receipt.md](docs/demo/d5-payload-agnostic-receipt.md)
for the framing contract, the end-to-end run, and the bounds of the claim.

### Receiver metrics

`--http-addr` serves Prometheus `/metrics` and a `/healthz` endpoint driven by
last-received-packet freshness. Every counter is labelled by `feed` and is
materialized at zero for each configured feed at startup, so a silent feed is
distinguishable from an unconfigured one.

`/healthz` is **readiness-shaped, not liveness-shaped.** It returns `503` from
process start until the first packet arrives, and again whenever the newest
packet is older than `--health-max-age` (default `30s`). Wiring it to a
Kubernetes `livenessProbe` will restart-loop a receiver that is healthy but has
simply not been sent traffic yet; use it as a `readinessProbe`, or gate the
liveness probe on something else.

| Metric | Unit | Meaning |
|---|---|---|
| `bcast_shred_gw_ingress_packets_total` | packets | Packets read from the feed socket. |
| `bcast_shred_gw_egress_packets_total` | **datagrams** | Successful writes to validator destinations. |
| `bcast_shred_gw_fanout_dropped_packets_total` | packets | Rejected at enqueue because the bounded ring was full. |
| `bcast_shred_gw_fanout_write_errors_total` | **datagrams** | Destination writes that failed or were short. |
| `bcast_shred_gw_shreds_unparsed_total` | packets | Delivered packets whose shred header did not parse. |

**Egress and write errors are counted per destination write, not per packet.**
One received packet fanned out to N `--dest-ip-ports` targets increments
`egress_packets_total` by N. To recover packets forwarded, divide by the
destination count:

```promql
rate(bcast_shred_gw_egress_packets_total[5m]) / <number of --dest-ip-ports>
```

The two silent drop sites are `fanout_dropped_packets_total` (ring overflow,
counted at enqueue) and `fanout_write_errors_total` (counted at the write).
Both represent packets that did not reach a destination; ingress minus drops is
not by itself a delivery guarantee. Scoring and metrics never gate delivery, so
a malformed or unattributable packet is still forwarded byte-identically.

`fanout_dropped_packets_total` counts **ring overflow only.** Enqueue also
refuses packets once the fan-out is closed, but that is a shutdown artifact
rather than receiver overload, so it is deliberately not counted: otherwise a
clean shutdown would inflate the metric and leave it disagreeing with
`Fanout.Stats().DroppedPackets`. A non-zero rate here always means the receiver
could not keep up.

These are receiver-observed counters. They describe what this process read and
wrote, not the validator's true replay deadline.

## License

MIT
