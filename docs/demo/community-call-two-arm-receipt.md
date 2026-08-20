# Community call — two-arm live receipt, prod vs union

Operator asset for the Solana validator community call. The theme is **path
diversity and how that affects your ability to decode**, so the demo runs one
`blockcast-shreds` client with two named arms and lets the receipt answer it.

Five minutes, three artifacts: an offline control anyone can recompute, a live
two-arm run on a DC-hosted receiver, and the receipt's own
`second_feed_measured_worth` line — the FEC sets the baseline arm could not
complete alone but the union could.

## The claim

One client, two feeds, first-arrival-wins. The baseline arm is the raw turbine
path; the second arm carries the additional ingest paths. The receipt reports
each arm's own erasure fraction, the union's, and the sets the extra arm
rescued. That last number is the claim, and it is a measurement of this run.

## What to run

Three commands. Every flag below is registered by the binary; CI asserts that,
because a previous revision of this script passed a `duration` and an `output`
flag that were never registered, and would have exited 1 on camera.

```sh
# 1. Offline control. Deterministic, no network, nothing to trust.
blockcast-shreds selftest --fixture

# 2. Live two-arm run. Order matters: prod first makes prod the baseline.
#    Both values are LOCAL bind addresses the taps forward into, not sources.
timeout -s TERM 300 blockcast-shreds \
  --feed prod=<receiver-bind-ip>:20001 \
  --feed union=<receiver-bind-ip>:20002 \
  --report-interval 5s \
  --http-addr 127.0.0.1:8080 \
  > receipt.txt

# 3. The live view, in a second pane, while 2 runs.
watch -n2 "curl -s http://127.0.0.1:8080/metrics | grep erasure_fraction"
```

### Why there is a third command

The receipt prints **once**, on the SIGINT/SIGTERM path. Nothing reaches stdout
before that. Verified: the redirect target is 0 bytes for the entire run and
2144 bytes after the signal. So a narration that says "watch the receipts
update" over command 2 alone is describing a blank screen for five minutes.
The live surface is `/metrics`; the receipt is the closing artifact.

`--report-interval` is why command 3 shows anything at all. It defaults to 30s,
and the erasure gauges read exactly `0` until the first window drains — at 5s
into a run with 401 payloads already ingested, every gauge was still `0`.
At `5s` the same run showed `prod 0.5` against `union 0`, which is the contrast
the demo exists to show. It also keeps a burst legible instead of averaging it
into a 30s window. The maximum accepted is 5m.

Prefer the human table over `--json` on camera. It is six lines and reads as the
narrative; the JSON reports percentiles in nanoseconds (`completion_p50_ns:
21000000`), which needs converting out loud.

## Expected numbers

Guardrails for the recording, not pass criteria. Live values come from the
rehearsal.

| Measure | prod / raw turbine | union | Notes |
|---|---:|---:|---|
| Unrecoverable FEC sets | 3–17% observed | ~0.06–0.3% observed | Show the run's own numerator and denominator. |
| `rescued_sets` | — | record live | Sets erased on prod alone, complete in the union. The headline. |
| `gap_closed_fraction` | — | record live | `rescued_sets` over total sets. |
| Time to 32nd shred, p50 | record live | ~21ms reference | Time to the 32nd shred. **Not** leader-to-receiver latency. |
| Turbine burst | 54% burst | near 0% same window | Keep the burst on the chart; do not smooth it. |
| At-source union control | n/a | 0.063% (`38/60,597`) | 2026-08-14 control, **not** a receiver result. |
| Receiver headroom | ≥~80 Mbit/s | same | A residential receiver read 33% erasure at ~23 Mbit/s effective against a ~70 Mbit/s feed. That is the receiver, not the feed. |

Two numbers on screen will be questioned, so state them before they are:

- **`bcast_shred_gw_erasure_grace_milliseconds` = 400.** This is what "erased"
  means: a set still under 32 of 64 shreds at the slot boundary plus this grace.
  It is on `/metrics`, so point at it rather than asserting it.
- **The fixture's own 28.57%.** It is a property of the bundled capture — a
  determinism control, not a quality result. Shown 30 seconds before "union is
  ~0.06%" it invites exactly the wrong inference, so name it as a replay
  artifact when it appears.

## Reading the word "union" on screen

The receipt uses `union` for two different things and the demo adds a third:

- `feed name=union` — the second **arm**, one input.
- `union erasure …` — the first-arrival **rollup of both arms**, computed by the
  client. With two arms this is a third number, better than either alone.
- "the union" in the narration — the product concept.

Say which one you are pointing at each time, or rename the second arm in the
invocation. The rollup is always the `union …` lines; the arm is always the
`feed name=` line.

## Dry-run checklist

Offline, no tap required:

- [ ] `selftest --fixture` prints the control receipt quoted under "Reproducing
      it" below, byte for byte.
- [ ] Two-arm command with **no traffic at all**, stopped with `timeout -s
      TERM`, still prints a full receipt whose last line reads
      `second_feed_measured_worth baseline=prod`. This rehearses the stop path
      and proves flag order, and needs neither a tap nor a packet.
- [ ] `timeout -s TERM` exits **124**, not 0 — don't read that as a failure, and
      don't wrap the command in `set -e`.
- [ ] `timeout -s KILL` is never used: SIGKILL skips the print and the run is
      lost. Verified — 0 bytes captured.
- [ ] Operator has rehearsed the manual Ctrl-C stop as the fallback.

Requires the DC host, CTO-side:

- [ ] Receiver is DC-hosted with ≥~80 Mbit/s downlink headroom, and is **not**
      the union source host. Measured interface recorded.
- [ ] Tap allowlist approved for both forward destinations.
- [ ] The two `--feed` values are **distinct** local bind ports, both taps
      confirmed forwarding into them.
- [ ] `prod` is listed first, and the receipt confirms `baseline=prod`.
- [ ] First received payload parses as a valid forwarder header with no offset
      adjustment or re-framing.
- [ ] `completions_above_ceiling` is **0** on the final receipt. Nonzero means a
      percentile among those completions understates by an unbounded amount and
      the documented 0.78% error does not apply — which voids the p50 headline.
      The ceiling is 4.194304s and the client prints a warning line when it
      happens.
- [ ] `erasure_frontier_resyncs_total` is 0 across the recorded window. Each
      resync is a discontinuity: sets in flight were dropped unscored, so the
      erasure series has a gap in it.
- [ ] `--mode` is left at its default. Generic mode reports no FEC erasure and
      no cross-feed union, which is both headline numbers.
- [ ] Recording shows both arms, the p50, the gap histogram, and the
      `second_feed_measured_worth` line.
- [ ] Narration states that raw-path erasure is the incompleteness of a single
      unstaked ingest path, and that the union is the answer.
- [ ] Reviewer records a dated pass or fail with artifact links.

## What this does not show

- **Not evidence of independently operated paths.** The receipt measures the run
  in front of it. It cannot tell whether the two arms are independently operated
  or share one tap, and it must never be presented as proof that they are
  decorrelated.
- **No claim of open access**, and nothing here is attested. The receipt is
  recomputable from the packets; that is a different and smaller claim.
- **No competitor attack framing.** The comparison is between two paths into our
  own receiver.
- **Not a latency benchmark.** Time to the 32nd shred is measured at the
  receiver from its own arrivals. It is not leader-to-receiver end-to-end
  latency, and the two must not be conflated.
- **Not a durability claim.** A five-minute window is a five-minute window.

## Reproducing it

The offline control, which the audience can run themselves:

```sh
blockcast-shreds selftest --fixture
```

```
time_to_32nd_shred p50=79.871ms p95=133.119ms p99=133.119ms
erasure sets=7 erased=2 fraction=0.285714 mean_shreds_per_set=30.71
gap_ms <1=137 1-2.4=25 2.4-7=26 7-32=14 >=32=12 reordered=0
```

Those three lines are asserted against the binary in CI, so this document cannot
drift from what the client actually prints. An earlier revision of this script
recorded an md5 of the same command that no longer matched a working build.
