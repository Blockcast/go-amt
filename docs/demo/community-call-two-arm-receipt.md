# Community call — two-arm live receipt, prod vs union

Operator asset for the Solana validator community call. The theme is **path
diversity and how that affects your ability to decode**, so the demo runs one
`blockcast-shreds` client with two named arms and lets the receipt answer it.

Five minutes, three artifacts: an offline control anyone can recompute, a live
two-arm run on a DC-hosted receiver, and the receipt's own
`second_feed_measured_worth` line — the FEC sets the baseline arm could not
complete alone but the union could.

## The claim

One client, two feeds, first-arrival-wins. The baseline arm is the production
forwarder path (`prod`); the second arm carries the additional ingest paths. The receipt reports
each arm's own erasure fraction, the union's, and the sets the extra arm
rescued. That last number is the claim, and it is a measurement of this run.

The `prod` arm's loss is ours: our own forwarder and receive-socket drops. Say
so when it is on screen, and never narrate it as Turbine loss.

## What to run

Three commands. Every flag below is registered by the binary; CI asserts that,
because a previous revision of this script passed a `duration` and an `output`
flag that were never registered, and would have exited 1 on camera.

```sh
# 1. Offline control. Deterministic, no network, nothing to trust.
blockcast-shreds selftest --fixture

# 2. Live two-arm run, derived from docs/demo/receipts/2026-10-13/rehearse2.sh
#    (that script forced 8 MiB via sock-rcvbuf.py and used :18080; this relies
#    on the built-in --rcvbuf default, also 8 MiB).
#    Order matters: prod first makes prod the baseline. Native SSM joins on an
#    on-net receiver; quote the values, the ? would otherwise glob.
timeout -s TERM 150 blockcast-shreds \
  --feed 'prod=ssm://69.25.95.197@232.0.0.1:5001?iface=eth0' \
  --feed 'union=ssm://69.25.95.57@232.0.0.2:5001?iface=eth0' \
  --report-interval 5s \
  --http-addr 127.0.0.1:8080 \
  > receipt.txt

# 3. The live view, in a second pane, while 2 runs.
watch -n2 "curl -s http://127.0.0.1:8080/metrics | grep erasure_fraction"
```

### Off-site variant: AMT through the relay

A receiver that is not on-net cannot join natively. Point the union arm at the
relay and let it fall back to an AMT tunnel:

```sh
timeout -s TERM 150 blockcast-shreds \
  --feed 'union=ssm://69.25.95.57@232.0.0.2:5001?relay=69.25.95.128' \
  --report-interval 5s \
  --http-addr 127.0.0.1:8080 \
  > receipt.txt
```

Operational guidance, not measurements (from the BLO-45838 build plan, as of
2026-10-16; no committed receipt backs these):

- The first ~10 s is the native probe. Nothing arrives until it times out and
  the tunnel comes up, so the gauges sit at `0`; do not narrate over that gap.
- Restart at most once per 13 minutes for this source and group, counted across
  every host, until the relay runs build #248. A faster re-join is not served.

### Why there is a third command

The receipt prints **once**, on the SIGINT/SIGTERM path. Nothing reaches stdout
before that. Verified: the redirect target is empty for the entire run and holds
the full receipt only after the signal. So a narration that says "watch the receipts
update" over command 2 alone is describing a blank screen for the whole 150 s run.
The live surface is `/metrics`; the receipt is the closing artifact.

`--report-interval` is why command 3 shows anything at all. It defaults to 30s,
and the erasure gauges read exactly `0` until the first window drains, however
many payloads have already arrived. At `5s` the first window shows the prod arm
above zero and the union arm at zero, which is the contrast the demo exists to
show. It also keeps a burst legible instead of averaging it
into a 30s window. The maximum accepted is 5m.

Prefer the human table over `--json` on camera. It is six lines and reads as the
narrative; the JSON reports percentiles in nanoseconds (`completion_p50_ns:
21000000`), which needs converting out loud.

## Expected numbers

Guardrails for the recording, not pass criteria. **Narrate the rehearsal's own
receipt, never this section's**: every figure here is dated, and each one links
the committed receipt it came from, or for 2026-10-16 a labelled transcription
of it until the verbatim `receipt.txt` lands.

**Post-G2, 2026-10-16** ([receipt](receipts/2026-10-16/w75-rebaseline.md),
devbox `69.25.95.32` in sfo12, 180 s, native joins, after the G2 roll at
12:06:50Z). The prod-source arm erased **310/16,469 = 1.88%**, the union-source
arm **18/16,469 = 0.11%**, and the two together **17/16,469 = 0.10%**.
`rescued_sets` was **293** (1.78% of sets). Host drops were 70 of 2,018,370
packets (0.003%), with no clamp warning. That run named its arms `listener` and
`merged`; the sources are the `prod` and `union` sources above.

**Pre-G2, 2026-10-13** ([all four runs](receipts/2026-10-13/README.md), same
receiver and sources). The prod arm erased **4,675/14,260 = 32.8%** and
**5,359/15,842 = 33.8%** on the two 150 s two-arm runs. Raising the receive
buffer is what fixed the two-arm receiver: the union arm went from
**339/14,260 = 2.38%** at the kernel default buffer to **45/15,842 = 0.28%** with
8 MiB, and host `UdpRcvbufErrors` fell from +54,026 to +1,331. The union-only
residual looked like the feed, not the receiver: **96/6,536 = 1.47%** with the
raised buffer, and **21/2,410 = 0.87%** clamped to the kernel default. That last
run covered only 2,410 sets, so treat it as a hint. These numbers describe the
feed before G2; do not narrate them as current.

So the contrast to expect is roughly 1.9% against 0.1%, not the pre-G2 33%
against under 1%.

| Measure | prod arm | union | Notes |
|---|---:|---:|---|
| Unrecoverable FEC sets | record live | record live | Show the run's own numerator and denominator. |
| `rescued_sets` | — | record live | Sets erased on prod alone, complete in the union. The headline. |
| `gap_closed_fraction` | — | record live | `rescued_sets` over total sets. |
| Time to 32nd shred, p50 | record live | record live | Time to the 32nd shred. **Not** leader-to-receiver latency. |
| Prod-arm burst | record live | record live, same window | Keep the burst on the chart; do not smooth it. |
| Receiver headroom | above the feed rate | same | A receiver below the feed rate scores its own drops as erasure. That is the receiver, not the feed. |

Two numbers on screen will be questioned, so state them before they are:

- **`bcast_shred_gw_erasure_grace_milliseconds` = 400.** This is what "erased"
  means: a set still under 32 of 64 shreds at the slot boundary plus this grace.
  It is on `/metrics`, so point at it rather than asserting it.
- **The fixture's own 28.57%.** It is a property of the bundled capture — a
  determinism control, not a quality result. Shown 30 seconds before the union's
  own figure it invites exactly the wrong inference, so name it as a replay
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

- [ ] Receiver is DC-hosted with downlink headroom above the feed rate, and is **not**
      the union source host. Measured interface recorded.
- [ ] The run starts with no `receive buffer clamped` warning: the receiver has
      `CAP_NET_ADMIN`, or `net.core.rmem_max` covers the 8 MiB each feed asks
      for (`--rcvbuf`). A clamped receiver drops bursts at its own socket and
      scores them as erasure. Bracket the run with `nstat -saz UdpRcvbufErrors`
      and quote the host's drop count beside the erasure numbers.
- [ ] Receiver is on-net for the native `ssm://` joins, or uses the off-site
      AMT variant above. The two `--feed` values name **distinct** sources.
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
