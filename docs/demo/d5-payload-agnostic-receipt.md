# D5 — the same delivery receipt, on a payload that isn't shreds

## The claim

**"the same delivery receipt, on a payload that isn't shreds"**

That sentence is the whole claim. Everything below either supports it or bounds it.

## Three modes of one prototype

D3, D4 and D5 are not three products and not three demonstrations of separate
capabilities. They are **three modes of one prototype** — the same
`blockcast-shreds` client binary, the same scoring primitives, one mode flag:

| Mode | Input | What the receipt reports |
|---|---|---|
| **D3** | a live shred feed through the tap | FEC-set completion, erasure fraction, arrival gaps |
| **D4** | two shred feeds at once | the same, per feed, plus the union across them |
| **D5** | generic framed records that are not shreds | window completeness, arrival percentiles, arrival gaps |

The point of showing all three together is the *sameness*, not the variety. The
gap histogram and percentile code paths are shared source, not
reimplementations — the two scorers call the same `GapHistogram.observe` and
`percentile`, so the modes cannot drift into reporting differently-computed
numbers. D5 exists to show that the measurement is a property of the rail, not
of the payload.

## What was run

A synthetic framed feed, sent as real datagrams, through the same forwarding
path the shred demo uses, into the same client:

```
blockcast-shreds gensend  →  SSM 232.10.10.1:7200  →  shred-demo-tap  →  127.0.0.1:7201  →  blockcast-shreds --mode generic
```

Tap counters for the run:

```text
DEMO ONLY: joining (S=10.244.13.46,G=232.10.10.1):7200 on 10.244.13.46; 1 reviewed destinations
packets_in=188 destination=d1-generic packets_out=188 send_errors=0
```

Client receipt for the same run:

```text
mode=generic source=synthetic rights=synthetic-generated-no-third-party-content
feed name=default
generic source=synthetic rights=synthetic-generated-no-third-party-content
window_fill p50=41.764506ms p95=48.770219ms p99=48.770219ms
completeness windows=6 complete=4 expected=192 received=186 fraction=0.968750
loss interior=3 trailing=3 duplicates=2 out_of_order=2
gap_ms <1=33 1-2.4=137 2.4-7=14 7-32=1 >=32=0
```

The loss figures — `expected=192 received=186`, `interior=3 trailing=3
duplicates=2 out_of_order=2` — are identical to the in-process fixture replay
(`selftest --generic`). That identity is the useful part: the anomalies are
baked into the synthetic feed, the transport delivered every datagram it was
given (`send_errors=0`, `packets_in == packets_out`), and the scoring is
therefore transport-independent. The timing lines differ between the two runs,
and should: those are real wire arrivals rather than fixture timestamps.

## The input is synthetic, and says so

The feed is generated, not captured. It contains no third-party content.

Both `--source-label` and `--rights-basis` are **mandatory** in generic mode —
the client refuses to start without them, and prints them at startup and again
in the receipt. There is no default and no unlabelled constructor, so a receipt
cannot be produced whose input provenance is unstated.

Public readability of a feed is not evidence of redistribution or
commercial-demo rights. No third-party capture is used here, and none should be
added without a recorded review of its governing terms.

## What the framing contract has to define

A receipt that only counts what arrived cannot say anything about what didn't.
Three things are defined explicitly so the completeness number means something:

- **Monotonic sequence** — every record carries one, which is what makes
  reordering detectable as reordering rather than as loss.
- **Expected terminal count** — every record repeats the window's declared
  length. Not a "final" flag on the last record: a flag is itself droppable, so
  a window whose tail was lost would be indistinguishable from one still in
  flight. Repeating the count means any one surviving record of a window
  establishes what completeness for that window requires.
- **Clock basis** — every latency is measured from the arrival instant observed
  by the receiving process. No sender timestamp is read from the wire, so these
  are receive-side observations and assert nothing about clock sync between
  sender and receiver.

Duplicates and out-of-order records are counted and reported, and neither can
raise completeness above what distinctly arrived.

## What this does not show

This mode demonstrates one thing: the receipt is computable on a payload that
is not shreds. It does **not** show, and must not be described as showing:

- a market-data product, or any product
- integration with any publisher, or the ability to integrate with one
- any redistribution or commercial-demo rights to any third-party feed
- schema or sequence semantics for any real-world feed — the framing here is
  ours, and defined for this demo
- freshness or staleness semantics
- loss recovery or repair — nothing here retransmits, reconstructs, or corrects
  anything, and no FEC erasure is reported in this mode because none is computed
- entitlement, authentication, metering, or access control
- operational readiness, deployment posture, or a handoff of anything to anyone

A window all of whose records are lost is invisible to this receipt, and the
receipt does not pretend otherwise: completeness is scoped to windows from which
at least one record arrived.

## Reproducing it

```bash
# In-process, no network — the deterministic fixture.
go run ./cmd/blockcast-shreds selftest --generic

# End to end through the tap. Same-host SSM needs no NET_ADMIN or veth;
# --iface must be the address the tap has configured as its SSM source.
shred-demo-tap --config config.yaml &
blockcast-shreds --mode generic --listen 127.0.0.1:7201 \
  --source-label synthetic \
  --rights-basis synthetic-generated-no-third-party-content &
blockcast-shreds gensend --to 232.10.10.1:7200 --iface <this host's IP>
```

`selftest --generic` is asserted byte-for-byte in CI, so the fixture receipt is
a regression artifact rather than a number that drifts between runs.
