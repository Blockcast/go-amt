# Installing the Blockcast shred receiver

Unattended install guide for validator operators. The receiver is one static
`linux/amd64` binary with no runtime dependencies: no libc, no interpreter, no
sidecar.

It does two jobs:

1. **Deliver.** Receive Solana shreds over a unicast UDP feed and fan them out,
   byte-identically, to every configured validator TVU port.
2. **Score.** Independently measure delivery quality, so you can audit the SLA
   from your own hardware rather than taking a vendor dashboard on trust.

Delivery never waits on scoring. Malformed and duplicate packets are forwarded
unchanged; scoring failures cannot drop or delay a packet.

> **Read [What the score actually means](#what-the-score-actually-means) before
> you rely on these numbers in a dispute.** The metric is receiver-observed. It
> is deliberately *not* a claim about your validator's true replay deadline.

## Install

### Binary

```sh
VERSION=<release>
curl -fsSLO "https://github.com/Blockcast/go-amt/releases/download/${VERSION}/blockcast-shreds_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/Blockcast/go-amt/releases/download/${VERSION}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
tar -xzf "blockcast-shreds_${VERSION}_linux_amd64.tar.gz"
sudo install -m 0755 blockcast-shreds /usr/local/bin/blockcast-shreds
```

### systemd

Configuration is an environment file so the unit itself never needs editing:

```sh
sudo install -d -m 0755 /etc/blockcast
sudo tee /etc/blockcast/shreds.env >/dev/null <<'EOF'
BLOCKCAST_SHREDS_ARGS=--listen 0.0.0.0:20000 --dest-ip-ports 127.0.0.1:8001 --http-addr 127.0.0.1:8080
EOF
sudo install -m 0644 packaging/systemd/blockcast-shreds.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blockcast-shreds
```

The unit runs unprivileged under `DynamicUser` with no capabilities — both
listeners are above port 1024. Verify:

```sh
systemctl is-active blockcast-shreds
curl -fsS http://127.0.0.1:8080/healthz
```

### Docker

```sh
docker run --rm \
  -p 20000:20000/udp -p 8080:8080 \
  ghcr.io/blockcast/blockcast-shreds:<tag> \
  --listen 0.0.0.0:20000 --dest-ip-ports 10.0.0.5:8001 --http-addr 0.0.0.0:8080
```

Fan-out targets must be reachable from inside the container: `127.0.0.1` refers
to the container, not the host.

### Verify the install

```sh
packaging/smoke-test.sh /usr/local/bin/blockcast-shreds
```

This exercises the shipped binary end to end — the documented scoring numbers,
`/healthz` before and after traffic, ingress/egress/unparsed counters,
byte-identical fan-out, and graceful `SIGTERM` shutdown. It is the same check CI
runs on every commit.

## Configuration

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `0.0.0.0:20000` | Unicast UDP ingress address. |
| `--feed NAME=IP:PORT` | — | Repeatable. Enables multi-feed first-arrival-wins scoring. Replaces `--listen` when given. |
| `--dest-ip-ports` | *(none)* | Comma-separated validator TVU targets. Empty means score-only, no forwarding. |
| `--http-addr` | `127.0.0.1:8080` | `/metrics` and `/healthz`. Empty disables HTTP. |
| `--health-max-age` | `30s` | Ingress freshness window for `/healthz`. |
| `--retain` | `2s` | How far behind the newest arrival per-shred scoring state is kept. |
| `--json` | off | Emit the shutdown receipt as JSON instead of a table. |

### `--retain` bounds memory, and also bounds duplicate detection

State is held for `--retain` past each arrival, so the receiver reaches a steady
size instead of growing for as long as it runs. Two seconds is roughly five
Solana slots.

The trade-off is real: `--retain` is also how long a second copy of a shred is
still recognised as a duplicate. If you run two feeds whose skew exceeds it, the
later copy is counted as a new shred and the union score is overstated. Raise it
if your feeds are further apart than a second; do not lower it below your worst
inter-feed skew.

### Receive buffer

The receiver does not currently set `SO_RCVBUF`. At mainnet shred rates a small
kernel default is the most likely cause of loss that shows up as erasure but is
actually local. Size it at the host:

```sh
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.rmem_default=134217728
```

Losses inside the receiver — as opposed to before it — appear as
`fanout_dropped_packets_total`, never as silent gaps.

## What the score actually means

### The definition

- A **FEC set** is identified by `(slot, fec_set_index)`.
- Each set carries up to **64** shreds. A set is **complete** at **32 distinct
  shreds** — the point at which the data is recoverable.
- A set still below 32 when it is scored is **erased**.
- Shreds are counted once per `(slot, shred_index)`, so a duplicate — whether a
  retransmit or the same shred arriving on a second feed — cannot inflate
  completion.
- A packet whose header will not parse increments `shreds_unparsed_total`. It is
  still forwarded, byte for byte.

### When a set is scored — read this carefully

The v1 specification scores a set at **`slot_boundary + erasure_grace`**, with
`erasure_grace` defaulting to **400 ms**.

**The shipped binary does not do this yet.** It scores a set when that set falls
out of the `--retain` window (default 2 s past the newest arrival). The
completion threshold, the dedup rule and the gap buckets are all as specified;
the *deadline* is retention expiry rather than a slot-boundary-anchored grace.

The grace-anchored implementation exists and is tested (`erasure.Tracker`) but is
not yet driven by the binary — tracked as
[BLO-28442](https://paperclip.blockcast.net/BLO/issues/BLO-28442). Until that
lands:

- The **shutdown receipt** on stdout carries the real numbers.
- The **`/metrics` erasure, rate and gap series report zero regardless of actual
  loss.** Do not scrape them for the SLA, and do not read
  `bcast_shred_gw_erasure_fraction 0` as a clean feed. `report_schema 0` and
  `erasure_grace_milliseconds 0` are the tell that the series is unwired — the
  specified values are `1` and `400`.

A receiver whose deadline is retention expiry is *more* forgiving than the
specified one: it gives a set up to two seconds to complete, where the
specification gives it 400 ms past the slot boundary. Reasoning from that alone,
it should report erasure equal to or lower than the specified definition — but
that is an expectation from the deadline arithmetic, not a measured result, and
it has not been validated against a grace-anchored run. Do not lean on it in a
dispute until [BLO-28442](https://paperclip.blockcast.net/BLO/issues/BLO-28442)
lands and the two can be compared directly.

### The gap histogram

Consecutive-arrival gaps land in five fixed buckets, in milliseconds:

`<1`, `1-2.4`, `2.4-7`, `7-32`, `>=32`

The 2.4 ms and 7 ms edges are T_safe-anchored and **fixed for v1** so that
measurements stay comparable across receivers and releases. They are not tunable
and will not be re-cut within v1.

### Receiver-observed, not replay-deadline truth

This score says: *of the FEC sets this receiver saw, that many did not reach 32
distinct shreds before the scoring deadline.*

It does **not** say a set was too late for your validator to replay. The true
replay deadline depends on your validator's own scheduling, its repair path, and
turbine retransmission that this receiver never sees. A set counted as erased
here may have been repaired and replayed perfectly well.

Treat it as a comparable, reproducible delivery measurement — the same
computation the broker records, so both sides can audit the same number — not as
a statement about consensus performance.

## Operating

### `/healthz` is a readiness probe, not a liveness probe

It reports healthy only once a packet has arrived within `--health-max-age`, so
it is **unhealthy at startup and stays unhealthy until traffic flows**. Wiring it
to a liveness probe produces a restart loop on a feed that is merely idle:

```
503 {"status":"unhealthy"}   # no packet yet, or none within the window
200 {"status":"ok"}
```

### `/metrics`

| Metric | Meaning |
|---|---|
| `bcast_shred_gw_ingress_packets_total` | Packets received per feed. |
| `bcast_shred_gw_egress_packets_total` | Destination writes. One packet to N targets adds N — divide by target count to recover packets forwarded. |
| `bcast_shred_gw_fanout_dropped_packets_total` | Packets dropped because the bounded fan-out ring was full. **The receiver-overload signal — alert on any increase.** |
| `bcast_shred_gw_fanout_write_errors_total` | Failed or short destination writes; each is a packet a target did not receive. |
| `bcast_shred_gw_shreds_unparsed_total` | Delivered packets whose shred header would not parse. |
| `bcast_shred_gw_erasure_*`, `_shreds_per_second`, `_gap_events` | Published but **not yet written** — see [BLO-28442](https://paperclip.blockcast.net/BLO/issues/BLO-28442). |

Drops are counted at the drop site; there is no silent discard path.

### Shutdown

`SIGTERM` and `SIGINT` close the ingress sockets, drain, print the delivery
receipt to stdout, and exit 0. Under systemd the receipt lands in the journal:

```sh
journalctl -u blockcast-shreds --since '10 min ago' | tail -40
```

`TimeoutStopSec` must stay long enough for that write — if systemd `SIGKILL`s
first, the run's final numbers are lost.

## Current limitations

Honest scope of this build, so you are not surprised in an audit:

- **No broker session.** mTLS identity, ticket renewal, certificate renewal and
  the 30-second heartbeat are not in this binary yet. It runs standalone.
- **No version string.** The binary cannot report its own version; identify a
  deployment by release artifact checksum until the broker lane lands.
- **Erasure metrics are unwired** ([BLO-28442](https://paperclip.blockcast.net/BLO/issues/BLO-28442)).
  Use the shutdown receipt.
- **Scoring deadline is retention expiry**, not `slot_boundary + 400 ms`. See
  above.
- **No AMT, no relay, no FEC decode or repair.** Scoring is counting only; the
  receiver never reconstructs a shred.
