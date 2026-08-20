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

> ⚠ **No release artifacts are published yet.** The repository has tags but zero
> GitHub releases, and no image is pushed to a registry — CI builds both on every
> commit (`goreleaser build --snapshot`, `docker build --push=false`) but nothing
> publishes them. **The tarball and Docker commands below will 404 today.** Until
> [BLO-28464](https://paperclip.blockcast.net/BLO/issues/BLO-28464) adds the
> tag-triggered release job and the image push, use *Build from source* below.
> Both sections are written and verified against the artifacts CI already
> produces, so they become correct the moment publishing lands.

### Build from source (works today)

```sh
git clone https://github.com/Blockcast/go-amt
cd go-amt
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o blockcast-shreds ./cmd/blockcast-shreds
sudo install -m 0755 blockcast-shreds /usr/local/bin/blockcast-shreds
```

`CGO_ENABLED=0` is what makes the result dependency-free; CI asserts the release
binary is statically linked so this cannot regress silently.

### Binary (pending BLO-28464)

```sh
VERSION=<release>
curl -fsSLO "https://github.com/Blockcast/go-amt/releases/download/${VERSION}/blockcast-shreds_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/Blockcast/go-amt/releases/download/${VERSION}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
tar -xzf "blockcast-shreds_${VERSION}_linux_amd64.tar.gz"
sudo install -m 0755 blockcast-shreds /usr/local/bin/blockcast-shreds
```

`checksums.txt` travels over the same channel as the artifact it validates, so it
gives integrity against corruption but **not** authenticity: anyone who can serve
a bad tarball can serve a matching checksum file. Artifact signing is tracked on
[BLO-28464](https://paperclip.blockcast.net/BLO/issues/BLO-28464) and should land
with the release job rather than after it.

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

**Requires systemd ≥ 247.** The hardening set uses `ProtectProc=` (247),
`ProtectClock=` (245), `ProtectKernelLogs=` (244) and `Type=exec` (240). On older
systemd — Ubuntu 20.04 ships 245, RHEL 8 ships 239 — an unknown directive is
logged as `Unknown lvalue` and *ignored*: the service still starts, but with
weaker isolation than this document describes, and `Type=exec` silently degrades
to `simple` so a failed exec is no longer reported at start. Check before you
rely on the hardening:

```sh
systemctl --version | head -1
journalctl -u blockcast-shreds | grep -i 'unknown lvalue'
```

`EnvironmentFile=` intentionally has no `-` prefix: a missing
`/etc/blockcast/shreds.env` fails the unit loudly rather than starting the
receiver with default arguments that silently forward nowhere.

### Docker (pending BLO-28464)

No image is published yet — `.goreleaser.yaml` has no `dockers:` block and CI
builds with `push: false`. Build it locally in the meantime:

```sh
docker build -t blockcast-shreds:local .
docker run --rm \
  -p 20000:20000/udp -p 8080:8080 \
  blockcast-shreds:local \
  --listen 0.0.0.0:20000 --dest-ip-ports 10.0.0.5:8001 --http-addr 0.0.0.0:8080
```

Once publishing lands the image will be `ghcr.io/blockcast/blockcast-shreds:<tag>`.

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

**Needs `python3` or `nc`** to bind a local UDP sink. That sink is not optional
padding: byte-identity is the only assertion here that proves a forwarded packet
actually arrived. The fan-out socket is unconnected, so a send to a closed port
succeeds — `egress_packets_total` and `fanout_write_errors_total` both look
healthy with nothing listening. Without a sink the script exits 2 rather than
passing. If you must run on a host with neither, `SMOKE_ALLOW_NO_SINK=1` runs the
remaining checks and reports the delivery assertion as `UNVERIFIED`.

## Configuration

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `0.0.0.0:20000` | Unicast UDP ingress address. |
| `--feed NAME=IP:PORT` | — | Repeatable. Enables multi-feed first-arrival-wins scoring. Replaces `--listen` when given. |
| `--dest-ip-ports` | *(none)* | Comma-separated validator TVU targets. Empty means score-only, no forwarding. |
| `--http-addr` | `127.0.0.1:8080` | `/metrics` and `/healthz`. Empty disables HTTP. |
| `--json` | off | Emit the shutdown receipt as JSON instead of a table. |
| `--mode` | `shred` | Scoring mode. `shred` parses Solana shred headers; `generic` scores framed records by size and arrival instead — see [the D5 note](../demo/d5-payload-agnostic-receipt.md). |
| `--source-label` | *(none)* | Required with `--mode generic`; rejected in `shred` mode. Provenance of the input, e.g. `synthetic`. Deliberately not defaulted, so a real capture cannot be scored under a synthetic label by omission. |
| `--rights-basis` | *(none)* | Required with `--mode generic`; rejected in `shred` mode. The rights basis recorded on the receipt for the input being scored. |
| `--health-max-age` | `30s` | `/healthz` ingress freshness window — how stale the newest arrival may be before readiness fails. Must be positive. |
| `--retain` | `2s` | How far behind the newest arrival to keep per-shred scoring state. This is what bounds the receiver's memory: duplicate recognition and FEC-set accounting only see arrivals inside the window, so raising it costs memory and lowers it loses duplicate detection across feeds. It does **not** bound completion percentiles: a set is aged on its newest arrival, so one that keeps receiving is never evicted and its first-to-32nd span can exceed the histogram's 4.194304s ceiling at any window, including the default (32 shreds 200ms apart span 6.2s). When that happens the receipt's `completions_above_ceiling` is nonzero and `time_to_32nd_shred` understates — check it rather than the flag. Measured on the arrival clock, not slot distance — a capture's slot numbers jump by hundreds and can arrive below their neighbours, so a slot-distance window reads those as ancient and drops them. Must be positive. |

These are all of them. The binary parses flags with `flag.ContinueOnError`, so any
flag not in this table is a parse error that exits non-zero — under the systemd
unit's `Restart=on-failure` that is a restart loop, so do not put a flag in
`BLOCKCAST_SHREDS_ARGS` that is not listed above. `TestHelpDocumentsEveryFlag`
fails the build if this table and the registered flag set drift apart.

### Fixed for v1

Two behaviours an operator might expect to tune are compiled in for v1, like the
gap-bucket edges:

- **`/healthz` freshness window: 30s.** `/healthz` reports unhealthy when no
  ingress packet has arrived for 30 seconds. Not configurable.
- **Scoring-state retention: none.** See below — this one is a defect, not a
  design choice.

### Scoring state is not bounded (BLO-28455)

Per-shred deduplication state is **never reclaimed**. The receiver's scorer keeps
one entry per distinct `(slot, fec_set_index, index_within_set)` for the lifetime
of the process and never deletes any of them, so its memory grows for as long as
it runs rather than reaching a steady size.

Measured: **59 bytes retained per distinct shred**, with nothing freed
(500,000 shreds → 29.5 MB). Multiply by your feed's shred rate to project it — at
an illustrative 10,000 shreds/s that is roughly 2.1 GB/hour.

Until [BLO-28455](https://paperclip.blockcast.net/BLO/issues/BLO-28455) lands,
treat the receiver as a process that must be restarted on a schedule, and give it
a memory ceiling so a leak degrades one service rather than the host:

```ini
# /etc/systemd/system/blockcast-shreds.service.d/memory.conf
[Service]
MemoryMax=2G
```

Restarting resets the receipt, so scrape `/metrics` before a planned restart if
you need the window. Note the trade-off retention *would* buy if it were
configurable: it is also how long a second copy of a shred is recognised as a
duplicate, so a bounded window smaller than your worst inter-feed skew would
count the later copy as a new shred and overstate the union score. That is why
the fix is a real retention window rather than a blunt cap.

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

Sizing it at the host is the only lever today. A per-socket setter exists and is
tested (`receiver.OpenUDPFlow`, `RcvBufBytes`), but the shipped binary opens its
ingress socket with bare `net.ListenUDP` and never calls it — the same
built-but-unwired shape as the erasure defect above.

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

**The shipped binary does not do this yet.** It has no scoring deadline at all:
`Scorer.Receipt()` walks every FEC set it has ever seen and counts any set still
short of 32 distinct shreds as erased. The effective deadline is therefore
**whenever the receipt is produced** — process shutdown — not a slot-boundary
grace. The completion threshold, the dedup rule and the gap buckets are all as
specified; only the deadline differs.

Two consequences worth knowing before you quote the number:

- A set that was still legitimately in flight when you sent `SIGTERM` is counted
  as erased. On a short run that tail bias is visible; on a long one it is
  negligible.
- Because sets are never aged out, the receipt is a whole-run figure, not a
  windowed one. It cannot be compared against a 30-second heartbeat window.

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

It reports healthy only once a packet has arrived within the fixed 30-second
freshness window, so it is **unhealthy at startup and stays unhealthy until
traffic flows**. Wiring it to a liveness probe produces a restart loop on a feed
that is merely idle:

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
