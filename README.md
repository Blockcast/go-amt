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

The receipt reports each feed's erasure fraction, the first-arrival-wins union
fraction, and the gap the second feed closes relative to the first feed. This
measures what the observed second input added during the run. It does not prove
the feeds are independently operated or path-decorrelated; state their actual
origins when presenting the result.

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

These are receiver-observed counters. They describe what this process read and
wrote, not the validator's true replay deadline.

## License

MIT
