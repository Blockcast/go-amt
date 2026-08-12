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

## License

MIT
