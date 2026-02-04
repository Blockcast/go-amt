# Blockcast CDN Architecture - Go AMT

This repository provides the **Go AMT library** with DRIAD discovery for the Blockcast CDN architecture.

## Architecture Reference

- **Interactive Diagrams**: https://blockcast.github.io/trafficcontrol/
- **Wiki**: https://github.com/Blockcast/trafficcontrol/wiki/LikeC4-Architecture
- **C4 Model Source**: [trafficcontrol/docs/architecture/likec4](https://github.com/Blockcast/trafficcontrol/tree/master/docs/architecture/likec4)

## Components in This Repository

### go-amt Library
- Pure Go or CGO with amt-protocol FFI
- `gateway.go`: AMT gateway implementation
- `relay.go`: AMT relay implementation
- `driad.go`: DRIAD discovery (RFC 8777)
- `relay_manager.go`: Relay connection management

### driad.go (DRIAD Discovery)
RFC 8777 implementation for AMT relay discovery:

1. Build reverse DNS query from source IP
2. Query for AMTRELAY RR (Type 260)
3. Parse relay address and preference
4. Return relay endpoints

## AMT Protocol (RFC 7450)

```
AMT Message Flow:

Gateway                              Relay
   │                                   │
   ├── Discovery ──────────────────────►
   │                                   │
   ◄────────────────── Advertisement ──┤
   │                                   │
   ├── Request ────────────────────────►
   │                                   │
   ◄──────────────────────── Query ────┤
   │                                   │
   ├── Membership Update ──────────────►
   │                                   │
   ◄────────────── Multicast Data ─────┤
```

## Build Modes

| Mode | Description |
|------|-------------|
| Pure Go | No CGO, portable |
| CGO + FFI | Links amt-protocol for performance |

## Related Repositories

| Repository | Relationship |
|------------|--------------|
| [amt-protocol](https://github.com/Blockcast/amt-protocol) | Rust FFI source for CGO |
| [linux-amt](https://github.com/Blockcast/linux-amt) | Kernel AMT + amtr service |
| [pim-multicast-gateway](https://github.com/Blockcast/pim-multicast-gateway) | Uses for gateway functionality |
