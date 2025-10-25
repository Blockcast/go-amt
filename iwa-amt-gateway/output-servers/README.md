# Output Servers

Protocol-agnostic output servers that forward raw UDP multicast payloads to clients via multiple transport protocols.

## Architecture

All output servers receive raw UDP multicast packets from the AMT gateway and forward them to subscribed clients. **No protocol parsing** is done by these servers - clients are responsible for interpreting the payload (MPEG-TS, RTP, MoQ, MAHP, or custom protocols).

## Servers

### UDP Server (`udp-server.js`)

- **Control Port:** 5000 (UDP)
- **Data Port:** Ephemeral (UDP)
- **Protocol:** JSON control messages, raw packet forwarding
- **Best For:** Local network clients, lowest latency
- **Status:** 🚧 To be implemented

### TCP/HTTP Server (`tcp-server.js`)

- **Port:** 5001 (TCP)
- **Protocol:** HTTP/1.1 Chunked Transfer Encoding
- **Best For:** Web clients, VLC, ffmpeg, curl
- **Status:** 🚧 To be implemented

### WebSocket Server (`websocket-server.js`)

- **Port:** 5002 (WebSocket)
- **Protocol:** JSON messages over WebSocket
- **Best For:** Web applications, bidirectional communication
- **Status:** 🚧 To be implemented

### WebRTC Server (`webrtc-server.js`)

- **Protocol:** WebRTC DataChannel
- **Best For:** Peer-to-peer scenarios, NAT traversal
- **Status:** 🚧 To be implemented

### WebTransport Server (`webtransport-server.js`)

- **Port:** 4433 (HTTP/3)
- **Protocol:** WebTransport bidirectional streams
- **Best For:** Modern web clients (experimental)
- **Status:** 🚧 To be implemented

## Server Manager (`server-manager.js`)

Orchestrates all output servers:
- Starts/stops servers
- Routes packets to subscribed clients
- Tracks subscriptions
- Provides unified status API

**Status:** 🚧 To be implemented

## Implementation Status

All servers will be implemented using **Test-Driven Development**:
1. Write tests first
2. Run tests (they fail)
3. Implement server
4. Run tests (they pass)
5. Move to next server

See `/tests/*.test.js` for test specifications.

## API Documentation

See [/iwa-reorganization-tdd.plan.md](/iwa-reorganization-tdd.plan.md) for complete API specifications for each server.




