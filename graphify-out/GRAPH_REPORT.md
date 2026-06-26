# Graph Report - go-amt  (2026-06-26)

## Corpus Check
- 40 files · ~23,871 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 452 nodes · 727 edges · 30 communities (25 shown, 5 thin omitted)
- Extraction: 94% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 44 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `681afc6f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 29|Community 29]]

## God Nodes (most connected - your core abstractions)
1. `RelayManager` - 31 edges
2. `ManagedConn` - 26 edges
3. `Gateway` - 21 edges
4. `MulticastConn` - 20 edges
5. `MulticastConn` - 18 edges
6. `PureGoProtocol` - 18 edges
7. `UDPTransport` - 18 edges
8. `CGOProtocol` - 17 edges
9. `Subscription` - 17 edges
10. `T` - 12 edges

## Surprising Connections (you probably didn't know these)
- `GetPlatformCapabilities()` --calls--> `IsCGOAvailable()`  [INFERRED]
  platform.go → protocol.go
- `GetPlatformCapabilities()` --calls--> `PlatformUDPAvailable()`  [INFERRED]
  platform.go → transport_udp.go
- `TestE2E_ReceiveMulticastData()` --calls--> `GetPlatformCapabilities()`  [INFERRED]
  e2e_test.go → platform.go
- `applyForcedBuffers()` --calls--> `IncSocketBufferClamped()`  [INFERRED]
  sockbuf.go → metrics/sockbuf.go
- `init()` --calls--> `RegisterProtocol()`  [INFERRED]
  protocol_cgo.go → protocol.go

## Import Cycles
- None detected.

## Communities (30 total, 5 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.09
Nodes (34): AMTProtocol, Bool, CancelFunc, DataPacket, RelayManager, RelayManagerConfig, RelayManagerStats, RelayState (+26 more)

### Community 1 - "Community 1"
Cohesion: 0.15
Nodes (31): BuildAMTRelayRdata(), BuildDRIADQuery(), DefaultDRIADConfig(), DiscoverRelay(), getDefaultDNSServer(), Addr, Context, Duration (+23 more)

### Community 2 - "Community 2"
Cohesion: 0.10
Nodes (15): DataPacket, ManagedConn, ManagedConnStats, Addr, ControlMessage, Duration, Interface, Message (+7 more)

### Community 3 - "Community 3"
Cohesion: 0.11
Nodes (16): T, TestE2E_ReceiveMulticastData(), TestVersion(), Error, determineAMTmessageType(), Addr, amt_gateway_handle_t, ControlMessage (+8 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (9): PureGoProtocol, MembershipQueryMessage, DecodeMembershipQueryMessage(), Addr, AMTState, Duration, Mutex, init() (+1 more)

### Community 5 - "Community 5"
Cohesion: 0.10
Nodes (15): UDPTransport, CreatePlatformTransport(), Addr, Context, ControlMessage, Message, PacketConn, Time (+7 more)

### Community 6 - "Community 6"
Cohesion: 0.17
Nodes (10): Addr, ControlMessage, Duration, Gateway, MulticastConn, Interface, Message, PacketConn (+2 more)

### Community 7 - "Community 7"
Cohesion: 0.15
Nodes (21): Platform, PlatformCapabilities, BestProtocolType(), BestTransportType(), DetectPlatform(), GetPlatformCapabilities(), ProtocolType, TransportConfig (+13 more)

### Community 8 - "Community 8"
Cohesion: 0.13
Nodes (8): Addr, ControlMessage, Duration, MulticastConn, Interface, Message, Time, UDPAddr

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (17): BufferClampedError, Addr, ControlFlags, Interface, PacketConn, RawInstruction, UDPAddr, ListenMulticastUDP4() (+9 more)

### Community 10 - "Community 10"
Cohesion: 0.11
Nodes (8): CGOProtocol, Addr, amt_gateway_handle_t, AMTState, Duration, Mutex, init(), NewCGOProtocol()

### Community 11 - "Community 11"
Cohesion: 0.17
Nodes (9): HardwareAddr, IGMPv2Message, IGMPv3GroupRecord, IGMPv3MembershipReport, MembershipTeardownMessage, MembershipUpdateMessage, DecodeMembershipTeardownMessage(), calculateChecksum() (+1 more)

### Community 12 - "Community 12"
Cohesion: 0.23
Nodes (9): IncSocketOverrun(), InitDropCounters(), T, grepLines(), TestHelp(), TestIncSocketOverrun_ZeroIsNoop(), TestInitDropCounters_AllFourSeriesAtZero(), TestPromhttpExposition_AllFourSeriesEmittedAtZero() (+1 more)

### Community 13 - "Community 13"
Cohesion: 0.23
Nodes (9): AMTProtocol, AMTState, ProtocolError, ProtocolFactory, ProtocolType, DefaultProtocol(), IsCGOAvailable(), NewProtocol() (+1 more)

### Community 14 - "Community 14"
Cohesion: 0.30
Nodes (9): Transport, TransportConfig, TransportError, TransportType, DefaultTransportConfig(), Duration, UDPAddr, NewTransport() (+1 more)

### Community 15 - "Community 15"
Cohesion: 0.47
Nodes (9): T, newUDPSocket(), TestBufferClampedErrorMessage(), TestSetForcedReceiveBufferBadFD(), TestSetForcedReceiveBufferDoesNotShrink(), TestSetForcedReceiveBufferGrows(), TestSetForcedReceiveBufferZero(), TestSetForcedSendBufferDoesNotShrink() (+1 more)

### Community 16 - "Community 16"
Cohesion: 0.22
Nodes (8): AMT Protocol (RFC 7450), Architecture Reference, Blockcast CDN Architecture - Go AMT, Build Modes, Components in This Repository, driad.go (DRIAD Discovery), go-amt Library, Related Repositories

### Community 17 - "Community 17"
Cohesion: 0.28
Nodes (6): MembershipProtocolFlag, AMTRelayRequest, MembershipProtocolFlag, DecodeRequestMessage(), FromBytes(), RequestMessage

### Community 18 - "Community 18"
Cohesion: 0.43
Nodes (5): AMTresponse, Message, Header, MessageBody, MessageType

### Community 19 - "Community 19"
Cohesion: 0.48
Nodes (6): T, TestDecodeRelayAdvertisementMessageErrorHandling(), TestDecodeRelayAdvertisementMessageIPv4(), TestDecodeRelayAdvertisementMessageIPv6(), TestEncodeRelayAdvertisementMessageIPv4(), TestEncodeRelayAdvertisementMessageIPv6()

### Community 20 - "Community 20"
Cohesion: 0.33
Nodes (5): Build Constraints, Installation, License, Usage, With CGO (optional, for Rust library performance)

### Community 23 - "Community 23"
Cohesion: 0.83
Nodes (3): setBufferAtLeast(), SetForcedReceiveBuffer(), SetForcedSendBuffer()

### Community 24 - "Community 24"
Cohesion: 0.83
Nodes (3): setBufferAtLeast(), SetForcedReceiveBuffer(), SetForcedSendBuffer()

## Knowledge Gaps
- **83 isolated node(s):** `MessageType`, `UDPAddr`, `Interface`, `Duration`, `PacketConn` (+78 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `RegisterProtocol()` connect `Community 13` to `Community 10`, `Community 4`?**
  _High betweenness centrality (0.140) - this node is a cross-community bridge._
- **Why does `DefaultProtocol()` connect `Community 13` to `Community 0`?**
  _High betweenness centrality (0.127) - this node is a cross-community bridge._
- **Why does `GetPlatformCapabilities()` connect `Community 7` to `Community 5`, `Community 3`, `Community 13`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **What connects `MessageType`, `UDPAddr`, `Interface` to the rest of the system?**
  _83 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.08521303258145363 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.14583333333333334 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.0967741935483871 - nodes in this community are weakly interconnected._