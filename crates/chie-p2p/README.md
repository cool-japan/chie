# chie-p2p v0.2.0

P2P networking layer for the CHIE Protocol using rust-libp2p.

**Stats**: 110 modules · 494+ tests · ~58,324 SLoC · 120 source files

## Overview

This crate implements the full peer-to-peer networking stack for CHIE Protocol, including:
- Custom bandwidth proof protocol with chunk transfer and dual-signature proofs
- Peer discovery (Kademlia DHT + mDNS) and peer exchange (PEX)
- Gossipsub for pub/sub messaging
- NAT traversal with relay economics
- Adaptive routing and topology management
- Multi-source content downloads with erasure coding
- Distributed bandwidth market with QoS enforcement
- Anti-sybil detection and reputation scoring
- OxiARC-based compression (LZ4, Zstd, Snappy) — Pure Rust

## What's New in v0.2.0

- **OxiARC compression**: All protocol-level compression migrated from `lz4_flex`/`zstd`/`snap` to `oxiarc-*` crates (Pure Rust LZ4, Zstd, Snappy)
- **rand 0.10 migration**: Updated all randomness usage to the `rand` 0.10 API
- **Expanded module scope**: 110 modules covering adaptive routing, multi-source downloads, erasure coding, bandwidth market, relay economics, anti-sybil detection, protocol compression with forward/backward compatibility negotiation
- **0 stubs**: All 110 modules are fully implemented and stable

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       P2PNode                               │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                  NodeBehaviour                         │ │
│  │  ┌─────────────┐  ┌──────────┐  ┌─────────────────┐  │ │
│  │  │  Request-   │  │ Kademlia │  │    Gossipsub    │  │ │
│  │  │  Response   │  │   DHT    │  │    (Pub/Sub)    │  │ │
│  │  └─────────────┘  └──────────┘  └─────────────────┘  │ │
│  │  ┌─────────────┐                                      │ │
│  │  │  Identify   │                                      │ │
│  │  └─────────────┘                                      │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Core Module Details

### codec.rs - Bandwidth Proof Protocol

Custom libp2p protocol for chunk transfer with proof generation.

**Protocol ID**: `/chie/bandwidth-proof/1.0.0`

```rust
// Request: ChunkRequest (requester → provider)
struct ChunkRequest {
    content_cid: String,
    chunk_index: u64,
    challenge_nonce: [u8; 32],  // Random, prevents replay
    requester_peer_id: String,
    requester_public_key: [u8; 32],
    timestamp_ms: i64,
}

// Response: ChunkResponse (provider → requester)
struct ChunkResponse {
    encrypted_chunk: Vec<u8>,
    chunk_hash: [u8; 32],       // BLAKE3 of original data
    provider_signature: Vec<u8>, // Ed25519 sig
    provider_public_key: [u8; 32],
    challenge_echo: [u8; 32],   // Echo back nonce
    timestamp_ms: i64,
}
```

**Message Format**: Length-prefixed (4-byte big-endian) with oxicode-encoded body

### discovery.rs - Peer Discovery

Configuration for peer discovery mechanisms.

```rust
DiscoveryConfig {
    bootstrap_nodes: Vec<Multiaddr>,  // Initial bootstrap nodes
    enable_mdns: bool,                // Local network discovery
    max_peers: usize,                 // Connection limit
}
```

### node/mod.rs - P2P Node

Full P2P node implementation with swarm management.

```rust
let (event_tx, event_rx) = mpsc::channel(100);
let config = NodeConfig::default();
let mut node = P2PNode::new(config, event_tx).await?;

// Request a chunk
let request_id = node.request_chunk(peer_id, chunk_request);

// Send response (when receiving ChunkRequested event)
node.send_response(channel, chunk_response)?;

// Run event loop
tokio::spawn(async move { node.run().await });
```

**Events emitted**:
- `ChunkRequested` - Incoming chunk request
- `ChunkReceived` - Response received
- `ChunkRequestFailed` - Request failed
- `PeerDiscovered` - New peer found
- `PeerDisconnected` - Peer left
- `ConnectionEstablished` - New connection

## Protocol Flow

```
Requester                             Provider
    │                                     │
    │ ─── ChunkRequest ─────────────────► │
    │     (nonce, chunk_index, pubkey)    │
    │                                     │
    │ ◄── ChunkResponse ──────────────── │
    │     (encrypted_chunk, sig, hash)    │
    │                                     │
    │  [Verify provider signature]        │
    │  [Decrypt & verify hash]            │
    │  [Sign receipt confirmation]        │
    │                                     │
    │ ─── BandwidthProof ───────────────► Coordinator
    │     (dual signatures)               │
```

## Configuration

```rust
NodeConfig {
    listen_addrs: vec![
        "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
        "/ip6/::/tcp/0".parse().unwrap(),
    ],
    bootstrap_nodes: vec![],
    enable_mdns: true,
    gossip_topic: "chie/network/v1".to_string(),
    idle_timeout: Duration::from_secs(30),
}
```

## Modules

The crate contains 110 modules organized into the following categories:

### Core Transport & Protocol (7 modules)
| Module | Purpose |
|--------|---------|
| `node/mod.rs` | P2P node with swarm management |
| `codec.rs` | Bandwidth proof protocol codec |
| `protocol/mod.rs` | Protocol versioning and negotiation |
| `discovery.rs` | Peer discovery (Kademlia DHT, mDNS) |
| `nat.rs` | NAT traversal and relay |
| `tls_mutual_auth.rs` | Mutual TLS authentication |
| `connection_manager/` · `connection_pool/` | Connection lifecycle management |

### Bandwidth Market & Relay Economics (12 modules)
`bandwidth/` — 8 modules: market, pricing, accounting, proof aggregation, escrow, settlement, dispute resolution, oracle  
`relay/` — 4 modules: routing, economics, capacity management, reputation

### Content Distribution (7 modules)
`content/` — content registry, pinning, distribution, demand tracking, CID resolution, prioritization, eviction

### Multi-Source Downloads & Erasure Coding (3 modules)
`multi_source_download.rs`, `erasure_coding.rs`, `merkle_tree.rs`

### Distributed Hash Table & Replication (3 modules)
`dht_replication.rs`, `cache.rs`, `prefetch.rs`, `range_request.rs`

### Gossip, Pub/Sub & Peer Exchange (3 modules)
`gossip.rs`, `pubsub.rs`, `pex.rs`

### Adaptive Routing & Topology (10 modules)
`adaptive/` — 9 modules: scoring, path selection, congestion control, latency estimation, multipath, failover, load balancing, topology awareness, rerouting  
`topology/` · `resilience/` — 10 modules total

### Security & Reputation (8 modules)
`security/` — anti-sybil detection, eclipse attack prevention, Sybil-resistant scoring  
`reputation/` — trust scoring, behavior history, reward weighting

### QoS & Traffic Management (8 modules)
`qos/` — rate shaping, priority queues, traffic classification, SLA enforcement  
`traffic/` — monitoring, anomaly detection, throttle policies

### Operations & Observability (12 modules)
`operations/` — health checks, diagnostics, graceful shutdown, peer eviction, metrics export, tracing integration, alert hooks, performance profiling, config hot-reload

### Compression & Protocol Upgrade (3 modules)
| Module | Purpose |
|--------|---------|
| `protocol_compression.rs` | OxiARC LZ4/Zstd/Snappy at protocol level |
| `protocol_upgrade.rs` | In-place protocol version upgrade |
| `backward_compat.rs` | Backward compatibility negotiation |

## Dependencies

```toml
libp2p = { version = "0.54", features = [
    "tokio", "tcp", "noise", "yamux",
    "request-response", "kad", "gossipsub", "identify"
]}
```

