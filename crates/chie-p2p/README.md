# chie-p2p

P2P networking layer for the CHIE Protocol using rust-libp2p.

## Overview

This crate implements the peer-to-peer networking stack for CHIE Protocol, including:
- Custom bandwidth proof protocol
- Peer discovery (Kademlia DHT + mDNS)
- Gossipsub for pub/sub messaging
- NAT traversal

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

## Modules

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

**Message Format**: Length-prefixed bincode (4-byte big-endian + bincode body)

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

| Module | Purpose |
|--------|---------|
| `node/mod.rs` | P2P node with swarm management |
| `codec.rs` | Bandwidth proof protocol codec |
| `protocol.rs` | Protocol versioning |
| `discovery.rs` | Peer discovery (DHT, mDNS) |
| `nat.rs` | NAT traversal and relay |
| `reputation.rs` | Peer reputation system |
| `throttle.rs` | Bandwidth throttling |
| `metrics.rs` | Connection metrics tracking |

## Dependencies

```toml
libp2p = { version = "0.54", features = [
    "tokio", "tcp", "noise", "yamux",
    "request-response", "kad", "gossipsub", "identify"
]}
```

