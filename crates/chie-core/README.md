# chie-core

Core protocol logic for the CHIE Protocol.

## Overview

This crate provides the main business logic for CHIE nodes, including:
- Content node management
- Bandwidth proof protocol implementation
- Content management and storage
- Coordinator communication

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                      ContentNode                           │
│  ┌──────────────────────────────────────────────────────┐ │
│  │ KeyPair (Ed25519)         │ NodeConfig               │ │
│  │ - Sign chunk responses    │ - max_storage_bytes     │ │
│  │ - Generate proofs         │ - max_bandwidth_bps     │ │
│  │                           │ - coordinator_url       │ │
│  └──────────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────┐ │
│  │              PinnedContents                          │ │
│  │ HashMap<CID, PinnedContent>                          │ │
│  │ - cid, size_bytes, encryption_key                    │ │
│  │ - predicted_revenue_per_gb                           │ │
│  └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
```

## Modules

### node/mod.rs - Content Node

Main node implementation for content providers.

```rust
use chie_core::{ContentNode, NodeConfig, PinnedContent};

let config = NodeConfig {
    max_storage_bytes: 50 * 1024 * 1024 * 1024,  // 50 GB
    max_bandwidth_bps: 100 * 1024 * 1024 / 8,     // 100 Mbps
    coordinator_url: "https://coordinator.chie.network".to_string(),
};

let mut node = ContentNode::new(config);

// Pin content for distribution
node.pin_content(PinnedContent {
    cid: "QmExample...".to_string(),
    size_bytes: 1024 * 1024 * 100,
    encryption_key: key,
    predicted_revenue_per_gb: 15.0,
});

// Handle incoming chunk request
let response = node.handle_chunk_request(request).await?;

// Submit proof to coordinator
node.submit_proof(proof).await?;
```

### protocol/mod.rs - Bandwidth Proof Protocol

Protocol helpers for creating requests and proofs.

```rust
use chie_core::{create_chunk_request, create_bandwidth_proof, generate_challenge_nonce};

// Create a request with random challenge
let request = create_chunk_request(
    content_cid,
    chunk_index,
    my_peer_id.to_string(),
    my_public_key,
);

// After receiving response and verifying, create proof
let proof = create_bandwidth_proof(
    &request,
    provider_peer_id,
    provider_public_key.to_vec(),
    bytes_transferred,
    provider_signature.to_vec(),
    my_signature.to_vec(),
    chunk_hash.to_vec(),
    start_timestamp,
    end_timestamp,
    latency_ms,
);
```

### content/mod.rs - Content Management

Content storage and metadata caching.

```rust
use chie_core::ContentManager;

let manager = ContentManager::new("/path/to/storage".into());

// Cache metadata for quick access
manager.cache_metadata(cid.clone(), metadata);

// Query cached metadata
if let Some(meta) = manager.get_metadata(&cid) {
    println!("Content size: {}", meta.size_bytes);
}

// Check total storage used
let used = manager.total_storage_used();
```

## Bandwidth Proof Flow

```
1. Requester                    2. Provider
   │                               │
   │ create_chunk_request()        │
   │ - Generate nonce              │
   │ - Set timestamp               │
   │ - Include public key          │
   │                               │
   │ ────── ChunkRequest ────────► │
   │                               │ handle_chunk_request()
   │                               │ - Read chunk from storage
   │                               │ - Hash chunk (BLAKE3)
   │                               │ - Sign (nonce||hash||req_pk)
   │                               │ - Encrypt chunk
   │ ◄───── ChunkResponse ──────── │
   │                               │
   │ Verify provider signature     │
   │ Decrypt chunk                 │
   │ Verify hash                   │
   │ Sign receipt                  │
   │                               │
   │ create_bandwidth_proof()      │
   │                               │
   │ ────── BandwidthProof ──────────────► Coordinator
```

## Investment Caching Strategy

Nodes can strategically choose which content to pin based on expected returns:

```rust
// High demand / Low supply = High returns
// Predicted revenue = base_reward * sqrt(demand/supply)

PinnedContent {
    cid: "QmPopular...",
    predicted_revenue_per_gb: 25.0,  // High demand content
    ...
}

PinnedContent {
    cid: "QmUnpopular...",
    predicted_revenue_per_gb: 3.0,   // Low demand content
    ...
}
```

## Modules

| Module | Purpose |
|--------|---------|
| `node/mod.rs` | Content node management |
| `protocol/mod.rs` | Bandwidth proof protocol helpers |
| `content/mod.rs` | Content management and metadata |
| `storage/mod.rs` | Chunk storage and retrieval |
| `chunk_encryption.rs` | Per-chunk encryption with nonces |
| `integrity.rs` | Content integrity verification |
| `pinning.rs` | Selective pinning optimizer |
| `popularity.rs` | Content popularity tracking |
| `prefetch.rs` | Chunk prefetching |
| `dedup.rs` | Content deduplication |
| `ratelimit.rs` | Bandwidth rate limiting |
| `proof_submit.rs` | Proof submission with retry |

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_storage_bytes` | 50 GB | Maximum storage allocation |
| `max_bandwidth_bps` | 100 Mbps | Maximum bandwidth provision |
| `coordinator_url` | https://coordinator.chie.network | Coordinator API endpoint |

