# chie-core

Core protocol logic for the CHIE Protocol (v0.2.0).

## Overview

This crate provides the main business logic for CHIE nodes.
It contains **70 modules** with **431 public items** and **400+ passing tests**.

Capabilities include:
- **Content node management** with real P2P integration (ContentNode + NetworkStateMonitor)
- **Bandwidth proof protocol** implementation
- **Content management and storage** (tiered, deduplication, pinning)
- **Coordinator communication** and proof submission
- **Caching**: tiered cache, cache admission, warming, invalidation, content-aware cache
- **Networking**: QUIC transport, HTTP connection pooling, connection multiplexing
- **Resilience**: circuit breaker, adaptive retry, degradation, auto-repair
- **Observability**: metrics, tracing, logging, dashboards, custom exporters
- **Compression**: OxiARC deflate (replaces flate2)

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

## Full Module List (70 modules)

### Sub-crates
| Module | Purpose |
|--------|---------|
| `content/mod.rs` | Content management and metadata |
| `node/mod.rs` | Content node + NetworkStateMonitor (real P2P) |
| `protocol/mod.rs` | Bandwidth proof protocol helpers |
| `storage/mod.rs` | Chunk storage and retrieval |

### Flat modules
| Module | Purpose |
|--------|---------|
| `adaptive_ratelimit.rs` | Adaptive bandwidth rate limiting |
| `adaptive_retry.rs` | Adaptive retry with backoff |
| `alerting.rs` | Alerting and notification system |
| `analytics.rs` | Usage analytics |
| `anomaly.rs` | Anomaly detection |
| `auto_repair.rs` | Automatic self-repair |
| `backup.rs` | Data backup and restore |
| `bandwidth_estimation.rs` | Real-time bandwidth estimation |
| `batch.rs` | Batch request processing |
| `cache.rs` | Core cache implementation |
| `cache_admission.rs` | Cache admission policies |
| `cache_invalidation.rs` | Cache invalidation strategies |
| `cache_warming.rs` | Proactive cache warming |
| `checkpoint.rs` | State checkpointing |
| `chunk_encryption.rs` | Per-chunk encryption with nonces |
| `circuit_breaker.rs` | Circuit breaker pattern |
| `compression.rs` | OxiARC deflate compression |
| `config.rs` | Configuration management |
| `connection_multiplexing.rs` | HTTP/QUIC connection multiplexing |
| `content_aware_cache.rs` | Content-type-aware caching |
| `content_router.rs` | Content routing and CDN selection |
| `custom_exporters.rs` | Custom metrics exporters |
| `dashboard.rs` | Observability dashboard |
| `dedup.rs` | Content deduplication |
| `degradation.rs` | Graceful degradation |
| `events.rs` | Event bus |
| `expiration.rs` | TTL expiration management |
| `forecasting.rs` | Demand forecasting |
| `gc.rs` | Garbage collection |
| `geo_selection.rs` | Geographic peer selection |
| `health.rs` | Health check endpoints |
| `http_pool.rs` | HTTP connection pooling |
| `integrity.rs` | Content integrity verification |
| `lifecycle.rs` | Component lifecycle management |
| `logging.rs` | Structured logging |
| `metrics.rs` | Prometheus-compatible metrics |
| `metrics_exporter.rs` | Metrics export pipeline |
| `network_diag.rs` | Network diagnostics |
| `orchestrator.rs` | System orchestration |
| `partial_chunk.rs` | Partial chunk handling |
| `peer_selection.rs` | Peer selection algorithms |
| `pinning.rs` | Selective pinning optimizer |
| `popularity.rs` | Content popularity tracking |
| `prefetch.rs` | Chunk prefetching |
| `priority_eviction.rs` | Priority-based cache eviction |
| `profiler.rs` | Performance profiling |
| `proof_submit.rs` | Proof submission with retry |
| `qos.rs` | Quality of service policies |
| `quic_transport.rs` | QUIC transport layer |
| `ratelimit.rs` | Bandwidth rate limiting |
| `reputation.rs` | Peer reputation tracking |
| `request_pipeline.rs` | Request processing pipeline |
| `resource_mgmt.rs` | Resource management |
| `serde_helpers.rs` | Serialization helpers |
| `storage_health.rs` | Storage health monitoring |
| `streaming.rs` | Streaming data transfer |
| `streaming_verification.rs` | Streaming content verification |
| `system_coordinator.rs` | System-level coordination |
| `test_utils.rs` | Test utilities |
| `tier_migration.rs` | Tiered storage migration |
| `tiered_cache.rs` | Multi-tier cache (TieredCacheConfig with CompressionAlgorithm) |
| `tiered_storage.rs` | Multi-tier storage |
| `tracing.rs` | Distributed tracing |
| `transaction.rs` | Transactional operations |
| `utils.rs` | Shared utilities |
| `validation.rs` | Input validation |
| `wal.rs` | Write-ahead log |

## v0.2.0 Changes

- **Real P2P integration**: `ContentNode` and `NetworkStateMonitor` now perform live peer discovery and communication
- **OxiARC deflate**: `compression.rs` migrated from flate2 to OxiARC (pure Rust, COOLJAPAN policy)
- **TieredCacheConfig**: new `CompressionAlgorithm` field for per-tier compression selection
- All 70 modules stable, 0 stubs

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_storage_bytes` | 50 GB | Maximum storage allocation |
| `max_bandwidth_bps` | 100 Mbps | Maximum bandwidth provision |
| `coordinator_url` | https://coordinator.chie.network | Coordinator API endpoint |

