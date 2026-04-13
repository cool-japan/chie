# chie-shared

Shared types, errors, and utilities for the CHIE Protocol.

## Overview

This crate provides common types and utilities used across all CHIE Protocol components including the coordinator server, P2P nodes, desktop client, and web applications.

**Version**: 0.2.0 | **Status**: Stable | **Tests**: 740 passing | **Public items**: 280

## Features

- **Core Protocol Types**: ContentMetadata, BandwidthProof, ChunkRequest/Response, ContentId, ChunkId, PeerId, ProofId, UserId
- **Gamification Types**: Badge, Quest, QuestType, QuestStatus, LeaderboardEntry, UserGamificationState (new in 0.2.0)
- **Error Types**: Comprehensive error handling with ProtocolError, VerificationError, RewardError
- **Database Conversions**: Traits for converting between domain types and database models
- **Utility Functions**: Formatting, validation, calculations, and more
- **JSON Schema Generation**: Optional schema generation for API documentation (enable `schema` feature)
- **Constants**: Protocol-wide constants for timeouts, limits, and thresholds

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
chie-shared = { path = "../chie-shared" }
```

Enable JSON schema generation:

```toml
[dependencies]
chie-shared = { path = "../chie-shared", features = ["schema"] }
```

## Examples

### Creating Content Metadata

```rust
use chie_shared::{ContentMetadataBuilder, ContentCategory, ContentStatus};
use uuid::Uuid;

let creator_id = Uuid::new_v4();
let metadata = ContentMetadataBuilder::new()
    .cid("QmExampleCID123")
    .title("My 3D Model")
    .description("A high-quality 3D model")
    .category(ContentCategory::ThreeDModels)
    .add_tag("blender")
    .add_tag("game-ready")
    .size_bytes(5 * 1024 * 1024) // 5 MB
    .price(1000)
    .creator_id(creator_id)
    .status(ContentStatus::Active)
    .build()
    .expect("Failed to build metadata");

assert!(metadata.is_valid());
assert_eq!(metadata.size_mb(), 5.0);
```

### Building a Bandwidth Proof

```rust
use chie_shared::BandwidthProofBuilder;

let proof = BandwidthProofBuilder::new()
    .content_cid("QmTest123")
    .chunk_index(0)
    .bytes_transferred(262144) // 256 KB
    .provider_peer_id("12D3KooProvider")
    .requester_peer_id("12D3KooRequester")
    .provider_public_key(vec![1u8; 32])
    .requester_public_key(vec![2u8; 32])
    .provider_signature(vec![3u8; 64])
    .requester_signature(vec![4u8; 64])
    .challenge_nonce(vec![5u8; 32])
    .chunk_hash(vec![6u8; 32])
    .timestamps(1000, 1250) // 250ms latency
    .build()
    .expect("Failed to build proof");

assert!(proof.is_valid());
assert!(proof.meets_quality_threshold());
```

### Using Utility Functions

```rust
use chie_shared::{format_bytes, format_points, calculate_demand_multiplier};

// Format bytes for display
assert_eq!(format_bytes(1_048_576), "1.00 MB");

// Format points with thousands separator
assert_eq!(format_points(1_234_567), "1,234,567");

// Calculate reward multiplier based on demand/supply
let multiplier = calculate_demand_multiplier(100, 50);
assert_eq!(multiplier, 3.0); // High demand = 3x multiplier
```

## Module Structure

- **types**: Core protocol types — 17 files covering content, bandwidth, peers, gamification, storage quotas, batch submissions, and more
  - Includes gamification sub-module: Badge, Quest, QuestType, QuestStatus, LeaderboardEntry, UserGamificationState (added in 0.2.0)
- **config**: Configuration types — 9 files
- **utils**: Utility functions — 11 files covering formatting, validation, calculations, and more
- **errors**: Error types for all protocol operations
- **conversions**: Database conversion traits and helpers
- **constants**: Protocol-wide constants
- **schema**: JSON schema generation (feature-gated via `schema` feature)

## Testing

Run tests (740 passing):

```bash
cargo test
```

Run property-based tests:

```bash
cargo test --test proptests
```

Run benchmarks:

```bash
cargo bench
```

## Performance

All core types are optimized for fast serialization/deserialization, minimal allocations, and efficient validation. See `benches/` for detailed performance metrics.

## Statistics

- **SLoC**: 15,301 code lines across 53 Rust files
- **Public items**: 280
- **Test suite**: 740 passing tests

## License

See LICENSE file in the project root.
