# chie

**CHIE Protocol** - Decentralized, privacy-preserving file sharing with zero-knowledge proofs.

[![Crates.io](https://img.shields.io/crates/v/chie.svg)](https://crates.io/crates/chie)
[![Documentation](https://docs.rs/chie/badge.svg)](https://docs.rs/chie)
[![License](https://img.shields.io/badge/license-UNLICENSED-red.svg)](LICENSE)

## Overview

CHIE (Collective Hybrid Intelligence Ecosystem / 知恵) is a next-generation decentralized content distribution protocol combining IPFS-based storage with innovative incentive mechanisms.

This is the **meta crate** that re-exports all CHIE Protocol components for convenient access:

| Module | Crate | Description |
|--------|-------|-------------|
| [`shared`] | `chie-shared` | Common types, errors, validation, and utilities |
| [`crypto`] | `chie-crypto` | Cryptographic primitives (encryption, signatures, ZK proofs) |
| [`core`] | `chie-core` | Node implementation, storage, and content management |
| [`p2p`] | `chie-p2p` | P2P networking layer using rust-libp2p |

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
chie = "0.1"
```

## Quick Start

```rust
use chie::prelude::*;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a content node
    let config = NodeConfig {
        storage_path: PathBuf::from("./chie-data"),
        max_storage_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
        max_bandwidth_bps: 100 * 1024 * 1024 / 8,   // 100 Mbps
        coordinator_url: "https://coordinator.chie.network".to_string(),
    };

    let mut node = ContentNode::with_storage(config).await?;

    // Generate cryptographic keys
    let keypair = KeyPair::generate();
    println!("Public key: {:?}", keypair.public_key());

    Ok(())
}
```

## Features

### Cryptography (`chie::crypto`)

```rust
use chie::crypto::{KeyPair, generate_key, generate_nonce, encrypt, decrypt};

// Generate keys
let keypair = KeyPair::generate();
let encryption_key = generate_key();
let nonce = generate_nonce();

// Encrypt/decrypt data
let plaintext = b"Hello, CHIE!";
let ciphertext = encrypt(plaintext, &encryption_key, &nonce).unwrap();
let decrypted = decrypt(&ciphertext, &encryption_key, &nonce).unwrap();
assert_eq!(plaintext.as_slice(), decrypted.as_slice());
```

**Capabilities:**
- **Core**: Ed25519 signatures, ChaCha20-Poly1305 AEAD, BLAKE3 hashing, HKDF key derivation
- **Advanced**: Threshold signatures (FROST), BLS aggregation, Schnorr signatures
- **Post-Quantum**: Kyber KEM, Dilithium signatures, SPHINCS+ hash-based signatures
- **Privacy**: Ring signatures, BBS+ selective disclosure, zero-knowledge range proofs

### Content Management (`chie::shared`)

```rust
use chie::shared::{ContentMetadataBuilder, ContentCategory, ContentStatus};
use uuid::Uuid;

let metadata = ContentMetadataBuilder::new()
    .cid("QmExampleCID123")
    .title("My Content")
    .description("A sample content item")
    .category(ContentCategory::ThreeDModels)
    .size_bytes(1024 * 1024)
    .price(100)
    .creator_id(Uuid::new_v4())
    .status(ContentStatus::Active)
    .build()
    .expect("Failed to build metadata");
```

### P2P Networking (`chie::p2p`)

```rust
use chie::p2p::{CompressionManager, CompressionAlgorithm, CompressionLevel};

let manager = CompressionManager::new(CompressionAlgorithm::Lz4, CompressionLevel::Fast);
let data = b"Data to compress";
let compressed = manager.compress(data).unwrap();
let decompressed = manager.decompress(&compressed).unwrap();
assert_eq!(data.as_slice(), decompressed.as_slice());
```

**Capabilities:**
- **Transport**: TCP, QUIC, WebRTC support with NAT traversal and relay
- **Discovery**: Kademlia DHT, mDNS, bootstrap nodes, peer exchange (PEX)
- **Protocol**: Custom bandwidth proof codec, Gossipsub for announcements
- **Resilience**: Circuit breaker, erasure coding, network partition detection

### Core Protocol (`chie::core`)

```rust
use chie::core::{ContentNode, NodeConfig, ChunkStorage};
use chie::prelude::*;

// Create bandwidth proof for verified transfers
let proof = create_bandwidth_proof(
    session_id,
    provider_id,
    requester_id,
    content_cid,
    bytes_transferred,
    latency_ms,
)?;
```

**Capabilities:**
- **Storage**: Chunk encryption, tiered storage (SSD/HDD), deduplication
- **Content**: Selective pinning optimizer, popularity tracking, prefetching
- **Network**: Peer selection, content routing, adaptive rate limiting
- **Monitoring**: Metrics (Prometheus), profiling, network diagnostics

## Prelude

For convenience, import commonly used types with the prelude:

```rust
use chie::prelude::*;
```

This includes:

| Category | Types |
|----------|-------|
| **Types** | `BandwidthProof`, `ChunkRequest`, `ChunkResponse`, `ContentMetadata`, `ContentCategory` |
| **Errors** | `ChieError`, `ChieResult` |
| **Crypto** | `KeyPair`, `PublicKey`, `SecretKey`, `encrypt`, `decrypt`, `hash` |
| **Node** | `ContentNode`, `NodeConfig`, `ChunkStorage` |
| **P2P** | `CompressionManager`, `BootstrapManager`, `ContentRouter`, `GossipConfig` |

## Bandwidth Proof Protocol

The core innovation is the cryptographically verifiable bandwidth proof:

```text
1. Requester → Provider: ChunkRequest
   - content_cid, chunk_index, challenge_nonce, timestamp

2. Provider → Requester: ChunkResponse
   - encrypted_chunk, chunk_hash, provider_signature, challenge_echo

3. Both parties generate BandwidthProof:
   - Dual signatures (provider + requester)
   - session_id, bytes_transferred, latency_ms
   - Submitted to coordinator for verification
```

## Technology Stack

| Component | Library | Purpose |
|-----------|---------|---------|
| P2P Networking | libp2p 0.54 | Swarm, Kademlia DHT, Gossipsub |
| Encryption | chacha20poly1305 | AEAD content encryption |
| Signing | ed25519-dalek | Digital signatures |
| Hashing | blake3 | Fast cryptographic hashing |
| Key Derivation | hkdf | HKDF-SHA256 |
| Async Runtime | Tokio 1.x | Full-featured async runtime |

## Minimum Supported Rust Version (MSRV)

Rust **1.83** or later is required.

## Related Crates

- [`chie-shared`](https://crates.io/crates/chie-shared) - Shared types and utilities
- [`chie-crypto`](https://crates.io/crates/chie-crypto) - Cryptographic primitives
- [`chie-core`](https://crates.io/crates/chie-core) - Core protocol logic
- [`chie-p2p`](https://crates.io/crates/chie-p2p) - P2P networking layer
- [`chie-coordinator`](https://crates.io/crates/chie-coordinator) - Central coordinator server

## License

UNLICENSED - All Rights Reserved

## Author

COOLJAPAN OU
