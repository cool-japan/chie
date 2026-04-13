# CHIE Protocol

**Collective Hybrid Intelligence Ecosystem** (集合的ハイブリッド知能エコシステム)

A high-performance decentralized content distribution protocol leveraging P2P technology and incentive mechanisms, written in Rust.

## Brand Concept

**CHIE** (知恵) represents multiple layers of meaning:

- **知恵 (Wisdom)**: Distributed intelligence across the network, not centralized knowledge
- **千重 (Thousand Layers)**: Millions of nodes forming a robust mesh network
- **地恵 (Blessings of Infrastructure)**: Rewards from the digital infrastructure

> "Yui connects the world, Chie makes it think."

## Overview

CHIE Protocol is a next-generation content delivery network that combines IPFS-based decentralized storage with an innovative incentive system. Creators distribute content through a mesh network of user nodes, while node operators earn rewards for providing bandwidth and storage.

### Key Features

- **P2P Content Distribution**: Decentralized delivery using rust-libp2p
- **Bandwidth Proof Protocol**: Cryptographically verifiable proof of content transfer with dual signatures
- **Dynamic Pricing Engine**: Supply/demand based reward calculation (up to 3x multiplier)
- **Desktop Node Client**: Tauri-based cross-platform application
- **Creator Portal**: Web-based content management and analytics
- **Anti-Fraud Detection**: Statistical anomaly detection (z-score), nonce-based replay prevention

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Desktop Client (Tauri)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Content Shop │  │ Node Control │  │ Earnings     │      │
│  │ (購入画面)    │  │ (ノード起動)  │  │ Dashboard    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────┬────────────────────────────────────────────────┘
             │ ← Rust backend (IPC)
             ↓
┌─────────────────────────────────────────────────────────────┐
│            P2P Node Core (rust-libp2p)                      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Custom Protocol: /bandwidth-proof/1.0.0                │ │
│  │ - Request chunks with challenge nonce                  │ │
│  │ - Respond with encrypted data + signature              │ │
│  │ - Generate mutual proof of transfer                    │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ IPFS Integration (kubo via HTTP API)                   │ │
│  │ - Encrypted content pinning (CIDv1)                    │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────┬────────────────────────────────────────────────┘
             │ HTTPS (Proof submission)
             ↓
┌─────────────────────────────────────────────────────────────┐
│      Central Coordinator (Axum + PostgreSQL)                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Proof Verification Engine                              │ │
│  │ - Replay attack detection (nonce DB)                   │ │
│  │ - Statistical anomaly detection (z-score > 3)          │ │
│  │ - Ed25519 signature verification                       │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Reward Calculation Engine                              │ │
│  │ - Dynamic pricing (supply/demand ratio)                │ │
│  │ - Quality-adjusted payment (latency penalties)         │ │
│  │ - Referral cascade (2-tier Referral)                   │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
chie/
├── Cargo.toml                    # Workspace manifest
├── README.md                     # This file
├── TODO.md                       # Development roadmap
├── CLAUDE.md                     # AI assistant instructions
│
├── crates/
│   ├── chie-core/                # Core protocol logic
│   │   └── src/
│   │       ├── node.rs           # P2P node management
│   │       ├── protocol.rs       # Bandwidth proof protocol
│   │       ├── content.rs        # Content management
│   │       ├── storage.rs        # Chunk storage/retrieval
│   │       ├── chunk_encryption.rs # Per-chunk encryption
│   │       ├── integrity.rs      # Content integrity verification
│   │       ├── pinning.rs        # Selective pinning optimizer
│   │       ├── popularity.rs     # Content popularity tracking
│   │       ├── prefetch.rs       # Chunk prefetching
│   │       ├── dedup.rs          # Content deduplication
│   │       ├── ratelimit.rs      # Bandwidth rate limiting
│   │       └── proof_submit.rs   # Proof submission with retry
│   │
│   ├── chie-p2p/                 # P2P networking layer
│   │   └── src/
│   │       ├── node.rs           # libp2p node setup
│   │       ├── codec.rs          # Protocol codec
│   │       ├── protocol.rs       # Protocol versioning
│   │       ├── discovery.rs      # Peer discovery (DHT, mDNS)
│   │       ├── nat.rs            # NAT traversal & relay
│   │       ├── reputation.rs     # Peer reputation system
│   │       ├── throttle.rs       # Bandwidth throttling
│   │       └── metrics.rs        # Connection metrics
│   │
│   ├── chie-coordinator/         # Central coordinator server
│   │   └── src/
│   │       ├── main.rs           # Server entry point
│   │       ├── api/              # REST API endpoints
│   │       ├── admin/            # Admin management sub-module
│   │       ├── alerting/         # Alerting & notifications sub-module
│   │       ├── gamification/     # Badges, quests, leaderboard, points engine
│   │       ├── referral/         # Creator referral API (/me/referral, /me/referrals)
│   │       ├── rewards/          # Reward calculation
│   │       ├── verification/     # Proof verification
│   │       └── db/               # Database models (SQLx)
│   │
│   ├── chie-crypto/              # Cryptographic primitives
│   │   └── src/
│   │       ├── encryption.rs     # ChaCha20-Poly1305
│   │       ├── signing.rs        # Ed25519 signatures
│   │       ├── hash.rs           # BLAKE3 hashing
│   │       ├── kdf.rs            # HKDF key derivation
│   │       ├── ct.rs             # Constant-time comparison
│   │       ├── streaming.rs      # Streaming encryption
│   │       ├── keyserde.rs       # Key serialization
│   │       └── rotation.rs       # Key rotation utilities
│   │
│   └── chie-shared/              # Shared types and utilities
│       └── src/
│           ├── types.rs          # BandwidthProof, ChunkRequest, etc.
│           ├── errors.rs         # Error definitions
│           ├── validation.rs     # Input validation
│           └── conversions.rs    # Type conversions
│
├── apps/
│   ├── desktop/                  # Tauri desktop application
│   ├── web/                      # Public web frontend (Next.js)
│   └── creator-portal/           # Creator dashboard (Next.js + tRPC)
│
├── workers/                      # Background job workers
│   └── src/
│       ├── queue.rs              # Redis job queue
│       ├── retry.rs              # Exponential backoff retry
│       ├── encryption_pipeline.rs # Content encryption
│       ├── ipfs_pinning.rs       # IPFS pinning service
│       ├── chunked_upload.rs     # Chunked upload manager
│       ├── moderation.rs         # Content moderation
│       ├── s3.rs                 # S3 integration
│       ├── health.rs             # Worker health checks
│       └── progress.rs           # Job progress tracking
│
└── tests/                        # Integration tests
```

## Crates Overview

| Crate | Description | SLOC | Tests | Status |
|-------|-------------|------|-------|--------|
| `chie-crypto` | Cryptographic primitives (82 modules) | ~47,569 | 1,034 passing | ✅ Stable |
| `chie-p2p` | P2P networking with libp2p (110 modules) | ~58,324 | 494+ passing | ✅ Stable |
| `chie-coordinator` | Central coordinator server (62 modules) | ~34,788 | 251 passing | ✅ Stable |
| `chie-core` | Core protocol logic (70 modules) | ~46,178 | 400+ passing | ✅ Stable |
| `chie-shared` | Shared types and utilities (30+ modules) | ~15,301 | 740 passing | ✅ Stable |
| `chie-workers` | Background workers (12 modules) | ~4,344 | 50+ passing | ✅ Stable |

**Total**: 198,922 Rust SLOC (211,716 total), 4,515 tests passing (12 skipped) — v0.2.0 (2026-04-13)

## Technology Stack

### Backend (Rust)

| Component | Library | Purpose |
|-----------|---------|---------|
| P2P Networking | libp2p 0.54 | Swarm, Kademlia DHT, Gossipsub, Request-Response |
| Web Framework | Axum 0.7 | REST API, WebSocket |
| Database | SQLx 0.7 | PostgreSQL async driver |
| Async Runtime | Tokio 1.x | Full-featured async runtime |
| Encryption | chacha20poly1305 | AEAD content encryption |
| Signing | ed25519-dalek | Digital signatures |
| Hashing | blake3 | Fast cryptographic hashing |
| Key Derivation | hkdf | HKDF-SHA256 |

### Frontend

| Component | Technology | Purpose |
|-----------|------------|---------|
| Desktop Client | Tauri 2.0 | Cross-platform native app |
| Web Frontend | Next.js 14 | Public website |
| Creator Portal | Next.js + tRPC | Creator dashboard |

### Infrastructure

| Component | Technology | Purpose |
|-----------|------------|---------|
| Primary Database | PostgreSQL 15+ | User data, proofs, content metadata |
| Cache/Queue | Redis | Job queue, real-time data, nonce cache |
| Content Storage | IPFS | Decentralized content addressing |
| Object Storage | S3 | Temporary upload staging |

## Implemented Features

### Cryptography (chie-crypto)
- **Core**: Ed25519 signatures, ChaCha20-Poly1305 AEAD, BLAKE3 hashing, HKDF key derivation
- **Advanced**: Threshold signatures (FROST), BLS aggregation, Schnorr signatures
- **Post-Quantum**: Kyber KEM, Dilithium signatures, SPHINCS+ hash-based signatures
- **Privacy**: Ring signatures, BBS+ selective disclosure, zero-knowledge range proofs
- **Protocol**: Merkle trees, Pedersen commitments, VRFs, oblivious transfer
- **Enterprise**: HSM integration, key rotation, certificate management, audit logging

### P2P Networking (chie-p2p)
- **Transport**: TCP, QUIC, WebRTC support with NAT traversal and relay
- **Discovery**: Kademlia DHT, mDNS, bootstrap nodes, peer exchange (PEX)
- **Protocol**: Custom bandwidth proof codec, Gossipsub for announcements
- **Optimization**: Connection pooling, load balancing, adaptive routing
- **Resilience**: Circuit breaker, erasure coding, network partition detection
- **QoS**: Traffic shaping, priority queues, bandwidth throttling

### Coordinator (chie-coordinator)
- **API**: REST endpoints (users, nodes, content, proofs, analytics)
- **Security**: JWT auth, API keys, rate limiting, brute force protection
- **Verification**: Nonce-based replay prevention, z-score anomaly detection
- **Rewards**: Dynamic pricing engine, demand/supply multipliers
- **Operations**: Graceful shutdown, Redis caching, connection pool tuning
- **Compliance**: GDPR data export, retention policies, audit logging

### Core (chie-core)
- **Storage**: Chunk encryption, tiered storage (SSD/HDD), deduplication
- **Content**: Selective pinning optimizer, popularity tracking, prefetching
- **Network**: Peer selection, content routing, adaptive rate limiting
- **Monitoring**: Metrics (Prometheus), profiling, network diagnostics
- **Resilience**: Circuit breaker, exponential backoff retry, health checks

### Workers (chie-workers)
- **Queue**: Redis-based job processing with exponential backoff
- **Content**: Chunked uploads, IPFS pinning, S3 staging
- **Moderation**: ClamAV scanning, AI content moderation, zip bomb detection
- **Operations**: Health checks, progress tracking, parallel processing

### Desktop Client (Tauri)
- **UI**: Content shop, node control, earnings dashboard
- **Backend**: Rust IPC commands, node lifecycle management

## What's New in v0.2.0 (2026-04-13)

- **Gamification system**: badges, quests, leaderboard, points engine — full `GamificationEngine` with persistence
- **Creator referral API**: `/me/referral` and `/me/referrals` endpoints with cascade rewards
- **Monthly leaderboard snapshots**: persistent leaderboard history with `/leaderboard/history` endpoint
- **Transfer history ring buffer**: 200-entry `VecDeque` powering the Transfers UI page
- **Settings + gamification persistence**: JSON serialization to disk, loaded on startup
- **Desktop onboarding wizard**: 4-step wizard (welcome, storage setup, identity, ready)
- **OxiARC compression throughout**: all compression/decompression via Pure Rust `oxiarc-*` crates (no C/Fortran)
- **Security patches**: aws-lc-sys 0.39.1, quinn-proto 0.11.14, rustls-webpki 0.103.11, time 0.3.47
- **File size policy**: all source files ≤ 2,000 lines — coordinator `admin.rs`, `alerting.rs`, `api/mod.rs` split into sub-modules
- **Dependency updates**: toml 1.1, uuid 1.23, async-graphql 7.2, aws-sdk-s3 1.129, criterion 0.8

## Bandwidth Proof Protocol

The core innovation is the cryptographically verifiable bandwidth proof:

```
1. Requester → Provider: ChunkRequest
   - content_cid: IPFS CID
   - chunk_index: u64
   - challenge_nonce: [u8; 32]
   - timestamp: i64

2. Provider → Requester: ChunkResponse
   - encrypted_chunk: Vec<u8>
   - chunk_hash: [u8; 32]
   - provider_signature: Vec<u8>
   - challenge_echo: [u8; 32]

3. Both parties generate BandwidthProof:
   - Dual signatures (provider + requester)
   - session_id, bytes_transferred, latency_ms
   - Submitted to coordinator for verification
```

## Reward Calculation

```rust
// Base: 10 points per GB
// Multiplier: Up to 3x based on demand/supply ratio
// Penalty: 50% reduction for latency > 500ms

reward = base_reward_per_gb
       * gb_transferred
       * min(demand / supply, 3.0)
       * (if latency_ms > 500 { 0.5 } else { 1.0 })
```

## Development Phases

| Phase | Focus | SLOC Target | Actual | Status |
|-------|-------|-------------|--------|--------|
| Phase 0 (PoC) | Core P2P protocol, bandwidth proof | 8,500 | **198,922** | ✅ Complete |
| Phase 1 (MVP) | Production infra, creator onboarding | 127,000 | - | In Progress |
| Phase 2 (Scale) | Multi-region, AI marketplace, mobile | 312,000 | - | Planned |
| Phase 3 (Global) | Global expansion, enterprise, DAO | 685,000 | - | Planned |

## Getting Started

### Prerequisites

- Rust 1.83+ (MSRV, install via [rustup](https://rustup.rs/))
- PostgreSQL 15+
- Redis 7+
- Node.js 20+ (for frontend)

### Build

```bash
# Clone and enter the project
cd chie

# Build all crates
cargo build --release

# Run tests (requires cargo-nextest)
cargo nextest run

# Check for warnings (must pass)
cargo clippy -- -D warnings
```

### Run Coordinator

```bash
# Set environment variables
export DATABASE_URL="postgresql://user:pass@localhost/chie"
export REDIS_URL="redis://localhost:6379"

# Run the coordinator server
cargo run --release -p chie-coordinator
```

### Run Desktop Client

```bash
cd apps/desktop
npm install
npm run tauri dev
```

## Code Standards

- **Rust Edition**: 2024 (MSRV 1.83)
- **No Warnings Policy**: All code must compile without warnings
- **Testing**: `cargo nextest run` must pass
- **File Limits**: Keep single files under 2000 lines

## Sponsorship

Chie is developed and maintained by **COOLJAPAN OU (Team Kitasan)**.

If you find Chie useful, please consider sponsoring the project to support continued development of the Pure Rust ecosystem.

[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-red?logo=github)](https://github.com/sponsors/cool-japan)

**[https://github.com/sponsors/cool-japan](https://github.com/sponsors/cool-japan)**

Your sponsorship helps us:
- Maintain and improve the COOLJAPAN ecosystem
- Keep the entire ecosystem (OxiBLAS, OxiFFT, SciRS2, etc.) 100% Pure Rust
- Provide long-term support and security updates

## License

UNLICENSED - All Rights Reserved

## Author

COOLJAPAN OU
