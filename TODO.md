# CHIE Protocol - Development Roadmap

## Current Status

**Phase 0 (PoC)**: ✅ **100% COMPLETE** - Core protocol, server infrastructure, mesh simulation, and all success criteria implemented

### Current Metrics (2026-01-18)
- **Rust Code**: 196,538 SLOC (243,995 total lines)
- **Total Project**: 208,012 SLOC (277,438 total lines)
- **Tests**: 2,000+ across all crates
- **Modules**: 82 crypto + 41 P2P + 50+ coordinator + 40+ core + 30+ workers

---

## Phase 0: Technical PoC (Target: 8,500 SLOC → ✅ Achieved: 196,538 SLOC)

### Core Protocol (chie-p2p, chie-shared)
- [x] `BandwidthProofCodec` for libp2p request-response
- [x] `ChunkRequest` and `ChunkResponse` structures
- [x] `BandwidthProof` structure with dual signatures
- [x] Protocol versioning (`/chie/bandwidth-proof/1.0.0`)
- [x] Content size limits and validation
- [x] 2-node chunk transfer simulation (`MeshSimulation::two_node()`)
- [x] 5-node mesh simulation (`MeshSimulation::five_node()`)
- [x] Custom scenario support with `MeshScenario` enum

### Cryptography (chie-crypto)
- [x] Ed25519 key generation and signing
- [x] Signature verification
- [x] ChaCha20-Poly1305 encryption/decryption
- [x] BLAKE3 hashing
- [x] HKDF key derivation
- [x] Streaming encryption for large files
- [x] Key rotation utilities
- [x] Constant-time comparison

### Server Infrastructure (chie-coordinator)
- [x] Axum-based REST API structure
- [x] PostgreSQL schema (SQLx models)
- [x] Proof submission endpoint
- [x] Nonce cache for replay prevention
- [x] Verification engine structure:
  - [x] Nonce replay attack detection
  - [x] Timestamp validation (5-minute window)
  - [x] Signature verification
  - [x] Statistical anomaly detection (z-score > 3)
- [x] Fraud detection system
- [x] Reward calculation engine
- [x] Batch proof processing
- [x] Prometheus metrics
- [x] Integration tests with real database

### P2P Networking (chie-p2p)
- [x] Node discovery (DHT, mDNS)
- [x] NAT traversal and relay
- [x] Peer reputation system
- [x] Bandwidth throttling
- [x] Connection metrics tracking
- [x] Gossipsub for content announcements

### Core Node Logic (chie-core)
- [x] Chunk storage and retrieval
- [x] Per-chunk encryption
- [x] Content integrity verification
- [x] Selective pinning optimizer
- [x] Content popularity tracking
- [x] Chunk prefetching
- [x] Content deduplication
- [x] Rate limiting
- [x] Proof submission with retry
- [x] Garbage collection for unprofitable content
- [x] ContentNode with integrated ChunkStorage backend
- [x] Verified chunk retrieval (`handle_chunk_request_verified`)

### Workers (chie-workers)
- [x] Redis job queue
- [x] Exponential backoff retry
- [x] Encryption pipeline
- [x] IPFS pinning service
- [x] Chunked upload manager
- [x] Content moderation (ClamAV, AI)
- [x] S3 integration
- [x] Worker health checks
- [x] Job progress tracking
- [x] Parallel job processing

### Desktop Client (Tauri)
- [x] Basic UI framework (apps/desktop/src/)
- [x] Node start/stop control (apps/desktop/src-tauri/src/lib.rs)
- [x] Earnings dashboard (apps/desktop/src/pages/Earnings.tsx)
- [x] Content pinning interface (apps/desktop/src/pages/Content.tsx)
- [x] Rust IPC commands (apps/desktop/src-tauri/src/lib.rs)

### Phase 0 Success Criteria ✅ ALL COMPLETE
- [x] 5 virtual nodes transferring encrypted content (MeshSimulation)
- [x] Tamper-proof BandwidthProof generation (dual-signed proofs)
- [x] Dynamic pricing functional (RewardEngine with demand/supply multiplier)
- [x] False positive rate < 1% for anomaly detection (z-score verification)

### Recent Technical Achievements (2026-01-18)
- [x] **Post-Quantum Cryptography**: Kyber, Dilithium, SPHINCS+ implementations
- [x] **FROST Threshold Signatures**: 2-round Schnorr threshold signatures
- [x] **BBS+ Selective Disclosure**: Privacy-preserving credentials (proof-of-concept)
- [x] **Mutex Deadlock Fixes**: Fixed critical deadlocks in adaptive_retry and feature_flags
- [x] **Slow Test Performance**: Reduced test times from 60+ seconds to <1 second
- [x] **Request Coalescing**: Added tokio::test attributes for proper async runtime

---

## Phase 1: MVP (Target: 127,000 SLOC)

### Month 1: Production Infrastructure

#### Week 1-2: Cloud Setup
- [ ] AWS Terraform configuration
  - [ ] Primary: Tokyo (ap-northeast-1)
  - [ ] Secondary: Singapore (ap-southeast-1)
- [ ] PostgreSQL RDS Multi-AZ
- [ ] Redis ElastiCache cluster
- [ ] Kubernetes deployment
- [ ] Grafana + Prometheus dashboards

#### Week 3-4: CMS Development
- [ ] Creator Portal (Next.js + tRPC)
  - [ ] Content upload with multipart
  - [ ] Earnings dashboard
  - [ ] Analytics views
- [ ] Content processing pipeline
  - [ ] S3 temporary upload
  - [ ] ChaCha20-Poly1305 encryption
  - [ ] IPFS pinning
  - [ ] Key storage

### Month 2: Creator Onboarding

#### Desktop Client Polish
- [ ] Auto-update mechanism
- [ ] Onboarding wizard
  - [ ] Storage allocation slider
  - [ ] Wallet generation
  - [ ] Welcome bonus
- [ ] macOS/Windows code signing

#### Creator Acquisition
- [ ] Target: 200 creator candidates
- [ ] DM outreach to 50 creators
- [ ] "Asset Creator Summit" online event
- [ ] First 10 creators onboarded

### Month 3: Node Operator Growth

#### User Acquisition
- [ ] Creator referral system
- [ ] Reddit/Discord community posts
- [ ] Target: 500 node operators

#### Gamification System
- [ ] Leaderboard (monthly rankings)
- [ ] Badges (Founder, TopSeeder, SuperNode)
- [ ] Quest system
  - [ ] Daily: 12-hour uptime
  - [ ] Weekly: Host 5 creators
  - [ ] Monthly: Transfer 100GB

### Phase 1 Success Metrics
- [ ] 50 creators
- [ ] 500 node operators (60%+ uptime)
- [ ] 100+ content items (500GB+)
- [ ] 5M JPY total transaction volume
- [ ] NPS >= 50

---

## Phase 2: Scale (Target: 312,000 SLOC)

### Month 1-2: Multi-Region
- [ ] Coordinator federation (3 regions)
- [ ] Raft consensus for demand sync
- [ ] Kubernetes HPA auto-scaling
- [ ] Tiered storage (Hot/Warm/Cold)

### Month 3-4: AI Model Marketplace
- [ ] New content categories
  - [ ] Stable Diffusion checkpoints
  - [ ] LLM models (GGUF/safetensors)
  - [ ] Voice conversion models
- [ ] Pickle security scanner
- [ ] CivitAI migration campaign

### Month 3-4 (parallel): Mobile App
- [ ] Flutter monitoring app
  - [ ] Earnings dashboard
  - [ ] Push notifications
  - [ ] Remote node control
- [ ] Firebase Cloud Messaging

### Month 5-6: Viral Growth
- [ ] 3-tier referral system
- [ ] Auto-generated promo videos
- [ ] Social share templates
- [ ] Media coverage campaign

### Phase 2 Success Metrics
- [ ] 500 creators
- [ ] 10,000 active nodes
- [ ] 50TB+ content
- [ ] 50M JPY monthly transaction
- [ ] NPS >= 60

---

## Phase 3: Global Expansion (Target: 685,000 SLOC)

### Q1: Global Infrastructure
- [ ] Expand to 10 regions
- [ ] Multi-language support (EN, ZH, KO, ES, PT)
- [ ] Multi-currency payments

### Q2: Enterprise & Token
- [ ] Enterprise private network
- [ ] Governance token design & audit
- [ ] IDO preparation

### Q3: DAO Launch
- [ ] Token distribution
- [ ] Governance proposals
- [ ] DAO treasury management

### Q4: Metaverse & Exit
- [ ] VRChat integration
- [ ] NFT marketplace
- [ ] Exit strategy evaluation

### Phase 3 Success Metrics
- [ ] 5,000 creators (70% non-Japan)
- [ ] 100,000 active nodes
- [ ] 500M JPY monthly transaction
- [ ] 50 enterprise customers
- [ ] 10B JPY token market cap

---

## Technical Debt Tracker

| Issue | Priority | Status |
|-------|----------|--------|
| Integration tests for verification pipeline | High | ✅ Complete |
| Full API documentation | Medium | ✅ Complete |
| P2P protocol versioning upgrade path | High | ✅ Complete |
| Benchmark suite for proof verification | Medium | ✅ Complete |
| Desktop client prototype | High | ✅ Complete |
| Post-quantum cryptography migration | Low | ✅ Ready (Kyber, Dilithium, SPHINCS+) |
| Slow test performance optimization | High | ✅ Complete (60s → <1s) |

---

## SLOC Breakdown by Phase

| Phase | Rust Backend | Frontend | Infra/Config | Total | Status |
|-------|-------------|----------|--------------|-------|--------|
| Phase 0 | ~~6,500~~ → **196,538** | 1,500 | 500 | ~~8,500~~ → **208,012** | ✅ COMPLETE |
| Phase 1 | 85,000 | 35,000 | 7,000 | 127,000 | 🔄 In Progress |
| Phase 2 | 180,000 | 100,000 | 32,000 | 312,000 | ⏳ Planned |
| Phase 3 | 350,000 | 250,000 | 85,000 | 685,000 | ⏳ Planned |

### Actual Crate SLOC (2026-01-18)
| Crate | SLOC | Tests | Status |
|-------|------|-------|--------|
| chie-crypto | ~50,000 | 1,034 | ✅ Complete (82 modules) |
| chie-p2p | ~26,000 | 494+ | ✅ Complete (41 modules) |
| chie-coordinator | ~30,000 | 251 | ✅ Complete (50+ modules) |
| chie-shared | ~14,000 | 740 | ✅ Complete |
| chie-core | ~20,000 | 400+ | ✅ Complete |
| workers | ~5,000 | 50+ | ✅ Complete |
