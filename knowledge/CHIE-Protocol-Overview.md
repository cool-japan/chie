# IPFS x Referral-Style Incentive CDN (CHIE Protocol)

## Overview

CHIE Protocol is a distributed content delivery network that combines IPFS-style content addressing with incentive-based bandwidth sharing. The protocol rewards users for providing bandwidth and storage resources, creating a sustainable P2P content distribution ecosystem.

## Related Documents

- [Business Model Refinement Analysis](./Business-Model-Analysis.md)
- [Deep Dive Analysis](./Deep-Dive-Analysis.md)

## Development Phases

### Phase 0: Technical PoC ✅ COMPLETE
**Target**: Core protocol implementation and validation
**Status**: 100% Complete (2026-01-18)
**SLOC**: 196,538 code lines (far exceeding initial 8,500 target)

Key achievements:
- P2P networking stack with libp2p
- Bandwidth proof protocol
- Coordinator server with fraud detection
- Mesh simulation (2, 5, N nodes)
- Desktop client prototype

### Phase 1: MVP (In Progress)
**Target**: 127,000 SLOC
**Focus**: Production infrastructure and creator onboarding

Milestones:
- Cloud deployment (AWS Tokyo/Singapore)
- CMS development (Next.js + tRPC)
- Desktop client polish
- Creator acquisition (200 candidates)

### Phase 2: Public Beta & Scale
**Target**: 312,000 SLOC
**Focus**: Multi-region expansion and AI marketplace

Milestones:
- Coordinator federation (3 regions)
- AI model marketplace (Stable Diffusion, LLMs, voice models)
- Mobile monitoring app (Flutter)
- Viral growth features (3-tier referral)

### Phase 3: Global Expansion
**Target**: 685,000 SLOC
**Focus**: International expansion and decentralization

Milestones:
- 10-region deployment
- Multi-language (EN, ZH, KO, ES, PT)
- Governance token and DAO
- Metaverse integration (VRChat)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     CHIE Protocol Stack                          │
├─────────────────────────────────────────────────────────────────┤
│  Applications                                                    │
│  ├── Desktop Client (Tauri + React)                             │
│  ├── Creator Portal (Next.js)                                   │
│  └── Mobile App (Flutter) [Phase 2]                             │
├─────────────────────────────────────────────────────────────────┤
│  Core Services                                                   │
│  ├── chie-coordinator (REST API, Fraud Detection, Rewards)      │
│  ├── chie-core (Content Management, Storage, Analytics)         │
│  └── chie-workers (Job Queue, Moderation, IPFS Pinning)         │
├─────────────────────────────────────────────────────────────────┤
│  Protocol Layer                                                  │
│  ├── chie-p2p (libp2p, DHT, Gossipsub, NAT Traversal)          │
│  ├── chie-shared (Types, Encoding, Configuration)               │
│  └── chie-crypto (Ed25519, ChaCha20, BLAKE3, Post-Quantum)     │
├─────────────────────────────────────────────────────────────────┤
│  Infrastructure                                                  │
│  ├── PostgreSQL (Transactions, Users, Content)                  │
│  ├── Redis (Caching, Job Queue)                                 │
│  └── IPFS (Content Addressing)                                  │
└─────────────────────────────────────────────────────────────────┘
```

## SLOC Analysis (2026-01-18)

| Crate | Code Lines | Total Lines | Tests | Modules |
|-------|------------|-------------|-------|---------|
| chie-crypto | ~50,000 | ~60,000 | 1,034 | 82 |
| chie-p2p | ~26,000 | ~30,000 | 494+ | 41 |
| chie-coordinator | ~30,000 | ~35,000 | 251 | 50+ |
| chie-shared | ~14,000 | ~16,000 | 740 | 30+ |
| chie-core | ~20,000 | ~25,000 | 400+ | 40+ |
| workers | ~5,000 | ~6,000 | 50+ | 10+ |
| **Total** | **196,538** | **243,995** | **2,000+** | **250+** |

## Branding: Multi-Layer Meaning

### "CHIE" (知恵)
The name carries multiple meanings:

1. **Japanese**: 知恵 (chie) = "wisdom, knowledge"
2. **Protocol Acronym**:
   - **C**ontent
   - **H**ashing
   - **I**ncentive
   - **E**cosystem
3. **Philosophy**: Collective intelligence of the network

### Value Proposition

"Creators and fans co-own the next-generation content delivery infrastructure"

- **For Creators**: Lower fees (15-25% vs 30-40% on traditional platforms)
- **For Node Operators**: Earn rewards by providing bandwidth
- **For Consumers**: Faster downloads through P2P distribution
- **For the Network**: Censorship-resistant, scalable content delivery

## Current Technical Achievements

### Cryptography (chie-crypto)
- Ed25519 signatures with batch verification
- ChaCha20-Poly1305 AEAD encryption
- BLAKE3 hashing with streaming support
- Post-quantum: Kyber, Dilithium, SPHINCS+
- FROST threshold signatures
- BBS+ selective disclosure (PoC)

### P2P Networking (chie-p2p)
- libp2p-based networking
- DHT and Gossipsub protocols
- NAT traversal with circuit relay
- QUIC transport support
- Erasure coding (Reed-Solomon)
- Peer reputation and load balancing

### Coordinator (chie-coordinator)
- Axum-based REST API
- PostgreSQL with SQLx
- Redis caching
- JWT authentication
- Fraud detection (z-score analysis)
- Webhook system
- GDPR compliance features

### Core (chie-core)
- Chunk storage with encryption
- Content deduplication
- Selective pinning optimizer
- Tiered storage (SSD/HDD)
- Network diagnostics
- Metrics and profiling
