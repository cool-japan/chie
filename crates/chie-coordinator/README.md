# chie-coordinator v0.2.0

Central Coordinator Server for the CHIE Protocol.

**Stats**: 62+ modules · 251 tests · ~34,788 SLoC · 82 source files · 11 SQL migrations

## Overview

The coordinator is the central trust authority that:
- Verifies bandwidth proofs submitted by nodes
- Calculates and distributes rewards (including gamification badges, quests, and leaderboards)
- Detects fraud and anomalies
- Maintains the content registry
- Tracks node reputation
- Manages creator referral chains with multi-tier reward distribution
- Exposes 54+ REST API endpoints under `/api/v1`

## What's New in v0.2.0

- **Gamification engine**: Full `GamificationEngine` with badge unlocks, quest tracking, and leaderboards. Includes a dedicated scheduler for periodic jobs and monthly leaderboard snapshot archiving.
- **Creator referral API**: `GET /api/v1/me/referral` and `GET /api/v1/me/referrals` — real-time referral link generation and chain inspection.
- **Admin module split**: `admin/` directory with 6 sub-modules — `system`, `moderation`, `management`, `operations`, `email`, and routes.
- **Alerting module split**: `alerting/` directory with 7 files — `channels`, `email`, `rules`, `types`, `utils`, and dispatcher.
- **API module split**: `api/` directory with 5 sub-modules — `core`, `proofs`, `stats`, `webhooks`, `developer`.
- **Monthly leaderboard snapshots**: Scheduler-driven archival of top-ranked users per period.
- **0 stubs**: All 62+ modules are fully implemented and stable.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Coordinator Server                       │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                    Axum Router (54+ endpoints)         │ │
│  │  /api/v1/*             → api/ (core, proofs, stats,   │ │
│  │                            webhooks, developer)        │ │
│  │  /api/v1/me/referral*  → referral routes              │ │
│  │  /api/v1/gamification* → gamification sub-router      │ │
│  │  /admin/*              → admin sub-router             │ │
│  │  GET  /health          → health_check()               │ │
│  └───────────────────────────────────────────────────────┘ │
│                           │                                 │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              Verification Engine                       │ │
│  │  1. Nonce replay check                                │ │
│  │  2. Timestamp validation (5-min window)               │ │
│  │  3. Signature verification (Ed25519)                  │ │
│  │  4. Statistical anomaly detection (z-score)           │ │
│  └───────────────────────────────────────────────────────┘ │
│                           │                                 │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                Reward Engine                           │ │
│  │  Formula: base * demand_multiplier * quality_factor   │ │
│  │  Distribution: provider + creator + referrers         │ │
│  └───────────────────────────────────────────────────────┘ │
│                           │                                 │
│  ┌───────────────────────────────────────────────────────┐ │
│  │              PostgreSQL Database                       │ │
│  │  users, content, nodes, bandwidth_proofs,             │ │
│  │  point_transactions, content_demand_hourly            │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Modules

### api/mod.rs - REST API

```rust
// Submit bandwidth proof
POST /api/proofs
Body: BandwidthProof (JSON)
Response: { accepted: bool, reward: Option<u64>, message: String }

// Register new content
POST /api/content
Body: { cid, title, description, size_bytes, price, creator_id }
Response: { success: bool, content_id: Option<UUID>, message: String }
```

### verification/mod.rs - Proof Verification

Multi-step verification pipeline:

```rust
let verifier = ProofVerifier::new(pool, VerificationConfig::default());
let result = verifier.verify(&proof).await?;

// VerificationResult
// - is_valid: bool
// - status: ProofStatus (Verified/Rejected)
// - rejection_reason: Option<String>
// - anomalies: Vec<AnomalyReport>
// - quality_score: f64 (0.0 to 1.0)
```

**Verification Steps**:
1. **Nonce Replay Check**: Ensure nonce hasn't been used before
2. **Timestamp Validation**: Within 5-minute window
3. **Latency Sanity**: Not impossibly fast (< 1ms)
4. **Provider Signature**: Ed25519 verification
5. **Requester Signature**: Ed25519 verification
6. **Statistical Anomaly**: Z-score analysis

### rewards/mod.rs - Reward Calculation

Dynamic pricing based on supply/demand:

```rust
let engine = RewardEngine::new(pool, RewardConfig::default());
let distribution = engine.calculate_and_distribute(
    &proof,
    proof_id,
    quality_score,
    provider_user_id,
    content_creator_id,
).await?;

// RewardDistribution
// - provider_reward: Points
// - creator_reward: Points (10% of total)
// - referrer_rewards: Vec<(UUID, Points)> (5%, 2%, 1% tiers)
// - platform_fee: Points (10% of total)
```

**Reward Formula**:
```
reward = base_per_gb * demand_multiplier * latency_factor * quality_score

demand_multiplier = sqrt(demand/supply)  // Capped at 3x
latency_factor = 1.0 if <100ms, 0.5 if >500ms
```

### db/ - Database Layer

**Models** (`models.rs`):
- `User`, `Content`, `Node`, `ContentPin`
- `BandwidthProofRecord`, `PointTransaction`, `Purchase`
- `ContentDemandHourly`, `FraudReport`

**Repositories** (`repository.rs`):
- `UserRepository`: User CRUD, points management, referral chain
- `ContentRepository`: Content CRUD, trending queries
- `NodeRepository`: Node registration, heartbeat, seeder lookup
- `ProofRepository`: Proof storage, nonce checking, reward recording
- `TransactionRepository`: Point transaction logging
- `AnalyticsRepository`: Demand metrics, hourly aggregation

## Configuration

```rust
VerificationConfig {
    timestamp_tolerance_ms: 300_000,  // 5 minutes
    anomaly_z_threshold: 3.0,
    min_latency_ms: 1,
    high_latency_threshold_ms: 500,
}

RewardConfig {
    base_reward_per_gb: 10,           // Points per GB
    max_demand_multiplier: 3.0,
    min_demand_multiplier: 0.5,
    optimal_latency_ms: 100,
    penalty_latency_ms: 500,
    max_latency_penalty: 0.5,
    creator_share: 0.1,               // 10%
    platform_fee_share: 0.1,          // 10%
    referral_tiers: [0.05, 0.02, 0.01], // 5%, 2%, 1%
}
```

## Modules

The crate contains 62+ modules organized as follows:

### Entry Point & Infrastructure
| Module | Purpose |
|--------|---------|
| `main.rs` | Server entry point, Axum router assembly |
| `config.rs` | Configuration loading and validation |
| `health.rs` | Health check endpoints |
| `metrics.rs` | Prometheus metrics export |
| `openapi.rs` | OpenAPI / Swagger spec generation |

### API Layer (`api/` — 5 sub-modules)
| Module | Purpose |
|--------|---------|
| `api/core.rs` | Core REST handler glue |
| `api/proofs.rs` | Proof submission and retrieval endpoints |
| `api/stats.rs` | Network and node statistics endpoints |
| `api/webhooks.rs` | Outbound webhook delivery |
| `api/developer.rs` | Developer API keys and sandbox tools |

### Verification & Rewards
| Module | Purpose |
|--------|---------|
| `verification/mod.rs` | Multi-step proof verification pipeline |
| `rewards/mod.rs` | Dynamic reward calculation engine |
| `referral/` | Creator referral chain tracking and payouts |

### Gamification (`gamification/` — 3 modules)
| Module | Purpose |
|--------|---------|
| `gamification/mod.rs` | GamificationEngine: badges, quests, leaderboards |
| `gamification/routes.rs` | REST routes for gamification sub-router |
| `gamification/scheduler.rs` | Periodic jobs and monthly leaderboard snapshots |

### Admin (`admin/` — 6 sub-modules)
`system`, `moderation`, `management`, `operations`, `email`, `routes`

### Alerting (`alerting/` — 7 files)
`channels`, `email`, `rules`, `types`, `utils`, `dispatcher`, `mod`

### Database Layer (`db/` — 2 modules)
| Module | Purpose |
|--------|---------|
| `db/models.rs` | ORM structs: User, Content, Node, BandwidthProofRecord, etc. |
| `db/repository.rs` | Repository traits: User, Content, Node, Proof, Analytics |

### Cross-Cutting Concerns (50+ top-level modules)
| Module | Purpose |
|--------|---------|
| `auth.rs` | JWT authentication and session management |
| `validation.rs` | Request validation middleware |
| `fraud.rs` | Fraud detection and anomaly scoring |
| `nonce_cache.rs` | Redis-backed nonce replay prevention |
| `redis_cache.rs` | General-purpose Redis caching layer |
| `rate_limit_quotas.rs` | Per-user and per-IP rate limiting |
| `request_coalescing.rs` | Deduplication of concurrent identical requests |
| `batch.rs` | Batch proof processing pipeline |
| `cache.rs` · `compression.rs` | Response caching; OxiARC compression middleware |
| `read_replicas.rs` | Read replica routing for PostgreSQL |
| `analytics.rs` | Demand metrics and hourly aggregation |
| `graphql.rs` | GraphQL API layer |
| `payment.rs` | Off-chain payment channel integration |
| `gdpr.rs` | GDPR data subject request handling |
| `migrations.rs` | Migration management helpers |
| `webhooks.rs` | Webhook fanout and retry logic |
| `websocket.rs` | Real-time WebSocket event stream |

## Database Schema

See `migrations/001_initial_schema.sql` for full schema.

Key tables:
- `users`: User accounts with points balance
- `content`: Content registry with metadata
- `nodes`: Node registry with reputation
- `bandwidth_proofs`: Proof records
- `point_transactions`: Audit trail
- `used_nonces`: Replay attack prevention

## Running

```bash
# Set environment
export DATABASE_URL="postgresql://user:pass@localhost/chie"
export RUST_LOG="info"

# Run migrations
sqlx migrate run

# Start server
cargo run --release -p chie-coordinator
# Listening on 0.0.0.0:3000
```

