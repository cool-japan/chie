# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-13

### Added

- **Gamification system**: leaderboard, badges (Founder/TopSeeder/SuperNode/EarlyAdopter/BandwidthHero/Reliable), quests (daily/weekly/monthly), and a points engine
- **Gamification API endpoints**: full REST API under `/api/v1/gamification/...` (leaderboard, user state, quest progress, badge eligibility)
- **Real OxiARC compression in chie-p2p**: replaced placeholder RLE with proper LZ4, Zstd, and Snappy codecs via `oxiarc-*`
- **OxiARC deflate/gzip in chie-core**: replaced `flate2` with Pure Rust OxiARC implementation
- **OxiARC deflate+brotli in chie-coordinator**: replaced `flate2` and `brotli` crates with `oxiarc-*`
- **Desktop app real P2P node integration**: replaced mock data with `ContentNode` + `NetworkStateMonitor` backed by live chie-core
- Quest scheduler: hourly background maintenance, daily checks, monthly points reset
- Gamification Desktop UI: Rewards page with badges, quests, leaderboard (real-time)
- Desktop onboarding wizard: 4-step first-run experience (storage, identity, welcome)
- `get_gamification_state` and `update_quest_progress` Tauri commands
- `is_onboarding_complete` and `complete_onboarding` Tauri commands
- **Transfer history ring buffer**: 200-entry `VecDeque<TransferEntry>` in `AppState`; `record_transfer` command; dedicated Transfers UI page with filter (All/Uploads/Downloads) and 30s auto-refresh
- **Settings + gamification persistence**: `load_persisted_settings` / `update_settings` now read/write JSON to the app data directory on startup and change
- **Creator referral system API**: `GET /api/v1/me/referral` (lazy code generation), `GET /api/v1/me/referrals` (list with earnings), backed by `crates/chie-coordinator/src/referral/`
- **Leaderboard monthly snapshots**: `save_monthly_snapshot` / `load_snapshots` on `GamificationEngine`; scheduler captures snapshot before each monthly reset; `GET /api/v1/gamification/leaderboard/history` endpoint

### Changed

- **Workspace version**: bumped to 0.2.0
- **schemars 0.8 → 1.2**: `Schema` now replaces `RootSchema`; schema generation updated throughout
- **rand 0.8 → 0.10**: `rng()` replaces deprecated `thread_rng()`
- **sha2 0.10 → 0.11, hkdf 0.12 → 0.13, hmac 0.12 → 0.13**: unified digest trait stack upgrade
- **redis 0.32 → 1.2**: migrated to `get_multiplexed_async_connection` and `ErrorKind::Io`
- **jsonwebtoken 9.3 → 10.3**: updated JWT library to latest
- **oxicode 0.1.1 → 0.2**: upgraded serialisation library
- **tokio 1.49 → 1.51**: latest async runtime
- **License**: updated from "MIT OR Apache-2.0" to "Apache-2.0"
- **Code structure**: Split `chie-coordinator` modules `admin` (4,636 lines), `alerting` (2,842 lines), and `api` (2,661 lines) into focused sub-modules; all source files now comply with the 2,000-line policy
- **Crate metadata**: Added `readme` field to all published crate `Cargo.toml` files; corrected `chie-desktop` license and repository URL

### Fixed

- Resolved `unwrap()` violations in `chie-p2p/protocol_compression.rs` and desktop app integration code
- All clippy warnings eliminated (zero warnings across workspace)
  - `needless_borrows_for_generic_args` in chie-crypto keyexchange.rs
  - `io_other_error` in chie-p2p, chie-core, chie-coordinator compression modules
  - `manual_div_ceil` in desktop lib.rs
  - Workspace policy: `rand = { workspace = true }` in chie-coordinator
- Fixed LZ4 round-trip doc example in `chie/src/lib.rs` (data was below `min_compress_size` threshold)
- Fixed doc example struct field mismatches in `chie-core`: `cache_admission.rs` (`TinyLFU` unsized key), `qos.rs` (missing `deadline_ms` field), `tiered_cache.rs` (missing `compression` field)
- Fixed hardcoded `/tmp/` path in `gdpr.rs` GDPR export — now uses `std::env::temp_dir()`
- Fixed bare URL in `alerting.rs` doc comment triggering rustdoc lint
- Fixed `chie-crypto` doc examples: `proxy_re.rs` (private codec access), `bbs_plus.rs` (unsound BBS+ verify marked `no_run`), `chie-p2p` compression examples (LZ4 min-size threshold)

### Security

- All compression throughout the workspace now uses Pure Rust OxiARC (no C/Fortran dependencies)
- Patched transitive dependency vulnerabilities: `aws-lc-sys` 0.36.0→0.39.1 (5 CVEs: timing side-channel, X.509/CRL/PKCS7 bypass), `quinn-proto` 0.11.13→0.11.14 (DoS), `rustls-webpki` 0.103.9→0.103.11 (CRL matching), `time` 0.3.45→0.3.47 (stack exhaustion DoS)

## [0.1.0] - 2026-01-18

### Added

#### chie-shared v0.1.0
- Core types: `ContentId`, `ChunkId`, `PeerId`, `ProofId`, `UserId`
- Error types: `ChieError`, `ValidationError`, `CryptoError`
- Configuration structures and serialization support
- Property-based testing with proptest

#### chie-crypto v0.1.0
- Ed25519 signature generation and verification
- X25519 key exchange (ECDH)
- ChaCha20-Poly1305 AEAD encryption
- BLAKE3 hashing
- Constant-time operations with auditing support
- Post-quantum cryptography (Kyber, Dilithium, SPHINCS+)
- Differential privacy mechanisms (Gaussian, Exponential)
- Password hashing with Argon2

#### chie-core v0.1.0
- Bandwidth proof protocol implementation
- Content chunk management with encryption
- Storage backend abstraction
- Rate limiting and throttling
- Content deduplication
- Prefetch and caching strategies
- Popularity tracking
- Proof submission with retry logic
- QUIC transport support
- Resource management and health monitoring
- Analytics and metrics collection

#### chie-p2p v0.1.0
- libp2p integration with custom protocols
- Kademlia DHT for peer discovery
- GossipSub for content announcements
- Request-response protocol for chunk transfers
- Connection management and multiplexing
- NAT traversal support
- Reed-Solomon erasure coding
- Multiple compression codecs (LZ4, Zstd, Snappy)

#### chie-coordinator v0.1.0
- Axum-based REST API server
- GraphQL API with async-graphql
- PostgreSQL database integration
- Redis caching layer
- JWT authentication
- Swagger/OpenAPI documentation
- Prometheus metrics export
- Email notifications with Lettre
- S3-compatible storage integration

### Security
- All cryptographic operations use constant-time implementations
- No unwrap() calls in production code
- Pure Rust implementation (no C/Fortran dependencies)

[0.2.0]: https://github.com/cool-japan/chie/releases/tag/v0.2.0
[0.1.0]: https://github.com/cool-japan/chie/releases/tag/v0.1.0
