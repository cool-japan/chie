# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/cool-japan/chie/releases/tag/v0.1.0
