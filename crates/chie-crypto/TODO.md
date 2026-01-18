# chie-crypto TODO

## Status: ✅ Feature Complete (Phase 0-19)

**Metrics (2026-01-18)**
- Modules: 82
- Unit Tests: 1,034 (1,025 passing, 9 ignored)
- Integration Tests: 44
- Doc Tests: 86
- Benchmark Groups: 47

---

## Implemented Features

### Core Cryptographic Primitives
- [x] **Ed25519 Signatures** - Key generation, signing, batch verification
- [x] **ChaCha20-Poly1305** - AEAD encryption/decryption
- [x] **BLAKE3 Hashing** - Incremental hashing for large files
- [x] **HKDF Key Derivation** - Content keys from master key
- [x] **Constant-Time Operations** - Secure comparison utilities
- [x] **Key Serialization** - PEM, hex, base64, DER, JWK formats
- [x] **Streaming Encryption** - Large file support with chunking
- [x] **Key Rotation** - Automatic key lifecycle management

### Advanced Signatures
- [x] **Batch Verification** - Efficient multi-signature verification
- [x] **Threshold Signatures** - M-of-N signing with coordinator
- [x] **Aggregate Signatures** - Combine multiple signatures
- [x] **Schnorr Signatures** - Simpler with batch verification
- [x] **BLS Signatures** - Pairing-based aggregation
- [x] **MuSig2** - Multi-signature aggregation protocol
- [x] **Adaptor Signatures** - Atomic swaps support
- [x] **FROST** - Flexible Round-Optimized Schnorr Threshold (2-round)

### Post-Quantum Cryptography
- [x] **Kyber** - NIST-standardized KEM (512, 768, 1024 security levels)
- [x] **Dilithium** - NIST-standardized signatures (2, 3, 5 levels)
- [x] **SPHINCS+** - Hash-based signatures (minimal assumptions)

### Privacy-Preserving Protocols
- [x] **Ring Signatures** - Anonymous signing within groups
- [x] **Linkable Ring Signatures** - Double-spend prevention
- [x] **BBS+ Signatures** - Selective disclosure (proof-of-concept)
- [x] **Zero-Knowledge Range Proofs** - Privacy-preserving value verification
- [x] **Bulletproofs** - Efficient range proofs
- [x] **Ring CT** - Confidential transactions
- [x] **Blind Signatures** - Unlinkable tokens

### Protocol Building Blocks
- [x] **Merkle Trees** - Efficient content verification with proofs
- [x] **Pedersen Commitments** - Homomorphic bandwidth aggregation
- [x] **VRF** - Verifiable random functions for challenges
- [x] **Oblivious Transfer** - 1-of-N private retrieval
- [x] **Private Set Intersection** - Content discovery without catalog reveal
- [x] **Searchable Encryption** - Encrypted content indexing

### Key Management
- [x] **Key Rotation Scheduler** - Time and usage-based policies
- [x] **Key Backup & Recovery** - Shamir secret sharing
- [x] **HSM Integration** - Hardware security module abstraction
- [x] **Certificate Management** - CA, CRL, revocation
- [x] **Secure Key Storage** - Encryption at rest
- [x] **Multi-party Key Generation** - Ceremony support

### Authentication
- [x] **SPAKE2** - Password-authenticated key exchange
- [x] **SRP** - Secure Remote Password protocol
- [x] **OPRF** - Oblivious pseudorandom functions
- [x] **Identity-Based Encryption** - Simplified key management

### Enterprise & Compliance
- [x] **Audit Logging** - Tamper-evident operation logs
- [x] **Compliance Reporting** - FIPS 140-3 readiness
- [x] **Key Policy Enforcement** - Usage restrictions
- [x] **Entropy Monitoring** - RNG health checks
- [x] **Side-channel Verification** - Timing attack detection
- [x] **Formal Verification Helpers** - Property-based testing

### Interoperability
- [x] **SSH Key Formats** - OpenSSH import/export
- [x] **OpenPGP Formats** - RFC 4880 compatibility
- [x] **TLS 1.3 Key Schedule** - RFC 8446 derivation
- [x] **WebCrypto API** - Browser compatibility layer
- [x] **PKCS#11** - Mock provider for testing

### Performance
- [x] **SIMD Operations** - Parallel cryptographic operations
- [x] **Constant-Time Audit** - Timing leak detection
- [x] **Cache-Timing Mitigations** - Table lookup protection
- [x] **Comprehensive Benchmarks** - 47 benchmark groups

---

## Quality

- Zero compiler warnings
- Zero clippy warnings
- Well-documented with examples
- Production-ready
- Quantum-resistant options available
