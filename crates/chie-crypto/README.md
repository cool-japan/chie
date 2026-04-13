# chie-crypto

Cryptographic primitives for the CHIE Protocol (v0.2.0).

## Overview

This crate provides all cryptographic operations required by CHIE Protocol.
It contains **82 modules** with **601 public items** and **1,034 passing tests**.

Core capabilities include:
- **Symmetric Encryption**: Content protection using ChaCha20-Poly1305
- **Asymmetric / Signing**: Ed25519, BLS, MuSig2, FROST threshold signatures
- **Hashing**: BLAKE3, SHA-2 family
- **Post-Quantum Cryptography (PQC)**: Kyber (ML-KEM), Dilithium (ML-DSA), SPHINCS+
- **Zero-Knowledge Proofs**: Bulletproofs, range proofs, zkSNARK helpers
- **Threshold / Multi-Party**: FROST, MuSig2, DKG, Shamir secret sharing
- **Anonymous Credentials**: BBS+, blind signatures, linkable ring signatures
- **Homomorphic Encryption**: Paillier, ElGamal
- **Key Management**: HSM interface, PKCS#11, key rotation, backup, OpenPGP/OpenSSH
- **Privacy**: Differential privacy, oblivious transfer, PSI, OPRF
- **Advanced Primitives**: Garbled circuits, time-lock puzzles, VDF, VRF, onion routing layer

## Modules

### encryption.rs - ChaCha20-Poly1305

Authenticated encryption for content protection.

```rust
use chie_crypto::{encrypt, decrypt, generate_key, generate_nonce};

let key = generate_key();       // 256-bit key
let nonce = generate_nonce();   // 96-bit nonce
let ciphertext = encrypt(plaintext, &key, &nonce)?;
let decrypted = decrypt(&ciphertext, &key, &nonce)?;
```

**Why ChaCha20-Poly1305?**
- Fast in software (no AES-NI required)
- Resistant to timing attacks
- AEAD (authenticated encryption with associated data)
- Used by WireGuard, TLS 1.3

### signing.rs - Ed25519

Digital signatures for bandwidth proof authentication.

```rust
use chie_crypto::{KeyPair, verify};

let keypair = KeyPair::generate();
let signature = keypair.sign(message);
let public_key = keypair.public_key();

// Verification (returns Result)
verify(&public_key, message, &signature)?;
```

**Why Ed25519?**
- Fast signature generation and verification
- Small signatures (64 bytes)
- Small keys (32 bytes public, 32 bytes secret)
- Deterministic (same message = same signature)
- Used by libp2p for peer identity

### hash.rs - BLAKE3

Fast cryptographic hashing for content integrity.

```rust
use chie_crypto::{hash, hash_multi, verify_hash};

let h = hash(data);                           // Single buffer
let h = hash_multi(&[chunk1, chunk2, chunk3]); // Streaming
assert!(verify_hash(data, &h));
```

**Why BLAKE3?**
- Extremely fast (faster than MD5!)
- Parallelizable
- 256-bit output
- Secure against length extension attacks

## Security Considerations

### Nonce Management
- **Never reuse nonces** with the same key
- Each chunk should have a unique nonce
- Consider using counter-based nonces for streaming

### Key Storage
- Content encryption keys stored in PostgreSQL (encrypted at rest)
- User signing keys stored locally on desktop client
- Never transmit secret keys

### Signature Protocol
The bandwidth proof protocol uses dual signatures:
1. Provider signs: `nonce || chunk_hash || requester_pubkey`
2. Requester signs: `nonce || chunk_hash || provider_pubkey || provider_sig`

This prevents:
- Replay attacks (nonce is unique per transfer)
- Man-in-the-middle (signatures bind to specific peers)
- Proof fabrication (both parties must cooperate)

## Full Module List (82 modules)

| Module | Purpose |
|--------|---------|
| `abe.rs` | Attribute-based encryption |
| `accumulator.rs` | Cryptographic accumulators |
| `adaptor.rs` | Adaptor signatures |
| `advanced_commitment.rs` | Advanced commitment schemes |
| `aggregate.rs` | Signature aggregation |
| `aggregate_mac.rs` | Aggregate MACs |
| `anonymous_credentials.rs` | Anonymous credential schemes |
| `audit_log.rs` | Cryptographic audit logging |
| `bbs_plus.rs` | BBS+ signatures for anonymous credentials |
| `blind.rs` | Blind signatures |
| `bls.rs` | BLS12-381 signatures |
| `bulletproof.rs` | Bulletproof range/inner-product proofs |
| `cache_timing.rs` | Cache-timing side-channel mitigations |
| `cert_manager.rs` | Certificate management |
| `certified_deletion.rs` | Certified deletion proofs |
| `codec.rs` | Key/data codec utilities |
| `commitment.rs` | Pedersen and other commitment schemes |
| `compliance.rs` | Regulatory compliance helpers |
| `ct.rs` | Constant-time comparison utilities |
| `ct_audit.rs` | Constant-time audit helpers |
| `differential_privacy.rs` | Differential privacy mechanisms |
| `dilithium.rs` | ML-DSA (Dilithium) post-quantum signatures |
| `dkg.rs` | Distributed key generation |
| `elgamal.rs` | ElGamal homomorphic encryption |
| `encryption.rs` | ChaCha20-Poly1305 AEAD encryption |
| `entropy.rs` | Entropy estimation and collection |
| `formal_verify.rs` | Formal verification helpers |
| `forward_secure.rs` | Forward-secure signatures |
| `frost.rs` | FROST threshold Schnorr signatures |
| `functional_encryption.rs` | Functional encryption |
| `garbled_circuit.rs` | Yao's garbled circuits |
| `hash.rs` | BLAKE3 + SHA-2 cryptographic hashing |
| `hmac.rs` | HMAC message authentication (unified 0.13) |
| `hsm.rs` | Hardware Security Module interface |
| `ibe.rs` | Identity-based encryption |
| `kdf.rs` | HKDF key derivation (unified 0.13) |
| `key_backup.rs` | Encrypted key backup |
| `key_formats.rs` | Key format conversions (DER, PEM, JWK) |
| `key_policy.rs` | Key usage policies |
| `key_rotation_scheduler.rs` | Automated key rotation scheduling |
| `keyexchange.rs` | X25519 / ECDH key exchange |
| `keygen_ceremony.rs` | Multi-party key generation ceremony |
| `keyserde.rs` | Key serialization (PEM, hex, base64) |
| `keystore.rs` | Secure key storage |
| `kyber.rs` | ML-KEM (Kyber) post-quantum KEM |
| `linkable_ring.rs` | Linkable ring signatures |
| `merkle.rs` | Merkle tree proofs |
| `musig2.rs` | MuSig2 multi-signatures |
| `onion.rs` | Onion routing encryption layer |
| `openpgp.rs` | OpenPGP key handling |
| `openssh.rs` | OpenSSH key format support |
| `oprf.rs` | Oblivious pseudorandom functions |
| `ot.rs` | Oblivious transfer |
| `paillier.rs` | Paillier homomorphic encryption |
| `pbkdf.rs` | Password-based key derivation |
| `pedersen.rs` | Pedersen commitments |
| `pkcs11.rs` | PKCS#11 token interface |
| `polycommit.rs` | Polynomial commitments (KZG) |
| `pos.rs` | Proof of storage |
| `proxy_re.rs` | Proxy re-encryption |
| `psi.rs` | Private set intersection |
| `rangeproof.rs` | Range proofs |
| `ring.rs` | Ring signatures |
| `ringct.rs` | RingCT confidential transactions |
| `rotation.rs` | Key rotation utilities |
| `schnorr.rs` | Schnorr signatures |
| `searchable.rs` | Searchable symmetric encryption |
| `shamir.rs` | Shamir secret sharing |
| `sidechannel.rs` | Side-channel resistance helpers |
| `signing.rs` | Ed25519 digital signatures |
| `simd.rs` | SIMD-accelerated crypto helpers |
| `spake2.rs` | SPAKE2 password-authenticated key exchange |
| `sphincs.rs` | SPHINCS+ post-quantum signatures |
| `srp.rs` | Secure Remote Password protocol |
| `streaming.rs` | Streaming encryption for large files |
| `threshold.rs` | Generic threshold cryptography |
| `threshold_ecdsa.rs` | Threshold ECDSA |
| `timelock.rs` | Time-lock puzzles |
| `tls13.rs` | TLS 1.3 key schedule helpers |
| `utils.rs` | Shared utilities |
| `vdf_delay.rs` | Verifiable delay functions |
| `vrf.rs` | Verifiable random functions |
| `webcrypto.rs` | WebCrypto-compatible API |
| `zeroizing.rs` | Zeroizing memory helpers |
| `zkproof.rs` | Zero-knowledge proof framework |

## v0.2.0 Changes

- **rand** upgraded 0.8 → 0.10: `rng()` replaces `thread_rng()`
- **sha2** upgraded to 0.11 (unified across workspace)
- **hmac** upgraded to 0.13 (unified across workspace)
- **hkdf** upgraded to 0.13 (unified across workspace)
- **schemars** upgraded to 1.2
- All 82 modules remain fully implemented (0 stubs)

## Dependencies

```toml
chacha20poly1305 = "0.10"
ed25519-dalek = "2"
blake3 = "1"
rand = "0.10"
hkdf = "0.13"
sha2 = "0.11"
hmac = "0.13"
```

