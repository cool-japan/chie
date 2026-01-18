# chie-crypto

Cryptographic primitives for the CHIE Protocol.

## Overview

This crate provides all cryptographic operations required by CHIE Protocol:
- **Encryption**: Content protection using ChaCha20-Poly1305
- **Signing**: Bandwidth proof authentication using Ed25519
- **Hashing**: Fast content verification using BLAKE3

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

## Modules

| Module | Purpose |
|--------|---------|
| `encryption.rs` | ChaCha20-Poly1305 AEAD encryption |
| `signing.rs` | Ed25519 digital signatures |
| `hash.rs` | BLAKE3 cryptographic hashing |
| `kdf.rs` | HKDF key derivation |
| `ct.rs` | Constant-time comparison utilities |
| `streaming.rs` | Streaming encryption for large files |
| `keyserde.rs` | Key serialization (PEM, hex, base64) |
| `rotation.rs` | Key rotation utilities |

## Dependencies

```toml
chacha20poly1305 = "0.10"
ed25519-dalek = "2"
blake3 = "1"
rand = "0.9"
hkdf = "0.12"
sha2 = "0.10"
```

