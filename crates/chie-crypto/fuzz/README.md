# Fuzzing Harnesses for chie-crypto

This directory contains fuzzing harnesses for cryptographic primitives using `cargo-fuzz`.

## Prerequisites

Install cargo-fuzz:
```bash
cargo install cargo-fuzz
```

## Available Fuzz Targets

- `fuzz_encryption` - ChaCha20-Poly1305 encryption/decryption roundtrip
- `fuzz_signing` - Ed25519 signing and verification
- `fuzz_hashing` - BLAKE3 hashing
- `fuzz_kdf` - HKDF key derivation
- `fuzz_keyexchange` - X25519 key exchange
- `fuzz_shamir` - Shamir Secret Sharing
- `fuzz_pedersen` - Pedersen commitments
- `fuzz_merkle` - Merkle tree operations

## Running Fuzz Tests

Run a specific fuzzer:
```bash
cd fuzz
cargo fuzz run fuzz_encryption
```

Run with a time limit:
```bash
cargo fuzz run fuzz_encryption -- -max_total_time=60
```

Run with corpus minimization:
```bash
cargo fuzz cmin fuzz_encryption
```

## Continuous Fuzzing

For continuous fuzzing in CI or long-running tests:
```bash
# Run each fuzzer for 5 minutes
for target in fuzz_encryption fuzz_signing fuzz_hashing fuzz_kdf fuzz_keyexchange fuzz_shamir fuzz_pedersen fuzz_merkle; do
    cargo fuzz run $target -- -max_total_time=300 -rss_limit_mb=2048
done
```

## Coverage-Guided Fuzzing

Generate coverage report:
```bash
cargo fuzz coverage fuzz_encryption
```

## Corpus Management

The fuzz corpus is stored in `fuzz/corpus/<target>/`. Interesting inputs that trigger new code paths are automatically saved.

## Notes

- All harnesses verify cryptographic properties (e.g., encryption roundtrip, signature verification)
- Harnesses test error handling and edge cases
- Use sanitizers for memory safety (enabled by default with cargo-fuzz)
