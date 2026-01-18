# Constant-Time Operation Verification

Constant-time operations are critical for preventing timing side-channel attacks in cryptographic implementations. This document describes the constant-time guarantees and verification methods used in `chie-crypto`.

## What are Timing Side-Channels?

Timing side-channel attacks exploit variations in execution time that depend on secret data. For example:
- Comparing secret keys byte-by-byte and returning early on mismatch
- Conditional branches based on secret values
- Variable-time operations like non-constant-time array lookups

## Constant-Time Guarantees

### Constant-Time Comparison

The `constant_time_eq()` function provides constant-time comparison of byte arrays:

```rust
use chie_crypto::constant_time_eq;

let key1 = [0x42; 32];
let key2 = [0x43; 32];

// Comparison time independent of where difference occurs
assert!(!constant_time_eq(&key1, &key2));
```

**Properties:**
- Execution time does not depend on input values
- Execution time does not depend on position of first difference
- Safe against timing attacks
- Uses bitwise operations to avoid conditional branches

### Encryption/Decryption

ChaCha20-Poly1305 AEAD provides:
- Constant-time encryption
- Constant-time authentication tag generation
- Constant-time authentication tag verification (critical!)

The authentication tag verification is constant-time to prevent attackers from learning information through timing analysis of tag comparison.

### Signature Verification

Ed25519 signature verification is designed to be constant-time:
- Point multiplication is constant-time
- Verification does not leak information about the signature or public key

## Verification Tests

The `tests/constant_time_verification.rs` file contains 13 comprehensive tests:

1. **Equal inputs** - Verify constant time for identical data
2. **Different inputs** - Verify constant time for different data
3. **Difference positions** - Time independent of where difference occurs
4. **Authentication failures** - Decryption fails in constant time
5. **Invalid signatures** - Verification fails in constant time
6. **Extreme values** - All-zero vs all-one inputs
7. **Single bit difference** - Minimal difference detection
8. **Plaintext independence** - Decryption time independent of content
9. **Message independence** - Signature time independent of message
10. **Heap allocation** - Works with heap-allocated data
11. **Timing property** - First difference position doesn't matter
12. **Output verification** - Different plaintexts produce different outputs
13. **Uniform arrays** - All same byte values

Run with:
```bash
cargo test --test constant_time_verification
```

## Side-Channel Resistance

The `src/sidechannel.rs` module provides additional side-channel analysis tools:

- **Timing analysis** - Detect variable-time operations
- **Correlation analysis** - Detect input-dependent timing
- **Constant-time verification** - Statistical analysis of timing variations

See [sidechannel.rs documentation](src/sidechannel.rs) for detailed usage.

## Best Practices

### DO:
- Use `constant_time_eq()` for comparing secrets
- Use constant-time primitives from trusted libraries
- Verify constant-time behavior with tests
- Use side-channel analysis tools during development

### DON'T:
- Use `==` operator for comparing secrets
- Use early-return comparisons on secret data
- Use conditional branches based on secrets
- Assume constant-time without verification

## Testing Strategy

1. **Unit Tests** - Verify correct behavior
2. **Property Tests** - Verify timing independence properties
3. **Statistical Analysis** - Use `sidechannel.rs` tools
4. **Code Review** - Manual inspection of assembly
5. **Fuzzing** - Coverage-guided testing

## Limitations

- Compiler optimizations may introduce timing variations
- CPU features (branch prediction, caching) can leak information
- Perfect constant-time is impossible; we aim for practical resistance
- Platform-specific behavior may vary

## References

- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.paulkocher.com/doc/TimingAttacks.pdf)
- [Cache-timing attacks on AES](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf)
- [The Subtle Crypto API](https://www.w3.org/TR/WebCryptoAPI/)

## Continuous Verification

Add constant-time tests to CI:
```yaml
constant-time:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - run: cargo test --test constant_time_verification
```
