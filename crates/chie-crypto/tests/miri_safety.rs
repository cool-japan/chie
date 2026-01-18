//! MIRI Memory Safety Tests
//!
//! This module contains tests specifically designed to be run under MIRI
//! to detect undefined behavior, memory safety violations, and data races.
//!
//! Run with: cargo +nightly miri test --test miri_safety

use chie_crypto::{
    KeyDerivation, KeyExchange, KeyExchangeKeypair, KeyPair, constant_time_eq, decrypt, encrypt,
    hash, pedersen, reconstruct_key_32, split_key_32,
};

/// Test encryption/decryption memory safety
#[test]
fn miri_encryption_memory_safety() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];

    // Test with various sizes
    for size in [0, 1, 16, 64, 1024, 4096] {
        let plaintext = vec![0x55u8; size];
        let ciphertext = encrypt(&plaintext, &key, &nonce).unwrap();
        let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

/// Test signing/verification memory safety
#[test]
fn miri_signing_memory_safety() {
    let keypair = KeyPair::generate();

    // Test with various message sizes
    for size in [0, 1, 16, 64, 1024, 4096] {
        let message = vec![0xAAu8; size];
        let signature = keypair.sign(&message);
        assert!(keypair.verify(&message, &signature));
    }
}

/// Test hashing memory safety
#[test]
fn miri_hashing_memory_safety() {
    // Test with various input sizes
    for size in [0, 1, 16, 64, 1024, 4096] {
        let data = vec![0xBBu8; size];
        let hash1 = hash(&data);
        let hash2 = hash(&data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}

/// Test constant-time comparison memory safety
#[test]
fn miri_constant_time_memory_safety() {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    let c = [0x43u8; 32];

    assert!(constant_time_eq(&a, &b));
    assert!(!constant_time_eq(&a, &c));

    // Test with stack and heap allocated data
    let heap_a = vec![0x42u8; 32];
    let heap_b = vec![0x42u8; 32];
    assert!(constant_time_eq(&heap_a, &heap_b));
}

/// Test key derivation memory safety
#[test]
fn miri_kdf_memory_safety() {
    let ikm = b"input key material";
    let salt = b"salt value";
    let info = b"application info";

    let kdf = KeyDerivation::new(ikm, Some(salt));

    // Test various output lengths
    for length in [16, 32, 64, 128, 256] {
        let okm = kdf.derive_bytes(info, length).unwrap();
        assert_eq!(okm.len(), length);
    }
}

/// Test key exchange memory safety
#[test]
fn miri_keyexchange_memory_safety() {
    let keypair_a = KeyExchangeKeypair::generate();
    let keypair_b = KeyExchangeKeypair::generate();

    let shared_ab = keypair_a.exchange(keypair_b.public_key());
    let shared_ba = keypair_b.exchange(keypair_a.public_key());

    assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
}

/// Test Shamir Secret Sharing memory safety
#[test]
fn miri_shamir_memory_safety() {
    let secret = [0x42u8; 32];

    // Test various threshold configurations
    let shares = split_key_32(&secret, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);

    let reconstructed = reconstruct_key_32(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);

    // Test with all shares
    let reconstructed_all = reconstruct_key_32(&shares).unwrap();
    assert_eq!(reconstructed_all, secret);
}

/// Test Pedersen commitments memory safety
#[test]
fn miri_pedersen_memory_safety() {
    let value = 42u64;

    let (commitment, opening) = pedersen::commit(value);
    assert!(pedersen::verify(&commitment, value, &opening));

    // Test homomorphic property
    let value2 = 58u64;
    let (commitment2, opening2) = pedersen::commit(value2);

    let commitment_sum = commitment.add(&commitment2);
    let opening_sum = opening.add(&opening2);

    assert!(pedersen::verify(
        &commitment_sum,
        value + value2,
        &opening_sum
    ));
}

/// Test array bounds and slice operations
#[test]
fn miri_array_bounds_safety() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"test message";

    // This should not cause out-of-bounds access
    let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();
    let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
    assert_eq!(&decrypted[..], plaintext);
}

/// Test uninitialized memory safety
#[test]
fn miri_uninitialized_memory_safety() {
    // Ensure we don't read uninitialized memory
    let mut buffer = vec![0u8; 1024];

    // Hash the buffer
    let _hash1 = hash(&buffer);

    // Modify buffer
    buffer[0] = 0xFF;
    let _hash2 = hash(&buffer);

    // Buffers for encryption should be properly initialized
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let _ciphertext = encrypt(&buffer, &key, &nonce).unwrap();
}

/// Test aliasing and mutable access
#[test]
fn miri_aliasing_safety() {
    let keypair = KeyPair::generate();
    let message = b"test message";

    // Multiple signatures of same message
    let sig1 = keypair.sign(message);
    let sig2 = keypair.sign(message);

    // Both should verify
    assert!(keypair.verify(message, &sig1));
    assert!(keypair.verify(message, &sig2));
}

/// Test drop and cleanup
#[test]
fn miri_cleanup_safety() {
    // Create and drop multiple keypairs
    for _ in 0..10 {
        let _keypair = KeyPair::generate();
        let _kex_keypair = KeyExchangeKeypair::generate();
    }

    // Create and drop KDF instances
    for _ in 0..10 {
        let kdf = KeyDerivation::new(b"ikm", Some(b"salt"));
        let _okm = kdf.derive_bytes(b"info", 32).unwrap();
    }
}
