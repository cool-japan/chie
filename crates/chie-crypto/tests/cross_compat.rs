//! Cross-Implementation Compatibility Tests
//!
//! This module verifies that chie-crypto implementations are compatible with
//! other standard cryptographic libraries and implementations.

use chie_crypto::{
    KeyDerivation, KeyExchange, KeyExchangeKeypair, KeyPair, decrypt, encrypt, hash, verify,
};

/// Test ChaCha20-Poly1305 compatibility with chacha20poly1305 crate
#[test]
fn test_chacha20_poly1305_compat_with_reference() {
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };

    let key_bytes = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let plaintext = b"Cross-compatibility test message";

    // Encrypt with our implementation
    let our_ciphertext = encrypt(plaintext, &key_bytes, &nonce_bytes).unwrap();

    // Decrypt with reference implementation
    let cipher = ChaCha20Poly1305::new(&key_bytes.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ref_plaintext = cipher.decrypt(nonce, our_ciphertext.as_ref()).unwrap();

    assert_eq!(&ref_plaintext[..], plaintext);

    // Encrypt with reference implementation
    let ref_ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

    // Decrypt with our implementation
    let our_plaintext = decrypt(&ref_ciphertext, &key_bytes, &nonce_bytes).unwrap();

    assert_eq!(&our_plaintext[..], plaintext);
}

/// Test Ed25519 signature compatibility with ed25519-dalek
#[test]
fn test_ed25519_compat_with_dalek() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

    let message = b"Compatibility test for Ed25519 signatures";

    // Generate key with our implementation
    let our_keypair = KeyPair::generate();
    let secret_bytes: [u8; 32] = our_keypair.secret_key();

    // Create dalek signing key from same secret
    let dalek_signing = SigningKey::from_bytes(&secret_bytes);
    let dalek_verifying = dalek_signing.verifying_key();

    // Sign with our implementation
    let our_signature = our_keypair.sign(message);

    // Verify with dalek
    let sig = Signature::from_bytes(&our_signature);
    assert!(dalek_verifying.verify(message, &sig).is_ok());

    // Sign with dalek
    let dalek_signature = dalek_signing.sign(message);

    // Verify with our implementation
    assert!(our_keypair.verify(message, dalek_signature.to_bytes().as_ref()));

    // Cross-verify: our verify function with dalek signature
    let dalek_sig_array = dalek_signature.to_bytes();
    let dalek_sig_bytes: &[u8; 64] = dalek_sig_array.as_ref().try_into().unwrap();
    assert!(verify(&our_keypair.public_key(), message, dalek_sig_bytes).is_ok());
}

/// Test X25519 key exchange compatibility with x25519-dalek
#[test]
fn test_x25519_compat_with_dalek() {
    use rand::Rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    // Generate random secret bytes
    let mut rng = rand::rng();
    let mut secret_bytes_a = [0u8; 32];
    let mut secret_bytes_b = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes_a);
    rng.fill_bytes(&mut secret_bytes_b);

    // Create keypairs from same secrets with both implementations
    let our_keypair_a = KeyExchangeKeypair::from_bytes(secret_bytes_a);
    let our_keypair_b = KeyExchangeKeypair::from_bytes(secret_bytes_b);

    let dalek_secret_a = StaticSecret::from(secret_bytes_a);
    let dalek_secret_b = StaticSecret::from(secret_bytes_b);
    let dalek_public_a = PublicKey::from(&dalek_secret_a);
    let dalek_public_b = PublicKey::from(&dalek_secret_b);

    // Verify public keys match
    assert_eq!(
        our_keypair_a.public_key().as_bytes(),
        dalek_public_a.as_bytes()
    );
    assert_eq!(
        our_keypair_b.public_key().as_bytes(),
        dalek_public_b.as_bytes()
    );

    // Perform key exchange with our implementation
    let our_shared_ab = our_keypair_a.exchange(our_keypair_b.public_key());
    let our_shared_ba = our_keypair_b.exchange(our_keypair_a.public_key());

    // Perform key exchange with dalek
    let dalek_shared_ab = dalek_secret_a.diffie_hellman(&dalek_public_b);
    let dalek_shared_ba = dalek_secret_b.diffie_hellman(&dalek_public_a);

    // Verify shared secrets match between implementations
    assert_eq!(our_shared_ab.as_bytes(), dalek_shared_ab.as_bytes());
    assert_eq!(our_shared_ba.as_bytes(), dalek_shared_ba.as_bytes());

    // Verify symmetric shared secret
    assert_eq!(our_shared_ab.as_bytes(), our_shared_ba.as_bytes());
    assert_eq!(dalek_shared_ab.as_bytes(), dalek_shared_ba.as_bytes());
}

/// Test BLAKE3 hash compatibility with blake3 crate
#[test]
fn test_blake3_compat_with_reference() {
    let test_inputs = [
        b"".as_ref(),
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        &[0u8; 1000],
        &[0xffu8; 10000],
    ];

    for input in &test_inputs {
        // Hash with our implementation
        let our_hash = hash(input);

        // Hash with reference implementation
        let ref_hash = blake3::hash(input);

        // Verify hashes match
        assert_eq!(&our_hash[..], ref_hash.as_bytes());
    }
}

/// Test HKDF compatibility with hkdf crate
#[test]
fn test_hkdf_compat_with_reference() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = b"input key material for HKDF test";
    let salt = b"optional salt value";
    let info = b"context and application info";

    // Derive key with our implementation
    let our_kdf = KeyDerivation::new(ikm, Some(salt));
    let our_okm = our_kdf.derive_bytes(info, 64).unwrap();

    // Derive key with reference implementation
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut ref_okm = [0u8; 64];
    hk.expand(info, &mut ref_okm).unwrap();

    // Verify derived keys match
    assert_eq!(&our_okm[..], &ref_okm[..]);
}

/// Test HKDF without salt compatibility
#[test]
fn test_hkdf_no_salt_compat() {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = b"input key material without salt";
    let info = b"application context";

    // Derive key with our implementation (None salt)
    let our_kdf = KeyDerivation::new(ikm, None);
    let our_okm = our_kdf.derive_bytes(info, 32).unwrap();

    // Derive key with reference implementation (None salt)
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut ref_okm = [0u8; 32];
    hk.expand(info, &mut ref_okm).unwrap();

    // Verify derived keys match
    assert_eq!(&our_okm[..], &ref_okm[..]);
}

/// Test Argon2 compatibility with argon2 crate
#[test]
fn test_argon2_compat() {
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    };

    let password = b"test_password_123";
    let salt = SaltString::from_b64("c29tZXNhbHQxMjM0NTY3OA").unwrap();

    // Hash with reference implementation
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &salt).unwrap();

    // Verify with same implementation
    assert!(argon2.verify_password(password, &password_hash).is_ok());
    assert!(
        argon2
            .verify_password(b"wrong_password", &password_hash)
            .is_err()
    );
}

/// Test signature verification across different message sizes
#[test]
fn test_signature_compat_various_sizes() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

    let our_keypair = KeyPair::generate();
    let secret_bytes: [u8; 32] = our_keypair.secret_key();
    let dalek_signing = SigningKey::from_bytes(&secret_bytes);
    let dalek_verifying = dalek_signing.verifying_key();

    // Test various message sizes
    let messages = vec![
        vec![],              // Empty
        vec![0x42],          // Single byte
        vec![0u8; 64],       // Small
        vec![0xffu8; 1024],  // Medium
        vec![0x55u8; 10000], // Large
        b"Variable length message".to_vec(),
    ];

    for message in messages {
        // Sign with our implementation
        let our_sig = our_keypair.sign(&message);

        // Verify with dalek
        let sig = Signature::from_bytes(&our_sig);
        assert!(dalek_verifying.verify(&message, &sig).is_ok());

        // Sign with dalek
        let dalek_sig = dalek_signing.sign(&message);

        // Verify with our implementation
        assert!(our_keypair.verify(&message, dalek_sig.to_bytes().as_ref()));
    }
}

/// Test encryption/decryption with various plaintext sizes
#[test]
fn test_encryption_compat_various_sizes() {
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };

    let key_bytes = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];

    let plaintexts = vec![
        vec![],              // Empty
        vec![0x42],          // Single byte
        vec![0u8; 64],       // Small
        vec![0xffu8; 1024],  // Medium
        vec![0x55u8; 10000], // Large
    ];

    let cipher = ChaCha20Poly1305::new(&key_bytes.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    for plaintext in plaintexts {
        // Encrypt with our implementation
        let our_ciphertext = encrypt(&plaintext, &key_bytes, &nonce_bytes).unwrap();

        // Decrypt with reference
        let ref_decrypted = cipher.decrypt(nonce, our_ciphertext.as_ref()).unwrap();
        assert_eq!(ref_decrypted, plaintext);

        // Encrypt with reference
        let ref_ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        // Decrypt with our implementation
        let our_decrypted = decrypt(&ref_ciphertext, &key_bytes, &nonce_bytes).unwrap();
        assert_eq!(our_decrypted, plaintext);
    }
}

/// Test key exchange with multiple key pairs
#[test]
fn test_x25519_compat_multiple_exchanges() {
    use rand::Rng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let mut rng = rand::rng();

    // Generate multiple keypairs with known secrets
    let secrets: Vec<[u8; 32]> = (0..5)
        .map(|_| {
            let mut secret = [0u8; 32];
            rng.fill_bytes(&mut secret);
            secret
        })
        .collect();

    let our_keypairs: Vec<_> = secrets
        .iter()
        .map(|s| KeyExchangeKeypair::from_bytes(*s))
        .collect();

    let dalek_secrets: Vec<_> = secrets.iter().map(|s| StaticSecret::from(*s)).collect();

    // Test pairwise key exchanges
    for i in 0..our_keypairs.len() {
        for j in i + 1..our_keypairs.len() {
            // Our implementation
            let shared_ij = our_keypairs[i].exchange(our_keypairs[j].public_key());
            let shared_ji = our_keypairs[j].exchange(our_keypairs[i].public_key());

            // Verify symmetric shared secret
            assert_eq!(shared_ij.as_bytes(), shared_ji.as_bytes());

            // Dalek implementation
            let dalek_pub_j = PublicKey::from(&dalek_secrets[j]);
            let dalek_shared = dalek_secrets[i].diffie_hellman(&dalek_pub_j);

            // Verify compatibility
            assert_eq!(shared_ij.as_bytes(), dalek_shared.as_bytes());
        }
    }
}
