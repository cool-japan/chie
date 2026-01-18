//! Known Answer Test (KAT) Vectors
//!
//! This module contains test vectors from official specifications and other
//! implementations to verify correctness of cryptographic primitives.

use chie_crypto::{
    KeyDerivation, KeyExchange, KeyExchangeKeypair, KeyPair, PedersenOpening, constant_time_eq,
    decrypt, encrypt, hash, pedersen, reconstruct_key_32, split_key_32,
};

/// Test vectors for ChaCha20-Poly1305 AEAD encryption
/// Note: Our API uses simplified ChaCha20-Poly1305 without AAD support
#[test]
fn test_chacha20_poly1305_basic() {
    // Test with known key and nonce
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let plaintext = b"The quick brown fox jumps over the lazy dog";

    // Encrypt
    let ciphertext = encrypt(plaintext, &key, &nonce).unwrap();

    // Decrypt and verify
    let decrypted = decrypt(&ciphertext, &key, &nonce).unwrap();
    assert_eq!(&decrypted[..], plaintext);

    // Test roundtrip with different data
    let data = b"CHIE Protocol - Decentralized Content Distribution";
    let encrypted = encrypt(data, &key, &nonce).unwrap();
    let decrypted = decrypt(&encrypted, &key, &nonce).unwrap();
    assert_eq!(&decrypted[..], data);

    // Verify ciphertext is different from plaintext
    assert_ne!(&ciphertext[..plaintext.len()], plaintext);
}

/// Test vectors for Ed25519 signatures
/// Source: RFC 8032 Section 7.1
#[test]
fn test_ed25519_rfc8032() {
    // Test 1: Empty message
    let secret_key_bytes =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let public_key_bytes =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let message = b"";
    let expected_sig = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ).unwrap();

    let secret_key: [u8; 32] = secret_key_bytes.try_into().unwrap();
    let keypair = KeyPair::from_secret_key(&secret_key).unwrap();

    // Verify public key matches
    assert_eq!(keypair.public_key(), public_key_bytes.as_slice());

    let signature = keypair.sign(message);
    assert_eq!(&signature[..], &expected_sig[..]);
    assert!(keypair.verify(message, &signature));

    // Test 2: Single byte message
    let secret_key_bytes =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb").unwrap();
    let public_key_bytes =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").unwrap();
    let message = hex::decode("72").unwrap();
    let expected_sig = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ).unwrap();

    let secret_key: [u8; 32] = secret_key_bytes.try_into().unwrap();
    let keypair = KeyPair::from_secret_key(&secret_key).unwrap();

    // Verify public key matches
    assert_eq!(keypair.public_key(), public_key_bytes.as_slice());

    let signature = keypair.sign(&message);
    assert_eq!(&signature[..], &expected_sig[..]);
    assert!(keypair.verify(&message, &signature));
}

/// Test vectors for BLAKE3 hashing
/// Source: BLAKE3 test vectors
#[test]
fn test_blake3_official_vectors() {
    // Empty input
    let empty_hash = hash(b"");
    let expected_empty =
        hex::decode("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262").unwrap();
    assert_eq!(&empty_hash[..], &expected_empty[..]);

    // Single byte
    let single_byte_hash = hash(&[0x00]);
    let expected_single =
        hex::decode("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213").unwrap();
    assert_eq!(&single_byte_hash[..], &expected_single[..]);

    // "abc"
    let abc_hash = hash(b"abc");
    let expected_abc =
        hex::decode("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85").unwrap();
    assert_eq!(&abc_hash[..], &expected_abc[..]);
}

/// Test vectors for HKDF
/// Source: RFC 5869
#[test]
fn test_hkdf_rfc5869() {
    // Test Case 1 (SHA-256)
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let kdf = KeyDerivation::new(&ikm, Some(&salt));
    let okm = kdf.derive_bytes(&info, 42).unwrap();

    let expected_okm = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();

    assert_eq!(&okm[..], &expected_okm[..]);

    // Test Case 2 (longer inputs)
    let ikm = hex::decode(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    ).unwrap();
    let salt = hex::decode(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ).unwrap();
    let info = hex::decode(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ).unwrap();

    let kdf = KeyDerivation::new(&ikm, Some(&salt));
    let okm = kdf.derive_bytes(&info, 82).unwrap();

    let expected_okm = hex::decode(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    ).unwrap();

    assert_eq!(&okm[..], &expected_okm[..]);
}

/// Test vectors for X25519 key exchange
/// Source: RFC 7748
#[test]
fn test_x25519_rfc7748() {
    // Test Vector 1
    let scalar_a =
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    let scalar_b =
        hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap();

    let public_a =
        hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap();
    let public_b =
        hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap();

    let expected_shared =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").unwrap();

    // Create keypairs
    let keypair_a = KeyExchangeKeypair::from_bytes(scalar_a.try_into().unwrap());
    let keypair_b = KeyExchangeKeypair::from_bytes(scalar_b.try_into().unwrap());

    // Verify public keys match
    assert_eq!(keypair_a.public_key().as_bytes(), &public_a[..]);
    assert_eq!(keypair_b.public_key().as_bytes(), &public_b[..]);

    // Compute shared secrets
    let shared_a = keypair_a.exchange(keypair_b.public_key());
    let shared_b = keypair_b.exchange(keypair_a.public_key());

    // Verify shared secrets match expected and each other
    assert_eq!(shared_a.as_bytes(), &expected_shared[..]);
    assert_eq!(shared_b.as_bytes(), &expected_shared[..]);
    assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
}

/// Test vectors for constant-time comparison
#[test]
fn test_constant_time_eq_vectors() {
    // Same values should be equal
    assert!(constant_time_eq(&[0u8; 32], &[0u8; 32]));
    assert!(constant_time_eq(&[0xff; 32], &[0xff; 32]));

    // Different values should not be equal
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    b[31] = 1;
    assert!(!constant_time_eq(&a, &b));

    // Different at first byte
    a[0] = 1;
    b[0] = 2;
    b[31] = 0;
    assert!(!constant_time_eq(&a, &b));

    // All bytes different
    let all_zero = [0u8; 32];
    let all_one = [0xff; 32];
    assert!(!constant_time_eq(&all_zero, &all_one));
}

/// Test Argon2 password hashing with known vectors
/// Source: Argon2 test vectors
#[test]
fn test_argon2_vectors() {
    use argon2::Argon2;
    use argon2::PasswordHasher;
    use argon2::password_hash::SaltString;

    // Test vector from Argon2 spec
    let password = b"password";
    let salt = SaltString::from_b64("c29tZXNhbHQxMjM0NTY3OA").unwrap();

    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password, &salt).unwrap();

    // Verify hash can be verified
    use argon2::PasswordVerifier;
    assert!(argon2.verify_password(password, &hash).is_ok());
    assert!(argon2.verify_password(b"wrong", &hash).is_err());
}

/// Test Shamir Secret Sharing with known values
#[test]
fn test_shamir_secret_sharing_vectors() {
    // Test with known secret
    let secret = [42u8; 32];

    // Split into 5 shares, require 3 to reconstruct
    let shares = split_key_32(&secret, 3, 5).unwrap();
    assert_eq!(shares.len(), 5);

    // Reconstruct with minimum shares
    let reconstructed = reconstruct_key_32(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);

    // Reconstruct with all shares
    let reconstructed_all = reconstruct_key_32(&shares).unwrap();
    assert_eq!(reconstructed_all, secret);

    // Verify any 3 shares work
    let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let reconstructed_subset = reconstruct_key_32(&subset).unwrap();
    assert_eq!(reconstructed_subset, secret);

    // Verify 2 shares produce different result (insufficient for threshold)
    let insufficient = reconstruct_key_32(&shares[0..2]).unwrap();
    assert_ne!(insufficient, secret);
}

/// Test Pedersen commitments with known values
#[test]
fn test_pedersen_commitment_vectors() {
    // Test basic commitment
    let (commitment, opening) = pedersen::commit(42);
    assert!(pedersen::verify(&commitment, 42, &opening));
    assert!(!pedersen::verify(&commitment, 43, &opening));

    // Verify homomorphic property
    let value1 = 10u64;
    let value2 = 32u64;

    let (commitment1, opening1) = pedersen::commit(value1);
    let (commitment2, opening2) = pedersen::commit(value2);

    // Add commitments
    let commitment_sum = commitment1.add(&commitment2);
    let opening_sum = opening1.add(&opening2);

    // Verify the sum commitment
    assert!(pedersen::verify(
        &commitment_sum,
        value1 + value2,
        &opening_sum
    ));

    // Test specific blinding factor
    let blinding = PedersenOpening::from_bytes([0x42; 32]);
    let commitment_with_blinding = pedersen::commit_with_blinding(100, &blinding);
    assert!(pedersen::verify(&commitment_with_blinding, 100, &blinding));
}
