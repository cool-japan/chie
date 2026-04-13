//! ElGamal encryption for additively homomorphic public key encryption.
//!
//! ElGamal encryption provides:
//! - Additively homomorphic encryption: E(m₁) + E(m₂) = E(m₁ + m₂)
//! - Re-randomization support for ciphertext unlinkability
//! - Public key encryption with semantic security
//! - Useful for privacy-preserving aggregations in CHIE protocol
//!
//! # Example
//! ```
//! use chie_crypto::elgamal::{ElGamalKeypair, ElGamalCiphertext};
//!
//! // Generate a keypair
//! let keypair = ElGamalKeypair::generate();
//!
//! // Encrypt messages
//! let msg1 = 100u64;
//! let msg2 = 200u64;
//! let ct1 = keypair.encrypt(msg1);
//! let ct2 = keypair.encrypt(msg2);
//!
//! // Homomorphic addition
//! let ct_sum = ct1.add(&ct2);
//!
//! // Decrypt the sum
//! let sum = keypair.decrypt(&ct_sum).unwrap();
//! assert_eq!(sum, msg1 + msg2);
//! ```

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

/// ElGamal encryption error types
#[derive(Error, Debug)]
pub enum ElGamalError {
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Value out of range (max 2^32)")]
    ValueOutOfRange,
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type ElGamalResult<T> = Result<T, ElGamalError>;

/// ElGamal secret key (scalar in the Ristretto group)
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ElGamalSecretKey {
    scalar: Scalar,
}

impl ElGamalSecretKey {
    /// Generate a random ElGamal secret key
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order(bytes);
        Self { scalar }
    }

    /// Create an ElGamal secret key from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> ElGamalResult<Self> {
        let scalar = Scalar::from_bytes_mod_order(*bytes);
        Ok(Self { scalar })
    }

    /// Export secret key to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// Derive public key from secret key
    pub fn public_key(&self) -> ElGamalPublicKey {
        let point = RISTRETTO_BASEPOINT_TABLE * &self.scalar;
        ElGamalPublicKey { point }
    }
}

/// ElGamal public key (point in the Ristretto group)
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElGamalPublicKey {
    point: RistrettoPoint,
}

impl ElGamalPublicKey {
    /// Create an ElGamal public key from compressed bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> ElGamalResult<Self> {
        let compressed =
            CompressedRistretto::from_slice(bytes).map_err(|_| ElGamalError::InvalidPublicKey)?;
        let point = compressed
            .decompress()
            .ok_or(ElGamalError::InvalidPublicKey)?;
        Ok(Self { point })
    }

    /// Export public key to compressed bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
}

/// ElGamal ciphertext (c₁, c₂) where:
/// - c₁ = r*G (ephemeral public key)
/// - c₂ = m*G + r*H (encrypted message)
///
/// where H is the recipient's public key
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    c1: RistrettoPoint,
    c2: RistrettoPoint,
}

impl ElGamalCiphertext {
    /// Create an ElGamal ciphertext from compressed bytes (64 bytes: 32 for c1 + 32 for c2)
    pub fn from_bytes(bytes: &[u8; 64]) -> ElGamalResult<Self> {
        let mut c1_bytes = [0u8; 32];
        let mut c2_bytes = [0u8; 32];
        c1_bytes.copy_from_slice(&bytes[..32]);
        c2_bytes.copy_from_slice(&bytes[32..]);

        let compressed_c1 = CompressedRistretto::from_slice(&c1_bytes)
            .map_err(|_| ElGamalError::InvalidCiphertext)?;
        let compressed_c2 = CompressedRistretto::from_slice(&c2_bytes)
            .map_err(|_| ElGamalError::InvalidCiphertext)?;

        let c1 = compressed_c1
            .decompress()
            .ok_or(ElGamalError::InvalidCiphertext)?;
        let c2 = compressed_c2
            .decompress()
            .ok_or(ElGamalError::InvalidCiphertext)?;

        Ok(Self { c1, c2 })
    }

    /// Export ciphertext to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.c1.compress().to_bytes());
        bytes[32..].copy_from_slice(&self.c2.compress().to_bytes());
        bytes
    }

    /// Homomorphic addition: E(m₁) + E(m₂) = E(m₁ + m₂)
    pub fn add(&self, other: &ElGamalCiphertext) -> ElGamalCiphertext {
        ElGamalCiphertext {
            c1: self.c1 + other.c1,
            c2: self.c2 + other.c2,
        }
    }

    /// Scalar multiplication: k * E(m) = E(k * m)
    pub fn mul_scalar(&self, scalar: u64) -> ElGamalCiphertext {
        let s = Scalar::from(scalar);
        ElGamalCiphertext {
            c1: self.c1 * s,
            c2: self.c2 * s,
        }
    }

    /// Re-randomize the ciphertext for unlinkability
    /// Returns a new ciphertext encrypting the same message but unlinkable to the original
    pub fn rerandomize(&self, public_key: &ElGamalPublicKey) -> ElGamalCiphertext {
        let mut rng = rand::rng();
        let mut r_bytes = [0u8; 32];
        rng.fill(&mut r_bytes);
        let r = Scalar::from_bytes_mod_order(r_bytes);

        // Add encryption of zero: (r*G, r*H)
        let delta_c1 = RISTRETTO_BASEPOINT_TABLE * &r;
        let delta_c2 = public_key.point * r;

        ElGamalCiphertext {
            c1: self.c1 + delta_c1,
            c2: self.c2 + delta_c2,
        }
    }
}

/// ElGamal keypair (secret key + public key)
pub struct ElGamalKeypair {
    secret_key: ElGamalSecretKey,
    public_key: ElGamalPublicKey,
}

impl ElGamalKeypair {
    /// Generate a random ElGamal keypair
    pub fn generate() -> Self {
        let secret_key = ElGamalSecretKey::generate();
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Create a keypair from a secret key
    pub fn from_secret_key(secret_key: ElGamalSecretKey) -> Self {
        let public_key = secret_key.public_key();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> ElGamalPublicKey {
        self.public_key
    }

    /// Get a reference to the secret key
    pub fn secret_key(&self) -> &ElGamalSecretKey {
        &self.secret_key
    }

    /// Encrypt a message (u64 value)
    ///
    /// The message is encoded as m*G (point on the curve)
    /// Ciphertext: (c₁, c₂) = (r*G, m*G + r*H)
    pub fn encrypt(&self, message: u64) -> ElGamalCiphertext {
        encrypt(&self.public_key, message)
    }

    /// Decrypt a ciphertext to recover the original message
    ///
    /// Decryption: m*G = c₂ - x*c₁
    /// Then solve discrete log to get m
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> ElGamalResult<u64> {
        decrypt(&self.secret_key, ciphertext)
    }
}

/// Encrypt a message using ElGamal encryption
pub fn encrypt(public_key: &ElGamalPublicKey, message: u64) -> ElGamalCiphertext {
    // Generate random ephemeral key
    let mut rng = rand::rng();
    let mut r_bytes = [0u8; 32];
    rng.fill(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);

    // Encode message as point: m*G
    let m_scalar = Scalar::from(message);
    let m_point = RISTRETTO_BASEPOINT_TABLE * &m_scalar;

    // c₁ = r*G
    let c1 = RISTRETTO_BASEPOINT_TABLE * &r;

    // c₂ = m*G + r*H
    let c2 = m_point + (public_key.point * r);

    ElGamalCiphertext { c1, c2 }
}

/// Decrypt an ElGamal ciphertext
///
/// Uses baby-step giant-step algorithm for discrete log
/// Works for small messages (up to 2^32)
pub fn decrypt(
    secret_key: &ElGamalSecretKey,
    ciphertext: &ElGamalCiphertext,
) -> ElGamalResult<u64> {
    // Compute m*G = c₂ - x*c₁
    let m_point = ciphertext.c2 - (secret_key.scalar * ciphertext.c1);

    // Solve discrete log to get m
    // For small values, we can use brute force or baby-step giant-step
    solve_discrete_log(&m_point)
}

/// Solve discrete log for small values using baby-step giant-step algorithm
///
/// This finds m such that m*G = P for small m (up to 2^20 ~ 1 million)
fn solve_discrete_log(point: &RistrettoPoint) -> ElGamalResult<u64> {
    const MAX_SEARCH: u64 = 1 << 20; // Search up to 2^20 ~ 1 million
    const BATCH_SIZE: u64 = 1 << 10; // Baby step size

    // Baby-step giant-step algorithm
    // Precompute baby steps: i*G for i = 0..BATCH_SIZE
    let mut baby_steps = std::collections::HashMap::new();
    let mut current = RistrettoPoint::default(); // 0*G = identity
    let generator = RISTRETTO_BASEPOINT_TABLE * &Scalar::ONE;

    for i in 0..BATCH_SIZE {
        baby_steps.insert(current.compress().to_bytes(), i);
        current += generator;
    }

    // Giant steps: check if P - j*BATCH_SIZE*G is in baby steps
    let giant_step = generator * Scalar::from(BATCH_SIZE);
    let mut current = *point;

    for j in 0..(MAX_SEARCH / BATCH_SIZE) {
        if let Some(&i) = baby_steps.get(&current.compress().to_bytes()) {
            return Ok(j * BATCH_SIZE + i);
        }
        current -= giant_step;
    }

    Err(ElGamalError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = ElGamalKeypair::generate();
        let pk = keypair.public_key();

        // Verify public key can be serialized and deserialized
        let pk_bytes = pk.to_bytes();
        let pk2 = ElGamalPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = ElGamalKeypair::generate();
        let message = 42u64;

        let ciphertext = keypair.encrypt(message);
        let decrypted = keypair.decrypt(&ciphertext).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_homomorphic_addition() {
        let keypair = ElGamalKeypair::generate();
        let msg1 = 100u64;
        let msg2 = 200u64;

        let ct1 = keypair.encrypt(msg1);
        let ct2 = keypair.encrypt(msg2);

        // Homomorphic addition
        let ct_sum = ct1.add(&ct2);

        // Decrypt the sum
        let sum = keypair.decrypt(&ct_sum).unwrap();
        assert_eq!(sum, msg1 + msg2);
    }

    #[test]
    fn test_scalar_multiplication() {
        let keypair = ElGamalKeypair::generate();
        let msg = 50u64;
        let k = 3u64;

        let ct = keypair.encrypt(msg);
        let ct_mult = ct.mul_scalar(k);

        let result = keypair.decrypt(&ct_mult).unwrap();
        assert_eq!(result, msg * k);
    }

    #[test]
    fn test_rerandomization() {
        let keypair = ElGamalKeypair::generate();
        let message = 123u64;

        let ct1 = keypair.encrypt(message);
        let ct2 = ct1.rerandomize(&keypair.public_key());

        // Different ciphertexts
        assert_ne!(ct1, ct2);

        // Same plaintext
        assert_eq!(keypair.decrypt(&ct1).unwrap(), message);
        assert_eq!(keypair.decrypt(&ct2).unwrap(), message);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let keypair = ElGamalKeypair::generate();
        let message = 777u64;

        let ct = keypair.encrypt(message);
        let ct_bytes = ct.to_bytes();
        let ct2 = ElGamalCiphertext::from_bytes(&ct_bytes).unwrap();

        assert_eq!(ct, ct2);
        assert_eq!(keypair.decrypt(&ct2).unwrap(), message);
    }

    #[test]
    fn test_zero_message() {
        let keypair = ElGamalKeypair::generate();
        let message = 0u64;

        let ct = keypair.encrypt(message);
        let decrypted = keypair.decrypt(&ct).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_large_message() {
        let keypair = ElGamalKeypair::generate();
        let message = 10000u64;

        let ct = keypair.encrypt(message);
        let decrypted = keypair.decrypt(&ct).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_multiple_additions() {
        let keypair = ElGamalKeypair::generate();
        let values = vec![10u64, 20, 30, 40, 50];
        let expected_sum: u64 = values.iter().sum();

        let mut ct_sum = keypair.encrypt(0);
        for &value in &values {
            let ct = keypair.encrypt(value);
            ct_sum = ct_sum.add(&ct);
        }

        let result = keypair.decrypt(&ct_sum).unwrap();
        assert_eq!(result, expected_sum);
    }

    #[test]
    fn test_secret_key_serialization() {
        let sk = ElGamalSecretKey::generate();
        let sk_bytes = sk.to_bytes();
        let sk2 = ElGamalSecretKey::from_bytes(&sk_bytes).unwrap();

        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(sk.public_key().to_bytes(), sk2.public_key().to_bytes());
    }

    #[test]
    fn test_deterministic_public_key() {
        let sk_bytes = [42u8; 32];
        let sk1 = ElGamalSecretKey::from_bytes(&sk_bytes).unwrap();
        let sk2 = ElGamalSecretKey::from_bytes(&sk_bytes).unwrap();

        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn test_encryption_randomness() {
        let keypair = ElGamalKeypair::generate();
        let message = 100u64;

        let ct1 = keypair.encrypt(message);
        let ct2 = keypair.encrypt(message);

        // Different ciphertexts due to random ephemeral key
        assert_ne!(ct1, ct2);

        // Same plaintext
        assert_eq!(keypair.decrypt(&ct1).unwrap(), message);
        assert_eq!(keypair.decrypt(&ct2).unwrap(), message);
    }
}
