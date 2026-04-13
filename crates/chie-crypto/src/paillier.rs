//! Paillier Homomorphic Encryption
//!
//! This module implements the Paillier cryptosystem, an additively homomorphic
//! public-key encryption scheme. It supports:
//! - Homomorphic addition: E(m1) + E(m2) = E(m1 + m2)
//! - Homomorphic scalar multiplication: k * E(m) = E(k * m)
//!
//! # Security Properties
//!
//! - Based on the decisional composite residuosity assumption (DCRA)
//! - Semantic security under chosen-plaintext attacks
//! - Supports privacy-preserving computation on encrypted data
//!
//! # Use Cases in CHIE Protocol
//!
//! - Privacy-preserving bandwidth aggregation
//! - Encrypted vote counting for content popularity
//! - Private computation on encrypted metrics
//! - Secure multi-party computation building block
//!
//! # Example
//!
//! ```
//! use chie_crypto::paillier::{PaillierKeypair, encrypt, decrypt};
//!
//! // Generate keypair (use larger bit size in production)
//! let keypair = PaillierKeypair::generate(512);
//!
//! // Encrypt two values
//! let m1 = 100u64;
//! let m2 = 50u64;
//! let c1 = encrypt(&keypair.public_key, m1);
//! let c2 = encrypt(&keypair.public_key, m2);
//!
//! // Homomorphic addition: E(100) + E(50) = E(150)
//! let c_sum = c1.add(&c2, &keypair.public_key);
//! let result = decrypt(&keypair, &c_sum);
//! assert_eq!(result, 150);
//!
//! // Scalar multiplication: 3 * E(100) = E(300)
//! let c_mul = c1.mul_scalar(3, &keypair.public_key);
//! let result = decrypt(&keypair, &c_mul);
//! assert_eq!(result, 300);
//! ```

use num_bigint::{BigUint, RandBigInt};
use num_prime::RandPrime;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

/// Paillier public key
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    /// Modulus n = p * q
    pub n: BigUint,
    /// n^2 (precomputed)
    pub n_squared: BigUint,
    /// Generator g (usually n + 1 for efficiency)
    pub g: BigUint,
}

/// Paillier private key
#[derive(Clone, Serialize, Deserialize)]
pub struct PaillierPrivateKey {
    /// Lambda = lcm(p-1, q-1)
    lambda: BigUint,
    /// Precomputed mu = (L(g^lambda mod n^2))^-1 mod n
    mu: BigUint,
}

/// Paillier keypair
#[derive(Clone, Serialize, Deserialize)]
pub struct PaillierKeypair {
    pub public_key: PaillierPublicKey,
    pub private_key: PaillierPrivateKey,
}

/// Paillier ciphertext
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PaillierCiphertext {
    /// Ciphertext value c = g^m * r^n mod n^2
    pub c: BigUint,
}

impl PaillierKeypair {
    /// Generate a new Paillier keypair with the specified bit size
    ///
    /// # Arguments
    ///
    /// * `bits` - Bit size of the modulus (typically 2048 or 3072 for production)
    ///
    /// # Note
    ///
    /// Key generation for large bit sizes can be slow. For testing, use 512 or 1024 bits.
    pub fn generate(bits: usize) -> Self {
        let mut rng = rand_core06::OsRng;

        // Generate two large primes p and q
        let p: BigUint = rng.gen_prime(bits / 2, None);
        let q: BigUint = rng.gen_prime(bits / 2, None);

        // Compute n = p * q
        let n = &p * &q;
        let n_squared = &n * &n;

        // Use g = n + 1 for efficiency (common optimization)
        let g: BigUint = &n + BigUint::one();

        // Compute lambda = lcm(p-1, q-1)
        let p_minus_1 = &p - BigUint::one();
        let q_minus_1 = &q - BigUint::one();
        let lambda = lcm(&p_minus_1, &q_minus_1);

        // Compute mu = (L(g^lambda mod n^2))^-1 mod n
        // L(x) = (x - 1) / n
        let g_lambda = g.modpow(&lambda, &n_squared);
        let l_value = l_function(&g_lambda, &n);
        let mu = mod_inverse(&l_value, &n);

        Self {
            public_key: PaillierPublicKey { n, n_squared, g },
            private_key: PaillierPrivateKey { lambda, mu },
        }
    }

    /// Export keypair to bytes (for serialization)
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).expect("serialization failed")
    }

    /// Import keypair from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(crate::codec::decode(bytes)?)
    }
}

impl PaillierCiphertext {
    /// Homomorphic addition: E(m1) + E(m2) = E(m1 + m2)
    ///
    /// # Arguments
    ///
    /// * `other` - Another ciphertext to add
    /// * `public_key` - Public key for the operation
    pub fn add(&self, other: &PaillierCiphertext, public_key: &PaillierPublicKey) -> Self {
        // c1 * c2 mod n^2 corresponds to E(m1 + m2)
        let c = (&self.c * &other.c) % &public_key.n_squared;
        PaillierCiphertext { c }
    }

    /// Homomorphic scalar multiplication: k * E(m) = E(k * m)
    ///
    /// # Arguments
    ///
    /// * `scalar` - Scalar value to multiply by
    /// * `public_key` - Public key for the operation
    pub fn mul_scalar(&self, scalar: u64, public_key: &PaillierPublicKey) -> Self {
        let k = BigUint::from(scalar);
        // c^k mod n^2 corresponds to E(k * m)
        let c = self.c.modpow(&k, &public_key.n_squared);
        PaillierCiphertext { c }
    }

    /// Export ciphertext to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).expect("serialization failed")
    }

    /// Import ciphertext from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(crate::codec::decode(bytes)?)
    }
}

/// Encrypt a message using Paillier encryption
///
/// # Arguments
///
/// * `public_key` - Public key for encryption
/// * `message` - Message to encrypt (as u64)
///
/// # Returns
///
/// Ciphertext containing the encrypted message
pub fn encrypt(public_key: &PaillierPublicKey, message: u64) -> PaillierCiphertext {
    let mut rng = rand_core06::OsRng;
    let m = BigUint::from(message);

    // Choose random r in Z*_n
    let r = loop {
        let candidate = rng.gen_biguint_below(&public_key.n);
        if gcd(&candidate, &public_key.n) == BigUint::one() {
            break candidate;
        }
    };

    // c = g^m * r^n mod n^2
    let g_m = public_key.g.modpow(&m, &public_key.n_squared);
    let r_n = r.modpow(&public_key.n, &public_key.n_squared);
    let c = (g_m * r_n) % &public_key.n_squared;

    PaillierCiphertext { c }
}

/// Decrypt a Paillier ciphertext
///
/// # Arguments
///
/// * `keypair` - Keypair containing both public and private keys
/// * `ciphertext` - Ciphertext to decrypt
///
/// # Returns
///
/// Decrypted message as u64
pub fn decrypt(keypair: &PaillierKeypair, ciphertext: &PaillierCiphertext) -> u64 {
    let pk = &keypair.public_key;
    let sk = &keypair.private_key;

    // m = L(c^lambda mod n^2) * mu mod n
    let c_lambda = ciphertext.c.modpow(&sk.lambda, &pk.n_squared);
    let l_value = l_function(&c_lambda, &pk.n);
    let m = (l_value * &sk.mu) % &pk.n;

    // Convert BigUint to u64
    m.to_u64_digits().first().copied().unwrap_or(0)
}

// Helper function: L(x) = (x - 1) / n
fn l_function(x: &BigUint, n: &BigUint) -> BigUint {
    (x - BigUint::one()) / n
}

// Compute GCD using Euclidean algorithm
fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let temp = b.clone();
        b = &a % &b;
        a = temp;
    }
    a
}

// Compute LCM(a, b) = (a * b) / gcd(a, b)
fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) / gcd(a, b)
}

// Compute modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigUint, m: &BigUint) -> BigUint {
    let (mut t, mut new_t) = (BigUint::zero(), BigUint::one());
    let (mut r, mut new_r) = (m.clone(), a.clone());

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let temp_t = new_t.clone();
        new_t = if t >= &quotient * &new_t {
            &t - &quotient * &new_t
        } else {
            m - (&quotient * &new_t - &t) % m
        };
        t = temp_t;

        let temp_r = new_r.clone();
        new_r = &r - &quotient * &new_r;
        r = temp_r;
    }

    if r > BigUint::one() {
        panic!("a is not invertible");
    }

    t % m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paillier_basic() {
        let keypair = PaillierKeypair::generate(512);
        let message = 42u64;

        let ciphertext = encrypt(&keypair.public_key, message);
        let decrypted = decrypt(&keypair, &ciphertext);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_homomorphic_addition() {
        let keypair = PaillierKeypair::generate(512);

        let m1 = 100u64;
        let m2 = 50u64;

        let c1 = encrypt(&keypair.public_key, m1);
        let c2 = encrypt(&keypair.public_key, m2);

        // Homomorphic addition
        let c_sum = c1.add(&c2, &keypair.public_key);
        let result = decrypt(&keypair, &c_sum);

        assert_eq!(result, m1 + m2);
    }

    #[test]
    fn test_homomorphic_scalar_multiplication() {
        let keypair = PaillierKeypair::generate(512);

        let m = 100u64;
        let k = 3u64;

        let c = encrypt(&keypair.public_key, m);

        // Homomorphic scalar multiplication
        let c_mul = c.mul_scalar(k, &keypair.public_key);
        let result = decrypt(&keypair, &c_mul);

        assert_eq!(result, m * k);
    }

    #[test]
    fn test_multiple_additions() {
        let keypair = PaillierKeypair::generate(512);

        let values = [10u64, 20, 30, 40, 50];
        let expected_sum: u64 = values.iter().sum();

        // Encrypt all values
        let ciphertexts: Vec<_> = values
            .iter()
            .map(|&v| encrypt(&keypair.public_key, v))
            .collect();

        // Sum all ciphertexts homomorphically
        let mut c_sum = ciphertexts[0].clone();
        for c in &ciphertexts[1..] {
            c_sum = c_sum.add(c, &keypair.public_key);
        }

        let result = decrypt(&keypair, &c_sum);
        assert_eq!(result, expected_sum);
    }

    #[test]
    fn test_combined_operations() {
        let keypair = PaillierKeypair::generate(512);

        // Compute: 2*E(10) + 3*E(20) = E(20 + 60) = E(80)
        let c1 = encrypt(&keypair.public_key, 10);
        let c2 = encrypt(&keypair.public_key, 20);

        let c1_scaled = c1.mul_scalar(2, &keypair.public_key);
        let c2_scaled = c2.mul_scalar(3, &keypair.public_key);

        let c_result = c1_scaled.add(&c2_scaled, &keypair.public_key);
        let result = decrypt(&keypair, &c_result);

        assert_eq!(result, 2 * 10 + 3 * 20);
    }

    #[test]
    fn test_zero_encryption() {
        let keypair = PaillierKeypair::generate(512);

        let c = encrypt(&keypair.public_key, 0);
        let result = decrypt(&keypair, &c);

        assert_eq!(result, 0);
    }

    #[test]
    fn test_deterministic_keypair() {
        // Different keypair generations should produce different keys
        let kp1 = PaillierKeypair::generate(512);
        let kp2 = PaillierKeypair::generate(512);

        assert_ne!(kp1.public_key.n, kp2.public_key.n);
    }

    #[test]
    fn test_encryption_randomness() {
        let keypair = PaillierKeypair::generate(512);
        let message = 42u64;

        // Same message encrypted twice should produce different ciphertexts
        let c1 = encrypt(&keypair.public_key, message);
        let c2 = encrypt(&keypair.public_key, message);

        assert_ne!(c1.c, c2.c);

        // But both should decrypt to the same value
        assert_eq!(decrypt(&keypair, &c1), message);
        assert_eq!(decrypt(&keypair, &c2), message);
    }

    #[test]
    fn test_large_values() {
        let keypair = PaillierKeypair::generate(512);

        let m1 = 1_000_000u64;
        let m2 = 2_000_000u64;

        let c1 = encrypt(&keypair.public_key, m1);
        let c2 = encrypt(&keypair.public_key, m2);

        let c_sum = c1.add(&c2, &keypair.public_key);
        let result = decrypt(&keypair, &c_sum);

        assert_eq!(result, m1 + m2);
    }

    #[test]
    fn test_keypair_serialization() {
        let keypair = PaillierKeypair::generate(512);
        let bytes = keypair.to_bytes();
        let restored = PaillierKeypair::from_bytes(&bytes).unwrap();

        // Test that the restored keypair works
        let message = 123u64;
        let c = encrypt(&restored.public_key, message);
        let result = decrypt(&restored, &c);

        assert_eq!(result, message);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let keypair = PaillierKeypair::generate(512);
        let message = 456u64;

        let c = encrypt(&keypair.public_key, message);
        let bytes = c.to_bytes();
        let restored = PaillierCiphertext::from_bytes(&bytes).unwrap();

        assert_eq!(c, restored);

        let result = decrypt(&keypair, &restored);
        assert_eq!(result, message);
    }

    #[test]
    fn test_addition_commutativity() {
        let keypair = PaillierKeypair::generate(512);

        let m1 = 100u64;
        let m2 = 200u64;

        let c1 = encrypt(&keypair.public_key, m1);
        let c2 = encrypt(&keypair.public_key, m2);

        // E(m1) + E(m2) should equal E(m2) + E(m1)
        let sum1 = c1.add(&c2, &keypair.public_key);
        let sum2 = c2.add(&c1, &keypair.public_key);

        let result1 = decrypt(&keypair, &sum1);
        let result2 = decrypt(&keypair, &sum2);

        assert_eq!(result1, result2);
        assert_eq!(result1, m1 + m2);
    }

    #[test]
    fn test_addition_associativity() {
        let keypair = PaillierKeypair::generate(512);

        let m1 = 10u64;
        let m2 = 20u64;
        let m3 = 30u64;

        let c1 = encrypt(&keypair.public_key, m1);
        let c2 = encrypt(&keypair.public_key, m2);
        let c3 = encrypt(&keypair.public_key, m3);

        // (E(m1) + E(m2)) + E(m3)
        let sum1 = c1.add(&c2, &keypair.public_key);
        let sum1 = sum1.add(&c3, &keypair.public_key);

        // E(m1) + (E(m2) + E(m3))
        let sum2 = c2.add(&c3, &keypair.public_key);
        let sum2 = c1.add(&sum2, &keypair.public_key);

        let result1 = decrypt(&keypair, &sum1);
        let result2 = decrypt(&keypair, &sum2);

        assert_eq!(result1, result2);
        assert_eq!(result1, m1 + m2 + m3);
    }

    #[test]
    fn test_scalar_distributivity() {
        let keypair = PaillierKeypair::generate(512);

        let m1 = 10u64;
        let m2 = 20u64;
        let k = 3u64;

        let c1 = encrypt(&keypair.public_key, m1);
        let c2 = encrypt(&keypair.public_key, m2);

        // k * (E(m1) + E(m2)) should equal k*E(m1) + k*E(m2)
        let sum = c1.add(&c2, &keypair.public_key);
        let scaled_sum = sum.mul_scalar(k, &keypair.public_key);

        let c1_scaled = c1.mul_scalar(k, &keypair.public_key);
        let c2_scaled = c2.mul_scalar(k, &keypair.public_key);
        let sum_scaled = c1_scaled.add(&c2_scaled, &keypair.public_key);

        let result1 = decrypt(&keypair, &scaled_sum);
        let result2 = decrypt(&keypair, &sum_scaled);

        assert_eq!(result1, result2);
        assert_eq!(result1, k * (m1 + m2));
    }

    #[test]
    fn test_bandwidth_aggregation_use_case() {
        // Simulate privacy-preserving bandwidth aggregation in CHIE protocol
        let keypair = PaillierKeypair::generate(512);

        // Three peers report encrypted bandwidth usage
        let peer1_bandwidth = 1024u64; // 1 KB
        let peer2_bandwidth = 2048u64; // 2 KB
        let peer3_bandwidth = 4096u64; // 4 KB

        let c1 = encrypt(&keypair.public_key, peer1_bandwidth);
        let c2 = encrypt(&keypair.public_key, peer2_bandwidth);
        let c3 = encrypt(&keypair.public_key, peer3_bandwidth);

        // Coordinator aggregates without knowing individual values
        let c_total = c1.add(&c2, &keypair.public_key);
        let c_total = c_total.add(&c3, &keypair.public_key);

        // Only authorized party can decrypt total
        let total_bandwidth = decrypt(&keypair, &c_total);

        assert_eq!(
            total_bandwidth,
            peer1_bandwidth + peer2_bandwidth + peer3_bandwidth
        );
        assert_eq!(total_bandwidth, 7168); // 7 KB
    }
}
