//! Functional Encryption (FE) primitives
//!
//! Functional encryption allows a client with a secret key SK_f to learn f(x) from an
//! encryption of x, without learning anything else about x. This is useful for
//! privacy-preserving computation where you want to compute on encrypted data.
//!
//! This module implements Inner Product Functional Encryption (IPFE), one of the most
//! practical forms of FE, allowing computation of inner products over encrypted vectors.
//!
//! # Example
//!
//! ```
//! use chie_crypto::functional_encryption::*;
//!
//! // Setup master keys for vectors of length 3
//! let (msk, mpk) = ipfe_setup(3);
//!
//! // Encrypt a vector [5, 10, 15]
//! let plaintext = vec![5, 10, 15];
//! let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();
//!
//! // Generate a functional key for computing inner product with [1, 2, 3]
//! let func_vector = vec![1, 2, 3];
//! let func_key = ipfe_keygen(&msk, &func_vector).unwrap();
//!
//! // Decrypt to get the inner product: 5*1 + 10*2 + 15*3 = 70
//! let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
//! assert_eq!(result, 70);
//! ```

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Functional encryption error types
#[derive(Error, Debug)]
pub enum FunctionalEncryptionError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for functional encryption operations
pub type FunctionalEncryptionResult<T> = Result<T, FunctionalEncryptionError>;

/// Master secret key for IPFE
#[derive(Clone, Serialize, Deserialize)]
pub struct IpfeMasterSecretKey {
    /// Secret key scalars (one per dimension)
    secret_scalars: Vec<Scalar>,
}

/// Master public key for IPFE
#[derive(Clone, Serialize, Deserialize)]
pub struct IpfeMasterPublicKey {
    /// Public key points (one per dimension)
    #[serde(with = "serde_point_vec")]
    public_points: Vec<RistrettoPoint>,
    /// Base generator
    #[serde(with = "serde_point")]
    generator: RistrettoPoint,
}

/// Functional secret key for computing inner products
#[derive(Clone, Serialize, Deserialize)]
pub struct IpfeFunctionalKey {
    /// Functional key scalar (derived from master secret and function vector)
    functional_scalar: Scalar,
    /// Function vector (needed for decryption)
    func_vector: Vec<i64>,
}

/// Ciphertext for IPFE
#[derive(Clone, Serialize, Deserialize)]
pub struct IpfeCiphertext {
    /// c_0 = g^r
    #[serde(with = "serde_point")]
    c0: RistrettoPoint,
    /// c_i = h_i^r * g^{x_i}
    #[serde(with = "serde_point_vec")]
    encrypted_points: Vec<RistrettoPoint>,
}

// Serde helpers for RistrettoPoint
mod serde_point {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(point: &RistrettoPoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = point.compress().to_bytes();
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<RistrettoPoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid point length"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        CompressedRistretto(arr)
            .decompress()
            .ok_or_else(|| serde::de::Error::custom("invalid point"))
    }
}

mod serde_point_vec {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(points: &[RistrettoPoint], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<Vec<u8>> = points
            .iter()
            .map(|p| p.compress().to_bytes().to_vec())
            .collect();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RistrettoPoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes_vec: Vec<Vec<u8>> = Deserialize::deserialize(deserializer)?;
        bytes_vec
            .into_iter()
            .map(|bytes| {
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("invalid point length"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                CompressedRistretto(arr)
                    .decompress()
                    .ok_or_else(|| serde::de::Error::custom("invalid point"))
            })
            .collect()
    }
}

/// Generate master secret and public keys for IPFE
///
/// # Arguments
/// * `dimension` - The dimension of vectors to be encrypted
///
/// # Returns
/// A tuple of (master_secret_key, master_public_key)
pub fn ipfe_setup(dimension: usize) -> (IpfeMasterSecretKey, IpfeMasterPublicKey) {
    let generator = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

    let mut secret_scalars = Vec::with_capacity(dimension);
    let mut public_points = Vec::with_capacity(dimension);

    for i in 0..dimension {
        // Generate secret scalar from hash
        let mut hasher = Sha256::new();
        hasher.update(b"ipfe_master_secret");
        hasher.update(i.to_le_bytes());
        hasher.update(rand::random::<[u8; 32]>());
        let hash = hasher.finalize();
        let scalar = Scalar::from_bytes_mod_order(hash.into());

        // Public key is g^s
        let public_point = generator * scalar;

        secret_scalars.push(scalar);
        public_points.push(public_point);
    }

    let msk = IpfeMasterSecretKey { secret_scalars };
    let mpk = IpfeMasterPublicKey {
        public_points,
        generator,
    };

    (msk, mpk)
}

/// Encrypt a plaintext vector using the master public key
///
/// # Arguments
/// * `mpk` - Master public key
/// * `plaintext` - Vector of integers to encrypt
///
/// # Returns
/// Encrypted ciphertext
pub fn ipfe_encrypt(
    mpk: &IpfeMasterPublicKey,
    plaintext: &[i64],
) -> FunctionalEncryptionResult<IpfeCiphertext> {
    if plaintext.len() != mpk.public_points.len() {
        return Err(FunctionalEncryptionError::InvalidInput(
            "plaintext dimension mismatch".to_string(),
        ));
    }

    // Generate random scalar r
    let r = Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());

    // c_0 = g^r
    let c0 = mpk.generator * r;

    let mut encrypted_points = Vec::with_capacity(plaintext.len());

    for (i, &value) in plaintext.iter().enumerate() {
        // Convert value to scalar
        let value_scalar = Scalar::from(value.unsigned_abs());
        let value_scalar = if value < 0 {
            -value_scalar
        } else {
            value_scalar
        };

        // c_i = h_i^r * g^{x_i}
        let encrypted = (mpk.public_points[i] * r) + (mpk.generator * value_scalar);
        encrypted_points.push(encrypted);
    }

    Ok(IpfeCiphertext {
        c0,
        encrypted_points,
    })
}

/// Generate a functional secret key for computing inner product with a given vector
///
/// # Arguments
/// * `msk` - Master secret key
/// * `func_vector` - Vector to compute inner product with
///
/// # Returns
/// Functional secret key
pub fn ipfe_keygen(
    msk: &IpfeMasterSecretKey,
    func_vector: &[i64],
) -> FunctionalEncryptionResult<IpfeFunctionalKey> {
    if func_vector.len() != msk.secret_scalars.len() {
        return Err(FunctionalEncryptionError::InvalidInput(
            "function vector dimension mismatch".to_string(),
        ));
    }

    // Compute functional key: sum of (y_i * s_i)
    let mut functional_scalar = Scalar::ZERO;

    for (i, &value) in func_vector.iter().enumerate() {
        let value_scalar = Scalar::from(value.unsigned_abs());
        let value_scalar = if value < 0 {
            -value_scalar
        } else {
            value_scalar
        };

        functional_scalar += value_scalar * msk.secret_scalars[i];
    }

    Ok(IpfeFunctionalKey {
        functional_scalar,
        func_vector: func_vector.to_vec(),
    })
}

/// Decrypt a ciphertext using a functional key to compute the inner product
///
/// # Arguments
/// * `func_key` - Functional secret key
/// * `ciphertext` - Encrypted vector
///
/// # Returns
/// The inner product result
pub fn ipfe_decrypt(
    func_key: &IpfeFunctionalKey,
    ciphertext: &IpfeCiphertext,
) -> FunctionalEncryptionResult<i64> {
    // Check dimension match
    if func_key.func_vector.len() != ciphertext.encrypted_points.len() {
        return Err(FunctionalEncryptionError::InvalidInput(
            "function vector and ciphertext dimension mismatch".to_string(),
        ));
    }

    // Compute: sum(y_i * c_i) - sk_y * c_0
    // This gives: sum(y_i * (h_i^r * g^{x_i})) - (sum(y_i * s_i)) * g^r
    //           = sum(y_i * g^{s_i * r} + y_i * g^{x_i}) - g^{r * sum(y_i * s_i)}
    //           = sum(y_i * g^{s_i * r}) + sum(y_i * g^{x_i}) - g^{r * sum(y_i * s_i)}
    //           = g^{r * sum(y_i * s_i)} + g^{sum(y_i * x_i)} - g^{r * sum(y_i * s_i)}
    //           = g^{<x,y>}

    let generator = curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    let mut result_point = RistrettoPoint::identity();

    // Compute weighted sum: sum(y_i * c_i)
    for (i, &y_i) in func_key.func_vector.iter().enumerate() {
        let y_scalar = Scalar::from(y_i.unsigned_abs());
        let y_scalar = if y_i < 0 { -y_scalar } else { y_scalar };

        result_point += ciphertext.encrypted_points[i] * y_scalar;
    }

    // Subtract: sk_y * c_0
    result_point -= ciphertext.c0 * func_key.functional_scalar;

    // Now result_point should be g^{<x,y>}
    // Discrete log solver for small values (brute force)
    // This works for results in range [-10000, 10000]
    for i in 0..=10000 {
        if result_point == generator * Scalar::from(i as u64) {
            return Ok(i);
        }
        if result_point == generator * (-Scalar::from(i as u64)) {
            return Ok(-i);
        }
    }

    Err(FunctionalEncryptionError::DecryptionFailed(
        "discrete log too large".to_string(),
    ))
}

/// Multi-client IPFE setup for privacy-preserving aggregation
pub struct MultiClientIpfe {
    dimension: usize,
    master_keys: Vec<(IpfeMasterSecretKey, IpfeMasterPublicKey)>,
}

impl MultiClientIpfe {
    /// Setup multi-client IPFE for n clients
    pub fn setup(num_clients: usize, dimension: usize) -> Self {
        let mut master_keys = Vec::with_capacity(num_clients);

        for _ in 0..num_clients {
            master_keys.push(ipfe_setup(dimension));
        }

        Self {
            dimension,
            master_keys,
        }
    }

    /// Get public key for client i
    pub fn get_public_key(&self, client_id: usize) -> Option<&IpfeMasterPublicKey> {
        self.master_keys.get(client_id).map(|(_, mpk)| mpk)
    }

    /// Generate functional key for computing sum of inner products
    pub fn keygen(
        &self,
        func_vector: &[i64],
    ) -> FunctionalEncryptionResult<Vec<IpfeFunctionalKey>> {
        if func_vector.len() != self.dimension {
            return Err(FunctionalEncryptionError::InvalidInput(
                "function vector dimension mismatch".to_string(),
            ));
        }

        let mut func_keys = Vec::with_capacity(self.master_keys.len());

        for (msk, _) in &self.master_keys {
            func_keys.push(ipfe_keygen(msk, func_vector)?);
        }

        Ok(func_keys)
    }

    /// Aggregate decrypt multiple ciphertexts from different clients
    pub fn aggregate_decrypt(
        func_keys: &[IpfeFunctionalKey],
        ciphertexts: &[IpfeCiphertext],
    ) -> FunctionalEncryptionResult<i64> {
        if func_keys.len() != ciphertexts.len() {
            return Err(FunctionalEncryptionError::InvalidInput(
                "number of keys and ciphertexts must match".to_string(),
            ));
        }

        // Sum all individual results
        let mut total = 0i64;
        for (fk, ct) in func_keys.iter().zip(ciphertexts.iter()) {
            total += ipfe_decrypt(fk, ct)?;
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfe_basic() {
        let (msk, mpk) = ipfe_setup(3);

        let plaintext = vec![5, 10, 15];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        let func_vector = vec![1, 2, 3];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        assert_eq!(result, 5 + 10 * 2 + 15 * 3); // 70
    }

    #[test]
    fn test_ipfe_negative_values() {
        let (msk, mpk) = ipfe_setup(4);

        let plaintext = vec![10, -5, 8, -3];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        let func_vector = vec![2, 1, -1, 4];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        assert_eq!(result, 10 * 2 + (-5) + -8 + (-3) * 4); // 20 - 5 - 8 - 12 = -5
    }

    #[test]
    fn test_ipfe_zero_vector() {
        let (msk, mpk) = ipfe_setup(3);

        let plaintext = vec![0, 0, 0];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        let func_vector = vec![1, 2, 3];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn test_ipfe_dimension_mismatch() {
        let (msk, mpk) = ipfe_setup(3);

        let plaintext = vec![1, 2];
        let result = ipfe_encrypt(&mpk, &plaintext);
        assert!(result.is_err());

        let func_vector = vec![1, 2, 3, 4];
        let result = ipfe_keygen(&msk, &func_vector);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipfe_multiple_keys() {
        let (msk, mpk) = ipfe_setup(3);

        let plaintext = vec![4, 5, 6];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        // First functional key
        let func_vector1 = vec![1, 0, 0];
        let func_key1 = ipfe_keygen(&msk, &func_vector1).unwrap();
        let result1 = ipfe_decrypt(&func_key1, &ciphertext).unwrap();
        assert_eq!(result1, 4);

        // Second functional key
        let func_vector2 = vec![0, 1, 0];
        let func_key2 = ipfe_keygen(&msk, &func_vector2).unwrap();
        let result2 = ipfe_decrypt(&func_key2, &ciphertext).unwrap();
        assert_eq!(result2, 5);

        // Third functional key
        let func_vector3 = vec![0, 0, 1];
        let func_key3 = ipfe_keygen(&msk, &func_vector3).unwrap();
        let result3 = ipfe_decrypt(&func_key3, &ciphertext).unwrap();
        assert_eq!(result3, 6);
    }

    #[test]
    fn test_ipfe_serialization() {
        let (msk, mpk) = ipfe_setup(3);

        // Serialize and deserialize public key
        let mpk_bytes = crate::codec::encode(&mpk).unwrap();
        let mpk_restored: IpfeMasterPublicKey = crate::codec::decode(&mpk_bytes).unwrap();

        // Serialize and deserialize secret key
        let msk_bytes = crate::codec::encode(&msk).unwrap();
        let msk_restored: IpfeMasterSecretKey = crate::codec::decode(&msk_bytes).unwrap();

        // Test that restored keys work
        let plaintext = vec![7, 8, 9];
        let ciphertext = ipfe_encrypt(&mpk_restored, &plaintext).unwrap();

        let func_vector = vec![1, 1, 1];
        let func_key = ipfe_keygen(&msk_restored, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        assert_eq!(result, 24);
    }

    #[test]
    fn test_multi_client_ipfe() {
        let mcipfe = MultiClientIpfe::setup(3, 2);

        // Each client encrypts their vector
        let plaintext1 = vec![10, 20];
        let plaintext2 = vec![5, 15];
        let plaintext3 = vec![3, 7];

        let ct1 = ipfe_encrypt(mcipfe.get_public_key(0).unwrap(), &plaintext1).unwrap();
        let ct2 = ipfe_encrypt(mcipfe.get_public_key(1).unwrap(), &plaintext2).unwrap();
        let ct3 = ipfe_encrypt(mcipfe.get_public_key(2).unwrap(), &plaintext3).unwrap();

        // Generate functional keys for computing weighted sum
        let func_vector = vec![2, 1];
        let func_keys = mcipfe.keygen(&func_vector).unwrap();

        // Aggregate decrypt
        let result = MultiClientIpfe::aggregate_decrypt(&func_keys, &[ct1, ct2, ct3]).unwrap();

        // Expected: (10*2 + 20*1) + (5*2 + 15*1) + (3*2 + 7*1) = 40 + 25 + 13 = 78
        assert_eq!(result, 78);
    }

    #[test]
    fn test_multi_client_dimension_mismatch() {
        let mcipfe = MultiClientIpfe::setup(2, 3);

        let func_vector = vec![1, 2];
        let result = mcipfe.keygen(&func_vector);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_client_aggregate_mismatch() {
        let mcipfe = MultiClientIpfe::setup(2, 2);

        let plaintext = vec![1, 2];
        let ct1 = ipfe_encrypt(mcipfe.get_public_key(0).unwrap(), &plaintext).unwrap();

        let func_vector = vec![1, 1];
        let func_keys = mcipfe.keygen(&func_vector).unwrap();

        // Only one ciphertext but two keys
        let result = MultiClientIpfe::aggregate_decrypt(&func_keys, &[ct1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipfe_large_dimension() {
        let dimension = 10;
        let (msk, mpk) = ipfe_setup(dimension);

        let plaintext: Vec<i64> = (1..=dimension as i64).collect();
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        let func_vector = vec![1; dimension];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        let expected: i64 = (1..=dimension as i64).sum();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_functional_key_serialization() {
        let (msk, mpk) = ipfe_setup(3);

        let func_vector = vec![2, 3, 4];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        // Serialize and deserialize functional key
        let fk_bytes = crate::codec::encode(&func_key).unwrap();
        let fk_restored: IpfeFunctionalKey = crate::codec::decode(&fk_bytes).unwrap();

        // Test that it works
        let plaintext = vec![1, 2, 3];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        let result = ipfe_decrypt(&fk_restored, &ciphertext).unwrap();
        assert_eq!(result, 2 + 2 * 3 + 3 * 4); // 20
    }

    #[test]
    fn test_ciphertext_serialization() {
        let (msk, mpk) = ipfe_setup(3);

        let plaintext = vec![5, 6, 7];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        // Serialize and deserialize ciphertext
        let ct_bytes = crate::codec::encode(&ciphertext).unwrap();
        let ct_restored: IpfeCiphertext = crate::codec::decode(&ct_bytes).unwrap();

        // Test that it works
        let func_vector = vec![1, 2, 1];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ct_restored).unwrap();
        assert_eq!(result, 5 + 6 * 2 + 7); // 24
    }

    #[test]
    fn test_ipfe_single_dimension() {
        let (msk, mpk) = ipfe_setup(1);

        let plaintext = vec![42];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        let func_vector = vec![3];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        assert_eq!(result, 42 * 3);
    }

    #[test]
    fn test_ipfe_orthogonal_vectors() {
        let (msk, mpk) = ipfe_setup(3);

        let plaintext = vec![1, 0, 0];
        let ciphertext = ipfe_encrypt(&mpk, &plaintext).unwrap();

        // Orthogonal function vector
        let func_vector = vec![0, 1, 0];
        let func_key = ipfe_keygen(&msk, &func_vector).unwrap();

        let result = ipfe_decrypt(&func_key, &ciphertext).unwrap();
        assert_eq!(result, 0); // Orthogonal vectors give zero
    }
}
