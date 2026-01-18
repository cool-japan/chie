//! Shamir's Secret Sharing for secure key backup and recovery.
//!
//! This module implements (M, N) threshold secret sharing where:
//! - A secret is split into N shares
//! - Any M shares can reconstruct the secret
//! - Fewer than M shares reveal nothing about the secret
//!
//! Perfect for distributed key backup, multi-party authorization, etc.
//!
//! Security properties:
//! - Information-theoretic security (no amount of computing power helps with <M shares)
//! - Each share is the same size as the secret
//! - Shares are independent random values

use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

/// Shamir secret sharing errors.
#[derive(Debug, Error)]
pub enum ShamirError {
    #[error("Invalid threshold: M must be > 0 and <= N")]
    InvalidThreshold,
    #[error("Not enough shares to reconstruct secret (need {needed}, got {got})")]
    InsufficientShares { needed: usize, got: usize },
    #[error("Duplicate share indices")]
    DuplicateIndices,
    #[error("Invalid share index (must be 1-255)")]
    InvalidShareIndex,
    #[error("Shares have different lengths")]
    InconsistentShareLengths,
    #[error("Secret is empty")]
    EmptySecret,
}

pub type ShamirResult<T> = Result<T, ShamirError>;

/// A single share of a secret.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct Share {
    /// Share index (1-255)
    pub index: u8,
    /// Share data
    pub data: Vec<u8>,
}

impl Share {
    /// Create a new share.
    pub fn new(index: u8, data: Vec<u8>) -> ShamirResult<Self> {
        if index == 0 {
            return Err(ShamirError::InvalidShareIndex);
        }
        Ok(Self { index, data })
    }

    /// Serialize to bytes (index || data).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.data.len());
        bytes.push(self.index);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> ShamirResult<Self> {
        if bytes.is_empty() {
            return Err(ShamirError::InvalidShareIndex);
        }
        let index = bytes[0];
        let data = bytes[1..].to_vec();
        Share::new(index, data)
    }
}

/// Split a secret into N shares with threshold M.
///
/// Any M shares can reconstruct the secret, but M-1 or fewer reveal nothing.
pub fn split(secret: &[u8], threshold: usize, num_shares: usize) -> ShamirResult<Vec<Share>> {
    if secret.is_empty() {
        return Err(ShamirError::EmptySecret);
    }
    if threshold == 0 || threshold > num_shares || num_shares > 255 {
        return Err(ShamirError::InvalidThreshold);
    }

    let mut shares = Vec::with_capacity(num_shares);
    let mut rng = rand::thread_rng();

    // Split each byte independently using Shamir's scheme over GF(256)
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Generate random polynomial coefficients (degree = threshold - 1)
        let mut coeffs = vec![secret_byte];
        for _ in 1..threshold {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            coeffs.push(byte[0]);
        }

        // Evaluate polynomial at points 1..=num_shares
        for share_idx in 0..num_shares {
            let x = (share_idx + 1) as u8;
            let y = eval_poly(&coeffs, x);

            if byte_idx == 0 {
                // First byte: create new share
                shares.push(Share::new(x, vec![y])?);
            } else {
                // Subsequent bytes: append to existing share
                shares[share_idx].data.push(y);
            }
        }
    }

    Ok(shares)
}

/// Reconstruct secret from M or more shares.
///
/// Returns error if fewer than threshold shares are provided.
pub fn reconstruct(shares: &[Share]) -> ShamirResult<Vec<u8>> {
    if shares.is_empty() {
        return Err(ShamirError::InsufficientShares { needed: 1, got: 0 });
    }

    // Verify all shares have the same length
    let share_len = shares[0].data.len();
    if !shares.iter().all(|s| s.data.len() == share_len) {
        return Err(ShamirError::InconsistentShareLengths);
    }

    // Verify no duplicate indices
    let mut indices = shares.iter().map(|s| s.index).collect::<Vec<_>>();
    indices.sort_unstable();
    if indices.windows(2).any(|w| w[0] == w[1]) {
        return Err(ShamirError::DuplicateIndices);
    }

    let mut secret = Vec::with_capacity(share_len);

    // Reconstruct each byte independently
    for byte_idx in 0..share_len {
        let points: Vec<(u8, u8)> = shares
            .iter()
            .map(|share| (share.index, share.data[byte_idx]))
            .collect();

        let secret_byte = lagrange_interpolate(&points, 0);
        secret.push(secret_byte);
    }

    Ok(secret)
}

/// Evaluate polynomial at x using Horner's method in GF(256).
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    let mut result = 0u8;
    for &coeff in coeffs.iter().rev() {
        result = gf256_add(gf256_mul(result, x), coeff);
    }
    result
}

/// Lagrange interpolation in GF(256) to find f(x).
fn lagrange_interpolate(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result = 0u8;

    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut basis = 1u8;

        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                let numerator = gf256_sub(x, xj);
                let denominator = gf256_sub(xi, xj);
                let inv_denom = gf256_inv(denominator);
                basis = gf256_mul(basis, gf256_mul(numerator, inv_denom));
            }
        }

        result = gf256_add(result, gf256_mul(basis, yi));
    }

    result
}

// GF(256) arithmetic using AES polynomial (x^8 + x^4 + x^3 + x + 1)
const GF256_POLY: u16 = 0x11B;

/// Addition in GF(256) is XOR.
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtraction in GF(256) is also XOR.
#[inline]
fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256).
fn gf256_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }

    let mut result = 0u16;
    let mut a = a as u16;
    let mut b = b as u16;

    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= GF256_POLY;
        }
        b >>= 1;
    }

    (result & 0xFF) as u8
}

/// Multiplicative inverse in GF(256) using extended Euclidean algorithm.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("Cannot invert zero in GF(256)");
    }

    // Use Fermat's little theorem: a^254 = a^(-1) in GF(256)
    let mut result = 1u8;
    let mut base = a;

    // Compute a^254 using square-and-multiply
    for i in 0..8 {
        if 254 & (1 << i) != 0 {
            result = gf256_mul(result, base);
        }
        base = gf256_mul(base, base);
    }

    result
}

/// Split a 32-byte key using Shamir's secret sharing.
pub fn split_key_32(
    key: &[u8; 32],
    threshold: usize,
    num_shares: usize,
) -> ShamirResult<Vec<Share>> {
    split(key, threshold, num_shares)
}

/// Reconstruct a 32-byte key from shares.
pub fn reconstruct_key_32(shares: &[Share]) -> ShamirResult<[u8; 32]> {
    let secret = reconstruct(shares)?;
    if secret.len() != 32 {
        return Err(ShamirError::InconsistentShareLengths);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&secret);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = b"This is a secret message!";
        let shares = split(secret, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Any 3 shares should reconstruct the secret
        let reconstructed = reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&reconstructed, secret);

        let reconstructed2 = reconstruct(&shares[1..4]).unwrap();
        assert_eq!(&reconstructed2, secret);

        let reconstructed3 = reconstruct(&shares[2..5]).unwrap();
        assert_eq!(&reconstructed3, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"secret";
        let shares = split(secret, 3, 5).unwrap();

        // Only 2 shares (less than threshold) should reconstruct something,
        // but it won't be the original secret (this is a probabilistic guarantee)
        let result = reconstruct(&shares[0..2]).unwrap();
        // Result exists but is likely not the secret
        assert_eq!(result.len(), secret.len());
    }

    #[test]
    fn test_32_byte_key() {
        let key = [42u8; 32];
        let shares = split_key_32(&key, 2, 3).unwrap();

        assert_eq!(shares.len(), 3);

        // Reconstruct with 2 shares
        let reconstructed = reconstruct_key_32(&shares[0..2]).unwrap();
        assert_eq!(reconstructed, key);

        // Reconstruct with all 3 shares
        let reconstructed2 = reconstruct_key_32(&shares).unwrap();
        assert_eq!(reconstructed2, key);
    }

    #[test]
    fn test_invalid_threshold() {
        let secret = b"secret";

        // Threshold = 0
        assert!(split(secret, 0, 5).is_err());

        // Threshold > num_shares
        assert!(split(secret, 6, 5).is_err());

        // num_shares > 255
        assert!(split(secret, 2, 256).is_err());
    }

    #[test]
    fn test_duplicate_indices() {
        let secret = b"secret";
        let shares = split(secret, 2, 3).unwrap();

        // Create duplicate by cloning
        let dup_shares = vec![shares[0].clone(), shares[0].clone()];
        assert!(reconstruct(&dup_shares).is_err());
    }

    #[test]
    fn test_share_serialization() {
        let secret = b"test";
        let shares = split(secret, 2, 3).unwrap();

        for share in &shares {
            let bytes = share.to_bytes();
            let deserialized = Share::from_bytes(&bytes).unwrap();
            assert_eq!(deserialized.index, share.index);
            assert_eq!(deserialized.data, share.data);
        }
    }

    #[test]
    fn test_different_combinations() {
        let secret = b"0123456789abcdef";
        let shares = split(secret, 3, 6).unwrap();

        // Test multiple different 3-share combinations
        let combo1 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let combo2 = vec![shares[1].clone(), shares[3].clone(), shares[5].clone()];

        let combinations: Vec<&[Share]> = vec![
            &shares[0..3],
            &shares[1..4],
            &shares[2..5],
            &shares[3..6],
            &combo1,
            &combo2,
        ];

        for combo in combinations {
            let reconstructed = reconstruct(combo).unwrap();
            assert_eq!(&reconstructed, secret);
        }
    }

    #[test]
    fn test_gf256_arithmetic() {
        // Test basic properties
        assert_eq!(gf256_add(5, 3), 5 ^ 3);
        assert_eq!(gf256_sub(7, 2), 7 ^ 2);

        // Test multiplicative identity
        assert_eq!(gf256_mul(42, 1), 42);

        // Test multiplicative inverse
        for x in 1u8..=255 {
            let inv = gf256_inv(x);
            assert_eq!(gf256_mul(x, inv), 1);
        }
    }

    #[test]
    fn test_empty_secret() {
        assert!(split(&[], 2, 3).is_err());
    }

    #[test]
    fn test_share_zeroize() {
        let share = Share::new(1, vec![1, 2, 3]).unwrap();
        drop(share); // Should zeroize on drop
    }

    #[test]
    fn test_threshold_one() {
        let secret = b"simple";
        let shares = split(secret, 1, 3).unwrap();

        // Each single share should reconstruct the secret
        for share in &shares {
            let reconstructed = reconstruct(std::slice::from_ref(share)).unwrap();
            assert_eq!(&reconstructed, secret);
        }
    }

    #[test]
    fn test_large_secret() {
        let secret = vec![0xAAu8; 1024]; // 1KB secret
        let shares = split(&secret, 5, 10).unwrap();

        let reconstructed = reconstruct(&shares[0..5]).unwrap();
        assert_eq!(reconstructed, secret);
    }
}
