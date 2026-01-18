//! Fixed-size array types with const generics for type-safe cryptographic operations.
//!
//! This module provides zero-cost abstractions over fixed-size byte arrays commonly used
//! in cryptographic operations. All types use const generics for compile-time size checking.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Generic fixed-size byte array with const generic size.
///
/// Provides a type-safe wrapper around fixed-size arrays with useful utility methods
/// for encoding, comparison, and serialization.
///
/// # Type Safety
///
/// Different sizes create incompatible types at compile time:
/// ```
/// # use chie_shared::FixedBytes;
/// let hash32 = FixedBytes::<32>::new([0u8; 32]);
/// let hash64 = FixedBytes::<64>::new([0u8; 64]);
/// // hash32 == hash64; // Compile error: different types
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FixedBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> FixedBytes<N> {
    /// Create a new fixed-size byte array.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Create from a byte slice. Returns `None` if the slice length doesn't match.
    ///
    /// # Example
    /// ```
    /// # use chie_shared::FixedBytes;
    /// let bytes = &[1, 2, 3, 4];
    /// let fixed = FixedBytes::<4>::from_slice(bytes).unwrap();
    /// assert_eq!(fixed.as_bytes(), bytes);
    /// ```
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == N {
            let mut bytes = [0u8; N];
            bytes.copy_from_slice(slice);
            Some(Self { bytes })
        } else {
            None
        }
    }

    /// Create from a hexadecimal string.
    ///
    /// # Errors
    /// Returns error if the hex string is invalid or has wrong length.
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != N * 2 {
            return Err(format!(
                "Invalid hex length: expected {} chars, got {}",
                N * 2,
                hex.len()
            ));
        }

        let mut bytes = [0u8; N];
        for i in 0..N {
            let byte_str = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_str, 16)
                .map_err(|e| format!("Invalid hex character: {e}"))?;
        }
        Ok(Self { bytes })
    }

    /// Get the byte array as a slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Get the byte array as a mutable slice.
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// Convert to hexadecimal string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    }

    /// Get the size of this array type at compile time.
    #[must_use]
    pub const fn size() -> usize {
        N
    }

    /// Check if all bytes are zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Create a zeroed array.
    #[must_use]
    pub const fn zero() -> Self {
        Self { bytes: [0u8; N] }
    }
}

impl<const N: usize> Default for FixedBytes<N> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> AsMut<[u8]> for FixedBytes<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<const N: usize> From<[u8; N]> for FixedBytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> From<FixedBytes<N>> for [u8; N] {
    fn from(fixed: FixedBytes<N>) -> Self {
        fixed.bytes
    }
}

impl<const N: usize> fmt::Debug for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FixedBytes<{}>({})", N, self.to_hex())
    }
}

impl<const N: usize> fmt::Display for FixedBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// Serde implementations for const generic arrays
impl<const N: usize> Serialize for FixedBytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as a byte array (array of u8 values)
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de, const N: usize> Deserialize<'de> for FixedBytes<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize from bytes
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(Self { bytes: array })
    }
}

// Type aliases for common cryptographic sizes

/// BLAKE3 hash (32 bytes / 256 bits)
pub type Blake3Hash = FixedBytes<32>;

/// Ed25519 signature (64 bytes / 512 bits)
pub type Ed25519Signature = FixedBytes<64>;

/// Ed25519 public key (32 bytes / 256 bits)
pub type Ed25519PublicKey = FixedBytes<32>;

/// Challenge nonce (32 bytes / 256 bits)
pub type Nonce32 = FixedBytes<32>;

/// SHA-256 hash (32 bytes / 256 bits)
pub type Sha256Hash = FixedBytes<32>;

/// SHA-512 hash (64 bytes / 512 bits)
pub type Sha512Hash = FixedBytes<64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_bytes_new() {
        let bytes = [1u8; 32];
        let fixed = FixedBytes::<32>::new(bytes);
        assert_eq!(fixed.as_bytes(), &bytes);
    }

    #[test]
    fn test_fixed_bytes_from_slice() {
        let slice = &[1, 2, 3, 4];
        let fixed = FixedBytes::<4>::from_slice(slice).unwrap();
        assert_eq!(fixed.as_bytes(), &[1, 2, 3, 4]);

        // Wrong size should fail
        let wrong = FixedBytes::<8>::from_slice(slice);
        assert!(wrong.is_none());
    }

    #[test]
    fn test_fixed_bytes_hex_roundtrip() {
        let bytes = [0x12, 0x34, 0xAB, 0xCD];
        let fixed = FixedBytes::<4>::new(bytes);
        let hex = fixed.to_hex();
        assert_eq!(hex, "1234abcd");

        let decoded = FixedBytes::<4>::from_hex(&hex).unwrap();
        assert_eq!(decoded, fixed);
    }

    #[test]
    fn test_fixed_bytes_from_hex_errors() {
        // Wrong length
        let result = FixedBytes::<4>::from_hex("12345");
        assert!(result.is_err());

        // Invalid hex character
        let result = FixedBytes::<4>::from_hex("1234567g");
        assert!(result.is_err());
    }

    #[test]
    fn test_fixed_bytes_size() {
        assert_eq!(FixedBytes::<32>::size(), 32);
        assert_eq!(FixedBytes::<64>::size(), 64);
        assert_eq!(Blake3Hash::size(), 32);
        assert_eq!(Ed25519Signature::size(), 64);
    }

    #[test]
    fn test_fixed_bytes_is_zero() {
        let zero = FixedBytes::<8>::zero();
        assert!(zero.is_zero());

        let mut non_zero = FixedBytes::<8>::zero();
        non_zero.as_bytes_mut()[0] = 1;
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_fixed_bytes_default() {
        let default = FixedBytes::<16>::default();
        assert!(default.is_zero());
    }

    #[test]
    fn test_fixed_bytes_display() {
        let fixed = FixedBytes::<4>::new([0xAA, 0xBB, 0xCC, 0xDD]);
        let display = format!("{fixed}");
        assert_eq!(display, "aabbccdd");
    }

    #[test]
    fn test_fixed_bytes_debug() {
        let fixed = FixedBytes::<4>::new([0xAA, 0xBB, 0xCC, 0xDD]);
        let debug = format!("{fixed:?}");
        assert_eq!(debug, "FixedBytes<4>(aabbccdd)");
    }

    #[test]
    fn test_type_aliases() {
        let _hash: Blake3Hash = FixedBytes::zero();
        let _sig: Ed25519Signature = FixedBytes::zero();
        let _pubkey: Ed25519PublicKey = FixedBytes::zero();
        let _nonce: Nonce32 = FixedBytes::zero();
        let _sha256: Sha256Hash = FixedBytes::zero();
        let _sha512: Sha512Hash = FixedBytes::zero();

        // Verify sizes
        assert_eq!(Blake3Hash::size(), 32);
        assert_eq!(Ed25519Signature::size(), 64);
        assert_eq!(Ed25519PublicKey::size(), 32);
        assert_eq!(Nonce32::size(), 32);
        assert_eq!(Sha256Hash::size(), 32);
        assert_eq!(Sha512Hash::size(), 64);
    }

    #[test]
    fn test_fixed_bytes_equality() {
        let a = FixedBytes::<8>::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let b = FixedBytes::<8>::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let c = FixedBytes::<8>::new([1, 2, 3, 4, 5, 6, 7, 9]);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_fixed_bytes_conversions() {
        let array = [1u8, 2, 3, 4];
        let fixed: FixedBytes<4> = array.into();
        let back: [u8; 4] = fixed.into();
        assert_eq!(array, back);
    }

    #[test]
    fn test_fixed_bytes_as_ref() {
        let fixed = FixedBytes::<4>::new([1, 2, 3, 4]);
        let slice: &[u8] = fixed.as_ref();
        assert_eq!(slice, &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fixed_bytes_serde() {
        let fixed = FixedBytes::<8>::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let json = serde_json::to_string(&fixed).unwrap();
        let decoded: FixedBytes<8> = serde_json::from_str(&json).unwrap();
        assert_eq!(fixed, decoded);
    }
}
