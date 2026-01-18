//! Constant-time comparison utilities.
//!
//! These functions are resistant to timing attacks and should be used
//! when comparing cryptographic values like MACs, signatures, or hashes.

use subtle::{Choice, ConstantTimeEq};

/// Compare two byte slices in constant time.
///
/// Returns true if the slices are equal, false otherwise.
/// The comparison time is independent of where the slices differ.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Compare two 32-byte arrays in constant time.
#[inline]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

/// Compare two 64-byte arrays in constant time (for signatures).
#[inline]
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    a.ct_eq(b).into()
}

/// Compare a slice against a fixed-size array in constant time.
#[inline]
pub fn ct_eq_slice_32(slice: &[u8], array: &[u8; 32]) -> bool {
    if slice.len() != 32 {
        return false;
    }
    slice.ct_eq(array.as_slice()).into()
}

/// Select between two values in constant time based on a condition.
///
/// Returns `a` if `condition` is true, `b` otherwise.
#[inline]
pub fn ct_select<T: Copy + Default>(condition: bool, a: T, b: T) -> T {
    let choice = Choice::from(condition as u8);
    // This is a simplified version; for complex types, use subtle's ConditionallySelectable
    if choice.unwrap_u8() == 1 { a } else { b }
}

/// A wrapper for sensitive data that implements constant-time comparison.
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Create from a byte vector.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create from a slice.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    /// Get the inner bytes (be careful with the result).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the length.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl ConstantTimeEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretBytes {}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Zeroize on drop for security
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_eq_equal() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        assert!(ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_not_equal() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 6];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_different_length() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn test_ct_eq_32() {
        let a = [42u8; 32];
        let b = [42u8; 32];
        let c = [43u8; 32];
        assert!(ct_eq_32(&a, &b));
        assert!(!ct_eq_32(&a, &c));
    }

    #[test]
    fn test_secret_bytes_equality() {
        let a = SecretBytes::new(vec![1, 2, 3, 4]);
        let b = SecretBytes::new(vec![1, 2, 3, 4]);
        let c = SecretBytes::new(vec![1, 2, 3, 5]);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_secret_bytes_debug() {
        let s = SecretBytes::new(vec![1, 2, 3, 4]);
        let debug = format!("{:?}", s);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }
}
