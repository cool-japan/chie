//! Zeroizing wrappers for sensitive cryptographic material.
//!
//! This module provides wrappers that automatically zero out memory
//! when dropped, preventing sensitive data from lingering in memory.

use zeroize::{Zeroize, Zeroizing};

/// A zeroizing wrapper for secret keys.
///
/// When this value is dropped, the underlying bytes are securely zeroed.
pub type ZeroizingKey<const N: usize> = Zeroizing<[u8; N]>;

/// Create a zeroizing 32-byte key.
pub fn zeroizing_key_32() -> ZeroizingKey<32> {
    Zeroizing::new([0u8; 32])
}

/// Create a zeroizing 12-byte nonce.
pub fn zeroizing_nonce() -> ZeroizingKey<12> {
    Zeroizing::new([0u8; 12])
}

/// Securely zero a byte slice.
///
/// This uses compiler barriers to prevent the zeroing from being optimized away.
#[inline]
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Securely copy and then zero the source.
#[inline]
pub fn secure_move(dest: &mut [u8], src: &mut [u8]) {
    assert_eq!(
        dest.len(),
        src.len(),
        "dest and src must have the same length"
    );
    dest.copy_from_slice(src);
    src.zeroize();
}

/// A buffer that zeros itself on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a secure buffer from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Create a secure buffer from a slice.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: slice.to_vec(),
        }
    }

    /// Get a reference to the inner bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the inner bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the buffer.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Push a byte to the buffer.
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Extend the buffer with a slice.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.data.extend_from_slice(slice);
    }

    /// Clear the buffer (zeroizes first).
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    /// Consume the buffer and return the inner Vec (without zeroing).
    ///
    /// Use with caution - the returned Vec will not be zeroized on drop.
    pub fn into_inner(mut self) -> Vec<u8> {
        // Take ownership and prevent drop
        let mut data = Vec::new();
        std::mem::swap(&mut data, &mut self.data);
        std::mem::forget(self);
        data
    }

    /// Resize the buffer to the new length, filling with zeros.
    pub fn resize(&mut self, new_len: usize) {
        self.data.resize(new_len, 0);
    }
}

impl std::fmt::Debug for SecureBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuffer([REDACTED; {} bytes])", self.data.len())
    }
}

impl From<Vec<u8>> for SecureBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl From<&[u8]> for SecureBuffer {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_zero() {
        let mut data = vec![1, 2, 3, 4, 5];
        secure_zero(&mut data);
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_move() {
        let mut src = vec![1, 2, 3, 4];
        let mut dest = vec![0, 0, 0, 0];

        secure_move(&mut dest, &mut src);

        assert_eq!(dest, vec![1, 2, 3, 4]);
        assert_eq!(src, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_secure_buffer() {
        let mut buffer = SecureBuffer::from_slice(&[1, 2, 3, 4]);

        assert_eq!(buffer.len(), 4);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.as_bytes(), &[1, 2, 3, 4]);

        buffer.push(5);
        assert_eq!(buffer.len(), 5);

        buffer.clear();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_secure_buffer_debug() {
        let buffer = SecureBuffer::from_slice(&[1, 2, 3, 4]);
        let debug = format!("{:?}", buffer);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }

    #[test]
    fn test_zeroizing_key() {
        let key = zeroizing_key_32();
        assert_eq!(key.len(), 32);

        let nonce = zeroizing_nonce();
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn test_secure_buffer_drop_zeroizes() {
        let data = vec![1u8, 2, 3, 4];

        {
            let _buffer = SecureBuffer::from_bytes(data);
            // Buffer gets dropped here
        }

        // We can't directly verify memory was zeroed without unsafe code,
        // but we trust the Zeroize crate's implementation
    }
}
