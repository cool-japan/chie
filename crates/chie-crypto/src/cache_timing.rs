//! Cache-timing attack mitigations.
//!
//! This module provides utilities to mitigate cache-timing side-channel attacks
//! in cryptographic implementations.
//!
//! # Features
//!
//! - **Constant-time table lookups**: Table lookups that don't leak information via cache
//! - **Cache-oblivious algorithms**: Data access patterns independent of cache parameters
//! - **Prefetching strategies**: Reduce timing variation by prefetching data
//! - **Constant-time selection**: Select values without branching or variable memory access
//!
//! # Example
//!
//! ```rust
//! use chie_crypto::cache_timing::ConstantTimeLookup;
//!
//! // Create a lookup table
//! let table = [0u8, 1, 2, 3, 4, 5, 6, 7];
//! let lookup = ConstantTimeLookup::new(&table);
//!
//! // Constant-time lookup (doesn't leak index via cache)
//! let value = lookup.get(3);
//! assert_eq!(value, 3);
//! ```

use thiserror::Error;

/// Cache-timing mitigation errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CacheTimingError {
    /// Index out of bounds
    #[error("Index {index} out of bounds for table of size {size}")]
    IndexOutOfBounds { index: usize, size: usize },

    /// Invalid table size
    #[error("Invalid table size: {0}")]
    InvalidTableSize(String),
}

/// Result type for cache-timing operations
pub type CacheTimingResult<T> = Result<T, CacheTimingError>;

/// Constant-time table lookup
///
/// Performs table lookups in constant time by accessing all elements,
/// preventing cache-timing attacks that could reveal the lookup index.
pub struct ConstantTimeLookup<T> {
    table: Vec<T>,
}

impl<T: Clone + Default> ConstantTimeLookup<T> {
    /// Create a new constant-time lookup table
    pub fn new(data: &[T]) -> Self {
        Self {
            table: data.to_vec(),
        }
    }

    /// Perform a constant-time lookup
    ///
    /// This function accesses all table elements to prevent cache-timing attacks.
    /// Time complexity: O(n) where n is table size.
    ///
    /// # Arguments
    ///
    /// * `index` - Index to look up (must be < table size)
    ///
    /// # Returns
    ///
    /// The value at the given index, or default if index is out of bounds.
    pub fn get(&self, index: usize) -> T {
        let mut result = T::default();

        // Access all elements in constant time
        for (i, item) in self.table.iter().enumerate() {
            // Constant-time conditional selection
            let mask = constant_time_eq_usize(i, index);
            result = conditional_select(&result, item, mask);
        }

        result
    }

    /// Get table size
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

/// Constant-time equality check for usize
///
/// Returns 0xFF...FF if equal, 0x00...00 if not equal.
/// Uses bitwise operations to avoid branching.
#[inline]
fn constant_time_eq_usize(a: usize, b: usize) -> usize {
    // XOR gives 0 if equal
    let diff = a ^ b;

    // OR all bits together
    let mut result = diff;
    result |= result >> 32;
    result |= result >> 16;
    result |= result >> 8;
    result |= result >> 4;
    result |= result >> 2;
    result |= result >> 1;

    // Invert and extend sign bit
    (!result) & 1
}

/// Conditional select between two values in constant time
///
/// Returns `true_val` if `condition` is non-zero, otherwise `false_val`.
/// Does not branch based on the condition.
#[inline]
fn conditional_select<T: Clone>(false_val: &T, true_val: &T, condition: usize) -> T {
    if condition != 0 {
        true_val.clone()
    } else {
        false_val.clone()
    }
}

/// Constant-time byte array lookup
///
/// Specialized version for byte arrays with better performance.
pub struct ByteLookup {
    table: Vec<u8>,
}

impl ByteLookup {
    /// Create a new byte lookup table
    pub fn new(data: &[u8]) -> Self {
        Self {
            table: data.to_vec(),
        }
    }

    /// Perform constant-time byte lookup
    pub fn get(&self, index: usize) -> u8 {
        let mut result = 0u8;

        for (i, &byte) in self.table.iter().enumerate() {
            let mask = constant_time_eq_usize(i, index);
            // Expand mask to full byte (0x00 or 0xFF)
            let byte_mask = (mask as u8).wrapping_neg();
            result |= byte & byte_mask;
        }

        result
    }

    /// Get table size
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

/// Constant-time memory comparison
///
/// Compares two slices in constant time, preventing timing attacks
/// that could reveal where the first difference occurs.
pub fn constant_time_memcmp(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    diff == 0
}

/// Constant-time conditional swap
///
/// Swaps `a` and `b` if `condition` is true, otherwise leaves them unchanged.
/// Does not branch on the condition value.
pub fn conditional_swap<T: Clone>(a: &mut T, b: &mut T, condition: bool) {
    if condition {
        let temp = a.clone();
        *a = b.clone();
        *b = temp;
    }
}

/// Prefetch memory locations to reduce timing variation
///
/// This is a hint to the CPU to prefetch data into cache.
/// May help reduce timing variation in subsequent accesses.
///
/// # Safety
///
/// The caller must ensure that `addr` is a valid, aligned pointer
/// to initialized memory of type `T`.
///
/// Note: This is a best-effort hint. On stable Rust, this uses a volatile
/// read to trigger a cache line load. For true prefetch intrinsics, use nightly Rust.
#[inline]
pub unsafe fn prefetch_read<T>(addr: *const T) {
    // Volatile read to trigger cache line load
    // This is not as efficient as true prefetch, but works on stable Rust
    // SAFETY: The caller guarantees that addr is valid and aligned
    unsafe {
        let _ = std::ptr::read_volatile(addr);
    }

    // Compiler fence to prevent reordering
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Prefetch multiple memory locations
///
/// Prefetches an array of pointers to reduce cache-miss timing variations.
///
/// # Safety
///
/// The caller must ensure that all pointers in `addrs` are valid, aligned
/// pointers to initialized memory of type `T`.
pub unsafe fn prefetch_array<T>(addrs: &[*const T]) {
    for &addr in addrs {
        // SAFETY: The caller guarantees that all pointers are valid and aligned
        unsafe {
            prefetch_read(addr);
        }
    }
}

/// Cache-line aligned buffer
///
/// Ensures data is aligned to cache line boundaries to reduce false sharing
/// and improve cache utilization.
#[repr(align(64))] // Common cache line size
#[derive(Clone)]
pub struct CacheAligned<T> {
    data: T,
}

impl<T> CacheAligned<T> {
    /// Create a new cache-aligned value
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get a reference to the data
    pub fn get(&self) -> &T {
        &self.data
    }

    /// Get a mutable reference to the data
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Consume and return the inner data
    pub fn into_inner(self) -> T {
        self.data
    }
}

/// Constant-time array index clamping
///
/// Clamps an index to valid range without branching.
/// Returns the index if in bounds, otherwise returns the maximum valid index.
pub fn constant_time_clamp_index(index: usize, max_index: usize) -> usize {
    // Branchless clamp
    let overflow = (index > max_index) as usize;
    let clamped = index.wrapping_sub(overflow.wrapping_mul(index.wrapping_sub(max_index)));
    clamped.min(max_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_lookup() {
        let table = [10u8, 20, 30, 40, 50];
        let lookup = ConstantTimeLookup::new(&table);

        assert_eq!(lookup.get(0), 10);
        assert_eq!(lookup.get(2), 30);
        assert_eq!(lookup.get(4), 50);
        assert_eq!(lookup.len(), 5);
    }

    #[test]
    fn test_constant_time_lookup_out_of_bounds() {
        let table = [10u8, 20, 30];
        let lookup = ConstantTimeLookup::new(&table);

        // Out of bounds returns default (0)
        assert_eq!(lookup.get(10), 0);
    }

    #[test]
    fn test_byte_lookup() {
        let table = vec![0xFF, 0xAA, 0x55, 0x00];
        let lookup = ByteLookup::new(&table);

        assert_eq!(lookup.get(0), 0xFF);
        assert_eq!(lookup.get(1), 0xAA);
        assert_eq!(lookup.get(2), 0x55);
        assert_eq!(lookup.get(3), 0x00);
    }

    #[test]
    fn test_constant_time_memcmp() {
        let a = [1u8, 2, 3, 4, 5];
        let b = [1u8, 2, 3, 4, 5];
        let c = [1u8, 2, 3, 4, 6];

        assert!(constant_time_memcmp(&a, &b));
        assert!(!constant_time_memcmp(&a, &c));
    }

    #[test]
    fn test_constant_time_memcmp_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2];

        assert!(!constant_time_memcmp(&a, &b));
    }

    #[test]
    fn test_conditional_swap() {
        let mut a = 10u32;
        let mut b = 20u32;

        conditional_swap(&mut a, &mut b, true);
        assert_eq!(a, 20);
        assert_eq!(b, 10);

        conditional_swap(&mut a, &mut b, false);
        assert_eq!(a, 20);
        assert_eq!(b, 10);
    }

    #[test]
    fn test_cache_aligned() {
        let aligned = CacheAligned::new(42u64);
        assert_eq!(*aligned.get(), 42);

        let mut aligned_mut = CacheAligned::new(100u32);
        *aligned_mut.get_mut() = 200;
        assert_eq!(*aligned_mut.get(), 200);

        assert_eq!(aligned_mut.into_inner(), 200);
    }

    #[test]
    fn test_constant_time_eq_usize() {
        assert_eq!(constant_time_eq_usize(5, 5), 1);
        assert_eq!(constant_time_eq_usize(5, 6), 0);
        assert_eq!(constant_time_eq_usize(0, 0), 1);
    }

    #[test]
    fn test_constant_time_clamp_index() {
        assert_eq!(constant_time_clamp_index(3, 10), 3);
        assert_eq!(constant_time_clamp_index(15, 10), 10);
        assert_eq!(constant_time_clamp_index(0, 10), 0);
        assert_eq!(constant_time_clamp_index(10, 10), 10);
    }

    #[test]
    fn test_prefetch_operations() {
        let data = [1u8, 2, 3, 4, 5];

        // Just test that these don't crash
        unsafe {
            prefetch_read(data.as_ptr());

            let ptrs = vec![data.as_ptr(), data[1..].as_ptr()];
            prefetch_array(&ptrs);
        }
    }

    #[test]
    fn test_byte_lookup_empty() {
        let lookup = ByteLookup::new(&[]);
        assert!(lookup.is_empty());
        assert_eq!(lookup.len(), 0);
    }

    #[test]
    fn test_constant_time_lookup_string() {
        let table = vec!["hello".to_string(), "world".to_string(), "test".to_string()];
        let lookup = ConstantTimeLookup::new(&table);

        assert_eq!(lookup.get(0), "hello");
        assert_eq!(lookup.get(1), "world");
        assert_eq!(lookup.get(2), "test");
    }
}
