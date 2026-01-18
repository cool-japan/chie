//! Security, cryptography, and byte manipulation utility functions.

/// Generate a random nonce for challenge-response.
#[must_use]
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).expect("Failed to generate random nonce");
    nonce
}

/// Constant-time comparison of two byte slices to prevent timing attacks.
/// Returns true if slices are equal, false otherwise.
/// This is critical for comparing signatures, hashes, and nonces securely.
///
/// # Examples
///
/// ```
/// use chie_shared::constant_time_eq;
///
/// // Comparing equal slices
/// let signature1 = b"valid_signature_data";
/// let signature2 = b"valid_signature_data";
/// assert!(constant_time_eq(signature1, signature2));
///
/// // Comparing different slices
/// let sig_a = b"signature_a";
/// let sig_b = b"signature_b";
/// assert!(!constant_time_eq(sig_a, sig_b));
///
/// // Different lengths always return false
/// assert!(!constant_time_eq(b"short", b"longer_text"));
/// ```
#[inline]
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

/// Constant-time comparison of two 32-byte arrays (common for hashes/keys).
/// Optimized version for fixed-size arrays.
#[inline]
#[must_use]
pub fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0u8;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

/// XOR two byte slices into a new vector.
/// Returns a vector with the XOR of each byte pair.
/// If slices have different lengths, uses the shorter length.
///
/// # Examples
///
/// ```
/// use chie_shared::xor_bytes;
///
/// // Basic XOR operation
/// let a = &[0xFF, 0x00, 0xAA];
/// let b = &[0xFF, 0xFF, 0x55];
/// assert_eq!(xor_bytes(a, b), vec![0x00, 0xFF, 0xFF]);
///
/// // Different lengths - uses shorter
/// let short = &[0xFF, 0x00];
/// let long = &[0xFF, 0xFF, 0xFF];
/// assert_eq!(xor_bytes(short, long), vec![0x00, 0xFF]);
/// ```
#[must_use]
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().min(b.len());
    let mut result = Vec::with_capacity(len);
    for i in 0..len {
        result.push(a[i] ^ b[i]);
    }
    result
}

/// Rotate bytes left by n positions.
/// Wraps around: \[1,2,3,4\] rotated left by 1 = \[2,3,4,1\]
#[must_use]
pub fn rotate_bytes_left(bytes: &[u8], n: usize) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let n = n % bytes.len();
    let mut result = Vec::with_capacity(bytes.len());
    result.extend_from_slice(&bytes[n..]);
    result.extend_from_slice(&bytes[..n]);
    result
}

/// Rotate bytes right by n positions.
/// Wraps around: \[1,2,3,4\] rotated right by 1 = \[4,1,2,3\]
#[must_use]
pub fn rotate_bytes_right(bytes: &[u8], n: usize) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let len = bytes.len();
    let n = n % len;
    rotate_bytes_left(bytes, len - n)
}

/// Check if all bytes in a slice are zero.
#[inline]
#[must_use]
pub fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Count the number of set bits (1s) in a byte slice.
#[must_use]
pub fn count_set_bits(bytes: &[u8]) -> usize {
    bytes.iter().map(|&b| b.count_ones() as usize).sum()
}

/// Encode bytes as hexadecimal string.
///
/// # Examples
///
/// ```
/// use chie_shared::encode_hex;
///
/// // Encode bytes to hex
/// let data = &[0xde, 0xad, 0xbe, 0xef];
/// assert_eq!(encode_hex(data), "deadbeef");
///
/// // Encode small numbers
/// let numbers = &[0, 15, 255];
/// assert_eq!(encode_hex(numbers), "000fff");
/// ```
pub fn encode_hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Decode hexadecimal string to bytes.
///
/// # Examples
///
/// ```
/// use chie_shared::decode_hex;
///
/// // Decode hex string
/// let bytes = decode_hex("deadbeef").unwrap();
/// assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
///
/// // Roundtrip encoding/decoding
/// let original = vec![1, 2, 3, 255];
/// let hex = chie_shared::encode_hex(&original);
/// let decoded = decode_hex(&hex).unwrap();
/// assert_eq!(original, decoded);
///
/// // Error on odd length
/// assert!(decode_hex("abc").is_err());
///
/// // Error on invalid hex
/// assert!(decode_hex("xyz").is_err());
/// ```
pub fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex character: {}", e))
        })
        .collect()
}

/// Apply random jitter to a value for backoff/retry timing.
///
/// # Arguments
/// * `value` - Base value to apply jitter to
/// * `factor` - Jitter factor as a fraction (e.g., 0.25 for ±25%)
///
/// # Returns
/// Value with random jitter applied in the range `[value * (1 - factor), value * (1 + factor)]`
#[must_use]
pub fn random_jitter(value: u64, factor: f64) -> u64 {
    if value == 0 || factor <= 0.0 {
        return value;
    }

    let mut random_bytes = [0u8; 8];
    getrandom::fill(&mut random_bytes).expect("Failed to generate random bytes");
    let random_u64 = u64::from_le_bytes(random_bytes);

    // Calculate jitter range
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let jitter_range = ((value as f64) * factor) as u64;

    if jitter_range == 0 {
        return value;
    }

    // Random value in range [-jitter_range, +jitter_range]
    let jitter = (random_u64 % (jitter_range * 2)).saturating_sub(jitter_range);

    value.saturating_add(jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 32);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello world";
        let b = b"hello world";
        let c = b"hello earth";
        let d = b"different";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
        assert!(!constant_time_eq(a, b"short"));
        assert!(constant_time_eq(&[], &[]));
    }

    #[test]
    fn test_constant_time_eq_32() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let mut c = [1u8; 32];
        c[31] = 2;

        assert!(constant_time_eq_32(&a, &b));
        assert!(!constant_time_eq_32(&a, &c));
        assert!(constant_time_eq_32(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn test_xor_bytes() {
        assert_eq!(xor_bytes(&[0xFF, 0x00], &[0xFF, 0xFF]), vec![0x00, 0xFF]);
        assert_eq!(xor_bytes(&[0xAA, 0x55], &[0x55, 0xAA]), vec![0xFF, 0xFF]);
        assert_eq!(xor_bytes(&[1, 2, 3], &[3, 2, 1]), vec![2, 0, 2]);
        assert_eq!(xor_bytes(&[], &[]), Vec::<u8>::new());
        // Different lengths - use shorter
        assert_eq!(xor_bytes(&[1, 2, 3], &[1, 1]), vec![0, 3]);
    }

    #[test]
    fn test_rotate_bytes_left() {
        assert_eq!(rotate_bytes_left(&[1, 2, 3, 4], 1), vec![2, 3, 4, 1]);
        assert_eq!(rotate_bytes_left(&[1, 2, 3, 4], 2), vec![3, 4, 1, 2]);
        assert_eq!(rotate_bytes_left(&[1, 2, 3, 4], 0), vec![1, 2, 3, 4]);
        assert_eq!(rotate_bytes_left(&[1, 2, 3, 4], 4), vec![1, 2, 3, 4]); // Full rotation
        assert_eq!(rotate_bytes_left(&[1, 2, 3, 4], 5), vec![2, 3, 4, 1]); // Wraps around
        assert_eq!(rotate_bytes_left(&[], 5), Vec::<u8>::new()); // Empty
    }

    #[test]
    fn test_rotate_bytes_right() {
        assert_eq!(rotate_bytes_right(&[1, 2, 3, 4], 1), vec![4, 1, 2, 3]);
        assert_eq!(rotate_bytes_right(&[1, 2, 3, 4], 2), vec![3, 4, 1, 2]);
        assert_eq!(rotate_bytes_right(&[1, 2, 3, 4], 0), vec![1, 2, 3, 4]);
        assert_eq!(rotate_bytes_right(&[1, 2, 3, 4], 4), vec![1, 2, 3, 4]); // Full rotation
        assert_eq!(rotate_bytes_right(&[1, 2, 3, 4], 5), vec![4, 1, 2, 3]); // Wraps around
        assert_eq!(rotate_bytes_right(&[], 5), Vec::<u8>::new()); // Empty
    }

    #[test]
    fn test_is_all_zeros() {
        assert!(is_all_zeros(&[0, 0, 0, 0]));
        assert!(is_all_zeros(&[0]));
        assert!(is_all_zeros(&[]));
        assert!(!is_all_zeros(&[0, 0, 1, 0]));
        assert!(!is_all_zeros(&[1, 2, 3]));
    }

    #[test]
    fn test_count_set_bits() {
        assert_eq!(count_set_bits(&[0b1111_1111]), 8);
        assert_eq!(count_set_bits(&[0b0000_0001]), 1);
        assert_eq!(count_set_bits(&[0b1010_1010]), 4);
        assert_eq!(count_set_bits(&[0b1111_1111, 0b0000_0000]), 8);
        assert_eq!(count_set_bits(&[0b1010_1010, 0b0101_0101]), 8);
        assert_eq!(count_set_bits(&[]), 0);
        assert_eq!(count_set_bits(&[0, 0, 0]), 0);
    }

    #[test]
    fn test_encode_hex() {
        assert_eq!(encode_hex(&[0, 15, 255]), "000fff");
        assert_eq!(encode_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(encode_hex(&[]), "");
    }

    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("000fff").unwrap(), vec![0, 15, 255]);
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());

        // Error cases
        assert!(decode_hex("abc").is_err()); // Odd length
        assert!(decode_hex("xyz").is_err()); // Invalid hex
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![1, 2, 3, 4, 5, 255, 0, 128];
        let hex = encode_hex(&data);
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_random_jitter() {
        // Test zero value
        assert_eq!(random_jitter(0, 0.25), 0);

        // Test zero factor
        assert_eq!(random_jitter(1000, 0.0), 1000);

        // Test normal jitter
        let value = 1000;
        let factor = 0.25;
        for _ in 0..100 {
            let jittered = random_jitter(value, factor);
            // Should be in range [750, 1250] (±25%)
            assert!((750..=1250).contains(&jittered));
        }

        // Test that jitter produces different values (generate many to ensure variability)
        let mut values = Vec::new();
        for _ in 0..10 {
            values.push(random_jitter(10_000, 0.25));
        }
        // With 10 random values in a range of 5000 (7500-12500), at least some should be different
        let all_same = values.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Random jitter should produce varying values");
    }
}
