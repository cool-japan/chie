//! Core type aliases and constants for CHIE Protocol.

/// Content identifier (IPFS CID).
pub type ContentCid = String;

/// Peer identifier string.
pub type PeerIdString = String;

/// Amount in platform points.
pub type Points = u64;

/// Bytes transferred.
pub type Bytes = u64;

/// Default chunk size (256 KB).
pub const CHUNK_SIZE: usize = 262_144;

/// Maximum message size (10 MB).
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum content size (100 GB).
pub const MAX_CONTENT_SIZE: u64 = 100 * 1024 * 1024 * 1024;

/// Minimum content size (1 KB).
pub const MIN_CONTENT_SIZE: u64 = 1024;

/// Maximum title length.
pub const MAX_TITLE_LENGTH: usize = 256;

/// Maximum description length.
pub const MAX_DESCRIPTION_LENGTH: usize = 10000;

/// Maximum tags count.
pub const MAX_TAGS_COUNT: usize = 20;

/// Maximum tag length.
pub const MAX_TAG_LENGTH: usize = 50;

/// Timestamp tolerance for validation (5 minutes in milliseconds).
pub const TIMESTAMP_TOLERANCE_MS: i64 = 300_000;

/// Minimum latency threshold (1 ms - anything below is suspicious).
pub const MIN_LATENCY_MS: u32 = 1;

/// Maximum reasonable latency (30 seconds).
pub const MAX_LATENCY_MS: u32 = 30_000;

// Compile-time helper functions

/// Calculate the number of chunks needed for a given size (const fn for compile-time).
#[inline]
#[must_use]
pub const fn chunks_needed(size_bytes: u64, chunk_size: usize) -> u64 {
    let chunks = size_bytes / chunk_size as u64;
    if size_bytes % chunk_size as u64 == 0 {
        chunks
    } else {
        chunks + 1
    }
}

/// Check if a size is within valid content bounds (const fn for compile-time).
#[inline]
#[must_use]
pub const fn is_valid_content_size(size_bytes: u64) -> bool {
    size_bytes >= MIN_CONTENT_SIZE && size_bytes <= MAX_CONTENT_SIZE
}

/// Convert bytes to megabytes (const fn for compile-time).
#[inline]
#[must_use]
pub const fn bytes_to_mb(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

/// Convert bytes to gigabytes (const fn for compile-time).
#[inline]
#[must_use]
pub const fn bytes_to_gb(bytes: u64) -> u64 {
    bytes / (1024 * 1024 * 1024)
}

/// Convert megabytes to bytes (const fn for compile-time).
#[inline]
#[must_use]
pub const fn mb_to_bytes(mb: u64) -> u64 {
    mb * 1024 * 1024
}

/// Convert gigabytes to bytes (const fn for compile-time).
#[inline]
#[must_use]
pub const fn gb_to_bytes(gb: u64) -> u64 {
    gb * 1024 * 1024 * 1024
}

/// Convert kilobytes to bytes (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::kb_to_bytes;
///
/// assert_eq!(kb_to_bytes(1), 1024);
/// assert_eq!(kb_to_bytes(256), 262_144); // CHUNK_SIZE
///
/// // Can be used in const context
/// const ONE_MB_IN_BYTES: u64 = kb_to_bytes(1024);
/// assert_eq!(ONE_MB_IN_BYTES, 1_048_576);
/// ```
#[inline]
#[must_use]
pub const fn kb_to_bytes(kb: u64) -> u64 {
    kb * 1024
}

/// Convert bytes to kilobytes (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::bytes_to_kb;
///
/// assert_eq!(bytes_to_kb(1024), 1);
/// assert_eq!(bytes_to_kb(262_144), 256);
/// assert_eq!(bytes_to_kb(1_048_576), 1024); // 1 MB
/// ```
#[inline]
#[must_use]
pub const fn bytes_to_kb(bytes: u64) -> u64 {
    bytes / 1024
}

/// Check if a latency value is within valid bounds (const fn for compile-time).
///
/// Valid latency is between 1ms and 30 seconds (30,000ms).
///
/// # Examples
///
/// ```
/// use chie_shared::{is_valid_latency, MIN_LATENCY_MS, MAX_LATENCY_MS};
///
/// assert!(is_valid_latency(100)); // 100ms is valid
/// assert!(is_valid_latency(MIN_LATENCY_MS)); // 1ms minimum
/// assert!(is_valid_latency(MAX_LATENCY_MS)); // 30s maximum
/// assert!(!is_valid_latency(0)); // Too low
/// assert!(!is_valid_latency(35_000)); // Too high
/// ```
#[inline]
#[must_use]
pub const fn is_valid_latency(latency_ms: u32) -> bool {
    latency_ms >= MIN_LATENCY_MS && latency_ms <= MAX_LATENCY_MS
}

/// Calculate the starting byte offset for a chunk (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::{chunk_start_offset, CHUNK_SIZE};
///
/// assert_eq!(chunk_start_offset(0, CHUNK_SIZE), 0);
/// assert_eq!(chunk_start_offset(1, CHUNK_SIZE), 262_144);
/// assert_eq!(chunk_start_offset(5, CHUNK_SIZE), 1_310_720);
/// ```
#[inline]
#[must_use]
pub const fn chunk_start_offset(chunk_index: u64, chunk_size: usize) -> u64 {
    chunk_index * chunk_size as u64
}

/// Calculate the ending byte offset for a chunk (const fn for compile-time).
///
/// This handles the case where the last chunk may be smaller than the chunk size.
///
/// # Examples
///
/// ```
/// use chie_shared::{chunk_end_offset, CHUNK_SIZE};
///
/// // Normal chunk
/// assert_eq!(chunk_end_offset(0, CHUNK_SIZE, 1_000_000), 262_144);
///
/// // Last chunk (partial)
/// let content_size = 500_000u64;
/// let last_idx = 1; // Second chunk is last
/// assert_eq!(chunk_end_offset(last_idx, CHUNK_SIZE, content_size), 500_000);
/// ```
#[inline]
#[must_use]
pub const fn chunk_end_offset(chunk_index: u64, chunk_size: usize, content_size: u64) -> u64 {
    let start = chunk_start_offset(chunk_index, chunk_size);
    let end = start + chunk_size as u64;
    if end > content_size {
        content_size
    } else {
        end
    }
}

/// Check if this is the last chunk for a given content size (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::{is_last_chunk, CHUNK_SIZE};
///
/// let content_size = 500_000u64;
///
/// assert!(!is_last_chunk(0, content_size, CHUNK_SIZE)); // First chunk
/// assert!(is_last_chunk(1, content_size, CHUNK_SIZE)); // Last chunk
///
/// // Single chunk case
/// assert!(is_last_chunk(0, 1024, CHUNK_SIZE));
/// ```
#[inline]
#[must_use]
pub const fn is_last_chunk(chunk_index: u64, content_size: u64, chunk_size: usize) -> bool {
    let total_chunks = chunks_needed(content_size, chunk_size);
    chunk_index == total_chunks - 1
}

/// Convert milliseconds to seconds (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::ms_to_seconds;
///
/// assert_eq!(ms_to_seconds(1000), 1);
/// assert_eq!(ms_to_seconds(5500), 5);
/// assert_eq!(ms_to_seconds(999), 0);
///
/// // Can be used in const context
/// const TIMEOUT_SEC: u64 = ms_to_seconds(30_000);
/// assert_eq!(TIMEOUT_SEC, 30);
/// ```
#[inline]
#[must_use]
pub const fn ms_to_seconds(ms: u64) -> u64 {
    ms / 1000
}

/// Convert seconds to milliseconds (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::seconds_to_ms;
///
/// assert_eq!(seconds_to_ms(1), 1000);
/// assert_eq!(seconds_to_ms(30), 30_000);
///
/// // Can be used in const context
/// const TIMEOUT_MS: u64 = seconds_to_ms(30);
/// assert_eq!(TIMEOUT_MS, 30_000);
/// ```
#[inline]
#[must_use]
pub const fn seconds_to_ms(seconds: u64) -> u64 {
    seconds * 1000
}

/// Convert minutes to milliseconds (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::minutes_to_ms;
///
/// assert_eq!(minutes_to_ms(1), 60_000);
/// assert_eq!(minutes_to_ms(5), 300_000);
///
/// // Can be used in const context
/// const CACHE_TIMEOUT_MS: u64 = minutes_to_ms(30);
/// assert_eq!(CACHE_TIMEOUT_MS, 1_800_000);
/// ```
#[inline]
#[must_use]
pub const fn minutes_to_ms(minutes: u64) -> u64 {
    minutes * 60 * 1000
}

/// Convert hours to milliseconds (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::hours_to_ms;
///
/// assert_eq!(hours_to_ms(1), 3_600_000);
/// assert_eq!(hours_to_ms(24), 86_400_000);
///
/// // Can be used in const context
/// const DAY_MS: u64 = hours_to_ms(24);
/// assert_eq!(DAY_MS, 86_400_000);
/// ```
#[inline]
#[must_use]
pub const fn hours_to_ms(hours: u64) -> u64 {
    hours * 60 * 60 * 1000
}

/// Convert days to milliseconds (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::days_to_ms;
///
/// assert_eq!(days_to_ms(1), 86_400_000);
/// assert_eq!(days_to_ms(7), 604_800_000);
///
/// // Can be used in const context
/// const WEEK_MS: u64 = days_to_ms(7);
/// assert_eq!(WEEK_MS, 604_800_000);
/// ```
#[inline]
#[must_use]
pub const fn days_to_ms(days: u64) -> u64 {
    days * 24 * 60 * 60 * 1000
}

/// Convert bytes to bits (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::bytes_to_bits;
///
/// assert_eq!(bytes_to_bits(1), 8);
/// assert_eq!(bytes_to_bits(1024), 8192);
///
/// // Can be used in const context
/// const CHUNK_SIZE_BITS: u64 = bytes_to_bits(262_144);
/// assert_eq!(CHUNK_SIZE_BITS, 2_097_152);
/// ```
#[inline]
#[must_use]
pub const fn bytes_to_bits(bytes: u64) -> u64 {
    bytes * 8
}

/// Convert bits to bytes (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::bits_to_bytes;
///
/// assert_eq!(bits_to_bytes(8), 1);
/// assert_eq!(bits_to_bytes(8192), 1024);
///
/// // Can be used in const context
/// const MEGABIT_BYTES: u64 = bits_to_bytes(1_000_000);
/// assert_eq!(MEGABIT_BYTES, 125_000);
/// ```
#[inline]
#[must_use]
pub const fn bits_to_bytes(bits: u64) -> u64 {
    bits / 8
}

/// Convert terabytes to bytes (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::tb_to_bytes;
///
/// assert_eq!(tb_to_bytes(1), 1_099_511_627_776);
/// assert_eq!(tb_to_bytes(5), 5_497_558_138_880);
///
/// // Can be used in const context
/// const MAX_STORAGE: u64 = tb_to_bytes(10);
/// assert_eq!(MAX_STORAGE, 10_995_116_277_760);
/// ```
#[inline]
#[must_use]
pub const fn tb_to_bytes(tb: u64) -> u64 {
    tb * 1024 * 1024 * 1024 * 1024
}

/// Convert bytes to terabytes (const fn for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::bytes_to_tb;
///
/// assert_eq!(bytes_to_tb(1_099_511_627_776), 1);
/// assert_eq!(bytes_to_tb(5_497_558_138_880), 5);
/// ```
#[inline]
#[must_use]
pub const fn bytes_to_tb(bytes: u64) -> u64 {
    bytes / (1024 * 1024 * 1024 * 1024)
}

/// Calculate the maximum number of chunks for max content size (const for compile-time).
///
/// # Examples
///
/// ```
/// use chie_shared::{max_chunks_for_content, CHUNK_SIZE, MAX_CONTENT_SIZE};
///
/// let max_chunks = max_chunks_for_content(CHUNK_SIZE);
/// assert_eq!(max_chunks, 409_600); // 100GB / 256KB
///
/// // Can be used in const context
/// const MAX_CHUNKS: u64 = max_chunks_for_content(CHUNK_SIZE);
/// ```
#[inline]
#[must_use]
pub const fn max_chunks_for_content(chunk_size: usize) -> u64 {
    chunks_needed(MAX_CONTENT_SIZE, chunk_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunks_needed() {
        assert_eq!(chunks_needed(CHUNK_SIZE as u64, CHUNK_SIZE), 1);
        assert_eq!(chunks_needed(CHUNK_SIZE as u64 * 2, CHUNK_SIZE), 2);
        assert_eq!(chunks_needed(CHUNK_SIZE as u64 * 2 + 1, CHUNK_SIZE), 3);
        assert_eq!(chunks_needed(1000, CHUNK_SIZE), 1);
    }

    #[test]
    fn test_is_valid_content_size() {
        assert!(!is_valid_content_size(MIN_CONTENT_SIZE - 1));
        assert!(is_valid_content_size(MIN_CONTENT_SIZE));
        assert!(is_valid_content_size(1024 * 1024));
        assert!(is_valid_content_size(MAX_CONTENT_SIZE));
        assert!(!is_valid_content_size(MAX_CONTENT_SIZE + 1));
    }

    #[test]
    fn test_bytes_conversions() {
        assert_eq!(bytes_to_mb(1024 * 1024), 1);
        assert_eq!(bytes_to_mb(5 * 1024 * 1024), 5);
        assert_eq!(bytes_to_gb(1024 * 1024 * 1024), 1);
        assert_eq!(bytes_to_gb(5 * 1024 * 1024 * 1024), 5);
    }

    #[test]
    fn test_bytes_roundtrip() {
        assert_eq!(mb_to_bytes(1), 1024 * 1024);
        assert_eq!(gb_to_bytes(1), 1024 * 1024 * 1024);
        assert_eq!(bytes_to_mb(mb_to_bytes(100)), 100);
        assert_eq!(bytes_to_gb(gb_to_bytes(10)), 10);
    }

    #[test]
    fn test_const_evaluation() {
        // These should be evaluable at compile time
        const _CHUNKS: u64 = chunks_needed(1024 * 1024, CHUNK_SIZE);
        const _VALID: bool = is_valid_content_size(MIN_CONTENT_SIZE);
        const _MB: u64 = bytes_to_mb(1024 * 1024);
        const _GB: u64 = bytes_to_gb(1024 * 1024 * 1024);
    }

    #[test]
    fn test_kb_conversions() {
        assert_eq!(kb_to_bytes(1), 1024);
        assert_eq!(kb_to_bytes(256), 262_144);
        assert_eq!(bytes_to_kb(1024), 1);
        assert_eq!(bytes_to_kb(262_144), 256);
        // Roundtrip
        assert_eq!(bytes_to_kb(kb_to_bytes(100)), 100);
    }

    #[test]
    fn test_is_valid_latency() {
        assert!(!is_valid_latency(0));
        assert!(is_valid_latency(MIN_LATENCY_MS));
        assert!(is_valid_latency(100));
        assert!(is_valid_latency(MAX_LATENCY_MS));
        assert!(!is_valid_latency(MAX_LATENCY_MS + 1));
        assert!(!is_valid_latency(u32::MAX));
    }

    #[test]
    fn test_chunk_offsets() {
        // First chunk
        assert_eq!(chunk_start_offset(0, CHUNK_SIZE), 0);
        assert_eq!(
            chunk_end_offset(0, CHUNK_SIZE, 1_000_000),
            CHUNK_SIZE as u64
        );

        // Second chunk
        assert_eq!(chunk_start_offset(1, CHUNK_SIZE), CHUNK_SIZE as u64);
        assert_eq!(
            chunk_end_offset(1, CHUNK_SIZE, 1_000_000),
            CHUNK_SIZE as u64 * 2
        );

        // Last chunk (smaller than chunk size)
        let content_size = 500_000u64;
        let last_chunk_idx = chunks_needed(content_size, CHUNK_SIZE) - 1;
        assert_eq!(
            chunk_end_offset(last_chunk_idx, CHUNK_SIZE, content_size),
            content_size
        );
    }

    #[test]
    fn test_is_last_chunk() {
        let content_size = 500_000u64;
        let total = chunks_needed(content_size, CHUNK_SIZE);

        assert!(!is_last_chunk(0, content_size, CHUNK_SIZE));
        assert!(is_last_chunk(total - 1, content_size, CHUNK_SIZE));

        // Edge case: exactly one chunk
        assert!(is_last_chunk(0, 1024, CHUNK_SIZE));
    }

    #[test]
    fn test_new_const_evaluation() {
        // All new functions should be evaluable at compile time
        const _KB: u64 = kb_to_bytes(256);
        const _KB_CONV: u64 = bytes_to_kb(262_144);
        const _VALID_LAT: bool = is_valid_latency(100);
        const _START: u64 = chunk_start_offset(5, CHUNK_SIZE);
        const _END: u64 = chunk_end_offset(5, CHUNK_SIZE, 10_000_000);
        const _LAST: bool = is_last_chunk(0, 1024, CHUNK_SIZE);
    }

    #[test]
    fn test_time_conversions() {
        // ms to seconds
        assert_eq!(ms_to_seconds(1000), 1);
        assert_eq!(ms_to_seconds(5500), 5);
        assert_eq!(ms_to_seconds(999), 0);
        assert_eq!(ms_to_seconds(30_000), 30);

        // seconds to ms
        assert_eq!(seconds_to_ms(1), 1000);
        assert_eq!(seconds_to_ms(30), 30_000);
        assert_eq!(seconds_to_ms(0), 0);

        // Roundtrip
        assert_eq!(ms_to_seconds(seconds_to_ms(100)), 100);
    }

    #[test]
    fn test_time_const_evaluation() {
        // Time conversion functions should be evaluable at compile time
        const _SECONDS: u64 = ms_to_seconds(30_000);
        const _MS: u64 = seconds_to_ms(30);
    }

    #[test]
    fn test_additional_time_conversions() {
        // Minutes
        assert_eq!(minutes_to_ms(1), 60_000);
        assert_eq!(minutes_to_ms(5), 300_000);
        assert_eq!(minutes_to_ms(30), 1_800_000);

        // Hours
        assert_eq!(hours_to_ms(1), 3_600_000);
        assert_eq!(hours_to_ms(24), 86_400_000);

        // Days
        assert_eq!(days_to_ms(1), 86_400_000);
        assert_eq!(days_to_ms(7), 604_800_000);
    }

    #[test]
    fn test_bits_bytes_conversions() {
        // Bytes to bits
        assert_eq!(bytes_to_bits(1), 8);
        assert_eq!(bytes_to_bits(1024), 8192);
        assert_eq!(bytes_to_bits(262_144), 2_097_152);

        // Bits to bytes
        assert_eq!(bits_to_bytes(8), 1);
        assert_eq!(bits_to_bytes(8192), 1024);

        // Roundtrip
        assert_eq!(bits_to_bytes(bytes_to_bits(1024)), 1024);
    }

    #[test]
    fn test_tb_conversions() {
        assert_eq!(tb_to_bytes(1), 1_099_511_627_776);
        assert_eq!(tb_to_bytes(5), 5_497_558_138_880);
        assert_eq!(bytes_to_tb(1_099_511_627_776), 1);
        assert_eq!(bytes_to_tb(5_497_558_138_880), 5);

        // Roundtrip
        assert_eq!(bytes_to_tb(tb_to_bytes(10)), 10);
    }

    #[test]
    fn test_max_chunks_for_content() {
        let max_chunks = max_chunks_for_content(CHUNK_SIZE);
        assert_eq!(max_chunks, 409_600); // 100GB / 256KB
    }

    #[test]
    fn test_new_const_functions_evaluation() {
        // All new functions should be evaluable at compile time
        const _MINUTES: u64 = minutes_to_ms(30);
        const _HOURS: u64 = hours_to_ms(24);
        const _DAYS: u64 = days_to_ms(7);
        const _BITS: u64 = bytes_to_bits(1024);
        const _BYTES: u64 = bits_to_bytes(8192);
        const _TB: u64 = tb_to_bytes(1);
        const _TB_CONV: u64 = bytes_to_tb(1_099_511_627_776);
        const _MAX_CHUNKS: u64 = max_chunks_for_content(CHUNK_SIZE);
    }
}
