//! Time and timestamp utility functions.

use chrono::Utc;

/// Get current Unix timestamp in milliseconds.
#[inline]
pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// Get current Unix timestamp in seconds.
#[inline]
pub fn now_secs() -> i64 {
    Utc::now().timestamp()
}

/// Convert milliseconds to seconds.
#[inline]
pub fn ms_to_secs(ms: i64) -> i64 {
    ms / 1000
}

/// Convert seconds to milliseconds.
#[inline]
pub fn secs_to_ms(secs: i64) -> i64 {
    secs * 1000
}

/// Check if a timestamp is within the valid range (not too old, not in future).
///
/// # Examples
///
/// ```
/// use chie_shared::{now_ms, is_timestamp_valid};
///
/// // Recent timestamp is valid
/// let recent = now_ms() - 1000; // 1 second ago
/// assert!(is_timestamp_valid(recent, 5000)); // 5 second tolerance
///
/// // Old timestamp is invalid
/// let old = now_ms() - 10000; // 10 seconds ago
/// assert!(!is_timestamp_valid(old, 5000)); // Only 5 second tolerance
///
/// // Future timestamp is always invalid
/// let future = now_ms() + 1000;
/// assert!(!is_timestamp_valid(future, 5000));
/// ```
#[inline]
pub fn is_timestamp_valid(timestamp_ms: i64, tolerance_ms: i64) -> bool {
    let now = now_ms();
    timestamp_ms <= now && (now - timestamp_ms) <= tolerance_ms
}

/// Format Unix timestamp (milliseconds) as human-readable string.
/// Returns format like "2024-12-16 14:30:45 UTC".
pub fn format_timestamp(timestamp_ms: i64) -> String {
    use chrono::{DateTime, Utc};

    if let Some(dt) = DateTime::<Utc>::from_timestamp(
        timestamp_ms / 1000,
        ((timestamp_ms % 1000) * 1_000_000) as u32,
    ) {
        dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    } else {
        "Invalid timestamp".to_string()
    }
}

/// Parse human-readable duration string to milliseconds.
/// Supports formats like "1h30m", "45s", "2h", "500ms".
/// Returns None if the format is invalid.
///
/// # Examples
///
/// ```
/// use chie_shared::parse_duration_str;
///
/// // Parse various duration formats
/// assert_eq!(parse_duration_str("500ms"), Some(500));
/// assert_eq!(parse_duration_str("5s"), Some(5000));
/// assert_eq!(parse_duration_str("2m"), Some(120_000));
/// assert_eq!(parse_duration_str("1h"), Some(3_600_000));
///
/// // Combined durations
/// assert_eq!(parse_duration_str("1h30m"), Some(5_400_000));
/// assert_eq!(parse_duration_str("2h15m30s"), Some(8_130_000));
///
/// // Invalid formats return None
/// assert_eq!(parse_duration_str("invalid"), None);
/// assert_eq!(parse_duration_str("10"), None); // Missing unit
/// ```
pub fn parse_duration_str(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }

    // Handle pure milliseconds (e.g., "500ms")
    if s.ends_with("ms") {
        return s.strip_suffix("ms")?.trim().parse().ok();
    }

    let mut total_ms = 0u64;
    let mut current_num = String::new();

    for ch in s.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else if !current_num.is_empty() {
            let num: u64 = current_num.parse().ok()?;
            current_num.clear();

            let multiplier = match ch {
                'd' => 24 * 60 * 60 * 1000, // days
                'h' => 60 * 60 * 1000,      // hours
                'm' => 60 * 1000,           // minutes
                's' => 1000,                // seconds
                _ => return None,
            };

            total_ms = total_ms.checked_add(num.checked_mul(multiplier)?)?;
        }
    }

    if total_ms == 0 { None } else { Some(total_ms) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_conversion() {
        let secs = 1000;
        let ms = secs_to_ms(secs);
        assert_eq!(ms, 1_000_000);
        assert_eq!(ms_to_secs(ms), secs);
    }

    #[test]
    fn test_timestamp_validation() {
        let now = now_ms();
        assert!(is_timestamp_valid(now, 1000));
        assert!(is_timestamp_valid(now - 500, 1000));
        assert!(!is_timestamp_valid(now + 1000, 1000));
        assert!(!is_timestamp_valid(now - 2000, 1000));
    }

    #[test]
    fn test_format_timestamp() {
        // Test a known timestamp
        let ts = 1_702_742_445_000_i64; // 2023-12-16 14:00:45
        let formatted = format_timestamp(ts);
        assert!(formatted.contains("2023-12-16"));
        assert!(formatted.contains("UTC"));

        // Test invalid timestamp
        let invalid = format_timestamp(i64::MAX);
        assert_eq!(invalid, "Invalid timestamp");
    }

    #[test]
    fn test_parse_duration_str() {
        assert_eq!(parse_duration_str("500ms"), Some(500));
        assert_eq!(parse_duration_str("5s"), Some(5000));
        assert_eq!(parse_duration_str("2m"), Some(120_000));
        assert_eq!(parse_duration_str("1h"), Some(3_600_000));
        assert_eq!(parse_duration_str("1d"), Some(86_400_000));
        assert_eq!(parse_duration_str("1h30m"), Some(5_400_000));
        assert_eq!(parse_duration_str("2h15m30s"), Some(8_130_000));
        assert_eq!(parse_duration_str(""), None);
        assert_eq!(parse_duration_str("invalid"), None);
        assert_eq!(parse_duration_str("10"), None); // No unit
    }
}
