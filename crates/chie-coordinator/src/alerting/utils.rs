//! Utility functions for the alerting system.

use std::time::{SystemTime, UNIX_EPOCH};

/// Get current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
