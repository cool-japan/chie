//! Quota management types for CHIE Protocol.
//!
//! This module provides types for tracking and managing user quotas,
//! including storage, bandwidth, and rate limits.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::core::Bytes;

/// Storage quota information for a user or node.
///
/// # Examples
///
/// ```
/// use chie_shared::StorageQuota;
///
/// // Create 10 GB quota with 5 GB used and 1 GB reserved
/// let quota = StorageQuota::new(
///     10 * 1024 * 1024 * 1024,  // 10 GB total
///     5 * 1024 * 1024 * 1024,   // 5 GB used
///     1 * 1024 * 1024 * 1024,   // 1 GB reserved
/// );
///
/// // Check available space
/// assert_eq!(quota.available_bytes(), 4 * 1024 * 1024 * 1024);
///
/// // Check utilization
/// assert_eq!(quota.utilization(), 0.5);
///
/// // Check if can allocate more
/// assert!(quota.can_allocate(3 * 1024 * 1024 * 1024));
/// assert!(!quota.is_nearly_full());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StorageQuota {
    /// Total allocated storage in bytes.
    pub total_bytes: Bytes,
    /// Currently used storage in bytes.
    pub used_bytes: Bytes,
    /// Reserved storage in bytes (pending operations).
    pub reserved_bytes: Bytes,
}

impl StorageQuota {
    /// Create a new storage quota.
    pub fn new(total_bytes: Bytes, used_bytes: Bytes, reserved_bytes: Bytes) -> Self {
        Self {
            total_bytes,
            used_bytes,
            reserved_bytes,
        }
    }

    /// Get available storage in bytes.
    pub fn available_bytes(&self) -> Bytes {
        self.total_bytes
            .saturating_sub(self.used_bytes)
            .saturating_sub(self.reserved_bytes)
    }

    /// Get utilization percentage (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.used_bytes as f64 / self.total_bytes as f64
        }
    }

    /// Check if there's enough space for additional bytes.
    pub fn can_allocate(&self, bytes: Bytes) -> bool {
        self.available_bytes() >= bytes
    }

    /// Check if quota is nearly full (>90% used).
    pub fn is_nearly_full(&self) -> bool {
        self.utilization() > 0.9
    }

    /// Get total allocated bytes (used + reserved).
    pub fn allocated_bytes(&self) -> Bytes {
        self.used_bytes.saturating_add(self.reserved_bytes)
    }
}

impl Default for StorageQuota {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

/// Bandwidth quota for a time period.
///
/// # Examples
///
/// ```
/// use chie_shared::BandwidthQuota;
///
/// let now = chrono::Utc::now().timestamp_millis() as u64;
///
/// // Create 100 GB monthly bandwidth quota
/// let quota = BandwidthQuota::new(
///     100 * 1024 * 1024 * 1024,  // 100 GB total
///     50 * 1024 * 1024 * 1024,   // 50 GB used
///     30 * 24 * 60 * 60,         // 30 days in seconds
///     now,
/// );
///
/// // Check remaining bandwidth
/// assert_eq!(quota.remaining_bytes(), 50 * 1024 * 1024 * 1024);
///
/// // Check utilization
/// assert_eq!(quota.utilization(), 0.5);
///
/// // Check if can consume more
/// assert!(quota.can_consume(30 * 1024 * 1024 * 1024));
/// assert!(!quota.is_exceeded());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BandwidthQuota {
    /// Total bandwidth quota in bytes.
    pub total_bytes: Bytes,
    /// Bandwidth used in current period (bytes).
    pub used_bytes: Bytes,
    /// Period duration in seconds.
    pub period_seconds: u64,
    /// Period start timestamp (Unix milliseconds).
    pub period_start_ms: u64,
}

impl BandwidthQuota {
    /// Create a new bandwidth quota.
    pub fn new(
        total_bytes: Bytes,
        used_bytes: Bytes,
        period_seconds: u64,
        period_start_ms: u64,
    ) -> Self {
        Self {
            total_bytes,
            used_bytes,
            period_seconds,
            period_start_ms,
        }
    }

    /// Get remaining bandwidth in bytes.
    pub fn remaining_bytes(&self) -> Bytes {
        self.total_bytes.saturating_sub(self.used_bytes)
    }

    /// Get utilization percentage (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.used_bytes as f64 / self.total_bytes as f64
        }
    }

    /// Check if there's enough bandwidth remaining.
    pub fn can_consume(&self, bytes: Bytes) -> bool {
        self.remaining_bytes() >= bytes
    }

    /// Check if quota is exceeded.
    pub fn is_exceeded(&self) -> bool {
        self.used_bytes >= self.total_bytes
    }

    /// Get average bytes per second used.
    pub fn avg_bytes_per_second(&self) -> f64 {
        if self.period_seconds == 0 {
            0.0
        } else {
            self.used_bytes as f64 / self.period_seconds as f64
        }
    }

    /// Check if period has expired (given current time).
    pub fn is_period_expired(&self, current_time_ms: u64) -> bool {
        let elapsed_ms = current_time_ms.saturating_sub(self.period_start_ms);
        let period_ms = self.period_seconds * 1000;
        elapsed_ms >= period_ms
    }
}

impl Default for BandwidthQuota {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// Rate limit quota for API requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RateLimitQuota {
    /// Maximum requests allowed in period.
    pub max_requests: u32,
    /// Current request count in period.
    pub current_requests: u32,
    /// Period duration in seconds.
    pub period_seconds: u64,
    /// Period start timestamp (Unix milliseconds).
    pub period_start_ms: u64,
}

impl RateLimitQuota {
    /// Create a new rate limit quota.
    pub fn new(
        max_requests: u32,
        current_requests: u32,
        period_seconds: u64,
        period_start_ms: u64,
    ) -> Self {
        Self {
            max_requests,
            current_requests,
            period_seconds,
            period_start_ms,
        }
    }

    /// Get remaining requests allowed.
    pub fn remaining_requests(&self) -> u32 {
        self.max_requests.saturating_sub(self.current_requests)
    }

    /// Check if another request is allowed.
    pub fn is_allowed(&self) -> bool {
        self.current_requests < self.max_requests
    }

    /// Check if rate limit is exceeded.
    pub fn is_exceeded(&self) -> bool {
        self.current_requests >= self.max_requests
    }

    /// Get utilization percentage (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.max_requests == 0 {
            0.0
        } else {
            self.current_requests as f64 / self.max_requests as f64
        }
    }

    /// Check if period has expired (given current time).
    pub fn is_period_expired(&self, current_time_ms: u64) -> bool {
        let elapsed_ms = current_time_ms.saturating_sub(self.period_start_ms);
        let period_ms = self.period_seconds * 1000;
        elapsed_ms >= period_ms
    }
}

impl Default for RateLimitQuota {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// Combined quota information for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct UserQuota {
    /// Storage quota.
    pub storage: StorageQuota,
    /// Bandwidth quota.
    pub bandwidth: BandwidthQuota,
    /// API rate limit quota.
    pub rate_limit: RateLimitQuota,
}

impl UserQuota {
    /// Create new user quota.
    pub fn new(
        storage: StorageQuota,
        bandwidth: BandwidthQuota,
        rate_limit: RateLimitQuota,
    ) -> Self {
        Self {
            storage,
            bandwidth,
            rate_limit,
        }
    }

    /// Check if user can perform an operation requiring both storage and bandwidth.
    pub fn can_perform_operation(&self, storage_bytes: Bytes, bandwidth_bytes: Bytes) -> bool {
        self.storage.can_allocate(storage_bytes) && self.bandwidth.can_consume(bandwidth_bytes)
    }

    /// Check if any quota is nearly exhausted (>90%).
    pub fn has_warning_threshold(&self) -> bool {
        self.storage.is_nearly_full()
            || self.bandwidth.utilization() > 0.9
            || self.rate_limit.utilization() > 0.9
    }
}

impl Default for UserQuota {
    fn default() -> Self {
        Self::new(
            StorageQuota::default(),
            BandwidthQuota::default(),
            RateLimitQuota::default(),
        )
    }
}

/// Builder for StorageQuota with fluent API.
#[derive(Debug, Default)]
pub struct StorageQuotaBuilder {
    total_bytes: Option<Bytes>,
    used_bytes: Option<Bytes>,
    reserved_bytes: Option<Bytes>,
}

impl StorageQuotaBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set total bytes.
    pub fn total_bytes(mut self, bytes: Bytes) -> Self {
        self.total_bytes = Some(bytes);
        self
    }

    /// Set used bytes.
    pub fn used_bytes(mut self, bytes: Bytes) -> Self {
        self.used_bytes = Some(bytes);
        self
    }

    /// Set reserved bytes.
    pub fn reserved_bytes(mut self, bytes: Bytes) -> Self {
        self.reserved_bytes = Some(bytes);
        self
    }

    /// Build the StorageQuota.
    pub fn build(self) -> StorageQuota {
        StorageQuota::new(
            self.total_bytes.unwrap_or(0),
            self.used_bytes.unwrap_or(0),
            self.reserved_bytes.unwrap_or(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_quota() {
        let quota = StorageQuota::new(1000, 400, 100);
        assert_eq!(quota.available_bytes(), 500);
        assert_eq!(quota.utilization(), 0.4);
        assert!(quota.can_allocate(400));
        assert!(!quota.can_allocate(600));
        assert!(!quota.is_nearly_full());
        assert_eq!(quota.allocated_bytes(), 500);
    }

    #[test]
    fn test_storage_quota_nearly_full() {
        let quota = StorageQuota::new(1000, 950, 0);
        assert!(quota.is_nearly_full());
    }

    #[test]
    fn test_storage_quota_saturating() {
        let quota = StorageQuota::new(100, 80, 50);
        assert_eq!(quota.available_bytes(), 0); // Saturating sub
    }

    #[test]
    fn test_bandwidth_quota() {
        let quota = BandwidthQuota::new(1000, 400, 3600, 0);
        assert_eq!(quota.remaining_bytes(), 600);
        assert_eq!(quota.utilization(), 0.4);
        assert!(quota.can_consume(500));
        assert!(!quota.can_consume(700));
        assert!(!quota.is_exceeded());
    }

    #[test]
    fn test_bandwidth_quota_exceeded() {
        let quota = BandwidthQuota::new(1000, 1200, 3600, 0);
        assert!(quota.is_exceeded());
        assert_eq!(quota.remaining_bytes(), 0);
    }

    #[test]
    fn test_bandwidth_quota_period_expired() {
        let quota = BandwidthQuota::new(1000, 400, 3600, 0);
        assert!(!quota.is_period_expired(1000 * 1000)); // 1000 seconds
        assert!(quota.is_period_expired(3600 * 1000 + 1)); // Just past period
    }

    #[test]
    fn test_bandwidth_quota_avg_bps() {
        let quota = BandwidthQuota::new(1000, 500, 10, 0);
        assert_eq!(quota.avg_bytes_per_second(), 50.0);
    }

    #[test]
    fn test_rate_limit_quota() {
        let quota = RateLimitQuota::new(100, 40, 60, 0);
        assert_eq!(quota.remaining_requests(), 60);
        assert!(quota.is_allowed());
        assert!(!quota.is_exceeded());
        assert_eq!(quota.utilization(), 0.4);
    }

    #[test]
    fn test_rate_limit_quota_exceeded() {
        let quota = RateLimitQuota::new(100, 120, 60, 0);
        assert!(!quota.is_allowed());
        assert!(quota.is_exceeded());
        assert_eq!(quota.remaining_requests(), 0);
    }

    #[test]
    fn test_rate_limit_period_expired() {
        let quota = RateLimitQuota::new(100, 40, 60, 0);
        assert!(!quota.is_period_expired(30 * 1000)); // 30 seconds
        assert!(quota.is_period_expired(60 * 1000 + 1)); // Just past period
    }

    #[test]
    fn test_user_quota() {
        let storage = StorageQuota::new(1000, 400, 0);
        let bandwidth = BandwidthQuota::new(2000, 800, 3600, 0);
        let rate_limit = RateLimitQuota::new(100, 40, 60, 0);

        let user_quota = UserQuota::new(storage, bandwidth, rate_limit);

        assert!(user_quota.can_perform_operation(500, 1000));
        assert!(!user_quota.can_perform_operation(700, 1000)); // Storage exceeded
        assert!(!user_quota.can_perform_operation(500, 1500)); // Bandwidth exceeded
        assert!(!user_quota.has_warning_threshold());
    }

    #[test]
    fn test_user_quota_warning() {
        let storage = StorageQuota::new(1000, 950, 0);
        let bandwidth = BandwidthQuota::new(2000, 800, 3600, 0);
        let rate_limit = RateLimitQuota::new(100, 40, 60, 0);

        let user_quota = UserQuota::new(storage, bandwidth, rate_limit);
        assert!(user_quota.has_warning_threshold());
    }

    #[test]
    fn test_storage_quota_serialization() {
        let quota = StorageQuota::new(1000, 400, 100);
        let json = serde_json::to_string(&quota).unwrap();
        let deserialized: StorageQuota = serde_json::from_str(&json).unwrap();
        assert_eq!(quota, deserialized);
    }

    #[test]
    fn test_storage_quota_builder() {
        let quota = StorageQuotaBuilder::new()
            .total_bytes(1000)
            .used_bytes(400)
            .reserved_bytes(100)
            .build();

        assert_eq!(quota.total_bytes, 1000);
        assert_eq!(quota.used_bytes, 400);
        assert_eq!(quota.reserved_bytes, 100);
    }

    #[test]
    fn test_storage_quota_builder_partial() {
        let quota = StorageQuotaBuilder::new().total_bytes(1000).build();

        assert_eq!(quota.total_bytes, 1000);
        assert_eq!(quota.used_bytes, 0);
        assert_eq!(quota.reserved_bytes, 0);
    }
}
