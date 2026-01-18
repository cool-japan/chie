//! Automatic content expiration policies.
//!
//! This module provides automatic expiration management for cached content,
//! allowing content to be automatically removed based on time-to-live (TTL),
//! access patterns, or custom policies.
//!
//! # Features
//!
//! - TTL-based expiration
//! - Access-based expiration (idle timeout)
//! - Size-based expiration quotas
//! - Custom expiration policies
//! - Batch expiration processing
//! - Expiration event notifications
//!
//! # Example
//!
//! ```
//! use chie_core::expiration::{ExpirationManager, ExpirationPolicy, ContentEntry};
//! use std::time::Duration;
//!
//! # fn example() {
//! // Create an expiration manager with TTL policy
//! let policy = ExpirationPolicy::ttl(Duration::from_secs(3600)); // 1 hour TTL
//! let mut manager = ExpirationManager::new(policy);
//!
//! // Register content
//! manager.register("content:123".to_string(), 1024);
//!
//! // Check for expired content
//! let expired = manager.get_expired();
//! println!("Expired content count: {}", expired.len());
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default maximum entries before forced cleanup
const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Default batch size for expiration processing
#[allow(dead_code)]
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Content entry with expiration metadata
#[derive(Debug, Clone)]
pub struct ContentEntry {
    /// Content identifier
    pub cid: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Timestamp when content was created
    pub created_at: Instant,
    /// Timestamp of last access
    pub last_accessed: Instant,
    /// Number of times accessed
    pub access_count: u64,
    /// Explicit expiration time (None = use policy)
    pub expires_at: Option<Instant>,
}

impl ContentEntry {
    /// Create a new content entry
    #[must_use]
    pub fn new(cid: String, size_bytes: u64) -> Self {
        let now = Instant::now();
        Self {
            cid,
            size_bytes,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            expires_at: None,
        }
    }

    /// Create an entry with explicit expiration time
    #[must_use]
    pub fn with_expiration(cid: String, size_bytes: u64, expires_at: Instant) -> Self {
        let now = Instant::now();
        Self {
            cid,
            size_bytes,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            expires_at: Some(expires_at),
        }
    }

    /// Record an access to this content
    pub fn record_access(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }

    /// Get age of this content
    #[must_use]
    #[inline]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get idle time (time since last access)
    #[must_use]
    #[inline]
    pub fn idle_time(&self) -> Duration {
        self.last_accessed.elapsed()
    }

    /// Check if this entry has an explicit expiration time
    #[must_use]
    #[inline]
    pub const fn has_explicit_expiration(&self) -> bool {
        self.expires_at.is_some()
    }
}

/// Expiration policy
#[derive(Debug, Clone, Default)]
pub enum ExpirationPolicy {
    /// Time-to-live: expire after fixed duration from creation
    Ttl(Duration),

    /// Idle timeout: expire after no access for duration
    IdleTimeout(Duration),

    /// Least recently used: keep only N most recently accessed items
    Lru(usize),

    /// Size quota: keep content up to max bytes
    SizeQuota(u64),

    /// Combined: expire if any condition is met
    Combined(Vec<ExpirationPolicy>),

    /// Never expire
    #[default]
    Never,
}

impl ExpirationPolicy {
    /// Create a TTL policy
    #[must_use]
    pub const fn ttl(duration: Duration) -> Self {
        Self::Ttl(duration)
    }

    /// Create an idle timeout policy
    #[must_use]
    pub const fn idle_timeout(duration: Duration) -> Self {
        Self::IdleTimeout(duration)
    }

    /// Create an LRU policy
    #[must_use]
    pub const fn lru(max_entries: usize) -> Self {
        Self::Lru(max_entries)
    }

    /// Create a size quota policy
    #[must_use]
    pub const fn size_quota(max_bytes: u64) -> Self {
        Self::SizeQuota(max_bytes)
    }

    /// Create a combined policy
    #[must_use]
    pub fn combined(policies: Vec<Self>) -> Self {
        Self::Combined(policies)
    }

    /// Check if an entry should be expired according to this policy
    #[must_use]
    #[inline]
    pub fn should_expire(&self, entry: &ContentEntry) -> bool {
        // Check explicit expiration first
        if let Some(expires_at) = entry.expires_at {
            if Instant::now() >= expires_at {
                return true;
            }
        }

        match self {
            Self::Ttl(duration) => entry.age() >= *duration,
            Self::IdleTimeout(duration) => entry.idle_time() >= *duration,
            Self::Combined(policies) => policies.iter().any(|p| p.should_expire(entry)),
            Self::Never | Self::Lru(_) | Self::SizeQuota(_) => false,
        }
    }
}

/// Statistics for expiration operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpirationStats {
    /// Total entries currently tracked
    pub total_entries: usize,
    /// Total bytes tracked
    pub total_bytes: u64,
    /// Number of expired entries removed
    pub expired_count: u64,
    /// Total bytes freed by expiration
    pub bytes_freed: u64,
    /// Number of expiration checks performed
    pub checks_performed: u64,
    /// Last expiration check timestamp
    pub last_check_ms: u64,
}

/// Manages automatic content expiration
pub struct ExpirationManager {
    /// Expiration policy
    policy: ExpirationPolicy,
    /// Content entries (cid -> entry)
    entries: HashMap<String, ContentEntry>,
    /// Access order queue (for LRU)
    access_order: VecDeque<String>,
    /// Statistics
    stats: ExpirationStats,
    /// Maximum entries before forced cleanup
    max_entries: usize,
}

impl ExpirationManager {
    /// Create a new expiration manager with a policy
    #[must_use]
    pub fn new(policy: ExpirationPolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            stats: ExpirationStats::default(),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// Create an expiration manager with custom max entries
    #[must_use]
    pub fn with_max_entries(policy: ExpirationPolicy, max_entries: usize) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
            access_order: VecDeque::new(),
            stats: ExpirationStats::default(),
            max_entries,
        }
    }

    /// Register content for expiration tracking
    pub fn register(&mut self, cid: String, size_bytes: u64) {
        let entry = ContentEntry::new(cid.clone(), size_bytes);
        self.insert_entry(entry);
    }

    /// Register content with explicit expiration time
    pub fn register_with_expiration(&mut self, cid: String, size_bytes: u64, expires_at: Instant) {
        let entry = ContentEntry::with_expiration(cid.clone(), size_bytes, expires_at);
        self.insert_entry(entry);
    }

    /// Insert an entry (internal helper)
    fn insert_entry(&mut self, entry: ContentEntry) {
        let cid = entry.cid.clone();
        let size = entry.size_bytes;

        self.entries.insert(cid.clone(), entry);
        self.access_order.push_back(cid);

        self.stats.total_entries = self.entries.len();
        self.stats.total_bytes += size;

        // Enforce max entries limit
        if self.entries.len() > self.max_entries {
            self.expire_oldest();
        }
    }

    /// Record access to content
    pub fn record_access(&mut self, cid: &str) {
        if let Some(entry) = self.entries.get_mut(cid) {
            entry.record_access();

            // Update LRU order
            if let Some(pos) = self.access_order.iter().position(|c| c == cid) {
                self.access_order.remove(pos);
                self.access_order.push_back(cid.to_string());
            }
        }
    }

    /// Get all expired content IDs
    #[must_use]
    pub fn get_expired(&mut self) -> Vec<String> {
        self.stats.checks_performed += 1;
        self.stats.last_check_ms = current_timestamp_ms();

        let mut expired = Vec::new();

        // Check time-based expiration
        for (cid, entry) in &self.entries {
            if self.policy.should_expire(entry) {
                expired.push(cid.clone());
            }
        }

        // Check LRU policy
        if let ExpirationPolicy::Lru(max_entries) = self.policy {
            if self.entries.len() > max_entries {
                let to_remove = self.entries.len() - max_entries;
                for cid in self.access_order.iter().take(to_remove) {
                    if !expired.contains(cid) {
                        expired.push(cid.clone());
                    }
                }
            }
        }

        // Check size quota policy
        if let ExpirationPolicy::SizeQuota(max_bytes) = self.policy {
            if self.stats.total_bytes > max_bytes {
                let mut bytes_to_free = self.stats.total_bytes - max_bytes;
                for cid in &self.access_order {
                    if bytes_to_free == 0 {
                        break;
                    }
                    if let Some(entry) = self.entries.get(cid) {
                        if !expired.contains(cid) {
                            expired.push(cid.clone());
                            bytes_to_free = bytes_to_free.saturating_sub(entry.size_bytes);
                        }
                    }
                }
            }
        }

        expired
    }

    /// Remove expired content (returns list of removed CIDs)
    pub fn expire(&mut self) -> Vec<String> {
        let expired = self.get_expired();
        for cid in &expired {
            self.remove(cid);
        }
        expired
    }

    /// Remove expired content in batches
    pub fn expire_batch(&mut self, batch_size: usize) -> Vec<String> {
        let expired = self.get_expired();
        let to_remove: Vec<_> = expired.into_iter().take(batch_size).collect();

        for cid in &to_remove {
            self.remove(cid);
        }

        to_remove
    }

    /// Remove a specific content entry
    pub fn remove(&mut self, cid: &str) -> Option<ContentEntry> {
        if let Some(entry) = self.entries.remove(cid) {
            // Update stats
            self.stats.total_entries = self.entries.len();
            self.stats.total_bytes = self.stats.total_bytes.saturating_sub(entry.size_bytes);
            self.stats.expired_count += 1;
            self.stats.bytes_freed += entry.size_bytes;

            // Remove from access order
            if let Some(pos) = self.access_order.iter().position(|c| c == cid) {
                self.access_order.remove(pos);
            }

            Some(entry)
        } else {
            None
        }
    }

    /// Expire oldest entries until under max_entries
    fn expire_oldest(&mut self) {
        while self.entries.len() > self.max_entries {
            if let Some(cid) = self.access_order.pop_front() {
                self.remove(&cid);
            } else {
                break;
            }
        }
    }

    /// Get current statistics
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &ExpirationStats {
        &self.stats
    }

    /// Get the number of tracked entries
    #[must_use]
    #[inline]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get total bytes tracked
    #[must_use]
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.stats.total_bytes
    }

    /// Check if a CID is being tracked
    #[must_use]
    #[inline]
    pub fn contains(&self, cid: &str) -> bool {
        self.entries.contains_key(cid)
    }

    /// Get an entry by CID
    #[must_use]
    #[inline]
    pub fn get(&self, cid: &str) -> Option<&ContentEntry> {
        self.entries.get(cid)
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
        self.stats.total_entries = 0;
        self.stats.total_bytes = 0;
    }

    /// Update the expiration policy
    pub fn set_policy(&mut self, policy: ExpirationPolicy) {
        self.policy = policy;
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_content_entry_new() {
        let entry = ContentEntry::new("test:123".to_string(), 1024);
        assert_eq!(entry.cid, "test:123");
        assert_eq!(entry.size_bytes, 1024);
        assert_eq!(entry.access_count, 0);
    }

    #[test]
    fn test_content_entry_access() {
        let mut entry = ContentEntry::new("test:123".to_string(), 1024);
        entry.record_access();
        assert_eq!(entry.access_count, 1);
    }

    #[test]
    fn test_expiration_policy_ttl() {
        let policy = ExpirationPolicy::ttl(Duration::from_millis(100));
        let entry = ContentEntry::new("test:123".to_string(), 1024);

        // Should not expire immediately
        assert!(!policy.should_expire(&entry));

        // Should expire after TTL
        sleep(Duration::from_millis(150));
        assert!(policy.should_expire(&entry));
    }

    #[test]
    fn test_expiration_policy_idle_timeout() {
        let policy = ExpirationPolicy::idle_timeout(Duration::from_millis(100));
        let mut entry = ContentEntry::new("test:123".to_string(), 1024);

        sleep(Duration::from_millis(150));
        assert!(policy.should_expire(&entry));

        // Access should reset idle timer
        entry.record_access();
        assert!(!policy.should_expire(&entry));
    }

    #[test]
    fn test_expiration_manager_register() {
        let policy = ExpirationPolicy::Never;
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:123".to_string(), 1024);

        assert_eq!(manager.entry_count(), 1);
        assert_eq!(manager.total_bytes(), 1024);
        assert!(manager.contains("test:123"));
    }

    #[test]
    fn test_expiration_manager_expire_ttl() {
        let policy = ExpirationPolicy::ttl(Duration::from_millis(100));
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:123".to_string(), 1024);

        // Should not expire immediately
        let expired = manager.get_expired();
        assert_eq!(expired.len(), 0);

        // Should expire after TTL
        sleep(Duration::from_millis(150));
        let expired = manager.expire();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "test:123");
        assert_eq!(manager.entry_count(), 0);
    }

    #[test]
    fn test_expiration_manager_lru() {
        let policy = ExpirationPolicy::lru(2);
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:1".to_string(), 1024);
        manager.register("test:2".to_string(), 1024);
        manager.register("test:3".to_string(), 1024);

        // Should expire oldest entry when over LRU limit
        let expired = manager.expire();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "test:1");
        assert_eq!(manager.entry_count(), 2);
    }

    #[test]
    fn test_expiration_manager_size_quota() {
        let policy = ExpirationPolicy::size_quota(2000);
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:1".to_string(), 1000);
        manager.register("test:2".to_string(), 1000);
        manager.register("test:3".to_string(), 1000);

        // Should expire until under quota
        let expired = manager.expire();
        assert!(!expired.is_empty());
        assert!(manager.total_bytes() <= 2000);
    }

    #[test]
    fn test_expiration_manager_record_access() {
        let policy = ExpirationPolicy::Never;
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:123".to_string(), 1024);
        manager.record_access("test:123");

        let entry = manager.get("test:123").unwrap();
        assert_eq!(entry.access_count, 1);
    }

    #[test]
    fn test_expiration_manager_remove() {
        let policy = ExpirationPolicy::Never;
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:123".to_string(), 1024);
        assert_eq!(manager.entry_count(), 1);

        let removed = manager.remove("test:123");
        assert!(removed.is_some());
        assert_eq!(manager.entry_count(), 0);
    }

    #[test]
    fn test_expiration_manager_stats() {
        let policy = ExpirationPolicy::ttl(Duration::from_millis(100));
        let mut manager = ExpirationManager::new(policy);

        manager.register("test:1".to_string(), 1024);
        manager.register("test:2".to_string(), 2048);

        sleep(Duration::from_millis(150));
        let _expired = manager.expire();

        let stats = manager.stats();
        assert_eq!(stats.expired_count, 2);
        assert_eq!(stats.bytes_freed, 3072);
    }

    #[test]
    fn test_expiration_manager_batch() {
        let policy = ExpirationPolicy::ttl(Duration::from_millis(100));
        let mut manager = ExpirationManager::new(policy);

        for i in 0..10 {
            manager.register(format!("test:{i}"), 1024);
        }

        sleep(Duration::from_millis(150));

        // Expire in batches of 3
        let batch1 = manager.expire_batch(3);
        assert_eq!(batch1.len(), 3);

        let batch2 = manager.expire_batch(3);
        assert_eq!(batch2.len(), 3);
    }

    #[test]
    fn test_expiration_manager_max_entries() {
        let policy = ExpirationPolicy::Never;
        let mut manager = ExpirationManager::with_max_entries(policy, 5);

        for i in 0..10 {
            manager.register(format!("test:{i}"), 1024);
        }

        // Should automatically expire oldest when over max
        assert_eq!(manager.entry_count(), 5);
    }

    #[test]
    fn test_explicit_expiration() {
        let policy = ExpirationPolicy::Never;
        let mut manager = ExpirationManager::new(policy);

        let expires_at = Instant::now() + Duration::from_millis(100);
        manager.register_with_expiration("test:123".to_string(), 1024, expires_at);

        // Should not expire immediately
        let expired = manager.get_expired();
        assert_eq!(expired.len(), 0);

        // Should expire after explicit time
        sleep(Duration::from_millis(150));
        let expired = manager.expire();
        assert_eq!(expired.len(), 1);
    }
}
