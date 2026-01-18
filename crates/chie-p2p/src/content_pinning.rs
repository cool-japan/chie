//! Content pinning manager for ensuring availability of critical data.
//!
//! This module provides mechanisms to pin important content to ensure it remains
//! available in the network, with configurable retention policies and storage limits.
//!
//! # Example
//! ```
//! use chie_p2p::content_pinning::{PinningManager, PinningConfig, PinPriority};
//! use std::time::Duration;
//!
//! let config = PinningConfig {
//!     max_pinned_items: 1000,
//!     max_total_size: 10_000_000_000, // 10 GB
//!     auto_unpin_threshold: 0.9,
//!     enable_replication: true,
//!     min_replicas: 3,
//! };
//!
//! let mut manager = PinningManager::new(config);
//!
//! // Pin critical content
//! manager.pin_content(
//!     "important-file".to_string(),
//!     1_000_000, // 1 MB
//!     PinPriority::Critical,
//!     Some(Duration::from_secs(86400)), // 24 hours
//! );
//!
//! assert!(manager.is_pinned(&"important-file".to_string()));
//! ```

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Content identifier
pub type ContentId = String;

/// Peer identifier
pub type PeerId = String;

/// Pin priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PinPriority {
    /// Background priority (can be unpinned first)
    Background = 0,
    /// Low priority
    Low = 1,
    /// Normal priority
    #[default]
    Normal = 2,
    /// High priority
    High = 3,
    /// Critical priority (never auto-unpinned)
    Critical = 4,
}

/// Pin status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// Content is pinned and available
    Pinned,
    /// Content is being fetched for pinning
    Fetching,
    /// Content pin failed
    Failed,
    /// Content was unpinned
    Unpinned,
}

/// Pinned content information
#[derive(Debug, Clone)]
pub struct PinnedContent {
    /// Content identifier
    pub content_id: ContentId,
    /// Content size in bytes
    pub size: u64,
    /// Pin priority
    pub priority: PinPriority,
    /// Pin status
    pub status: PinStatus,
    /// When the content was pinned
    pub pinned_at: Instant,
    /// When the pin expires (None = permanent)
    pub expires_at: Option<Instant>,
    /// Peers hosting this content
    pub replicas: HashSet<PeerId>,
    /// Target number of replicas
    pub target_replicas: usize,
    /// Access count
    pub access_count: u64,
    /// Last accessed time
    pub last_accessed: Instant,
}

impl PinnedContent {
    /// Check if pin has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() >= expires_at
        } else {
            false
        }
    }

    /// Get remaining pin time
    pub fn remaining_time(&self) -> Option<Duration> {
        self.expires_at
            .map(|exp| exp.saturating_duration_since(Instant::now()))
    }

    /// Check if replication is healthy
    pub fn is_healthy(&self) -> bool {
        self.replicas.len() >= self.target_replicas
    }

    /// Get replication ratio
    pub fn replication_ratio(&self) -> f64 {
        if self.target_replicas == 0 {
            return 1.0;
        }
        self.replicas.len() as f64 / self.target_replicas as f64
    }
}

/// Pinning manager configuration
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// Maximum number of pinned items
    pub max_pinned_items: usize,
    /// Maximum total size of pinned content (bytes)
    pub max_total_size: u64,
    /// Auto-unpin threshold (0.0-1.0) when storage is full
    pub auto_unpin_threshold: f64,
    /// Enable automatic replication
    pub enable_replication: bool,
    /// Minimum number of replicas
    pub min_replicas: usize,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            max_pinned_items: 10000,
            max_total_size: 100_000_000_000, // 100 GB
            auto_unpin_threshold: 0.9,
            enable_replication: true,
            min_replicas: 3,
        }
    }
}

/// Content pinning manager
pub struct PinningManager {
    /// Configuration
    config: PinningConfig,
    /// Pinned content
    pinned: HashMap<ContentId, PinnedContent>,
    /// Total size of pinned content
    total_size: u64,
    /// Total pins created
    total_pins: u64,
    /// Total unpins
    total_unpins: u64,
    /// Total auto-unpins
    total_auto_unpins: u64,
}

impl PinningManager {
    /// Create a new pinning manager
    pub fn new(config: PinningConfig) -> Self {
        Self {
            config,
            pinned: HashMap::new(),
            total_size: 0,
            total_pins: 0,
            total_unpins: 0,
            total_auto_unpins: 0,
        }
    }

    /// Pin content
    pub fn pin_content(
        &mut self,
        content_id: ContentId,
        size: u64,
        priority: PinPriority,
        ttl: Option<Duration>,
    ) -> bool {
        // Check if already pinned
        if self.pinned.contains_key(&content_id) {
            return false;
        }

        // Check storage limits
        if !self.has_space_for(size) {
            self.make_space_for(size, priority);
        }

        // Final check after making space
        if self.total_size + size > self.config.max_total_size {
            return false;
        }

        let now = Instant::now();
        let expires_at = ttl.map(|d| now + d);

        let pinned = PinnedContent {
            content_id: content_id.clone(),
            size,
            priority,
            status: PinStatus::Pinned,
            pinned_at: now,
            expires_at,
            replicas: HashSet::new(),
            target_replicas: self.config.min_replicas,
            access_count: 0,
            last_accessed: now,
        };

        self.pinned.insert(content_id, pinned);
        self.total_size += size;
        self.total_pins += 1;

        true
    }

    /// Unpin content
    pub fn unpin_content(&mut self, content_id: &ContentId) -> bool {
        if let Some(pinned) = self.pinned.remove(content_id) {
            self.total_size -= pinned.size;
            self.total_unpins += 1;
            true
        } else {
            false
        }
    }

    /// Check if content is pinned
    pub fn is_pinned(&self, content_id: &ContentId) -> bool {
        self.pinned
            .get(content_id)
            .map(|p| p.status == PinStatus::Pinned)
            .unwrap_or(false)
    }

    /// Get pinned content info
    pub fn get_pinned(&self, content_id: &ContentId) -> Option<&PinnedContent> {
        self.pinned.get(content_id)
    }

    /// Record content access
    pub fn record_access(&mut self, content_id: &ContentId) {
        if let Some(pinned) = self.pinned.get_mut(content_id) {
            pinned.access_count += 1;
            pinned.last_accessed = Instant::now();
        }
    }

    /// Add replica for content
    pub fn add_replica(&mut self, content_id: &ContentId, peer_id: PeerId) -> bool {
        if let Some(pinned) = self.pinned.get_mut(content_id) {
            pinned.replicas.insert(peer_id);
            true
        } else {
            false
        }
    }

    /// Remove replica
    pub fn remove_replica(&mut self, content_id: &ContentId, peer_id: &PeerId) -> bool {
        if let Some(pinned) = self.pinned.get_mut(content_id) {
            pinned.replicas.remove(peer_id);
            true
        } else {
            false
        }
    }

    /// Get content needing replication
    pub fn get_underreplicated(&self) -> Vec<&PinnedContent> {
        self.pinned
            .values()
            .filter(|p| p.status == PinStatus::Pinned && !p.is_healthy())
            .collect()
    }

    /// Cleanup expired pins
    pub fn cleanup_expired(&mut self) -> usize {
        let expired: Vec<ContentId> = self
            .pinned
            .iter()
            .filter(|(_, p)| p.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for id in expired {
            self.unpin_content(&id);
        }

        count
    }

    /// Check if there's space for new content
    fn has_space_for(&self, size: u64) -> bool {
        let usage_ratio = self.total_size as f64 / self.config.max_total_size as f64;
        usage_ratio < self.config.auto_unpin_threshold
            && self.pinned.len() < self.config.max_pinned_items
            && self.total_size + size <= self.config.max_total_size
    }

    /// Make space for new content
    fn make_space_for(&mut self, needed: u64, priority: PinPriority) {
        // Get candidates for unpinning (lower priority, least recently used)
        let mut candidates: Vec<_> = self
            .pinned
            .values()
            .filter(|p| {
                p.priority < priority
                    || (p.priority == priority && p.priority != PinPriority::Critical)
            })
            .collect();

        // Sort by priority (ascending) then by last access (ascending)
        candidates.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.last_accessed.cmp(&b.last_accessed))
        });

        let mut freed = 0u64;
        let mut to_unpin = Vec::new();

        for candidate in candidates {
            if freed >= needed {
                break;
            }
            freed += candidate.size;
            to_unpin.push(candidate.content_id.clone());
        }

        for id in to_unpin {
            self.unpin_content(&id);
            self.total_auto_unpins += 1;
        }
    }

    /// Get all pinned content
    pub fn get_all_pinned(&self) -> Vec<&PinnedContent> {
        self.pinned.values().collect()
    }

    /// Get pinned content by priority
    pub fn get_by_priority(&self, priority: PinPriority) -> Vec<&PinnedContent> {
        self.pinned
            .values()
            .filter(|p| p.priority == priority)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> PinningStats {
        let healthy = self.pinned.values().filter(|p| p.is_healthy()).count();
        let expired = self.pinned.values().filter(|p| p.is_expired()).count();

        PinningStats {
            total_pinned: self.pinned.len(),
            total_size: self.total_size,
            healthy_pins: healthy,
            expired_pins: expired,
            total_pins_created: self.total_pins,
            total_unpins: self.total_unpins,
            total_auto_unpins: self.total_auto_unpins,
            storage_usage_ratio: self.total_size as f64 / self.config.max_total_size as f64,
        }
    }
}

/// Pinning statistics
#[derive(Debug, Clone)]
pub struct PinningStats {
    /// Total pinned items
    pub total_pinned: usize,
    /// Total size of pinned content
    pub total_size: u64,
    /// Healthy pins (sufficient replicas)
    pub healthy_pins: usize,
    /// Expired pins
    pub expired_pins: usize,
    /// Total pins created
    pub total_pins_created: u64,
    /// Total unpins
    pub total_unpins: u64,
    /// Total auto-unpins
    pub total_auto_unpins: u64,
    /// Storage usage ratio
    pub storage_usage_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_content() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        assert!(manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None));

        assert!(manager.is_pinned(&"content1".to_string()));
        assert_eq!(manager.total_size, 1000);
    }

    #[test]
    fn test_pin_duplicate() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        assert!(manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None));

        assert!(!manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None));
    }

    #[test]
    fn test_unpin_content() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);
        assert!(manager.unpin_content(&"content1".to_string()));
        assert!(!manager.is_pinned(&"content1".to_string()));
        assert_eq!(manager.total_size, 0);
    }

    #[test]
    fn test_pin_with_ttl() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content(
            "content1".to_string(),
            1000,
            PinPriority::Normal,
            Some(Duration::from_millis(50)),
        );

        std::thread::sleep(Duration::from_millis(100));

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert!(pinned.is_expired());
    }

    #[test]
    fn test_cleanup_expired() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content(
            "content1".to_string(),
            1000,
            PinPriority::Normal,
            Some(Duration::from_millis(50)),
        );
        manager.pin_content("content2".to_string(), 1000, PinPriority::Normal, None);

        std::thread::sleep(Duration::from_millis(100));

        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert!(!manager.is_pinned(&"content1".to_string()));
        assert!(manager.is_pinned(&"content2".to_string()));
    }

    #[test]
    fn test_record_access() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);

        manager.record_access(&"content1".to_string());
        manager.record_access(&"content1".to_string());

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert_eq!(pinned.access_count, 2);
    }

    #[test]
    fn test_add_replica() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);

        assert!(manager.add_replica(&"content1".to_string(), "peer1".to_string()));
        assert!(manager.add_replica(&"content1".to_string(), "peer2".to_string()));

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert_eq!(pinned.replicas.len(), 2);
    }

    #[test]
    fn test_remove_replica() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);
        manager.add_replica(&"content1".to_string(), "peer1".to_string());

        assert!(manager.remove_replica(&"content1".to_string(), &"peer1".to_string()));

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert_eq!(pinned.replicas.len(), 0);
    }

    #[test]
    fn test_replication_health() {
        let config = PinningConfig {
            min_replicas: 3,
            ..Default::default()
        };
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert!(!pinned.is_healthy());

        manager.add_replica(&"content1".to_string(), "peer1".to_string());
        manager.add_replica(&"content1".to_string(), "peer2".to_string());
        manager.add_replica(&"content1".to_string(), "peer3".to_string());

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert!(pinned.is_healthy());
    }

    #[test]
    fn test_get_underreplicated() {
        let config = PinningConfig {
            min_replicas: 2,
            ..Default::default()
        };
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);
        manager.pin_content("content2".to_string(), 1000, PinPriority::Normal, None);

        manager.add_replica(&"content2".to_string(), "peer1".to_string());
        manager.add_replica(&"content2".to_string(), "peer2".to_string());

        let under = manager.get_underreplicated();
        assert_eq!(under.len(), 1);
        assert_eq!(under[0].content_id, "content1");
    }

    #[test]
    fn test_auto_unpin() {
        let config = PinningConfig {
            max_total_size: 5000,
            auto_unpin_threshold: 0.8,
            ..Default::default()
        };
        let mut manager = PinningManager::new(config);

        // Fill to threshold
        manager.pin_content("content1".to_string(), 2000, PinPriority::Low, None);
        manager.pin_content("content2".to_string(), 2000, PinPriority::Normal, None);

        // This should trigger auto-unpin of content1
        assert!(manager.pin_content("content3".to_string(), 2000, PinPriority::High, None));

        assert!(!manager.is_pinned(&"content1".to_string()));
        assert!(manager.is_pinned(&"content3".to_string()));
    }

    #[test]
    fn test_priority_ordering() {
        assert!(PinPriority::Critical > PinPriority::High);
        assert!(PinPriority::High > PinPriority::Normal);
        assert!(PinPriority::Normal > PinPriority::Low);
        assert!(PinPriority::Low > PinPriority::Background);
    }

    #[test]
    fn test_get_by_priority() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Critical, None);
        manager.pin_content("content2".to_string(), 1000, PinPriority::Normal, None);
        manager.pin_content("content3".to_string(), 1000, PinPriority::Critical, None);

        let critical = manager.get_by_priority(PinPriority::Critical);
        assert_eq!(critical.len(), 2);
    }

    #[test]
    fn test_stats() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);
        manager.pin_content("content2".to_string(), 2000, PinPriority::Normal, None);

        let stats = manager.stats();
        assert_eq!(stats.total_pinned, 2);
        assert_eq!(stats.total_size, 3000);
        assert_eq!(stats.total_pins_created, 2);
    }

    #[test]
    fn test_critical_never_auto_unpinned() {
        let config = PinningConfig {
            max_total_size: 5000,
            auto_unpin_threshold: 0.8,
            ..Default::default()
        };
        let mut manager = PinningManager::new(config);

        manager.pin_content("critical".to_string(), 2000, PinPriority::Critical, None);
        manager.pin_content("normal".to_string(), 2000, PinPriority::Normal, None);

        // Try to pin high priority content
        let result = manager.pin_content("high".to_string(), 2000, PinPriority::High, None);

        // Critical should remain pinned
        assert!(manager.is_pinned(&"critical".to_string()));
        // Normal might be unpinned
        assert!(!manager.is_pinned(&"normal".to_string()) || !result);
    }

    #[test]
    fn test_replication_ratio() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content("content1".to_string(), 1000, PinPriority::Normal, None);

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert_eq!(pinned.replication_ratio(), 0.0);

        manager.add_replica(&"content1".to_string(), "peer1".to_string());

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        assert!((pinned.replication_ratio() - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_remaining_time() {
        let config = PinningConfig::default();
        let mut manager = PinningManager::new(config);

        manager.pin_content(
            "content1".to_string(),
            1000,
            PinPriority::Normal,
            Some(Duration::from_secs(10)),
        );

        let pinned = manager.get_pinned(&"content1".to_string()).unwrap();
        let remaining = pinned.remaining_time().unwrap();
        assert!(remaining <= Duration::from_secs(10));
    }
}
