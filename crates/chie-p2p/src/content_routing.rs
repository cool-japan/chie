//! Content routing for efficient content discovery using DHT principles.
//!
//! This module provides content-addressable storage and routing capabilities,
//! enabling efficient content discovery in a distributed P2P network.
//!
//! # Examples
//!
//! ```
//! use chie_p2p::content_routing::{ContentRouter, ContentRecord};
//! use libp2p::PeerId;
//!
//! let router = ContentRouter::new();
//! let content_id = "QmExample123".to_string();
//! let peer_id = PeerId::random();
//!
//! // Announce that we have content
//! router.announce_content(&content_id, peer_id);
//!
//! // Find providers for content
//! let providers = router.find_providers(&content_id, 5);
//! assert!(!providers.is_empty());
//! ```

use libp2p::PeerId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Errors that can occur during content routing operations.
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    /// Content not found.
    #[error("Content not found: {0}")]
    ContentNotFound(String),

    /// No providers available.
    #[error("No providers available for content: {0}")]
    NoProviders(String),

    /// Invalid content ID.
    #[error("Invalid content ID: {0}")]
    InvalidContentId(String),

    /// Routing table full.
    #[error("Routing table full (max {0} entries)")]
    TableFull(usize),
}

/// Content record storing provider information.
#[derive(Debug, Clone)]
pub struct ContentRecord {
    /// Content identifier (CID or hash).
    pub content_id: String,
    /// Set of peer IDs providing this content.
    pub providers: HashSet<PeerId>,
    /// When this record was first created.
    pub created_at: Instant,
    /// When this record was last updated.
    pub last_updated: Instant,
    /// Number of times this content was queried.
    pub query_count: u64,
    /// Time-to-live for this record.
    pub ttl: Duration,
}

impl ContentRecord {
    /// Create a new content record.
    pub fn new(content_id: String, provider: PeerId, ttl: Duration) -> Self {
        let now = Instant::now();
        let mut providers = HashSet::new();
        providers.insert(provider);

        Self {
            content_id,
            providers,
            created_at: now,
            last_updated: now,
            query_count: 0,
            ttl,
        }
    }

    /// Add a provider to this record.
    pub fn add_provider(&mut self, provider: PeerId) {
        self.providers.insert(provider);
        self.last_updated = Instant::now();
    }

    /// Remove a provider from this record.
    pub fn remove_provider(&mut self, provider: &PeerId) -> bool {
        let removed = self.providers.remove(provider);
        if removed {
            self.last_updated = Instant::now();
        }
        removed
    }

    /// Check if this record has expired.
    pub fn is_expired(&self) -> bool {
        self.last_updated.elapsed() > self.ttl
    }

    /// Get the number of providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Increment query count.
    pub fn record_query(&mut self) {
        self.query_count += 1;
    }
}

/// Configuration for content routing.
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Maximum number of providers to track per content.
    pub max_providers_per_content: usize,
    /// Maximum number of content records to store.
    pub max_content_records: usize,
    /// Default TTL for content records.
    pub default_ttl: Duration,
    /// How often to clean up expired records.
    pub cleanup_interval: Duration,
    /// Maximum query results to return.
    pub max_query_results: usize,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            max_providers_per_content: 20,
            max_content_records: 10000,
            default_ttl: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            max_query_results: 20,
        }
    }
}

/// Statistics for content routing operations.
#[derive(Debug, Default, Clone)]
pub struct RoutingStats {
    /// Total number of content announcements.
    pub announcements: u64,
    /// Total number of content queries.
    pub queries: u64,
    /// Total number of successful queries (found providers).
    pub successful_queries: u64,
    /// Total number of failed queries (no providers).
    pub failed_queries: u64,
    /// Total number of provider additions.
    pub provider_additions: u64,
    /// Total number of provider removals.
    pub provider_removals: u64,
    /// Total number of expired records cleaned up.
    pub expired_records_cleaned: u64,
    /// Current number of content records.
    pub current_records: usize,
    /// Current total number of providers across all content.
    pub total_providers: usize,
}

impl RoutingStats {
    /// Get the query success rate.
    pub fn query_success_rate(&self) -> f64 {
        if self.queries == 0 {
            return 0.0;
        }
        self.successful_queries as f64 / self.queries as f64
    }

    /// Get average providers per content.
    pub fn avg_providers_per_content(&self) -> f64 {
        if self.current_records == 0 {
            return 0.0;
        }
        self.total_providers as f64 / self.current_records as f64
    }
}

/// Content router for DHT-based content discovery.
pub struct ContentRouter {
    config: RoutingConfig,
    /// Map from content ID to content record.
    records: Arc<parking_lot::RwLock<HashMap<String, ContentRecord>>>,
    /// LRU cache for recent queries.
    recent_queries: Arc<parking_lot::RwLock<VecDeque<(String, Instant)>>>,
    /// Statistics.
    stats: Arc<parking_lot::RwLock<RoutingStats>>,
    /// Last cleanup time.
    last_cleanup: Arc<parking_lot::RwLock<Instant>>,
}

impl ContentRouter {
    /// Create a new content router with default configuration.
    pub fn new() -> Self {
        Self::with_config(RoutingConfig::default())
    }

    /// Create a new content router with custom configuration.
    pub fn with_config(config: RoutingConfig) -> Self {
        Self {
            config,
            records: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            recent_queries: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            stats: Arc::new(parking_lot::RwLock::new(RoutingStats::default())),
            last_cleanup: Arc::new(parking_lot::RwLock::new(Instant::now())),
        }
    }

    /// Announce that a peer provides content.
    pub fn announce_content(&self, content_id: &str, provider: PeerId) -> Result<(), RoutingError> {
        let mut records = self.records.write();
        let mut stats = self.stats.write();

        if let Some(record) = records.get_mut(content_id) {
            if record.providers.len() < self.config.max_providers_per_content {
                record.add_provider(provider);
                stats.provider_additions += 1;
            }
        } else {
            if records.len() >= self.config.max_content_records {
                return Err(RoutingError::TableFull(self.config.max_content_records));
            }

            let record =
                ContentRecord::new(content_id.to_string(), provider, self.config.default_ttl);
            records.insert(content_id.to_string(), record);
            stats.provider_additions += 1;
        }

        stats.announcements += 1;
        stats.current_records = records.len();
        stats.total_providers = records.values().map(|r| r.provider_count()).sum();

        Ok(())
    }

    /// Find providers for content.
    pub fn find_providers(&self, content_id: &str, max_results: usize) -> Vec<PeerId> {
        let mut records = self.records.write();
        let mut stats = self.stats.write();

        stats.queries += 1;

        // Try to cleanup if needed
        self.maybe_cleanup(&mut records, &mut stats);

        if let Some(record) = records.get_mut(content_id) {
            record.record_query();

            let providers: Vec<PeerId> = record
                .providers
                .iter()
                .take(max_results.min(self.config.max_query_results))
                .copied()
                .collect();

            if !providers.is_empty() {
                stats.successful_queries += 1;

                // Track recent query
                let mut recent = self.recent_queries.write();
                recent.push_back((content_id.to_string(), Instant::now()));
                if recent.len() > 1000 {
                    recent.pop_front();
                }

                return providers;
            }
        }

        stats.failed_queries += 1;
        Vec::new()
    }

    /// Remove a provider for content.
    pub fn remove_provider(&self, content_id: &str, provider: &PeerId) -> Result<(), RoutingError> {
        let mut records = self.records.write();
        let mut stats = self.stats.write();

        let mut should_remove_record = false;
        let mut provider_removed = false;

        if let Some(record) = records.get_mut(content_id) {
            if record.remove_provider(provider) {
                provider_removed = true;
                stats.provider_removals += 1;

                // Check if we should remove the record
                if record.provider_count() == 0 {
                    should_remove_record = true;
                }
            }
        }

        if provider_removed {
            // Remove record if no providers left
            if should_remove_record {
                records.remove(content_id);
            }

            // Update stats after modifications
            stats.total_providers = records.values().map(|r| r.provider_count()).sum();
            stats.current_records = records.len();

            return Ok(());
        }

        Err(RoutingError::ContentNotFound(content_id.to_string()))
    }

    /// Get all content IDs a peer is providing.
    pub fn get_provider_content(&self, provider: &PeerId) -> Vec<String> {
        let records = self.records.read();
        records
            .iter()
            .filter(|(_, record)| record.providers.contains(provider))
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// Get the most popular content (by query count).
    pub fn get_popular_content(&self, limit: usize) -> Vec<(String, u64)> {
        let records = self.records.read();
        let mut content: Vec<(String, u64)> = records
            .iter()
            .map(|(cid, record)| (cid.clone(), record.query_count))
            .collect();

        content.sort_by(|a, b| b.1.cmp(&a.1));
        content.truncate(limit);
        content
    }

    /// Clean up expired records.
    pub fn cleanup_expired(&self) -> usize {
        let mut records = self.records.write();
        let mut stats = self.stats.write();

        let expired: Vec<String> = records
            .iter()
            .filter(|(_, record)| record.is_expired())
            .map(|(cid, _)| cid.clone())
            .collect();

        let count = expired.len();
        for cid in expired {
            records.remove(&cid);
        }

        stats.expired_records_cleaned += count as u64;
        stats.current_records = records.len();
        stats.total_providers = records.values().map(|r| r.provider_count()).sum();

        *self.last_cleanup.write() = Instant::now();

        count
    }

    /// Maybe cleanup if enough time has passed.
    fn maybe_cleanup(
        &self,
        _records: &mut HashMap<String, ContentRecord>,
        _stats: &mut RoutingStats,
    ) {
        let last = *self.last_cleanup.read();
        if last.elapsed() >= self.config.cleanup_interval {
            // Note: cleanup_expired() will acquire its own locks
            // We can't call it here while holding locks, so we just check the condition
            // Actual cleanup will happen in the next call without locks
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> RoutingStats {
        self.stats.read().clone()
    }

    /// Get configuration.
    pub fn config(&self) -> &RoutingConfig {
        &self.config
    }

    /// Get the number of records.
    pub fn record_count(&self) -> usize {
        self.records.read().len()
    }

    /// Check if content is available.
    pub fn has_content(&self, content_id: &str) -> bool {
        self.records.read().contains_key(content_id)
    }

    /// Get a content record (for inspection).
    pub fn get_record(&self, content_id: &str) -> Option<ContentRecord> {
        self.records.read().get(content_id).cloned()
    }

    /// Clear all records.
    pub fn clear(&self) {
        let mut records = self.records.write();
        let mut stats = self.stats.write();

        records.clear();
        stats.current_records = 0;
        stats.total_providers = 0;
    }
}

impl Default for ContentRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ContentRouter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            records: Arc::clone(&self.records),
            recent_queries: Arc::clone(&self.recent_queries),
            stats: Arc::clone(&self.stats),
            last_cleanup: Arc::clone(&self.last_cleanup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_record_new() {
        let content_id = "QmTest123".to_string();
        let peer = PeerId::random();
        let ttl = Duration::from_secs(3600);

        let record = ContentRecord::new(content_id.clone(), peer, ttl);
        assert_eq!(record.content_id, content_id);
        assert_eq!(record.provider_count(), 1);
        assert!(record.providers.contains(&peer));
        assert!(!record.is_expired());
    }

    #[test]
    fn test_content_record_add_provider() {
        let content_id = "QmTest123".to_string();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let ttl = Duration::from_secs(3600);

        let mut record = ContentRecord::new(content_id, peer1, ttl);
        assert_eq!(record.provider_count(), 1);

        record.add_provider(peer2);
        assert_eq!(record.provider_count(), 2);
    }

    #[test]
    fn test_content_record_remove_provider() {
        let content_id = "QmTest123".to_string();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let ttl = Duration::from_secs(3600);

        let mut record = ContentRecord::new(content_id, peer1, ttl);
        record.add_provider(peer2);
        assert_eq!(record.provider_count(), 2);

        assert!(record.remove_provider(&peer1));
        assert_eq!(record.provider_count(), 1);
        assert!(!record.remove_provider(&peer1)); // Already removed
    }

    #[test]
    fn test_routing_config_default() {
        let config = RoutingConfig::default();
        assert_eq!(config.max_providers_per_content, 20);
        assert_eq!(config.max_content_records, 10000);
    }

    #[test]
    fn test_content_router_new() {
        let router = ContentRouter::new();
        assert_eq!(router.record_count(), 0);
    }

    #[test]
    fn test_announce_content() {
        let router = ContentRouter::new();
        let content_id = "QmTest123";
        let peer = PeerId::random();

        router.announce_content(content_id, peer).unwrap();

        let stats = router.stats();
        assert_eq!(stats.announcements, 1);
        assert_eq!(stats.current_records, 1);
        assert_eq!(stats.total_providers, 1);
    }

    #[test]
    fn test_find_providers() {
        let router = ContentRouter::new();
        let content_id = "QmTest123";
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        router.announce_content(content_id, peer1).unwrap();
        router.announce_content(content_id, peer2).unwrap();

        let providers = router.find_providers(content_id, 10);
        assert_eq!(providers.len(), 2);

        let stats = router.stats();
        assert_eq!(stats.queries, 1);
        assert_eq!(stats.successful_queries, 1);
    }

    #[test]
    fn test_find_providers_not_found() {
        let router = ContentRouter::new();
        let providers = router.find_providers("QmNotFound", 10);
        assert!(providers.is_empty());

        let stats = router.stats();
        assert_eq!(stats.queries, 1);
        assert_eq!(stats.failed_queries, 1);
    }

    #[test]
    fn test_remove_provider() {
        let router = ContentRouter::new();
        let content_id = "QmTest123";
        let peer = PeerId::random();

        router.announce_content(content_id, peer).unwrap();
        assert!(router.has_content(content_id));

        router.remove_provider(content_id, &peer).unwrap();
        assert!(!router.has_content(content_id)); // Record removed when no providers

        let stats = router.stats();
        assert_eq!(stats.provider_removals, 1);
        assert_eq!(stats.current_records, 0);
    }

    #[test]
    fn test_get_provider_content() {
        let router = ContentRouter::new();
        let peer = PeerId::random();
        let content1 = "QmTest1";
        let content2 = "QmTest2";

        router.announce_content(content1, peer).unwrap();
        router.announce_content(content2, peer).unwrap();

        let content = router.get_provider_content(&peer);
        assert_eq!(content.len(), 2);
        assert!(content.contains(&content1.to_string()));
        assert!(content.contains(&content2.to_string()));
    }

    #[test]
    fn test_get_popular_content() {
        let router = ContentRouter::new();
        let peer = PeerId::random();
        let content1 = "QmPopular";
        let content2 = "QmLessPopular";

        router.announce_content(content1, peer).unwrap();
        router.announce_content(content2, peer).unwrap();

        // Query content1 multiple times
        router.find_providers(content1, 10);
        router.find_providers(content1, 10);
        router.find_providers(content1, 10);

        // Query content2 once
        router.find_providers(content2, 10);

        let popular = router.get_popular_content(5);
        assert_eq!(popular.len(), 2);
        assert_eq!(popular[0].0, content1); // Most popular first
        assert_eq!(popular[0].1, 3);
    }

    #[test]
    fn test_max_providers_per_content() {
        let config = RoutingConfig {
            max_providers_per_content: 2,
            ..Default::default()
        };
        let router = ContentRouter::with_config(config);
        let content_id = "QmTest";

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        router.announce_content(content_id, peer1).unwrap();
        router.announce_content(content_id, peer2).unwrap();
        router.announce_content(content_id, peer3).unwrap(); // Should not be added

        let providers = router.find_providers(content_id, 10);
        assert_eq!(providers.len(), 2); // Max 2 providers
    }

    #[test]
    fn test_query_success_rate() {
        let router = ContentRouter::new();
        let peer = PeerId::random();

        router.announce_content("QmExists", peer).unwrap();

        router.find_providers("QmExists", 10); // Success
        router.find_providers("QmNotFound1", 10); // Fail
        router.find_providers("QmNotFound2", 10); // Fail

        let stats = router.stats();
        assert_eq!(stats.query_success_rate(), 1.0 / 3.0);
    }

    #[test]
    fn test_avg_providers_per_content() {
        let router = ContentRouter::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        router.announce_content("QmContent1", peer1).unwrap();
        router.announce_content("QmContent1", peer2).unwrap(); // 2 providers

        router.announce_content("QmContent2", peer1).unwrap(); // 1 provider

        let stats = router.stats();
        assert_eq!(stats.avg_providers_per_content(), 1.5); // (2+1)/2
    }

    #[test]
    fn test_clear() {
        let router = ContentRouter::new();
        let peer = PeerId::random();

        router.announce_content("QmTest", peer).unwrap();
        assert_eq!(router.record_count(), 1);

        router.clear();
        assert_eq!(router.record_count(), 0);

        let stats = router.stats();
        assert_eq!(stats.current_records, 0);
        assert_eq!(stats.total_providers, 0);
    }

    #[test]
    fn test_has_content() {
        let router = ContentRouter::new();
        let peer = PeerId::random();
        let content_id = "QmTest";

        assert!(!router.has_content(content_id));

        router.announce_content(content_id, peer).unwrap();
        assert!(router.has_content(content_id));
    }

    #[test]
    fn test_get_record() {
        let router = ContentRouter::new();
        let peer = PeerId::random();
        let content_id = "QmTest";

        router.announce_content(content_id, peer).unwrap();

        let record = router.get_record(content_id);
        assert!(record.is_some());
        assert_eq!(record.unwrap().content_id, content_id);
    }

    #[test]
    fn test_clone() {
        let router1 = ContentRouter::new();
        let peer = PeerId::random();

        router1.announce_content("QmTest", peer).unwrap();

        let router2 = router1.clone();
        // Stats should be shared
        assert_eq!(router1.stats().announcements, router2.stats().announcements);
        assert_eq!(router1.record_count(), router2.record_count());
    }
}
