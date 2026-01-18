//! Tiered storage for CHIE nodes.
//!
//! This module provides automatic content placement across different storage tiers:
//! - Hot tier (SSD): Frequently accessed content
//! - Warm tier (HDD): Moderately accessed content
//! - Cold tier (Archive): Rarely accessed content
//!
//! Content is automatically promoted/demoted based on access patterns.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;
use tracing::{debug, info};

/// Storage tier types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum StorageTier {
    /// Fast storage (SSD) for hot content.
    Hot,
    /// Medium storage (HDD) for warm content.
    #[default]
    Warm,
    /// Archive storage for cold content.
    Cold,
}

/// Configuration for a single storage tier.
#[derive(Debug, Clone)]
pub struct TierConfig {
    /// Tier type.
    pub tier: StorageTier,
    /// Storage path for this tier.
    pub path: PathBuf,
    /// Maximum capacity (bytes).
    pub capacity: u64,
    /// Read speed (MB/s) for planning.
    pub read_speed_mbps: u32,
    /// Write speed (MB/s) for planning.
    pub write_speed_mbps: u32,
    /// Whether this tier is enabled.
    pub enabled: bool,
}

impl TierConfig {
    /// Create a new tier config.
    #[must_use]
    pub fn new(tier: StorageTier, path: impl Into<PathBuf>, capacity: u64) -> Self {
        let (read_speed, write_speed) = match tier {
            StorageTier::Hot => (500, 400),  // SSD
            StorageTier::Warm => (150, 100), // HDD
            StorageTier::Cold => (50, 30),   // Archive
        };

        Self {
            tier,
            path: path.into(),
            capacity,
            read_speed_mbps: read_speed,
            write_speed_mbps: write_speed,
            enabled: true,
        }
    }
}

/// Configuration for tiered storage.
#[derive(Debug, Clone)]
pub struct TieredStorageConfig {
    /// Hot tier configuration.
    pub hot: Option<TierConfig>,
    /// Warm tier configuration.
    pub warm: TierConfig,
    /// Cold tier configuration.
    pub cold: Option<TierConfig>,
    /// Minimum access count to promote to hot.
    pub hot_promotion_threshold: u32,
    /// Maximum inactivity to demote from hot (seconds).
    pub hot_demotion_inactive_secs: u64,
    /// Maximum inactivity to demote to cold (seconds).
    pub cold_demotion_inactive_secs: u64,
    /// How often to run tier rebalancing (seconds).
    pub rebalance_interval_secs: u64,
    /// Maximum bytes to move per rebalance cycle.
    pub max_move_per_cycle: u64,
}

impl Default for TieredStorageConfig {
    fn default() -> Self {
        Self {
            hot: None, // SSD optional
            warm: TierConfig::new(
                StorageTier::Warm,
                "/var/chie/warm",
                100 * 1024 * 1024 * 1024,
            ),
            cold: None, // Archive optional
            hot_promotion_threshold: 10,
            hot_demotion_inactive_secs: 3600,           // 1 hour
            cold_demotion_inactive_secs: 7 * 24 * 3600, // 1 week
            rebalance_interval_secs: 300,               // 5 minutes
            max_move_per_cycle: 1024 * 1024 * 1024,     // 1 GB
        }
    }
}

/// Content location in tiered storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentLocation {
    /// Content CID.
    pub cid: String,
    /// Current storage tier.
    pub tier: StorageTier,
    /// Size in bytes.
    pub size: u64,
    /// Access count.
    pub access_count: u32,
    /// Last access time (Unix timestamp).
    pub last_accessed: u64,
    /// When content was placed in current tier (Unix timestamp).
    pub tier_placed_at: u64,
}

/// Access record for content.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AccessRecord {
    timestamp: Instant,
    cid: String,
}

/// Tiered storage manager.
pub struct TieredStorageManager {
    /// Configuration.
    config: TieredStorageConfig,
    /// Content locations.
    locations: RwLock<HashMap<String, ContentLocation>>,
    /// Tier usage (tier -> used bytes).
    tier_usage: RwLock<HashMap<StorageTier, u64>>,
    /// Recent access history.
    access_history: RwLock<VecDeque<AccessRecord>>,
    /// Pending moves (source tier -> target tier -> CIDs).
    pending_moves: RwLock<Vec<PendingMove>>,
}

/// A pending content move between tiers.
#[derive(Debug, Clone)]
pub struct PendingMove {
    /// Content CID.
    pub cid: String,
    /// Source tier.
    pub from: StorageTier,
    /// Target tier.
    pub to: StorageTier,
    /// Content size.
    pub size: u64,
    /// Priority (higher = sooner).
    pub priority: u32,
}

impl TieredStorageManager {
    /// Create a new tiered storage manager.
    #[must_use]
    pub fn new(config: TieredStorageConfig) -> Self {
        let mut tier_usage = HashMap::new();
        tier_usage.insert(StorageTier::Warm, 0);
        if config.hot.is_some() {
            tier_usage.insert(StorageTier::Hot, 0);
        }
        if config.cold.is_some() {
            tier_usage.insert(StorageTier::Cold, 0);
        }

        Self {
            config,
            locations: RwLock::new(HashMap::new()),
            tier_usage: RwLock::new(tier_usage),
            access_history: RwLock::new(VecDeque::with_capacity(10000)),
            pending_moves: RwLock::new(Vec::new()),
        }
    }

    /// Register new content with initial tier placement.
    #[must_use]
    pub fn register_content(&self, cid: &str, size: u64) -> StorageTier {
        let initial_tier = self.determine_initial_tier(size);
        let now = current_timestamp();

        let location = ContentLocation {
            cid: cid.to_string(),
            tier: initial_tier,
            size,
            access_count: 0,
            last_accessed: now,
            tier_placed_at: now,
        };

        {
            let mut locations = self.locations.write().unwrap();
            locations.insert(cid.to_string(), location);
        }

        {
            let mut usage = self.tier_usage.write().unwrap();
            *usage.entry(initial_tier).or_insert(0) += size;
        }

        info!(
            "Registered content {} ({} bytes) in {:?} tier",
            cid, size, initial_tier
        );
        initial_tier
    }

    /// Record content access.
    pub fn record_access(&self, cid: &str) {
        let mut locations = self.locations.write().unwrap();
        if let Some(location) = locations.get_mut(cid) {
            location.access_count += 1;
            location.last_accessed = current_timestamp();
        }

        // Record in history
        let mut history = self.access_history.write().unwrap();
        history.push_back(AccessRecord {
            timestamp: Instant::now(),
            cid: cid.to_string(),
        });

        // Limit history size
        while history.len() > 10000 {
            history.pop_front();
        }
    }

    /// Get content location.
    #[must_use]
    #[inline]
    pub fn get_location(&self, cid: &str) -> Option<ContentLocation> {
        let locations = self.locations.read().unwrap();
        locations.get(cid).cloned()
    }

    /// Get path for content based on its tier.
    #[must_use]
    #[inline]
    pub fn get_content_path(&self, cid: &str) -> Option<PathBuf> {
        let locations = self.locations.read().unwrap();
        let location = locations.get(cid)?;

        let tier_config = match location.tier {
            StorageTier::Hot => self.config.hot.as_ref(),
            StorageTier::Warm => Some(&self.config.warm),
            StorageTier::Cold => self.config.cold.as_ref(),
        };

        tier_config.map(|c| c.path.join(cid))
    }

    /// Determine initial tier for new content.
    #[inline]
    fn determine_initial_tier(&self, size: u64) -> StorageTier {
        // Small content goes to hot tier if available
        if size < 10 * 1024 * 1024 {
            if let Some(hot) = &self.config.hot {
                if hot.enabled && self.has_space(StorageTier::Hot, size) {
                    return StorageTier::Hot;
                }
            }
        }

        // Default to warm tier
        if self.has_space(StorageTier::Warm, size) {
            return StorageTier::Warm;
        }

        // Fall back to cold tier
        if let Some(cold) = &self.config.cold {
            if cold.enabled && self.has_space(StorageTier::Cold, size) {
                return StorageTier::Cold;
            }
        }

        // Default to warm even if over capacity
        StorageTier::Warm
    }

    /// Check if tier has space for content.
    #[inline]
    fn has_space(&self, tier: StorageTier, size: u64) -> bool {
        let capacity = match tier {
            StorageTier::Hot => self.config.hot.as_ref().map(|c| c.capacity).unwrap_or(0),
            StorageTier::Warm => self.config.warm.capacity,
            StorageTier::Cold => self.config.cold.as_ref().map(|c| c.capacity).unwrap_or(0),
        };

        let usage = self.tier_usage.read().unwrap();
        let used = *usage.get(&tier).unwrap_or(&0);

        used + size <= capacity
    }

    /// Analyze content for tier changes.
    #[must_use]
    #[inline]
    pub fn analyze_tier_changes(&self) -> Vec<PendingMove> {
        let mut moves = Vec::new();
        let now = current_timestamp();
        let locations = self.locations.read().unwrap();

        for location in locations.values() {
            // Check for promotion to hot
            if location.tier != StorageTier::Hot
                && location.access_count >= self.config.hot_promotion_threshold
                && self.config.hot.is_some()
                && self.has_space(StorageTier::Hot, location.size)
            {
                moves.push(PendingMove {
                    cid: location.cid.clone(),
                    from: location.tier,
                    to: StorageTier::Hot,
                    size: location.size,
                    priority: location.access_count,
                });
                continue;
            }

            // Check for demotion from hot
            if location.tier == StorageTier::Hot {
                let inactive_secs = now.saturating_sub(location.last_accessed);
                if inactive_secs > self.config.hot_demotion_inactive_secs {
                    moves.push(PendingMove {
                        cid: location.cid.clone(),
                        from: StorageTier::Hot,
                        to: StorageTier::Warm,
                        size: location.size,
                        priority: 100 - location.access_count.min(100),
                    });
                    continue;
                }
            }

            // Check for demotion to cold
            if location.tier == StorageTier::Warm && self.config.cold.is_some() {
                let inactive_secs = now.saturating_sub(location.last_accessed);
                if inactive_secs > self.config.cold_demotion_inactive_secs
                    && self.has_space(StorageTier::Cold, location.size)
                {
                    moves.push(PendingMove {
                        cid: location.cid.clone(),
                        from: StorageTier::Warm,
                        to: StorageTier::Cold,
                        size: location.size,
                        priority: 0,
                    });
                }
            }
        }

        // Sort by priority (highest first)
        moves.sort_by(|a, b| b.priority.cmp(&a.priority));

        moves
    }

    /// Execute a tier move (call after actually moving the data).
    pub fn execute_move(&self, cid: &str, new_tier: StorageTier) {
        let mut locations = self.locations.write().unwrap();
        let mut usage = self.tier_usage.write().unwrap();

        if let Some(location) = locations.get_mut(cid) {
            let old_tier = location.tier;
            let size = location.size;

            // Update usage
            if let Some(old_usage) = usage.get_mut(&old_tier) {
                *old_usage = old_usage.saturating_sub(size);
            }
            *usage.entry(new_tier).or_insert(0) += size;

            // Update location
            location.tier = new_tier;
            location.tier_placed_at = current_timestamp();

            debug!("Moved {} from {:?} to {:?}", cid, old_tier, new_tier);
        }
    }

    /// Remove content from tracking.
    pub fn remove_content(&self, cid: &str) {
        let mut locations = self.locations.write().unwrap();
        let mut usage = self.tier_usage.write().unwrap();

        if let Some(location) = locations.remove(cid) {
            if let Some(tier_usage) = usage.get_mut(&location.tier) {
                *tier_usage = tier_usage.saturating_sub(location.size);
            }
        }
    }

    /// Get tier statistics.
    #[must_use]
    pub fn tier_stats(&self) -> TierStats {
        let usage = self.tier_usage.read().unwrap();
        let locations = self.locations.read().unwrap();

        let hot_used = *usage.get(&StorageTier::Hot).unwrap_or(&0);
        let warm_used = *usage.get(&StorageTier::Warm).unwrap_or(&0);
        let cold_used = *usage.get(&StorageTier::Cold).unwrap_or(&0);

        let hot_capacity = self.config.hot.as_ref().map(|c| c.capacity).unwrap_or(0);
        let warm_capacity = self.config.warm.capacity;
        let cold_capacity = self.config.cold.as_ref().map(|c| c.capacity).unwrap_or(0);

        let content_by_tier = locations.values().fold(HashMap::new(), |mut acc, loc| {
            *acc.entry(loc.tier).or_insert(0) += 1;
            acc
        });

        TierStats {
            hot_used,
            hot_capacity,
            hot_content_count: *content_by_tier.get(&StorageTier::Hot).unwrap_or(&0),
            warm_used,
            warm_capacity,
            warm_content_count: *content_by_tier.get(&StorageTier::Warm).unwrap_or(&0),
            cold_used,
            cold_capacity,
            cold_content_count: *content_by_tier.get(&StorageTier::Cold).unwrap_or(&0),
            total_content: locations.len(),
        }
    }

    /// Get pending moves.
    #[must_use]
    #[inline]
    pub fn get_pending_moves(&self) -> Vec<PendingMove> {
        self.pending_moves.read().unwrap().clone()
    }

    /// Get the storage path for a specific tier.
    #[must_use]
    #[inline]
    pub fn get_tier_path(&self, tier: StorageTier) -> Option<PathBuf> {
        match tier {
            StorageTier::Hot => self.config.hot.as_ref().map(|c| c.path.clone()),
            StorageTier::Warm => Some(self.config.warm.path.clone()),
            StorageTier::Cold => self.config.cold.as_ref().map(|c| c.path.clone()),
        }
    }

    /// Get the tier configuration.
    #[must_use]
    #[inline]
    pub fn get_tier_config(&self, tier: StorageTier) -> Option<&TierConfig> {
        match tier {
            StorageTier::Hot => self.config.hot.as_ref(),
            StorageTier::Warm => Some(&self.config.warm),
            StorageTier::Cold => self.config.cold.as_ref(),
        }
    }

    /// Run a rebalance cycle.
    #[must_use]
    pub fn rebalance(&self) -> RebalanceResult {
        let moves = self.analyze_tier_changes();
        let mut bytes_moved = 0u64;
        let mut moves_executed = 0;

        let mut pending = self.pending_moves.write().unwrap();
        pending.clear();

        for m in moves {
            if bytes_moved + m.size > self.config.max_move_per_cycle {
                // Queue for next cycle
                pending.push(m);
            } else {
                // Would execute move here in real implementation
                bytes_moved += m.size;
                moves_executed += 1;
            }
        }

        RebalanceResult {
            moves_executed,
            bytes_moved,
            pending_moves: pending.len(),
        }
    }
}

/// Tier statistics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TierStats {
    /// Hot tier used bytes.
    pub hot_used: u64,
    /// Hot tier capacity.
    pub hot_capacity: u64,
    /// Hot tier content count.
    pub hot_content_count: usize,
    /// Warm tier used bytes.
    pub warm_used: u64,
    /// Warm tier capacity.
    pub warm_capacity: u64,
    /// Warm tier content count.
    pub warm_content_count: usize,
    /// Cold tier used bytes.
    pub cold_used: u64,
    /// Cold tier capacity.
    pub cold_capacity: u64,
    /// Cold tier content count.
    pub cold_content_count: usize,
    /// Total content items.
    pub total_content: usize,
}

/// Result of a rebalance operation.
#[derive(Debug, Clone)]
pub struct RebalanceResult {
    /// Number of moves executed.
    pub moves_executed: usize,
    /// Total bytes moved.
    pub bytes_moved: u64,
    /// Number of pending moves for next cycle.
    pub pending_moves: usize,
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tiered_storage_default_config() {
        let config = TieredStorageConfig::default();
        assert!(config.hot.is_none());
        assert!(config.cold.is_none());
    }

    #[test]
    fn test_register_content() {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);

        let tier = manager.register_content("QmTest123", 1024 * 1024);
        assert_eq!(tier, StorageTier::Warm);

        let location = manager.get_location("QmTest123").unwrap();
        assert_eq!(location.tier, StorageTier::Warm);
        assert_eq!(location.size, 1024 * 1024);
    }

    #[test]
    fn test_record_access() {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);

        let _ = manager.register_content("QmTest123", 1024);

        for _ in 0..5 {
            manager.record_access("QmTest123");
        }

        let location = manager.get_location("QmTest123").unwrap();
        assert_eq!(location.access_count, 5);
    }

    #[test]
    fn test_tier_stats() {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);

        let _ = manager.register_content("QmTest1", 1024);
        let _ = manager.register_content("QmTest2", 2048);

        let stats = manager.tier_stats();
        assert_eq!(stats.warm_used, 3072);
        assert_eq!(stats.total_content, 2);
    }

    #[test]
    fn test_content_removal() {
        let config = TieredStorageConfig::default();
        let manager = TieredStorageManager::new(config);

        let _ = manager.register_content("QmTest123", 1024);
        assert!(manager.get_location("QmTest123").is_some());

        manager.remove_content("QmTest123");
        assert!(manager.get_location("QmTest123").is_none());
    }

    #[test]
    fn test_hot_tier_placement() {
        let config = TieredStorageConfig {
            hot: Some(TierConfig::new(
                StorageTier::Hot,
                "/tmp/hot",
                100 * 1024 * 1024,
            )),
            ..Default::default()
        };

        let manager = TieredStorageManager::new(config);

        // Small content should go to hot tier
        let tier = manager.register_content("QmSmall", 1024);
        assert_eq!(tier, StorageTier::Hot);

        // Large content should go to warm tier
        let tier = manager.register_content("QmLarge", 50 * 1024 * 1024);
        assert_eq!(tier, StorageTier::Warm);
    }
}
