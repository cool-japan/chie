//! Garbage collection for unprofitable content.
//!
//! This module provides automatic cleanup of content that is no longer profitable
//! to host, based on the pinning optimizer's recommendations.

use crate::pinning::{PinRecommendation, PinningOptimizer};
use crate::storage::{ChunkStorage, StorageError};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Configuration for garbage collection.
#[derive(Debug, Clone)]
pub struct GarbageCollectionConfig {
    /// How often to run GC (default: 1 hour).
    pub gc_interval: Duration,
    /// Maximum content items to unpin per GC run.
    pub max_unpin_per_run: usize,
    /// Storage usage threshold to trigger aggressive GC (0.0-1.0).
    pub aggressive_threshold: f64,
    /// Storage target after aggressive GC (0.0-1.0).
    pub target_usage: f64,
    /// Whether to enable automatic GC.
    pub auto_gc_enabled: bool,
}

impl Default for GarbageCollectionConfig {
    fn default() -> Self {
        Self {
            gc_interval: Duration::from_secs(3600), // 1 hour
            max_unpin_per_run: 10,
            aggressive_threshold: 0.9, // Start aggressive GC at 90% full
            target_usage: 0.8,         // Target 80% usage after aggressive GC
            auto_gc_enabled: true,
        }
    }
}

/// Result of a content garbage collection run.
#[derive(Debug, Clone)]
pub struct ContentGcResult {
    /// Number of content items unpinned.
    pub unpinned_count: usize,
    /// Total bytes freed.
    pub bytes_freed: u64,
    /// Content IDs that were unpinned.
    pub unpinned_cids: Vec<String>,
    /// Whether aggressive GC was triggered.
    pub was_aggressive: bool,
    /// Errors encountered during GC.
    pub errors: Vec<String>,
}

impl ContentGcResult {
    #[must_use]
    #[inline]
    fn new() -> Self {
        Self {
            unpinned_count: 0,
            bytes_freed: 0,
            unpinned_cids: Vec::new(),
            was_aggressive: false,
            errors: Vec::new(),
        }
    }
}

/// Garbage collector for content storage.
pub struct GarbageCollector {
    config: GarbageCollectionConfig,
    storage: Arc<RwLock<ChunkStorage>>,
    optimizer: Arc<RwLock<PinningOptimizer>>,
}

impl GarbageCollector {
    /// Create a new garbage collector.
    #[must_use]
    #[inline]
    pub fn new(
        config: GarbageCollectionConfig,
        storage: Arc<RwLock<ChunkStorage>>,
        optimizer: Arc<RwLock<PinningOptimizer>>,
    ) -> Self {
        Self {
            config,
            storage,
            optimizer,
        }
    }

    /// Run garbage collection once.
    #[must_use]
    pub async fn run_gc(&self) -> ContentGcResult {
        let mut result = ContentGcResult::new();

        // Get storage stats
        let storage = self.storage.read().await;
        let stats = storage.stats();
        drop(storage);

        let usage_ratio = stats.usage_percent / 100.0;
        let is_aggressive = usage_ratio >= self.config.aggressive_threshold;
        result.was_aggressive = is_aggressive;

        if is_aggressive {
            info!(
                "Storage at {:.1}%, triggering aggressive GC (target: {:.1}%)",
                stats.usage_percent,
                self.config.target_usage * 100.0
            );
        }

        // Get recommendations from optimizer
        let optimizer = self.optimizer.read().await;
        let recommendations = optimizer.get_recommendations();
        drop(optimizer);

        // Find content to unpin
        let unpin_candidates: Vec<_> = recommendations
            .iter()
            .filter(|r| r.recommendation == PinRecommendation::Unpin)
            .collect();

        if unpin_candidates.is_empty() {
            debug!("No content marked for unpinning");
            return result;
        }

        // Calculate how many to unpin
        let target_count = if is_aggressive {
            // For aggressive GC, unpin more to reach target usage
            let target_bytes = (stats.max_bytes as f64 * self.config.target_usage) as u64;
            let excess_bytes = stats.used_bytes.saturating_sub(target_bytes);
            let avg_size = stats.used_bytes / stats.pinned_content_count.max(1) as u64;

            ((excess_bytes / avg_size.max(1)) as usize)
                .max(1)
                .min(unpin_candidates.len())
        } else {
            self.config.max_unpin_per_run.min(unpin_candidates.len())
        };

        info!(
            "GC: {} candidates, unpinning up to {}",
            unpin_candidates.len(),
            target_count
        );

        // Unpin content
        for (i, scored) in unpin_candidates.iter().take(target_count).enumerate() {
            match self.unpin_content(&scored.cid, scored.size_bytes).await {
                Ok(freed) => {
                    result.unpinned_count += 1;
                    result.bytes_freed += freed;
                    result.unpinned_cids.push(scored.cid.clone());
                    debug!(
                        "GC unpinned {} ({}/{}): {} bytes freed",
                        scored.cid,
                        i + 1,
                        target_count,
                        freed
                    );
                }
                Err(e) => {
                    warn!("GC failed to unpin {}: {}", scored.cid, e);
                    result.errors.push(format!("{}: {}", scored.cid, e));
                }
            }
        }

        info!(
            "GC completed: {} items unpinned, {} bytes freed",
            result.unpinned_count, result.bytes_freed
        );

        result
    }

    /// Unpin a single content item.
    async fn unpin_content(&self, cid: &str, expected_size: u64) -> Result<u64, StorageError> {
        // Unregister from optimizer
        {
            let mut optimizer = self.optimizer.write().await;
            optimizer.unregister_content(cid);
        }

        // Remove from storage
        {
            let mut storage = self.storage.write().await;
            storage.unpin_content(cid).await?;
        }

        Ok(expected_size)
    }

    /// Start automatic garbage collection loop.
    pub async fn start_auto_gc(self: Arc<Self>, shutdown: tokio::sync::watch::Receiver<bool>) {
        if !self.config.auto_gc_enabled {
            info!("Auto GC disabled");
            return;
        }

        let mut interval = tokio::time::interval(self.config.gc_interval);
        let mut shutdown = shutdown;

        info!(
            "Starting auto GC with interval: {:?}",
            self.config.gc_interval
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let result = self.run_gc().await;
                    if !result.errors.is_empty() {
                        warn!("GC completed with {} errors", result.errors.len());
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("GC shutdown signal received");
                        break;
                    }
                }
            }
        }
    }

    /// Get current garbage collection statistics.
    #[must_use]
    pub async fn stats(&self) -> GcStats {
        let storage = self.storage.read().await;
        let storage_stats = storage.stats();
        drop(storage);

        let optimizer = self.optimizer.read().await;
        let recommendations = optimizer.get_recommendations();
        drop(optimizer);

        let unpin_candidates = recommendations
            .iter()
            .filter(|r| r.recommendation == PinRecommendation::Unpin)
            .count();

        let bytes_reclaimable: u64 = recommendations
            .iter()
            .filter(|r| r.recommendation == PinRecommendation::Unpin)
            .map(|r| r.size_bytes)
            .sum();

        GcStats {
            storage_used_bytes: storage_stats.used_bytes,
            storage_max_bytes: storage_stats.max_bytes,
            storage_usage_percent: storage_stats.usage_percent,
            unpin_candidates,
            bytes_reclaimable,
            is_aggressive_threshold: storage_stats.usage_percent
                >= self.config.aggressive_threshold * 100.0,
        }
    }
}

/// Garbage collection statistics.
#[derive(Debug, Clone)]
pub struct GcStats {
    /// Current storage usage in bytes.
    pub storage_used_bytes: u64,
    /// Maximum storage in bytes.
    pub storage_max_bytes: u64,
    /// Storage usage percentage.
    pub storage_usage_percent: f64,
    /// Number of content items eligible for unpinning.
    pub unpin_candidates: usize,
    /// Total bytes that can be reclaimed.
    pub bytes_reclaimable: u64,
    /// Whether aggressive GC would be triggered.
    pub is_aggressive_threshold: bool,
}

/// Helper to create and run garbage collection.
#[must_use]
pub async fn run_gc_once(
    storage: Arc<RwLock<ChunkStorage>>,
    optimizer: Arc<RwLock<PinningOptimizer>>,
) -> ContentGcResult {
    let gc = GarbageCollector::new(GarbageCollectionConfig::default(), storage, optimizer);
    gc.run_gc().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pinning::PinningConfig;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_gc_config_defaults() {
        let config = GarbageCollectionConfig::default();
        assert!(config.auto_gc_enabled);
        assert_eq!(config.gc_interval, Duration::from_secs(3600));
        assert_eq!(config.aggressive_threshold, 0.9);
    }

    #[tokio::test]
    async fn test_gc_result_new() {
        let result = ContentGcResult::new();
        assert_eq!(result.unpinned_count, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.unpinned_cids.is_empty());
        assert!(!result.was_aggressive);
    }

    #[tokio::test]
    async fn test_gc_no_candidates() {
        let tmp = tempdir().unwrap();
        let storage = ChunkStorage::new(tmp.path().to_path_buf(), 1024 * 1024 * 100)
            .await
            .unwrap();
        let storage = Arc::new(RwLock::new(storage));

        let optimizer = PinningOptimizer::new(PinningConfig::default());
        let optimizer = Arc::new(RwLock::new(optimizer));

        let gc = GarbageCollector::new(GarbageCollectionConfig::default(), storage, optimizer);
        let result = gc.run_gc().await;

        assert_eq!(result.unpinned_count, 0);
        assert_eq!(result.bytes_freed, 0);
    }
}
