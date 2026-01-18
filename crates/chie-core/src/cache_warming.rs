//! Cache warming strategies for cold starts.
//!
//! This module implements intelligent cache pre-loading strategies to minimize
//! cold start latency. It analyzes access patterns and proactively loads
//! frequently accessed content into cache during system startup or idle periods.
//!
//! # Example
//!
//! ```rust
//! use chie_core::cache_warming::{CacheWarmer, WarmingStrategy, WarmingConfig};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = WarmingConfig {
//!     strategy: WarmingStrategy::FrequencyBased,
//!     max_items: 100,
//!     max_bytes: 100 * 1024 * 1024, // 100 MB
//!     access_log_path: PathBuf::from("/tmp/access.log"),
//!     warmup_on_startup: true,
//! };
//!
//! let mut warmer = CacheWarmer::new(config)?;
//!
//! // Record access patterns during runtime
//! warmer.record_access("QmContent1".to_string(), 1024).await;
//! warmer.record_access("QmContent2".to_string(), 2048).await;
//!
//! // Get warming candidates for next cold start
//! let candidates = warmer.get_warming_candidates()?;
//! for candidate in candidates {
//!     println!("Should warm: {} (score: {})", candidate.cid, candidate.score);
//! }
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Cache warming error types.
#[derive(Debug, Error)]
pub enum WarmingError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Cache warming strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WarmingStrategy {
    /// Load most frequently accessed items first.
    FrequencyBased,
    /// Load most recently accessed items first.
    RecencyBased,
    /// Balanced approach considering both frequency and recency.
    Hybrid,
    /// Load items based on predicted access patterns.
    Predictive,
}

/// Cache warming configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmingConfig {
    /// Warming strategy to use.
    pub strategy: WarmingStrategy,
    /// Maximum number of items to warm.
    pub max_items: usize,
    /// Maximum total bytes to warm.
    pub max_bytes: u64,
    /// Path to access log file.
    pub access_log_path: PathBuf,
    /// Whether to warm cache on startup.
    pub warmup_on_startup: bool,
}

impl Default for WarmingConfig {
    fn default() -> Self {
        Self {
            strategy: WarmingStrategy::Hybrid,
            max_items: 100,
            max_bytes: 100 * 1024 * 1024, // 100 MB
            access_log_path: PathBuf::from("/tmp/chie_access.log"),
            warmup_on_startup: true,
        }
    }
}

/// Access record for a content item.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessRecord {
    cid: String,
    size_bytes: u64,
    access_count: u64,
    last_access_ms: u64,
    first_access_ms: u64,
}

/// Warming candidate with priority score.
#[derive(Debug, Clone)]
pub struct WarmingCandidate {
    /// Content identifier.
    pub cid: String,
    /// Content size in bytes.
    pub size_bytes: u64,
    /// Priority score (higher = more important).
    pub score: f64,
    /// Number of accesses.
    pub access_count: u64,
    /// Last access timestamp (milliseconds).
    pub last_access_ms: u64,
}

/// Cache warmer for pre-loading content.
pub struct CacheWarmer {
    config: WarmingConfig,
    access_records: HashMap<String, AccessRecord>,
}

impl CacheWarmer {
    /// Create a new cache warmer.
    #[inline]
    pub fn new(config: WarmingConfig) -> Result<Self, WarmingError> {
        if config.max_items == 0 {
            return Err(WarmingError::InvalidConfig(
                "max_items must be > 0".to_string(),
            ));
        }
        if config.max_bytes == 0 {
            return Err(WarmingError::InvalidConfig(
                "max_bytes must be > 0".to_string(),
            ));
        }

        Ok(Self {
            config,
            access_records: HashMap::new(),
        })
    }

    /// Record an access to content.
    #[inline]
    pub async fn record_access(&mut self, cid: String, size_bytes: u64) {
        let now_ms = Self::current_timestamp_ms();

        self.access_records
            .entry(cid.clone())
            .and_modify(|record| {
                record.access_count += 1;
                record.last_access_ms = now_ms;
            })
            .or_insert_with(|| AccessRecord {
                cid,
                size_bytes,
                access_count: 1,
                last_access_ms: now_ms,
                first_access_ms: now_ms,
            });
    }

    /// Persist access records to disk.
    pub async fn persist(&self) -> Result<(), WarmingError> {
        let records: Vec<&AccessRecord> = self.access_records.values().collect();
        let json = serde_json::to_string_pretty(&records)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.config.access_log_path)
            .await?;

        file.write_all(json.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }

    /// Load access records from disk.
    pub async fn load(&mut self) -> Result<(), WarmingError> {
        if !self.config.access_log_path.exists() {
            return Ok(()); // No log file yet
        }

        let mut file = fs::File::open(&self.config.access_log_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let records: Vec<AccessRecord> = serde_json::from_str(&contents)?;

        self.access_records.clear();
        for record in records {
            self.access_records.insert(record.cid.clone(), record);
        }

        Ok(())
    }

    /// Get warming candidates based on configured strategy.
    pub fn get_warming_candidates(&self) -> Result<Vec<WarmingCandidate>, WarmingError> {
        let mut candidates: Vec<WarmingCandidate> = self
            .access_records
            .values()
            .map(|record| {
                let score = self.calculate_score(record);
                WarmingCandidate {
                    cid: record.cid.clone(),
                    size_bytes: record.size_bytes,
                    score,
                    access_count: record.access_count,
                    last_access_ms: record.last_access_ms,
                }
            })
            .collect();

        // Sort by score (descending)
        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Apply constraints
        self.apply_constraints(&mut candidates);

        Ok(candidates)
    }

    /// Calculate warming score for an access record.
    #[inline]
    fn calculate_score(&self, record: &AccessRecord) -> f64 {
        match self.config.strategy {
            WarmingStrategy::FrequencyBased => {
                // Score based purely on access count
                record.access_count as f64
            }
            WarmingStrategy::RecencyBased => {
                // Score based on recency (inverse of time since last access)
                let now = Self::current_timestamp_ms();
                let age_ms = now.saturating_sub(record.last_access_ms);
                let age_hours = age_ms as f64 / (1000.0 * 3600.0);

                // Decay function: score = 1 / (1 + age_hours)
                1.0 / (1.0 + age_hours)
            }
            WarmingStrategy::Hybrid => {
                // Combine frequency and recency
                let frequency_score = record.access_count as f64;

                let now = Self::current_timestamp_ms();
                let age_ms = now.saturating_sub(record.last_access_ms);
                let age_hours = age_ms as f64 / (1000.0 * 3600.0);
                let recency_score = 1.0 / (1.0 + age_hours);

                // Weighted combination (70% frequency, 30% recency)
                0.7 * frequency_score + 0.3 * recency_score * 100.0
            }
            WarmingStrategy::Predictive => {
                // Predict future access based on historical patterns
                let frequency = record.access_count as f64;
                let lifetime_days =
                    (record.last_access_ms - record.first_access_ms) as f64 / (1000.0 * 86400.0);

                if lifetime_days < 0.01 {
                    // Too new for prediction
                    return frequency;
                }

                // Access rate (accesses per day)
                let access_rate = frequency / lifetime_days;

                // Recent access boost
                let now = Self::current_timestamp_ms();
                let age_hours =
                    (now.saturating_sub(record.last_access_ms)) as f64 / (1000.0 * 3600.0);
                let recency_boost = if age_hours < 24.0 {
                    2.0 // Recently accessed content gets 2x boost
                } else if age_hours < 168.0 {
                    // 1 week
                    1.5
                } else {
                    1.0
                };

                access_rate * recency_boost
            }
        }
    }

    /// Apply max items and max bytes constraints to candidates.
    #[inline]
    fn apply_constraints(&self, candidates: &mut Vec<WarmingCandidate>) {
        let mut total_bytes = 0u64;
        let mut keep_count = 0usize;

        for candidate in candidates.iter() {
            if keep_count >= self.config.max_items {
                break;
            }
            if total_bytes + candidate.size_bytes > self.config.max_bytes {
                break;
            }

            total_bytes += candidate.size_bytes;
            keep_count += 1;
        }

        candidates.truncate(keep_count);
    }

    /// Get statistics about warming candidates.
    #[must_use]
    #[inline]
    pub fn warming_stats(&self) -> WarmingStats {
        let candidates = self.get_warming_candidates().unwrap_or_default();

        let total_items = candidates.len();
        let total_bytes: u64 = candidates.iter().map(|c| c.size_bytes).sum();
        let avg_score = if !candidates.is_empty() {
            candidates.iter().map(|c| c.score).sum::<f64>() / candidates.len() as f64
        } else {
            0.0
        };

        WarmingStats {
            total_items,
            total_bytes,
            avg_score,
            strategy: self.config.strategy,
        }
    }

    /// Clear all access records.
    #[inline]
    pub fn clear(&mut self) {
        self.access_records.clear();
    }

    /// Get current timestamp in milliseconds.
    #[inline]
    fn current_timestamp_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

/// Warming statistics.
#[derive(Debug, Clone)]
pub struct WarmingStats {
    /// Number of items to warm.
    pub total_items: usize,
    /// Total bytes to warm.
    pub total_bytes: u64,
    /// Average warming score.
    pub avg_score: f64,
    /// Strategy used.
    pub strategy: WarmingStrategy,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_warmer() -> CacheWarmer {
        let config = WarmingConfig {
            strategy: WarmingStrategy::FrequencyBased,
            max_items: 10,
            max_bytes: 1024 * 1024, // 1 MB
            access_log_path: PathBuf::from("/tmp/test_access.log"),
            warmup_on_startup: false,
        };
        CacheWarmer::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_record_access() {
        let mut warmer = create_test_warmer();

        warmer.record_access("QmTest1".to_string(), 1024).await;
        warmer.record_access("QmTest1".to_string(), 1024).await;
        warmer.record_access("QmTest2".to_string(), 2048).await;

        assert_eq!(warmer.access_records.len(), 2);
        assert_eq!(warmer.access_records["QmTest1"].access_count, 2);
        assert_eq!(warmer.access_records["QmTest2"].access_count, 1);
    }

    #[tokio::test]
    async fn test_frequency_based_warming() {
        let mut warmer = create_test_warmer();

        // Record different access patterns
        for _ in 0..10 {
            warmer.record_access("QmFrequent".to_string(), 100).await;
        }
        for _ in 0..3 {
            warmer.record_access("QmMedium".to_string(), 100).await;
        }
        warmer.record_access("QmRare".to_string(), 100).await;

        let candidates = warmer.get_warming_candidates().unwrap();

        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].cid, "QmFrequent");
        assert_eq!(candidates[1].cid, "QmMedium");
        assert_eq!(candidates[2].cid, "QmRare");
    }

    #[tokio::test]
    async fn test_max_items_constraint() {
        let mut warmer = create_test_warmer();

        // Add more items than max_items
        for i in 0..20 {
            warmer.record_access(format!("QmTest{}", i), 100).await;
        }

        let candidates = warmer.get_warming_candidates().unwrap();

        // Should be limited to max_items (10)
        assert_eq!(candidates.len(), 10);
    }

    #[tokio::test]
    async fn test_max_bytes_constraint() {
        let mut warmer = create_test_warmer();

        // Add items that would exceed max_bytes
        for i in 0..10 {
            warmer
                .record_access(format!("QmTest{}", i), 200 * 1024)
                .await; // 200 KB each
        }

        let candidates = warmer.get_warming_candidates().unwrap();

        let total_bytes: u64 = candidates.iter().map(|c| c.size_bytes).sum();
        assert!(total_bytes <= 1024 * 1024); // Should not exceed 1 MB
    }

    #[tokio::test]
    async fn test_persist_and_load() {
        let log_path = PathBuf::from("/tmp/test_persist_access.log");

        // Create warmer and record accesses
        let mut warmer = CacheWarmer::new(WarmingConfig {
            access_log_path: log_path.clone(),
            ..Default::default()
        })
        .unwrap();

        warmer.record_access("QmTest1".to_string(), 1024).await;
        warmer.record_access("QmTest2".to_string(), 2048).await;

        // Persist
        warmer.persist().await.unwrap();

        // Create new warmer and load
        let mut new_warmer = CacheWarmer::new(WarmingConfig {
            access_log_path: log_path.clone(),
            ..Default::default()
        })
        .unwrap();

        new_warmer.load().await.unwrap();

        assert_eq!(new_warmer.access_records.len(), 2);
        assert!(new_warmer.access_records.contains_key("QmTest1"));
        assert!(new_warmer.access_records.contains_key("QmTest2"));

        // Cleanup
        let _ = std::fs::remove_file(log_path);
    }

    #[tokio::test]
    async fn test_hybrid_strategy() {
        let config = WarmingConfig {
            strategy: WarmingStrategy::Hybrid,
            max_items: 10,
            max_bytes: 1024 * 1024,
            access_log_path: PathBuf::from("/tmp/test_hybrid.log"),
            warmup_on_startup: false,
        };

        let mut warmer = CacheWarmer::new(config).unwrap();

        // Frequent but old
        for _ in 0..100 {
            warmer.record_access("QmOldFrequent".to_string(), 100).await;
        }

        // Wait a bit (simulate time passing)
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Recent but infrequent
        for _ in 0..5 {
            warmer.record_access("QmRecentRare".to_string(), 100).await;
        }

        let candidates = warmer.get_warming_candidates().unwrap();

        // Should prioritize based on hybrid score
        assert!(!candidates.is_empty());
    }

    #[test]
    fn test_warming_stats() {
        let warmer = create_test_warmer();

        let stats = warmer.warming_stats();
        assert_eq!(stats.total_items, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[test]
    fn test_invalid_config() {
        let config = WarmingConfig {
            max_items: 0,
            ..Default::default()
        };

        assert!(CacheWarmer::new(config).is_err());
    }

    #[tokio::test]
    async fn test_clear() {
        let mut warmer = create_test_warmer();

        warmer.record_access("QmTest1".to_string(), 1024).await;
        warmer.record_access("QmTest2".to_string(), 2048).await;

        assert_eq!(warmer.access_records.len(), 2);

        warmer.clear();

        assert_eq!(warmer.access_records.len(), 0);
    }
}
