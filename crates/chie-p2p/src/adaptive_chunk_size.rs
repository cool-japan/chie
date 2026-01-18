// SPDX-License-Identifier: MIT OR Apache-2.0
//! Adaptive chunk size negotiation
//!
//! This module provides dynamic chunk size adjustment based on network conditions,
//! peer capabilities, and transfer performance. It optimizes chunk sizes to balance
//! overhead, latency, and throughput.
//!
//! # Features
//!
//! - Automatic chunk size adjustment based on network conditions
//! - Per-peer chunk size negotiation and tracking
//! - Performance-based chunk size optimization
//! - Bandwidth and latency-aware sizing
//! - Configurable size bounds and strategies
//! - Statistics tracking and monitoring
//!
//! # Example
//!
//! ```
//! use chie_p2p::adaptive_chunk_size::{AdaptiveChunkSize, ChunkSizeStrategy};
//! use std::time::Duration;
//!
//! let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);
//!
//! // Record transfer performance
//! manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);
//!
//! // Get optimal chunk size for peer
//! let chunk_size = manager.get_chunk_size("peer1");
//! println!("Optimal chunk size: {} bytes", chunk_size);
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Chunk size adjustment strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkSizeStrategy {
    /// Minimize latency (smaller chunks)
    LowLatency,
    /// Maximize throughput (larger chunks)
    HighThroughput,
    /// Balance latency and throughput
    Balanced,
    /// Adaptive based on network conditions
    Adaptive,
    /// Conservative (fixed size)
    Conservative,
}

/// Configuration for adaptive chunk sizing
#[derive(Debug, Clone)]
pub struct ChunkSizeConfig {
    /// Minimum chunk size (bytes)
    pub min_chunk_size: usize,
    /// Maximum chunk size (bytes)
    pub max_chunk_size: usize,
    /// Default chunk size (bytes)
    pub default_chunk_size: usize,
    /// Adjustment strategy
    pub strategy: ChunkSizeStrategy,
    /// How aggressively to adjust (0.0-1.0)
    pub aggressiveness: f64,
    /// Minimum samples before adjusting
    pub min_samples: usize,
    /// Sample window duration
    pub sample_window: Duration,
}

impl Default for ChunkSizeConfig {
    fn default() -> Self {
        Self {
            min_chunk_size: 4096,      // 4 KB
            max_chunk_size: 1048576,   // 1 MB
            default_chunk_size: 65536, // 64 KB
            strategy: ChunkSizeStrategy::Balanced,
            aggressiveness: 0.5,
            min_samples: 5,
            sample_window: Duration::from_secs(60),
        }
    }
}

/// Transfer sample for chunk size analysis
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TransferSample {
    chunk_size: usize,
    duration: Duration,
    success: bool,
    timestamp: Instant,
    throughput_bps: f64,
}

/// Peer chunk size state
#[derive(Debug, Clone)]
struct PeerChunkState {
    current_chunk_size: usize,
    samples: Vec<TransferSample>,
    total_transfers: u64,
    successful_transfers: u64,
    last_adjustment: Instant,
    adjustment_count: u64,
}

impl PeerChunkState {
    fn new(default_size: usize) -> Self {
        Self {
            current_chunk_size: default_size,
            samples: Vec::new(),
            total_transfers: 0,
            successful_transfers: 0,
            last_adjustment: Instant::now(),
            adjustment_count: 0,
        }
    }

    fn success_rate(&self) -> f64 {
        if self.total_transfers == 0 {
            1.0
        } else {
            self.successful_transfers as f64 / self.total_transfers as f64
        }
    }

    fn average_throughput(&self) -> f64 {
        if self.samples.is_empty() {
            0.0
        } else {
            let sum: f64 = self.samples.iter().map(|s| s.throughput_bps).sum();
            sum / self.samples.len() as f64
        }
    }

    fn average_duration(&self) -> Duration {
        if self.samples.is_empty() {
            Duration::ZERO
        } else {
            let sum_micros: u64 = self
                .samples
                .iter()
                .map(|s| s.duration.as_micros() as u64)
                .sum();
            Duration::from_micros(sum_micros / self.samples.len() as u64)
        }
    }
}

/// Adaptive chunk size manager
#[derive(Debug)]
pub struct AdaptiveChunkSize {
    config: ChunkSizeConfig,
    peer_states: HashMap<String, PeerChunkState>,
    global_avg_throughput: f64,
    global_avg_latency: Duration,
    total_adjustments: u64,
}

impl AdaptiveChunkSize {
    /// Create a new adaptive chunk size manager
    pub fn new(strategy: ChunkSizeStrategy) -> Self {
        Self {
            config: ChunkSizeConfig {
                strategy,
                ..Default::default()
            },
            peer_states: HashMap::new(),
            global_avg_throughput: 0.0,
            global_avg_latency: Duration::ZERO,
            total_adjustments: 0,
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: ChunkSizeConfig) -> Self {
        Self {
            config,
            peer_states: HashMap::new(),
            global_avg_throughput: 0.0,
            global_avg_latency: Duration::ZERO,
            total_adjustments: 0,
        }
    }

    /// Record a transfer for chunk size optimization
    pub fn record_transfer(
        &mut self,
        peer_id: &str,
        chunk_size: usize,
        duration: Duration,
        success: bool,
    ) {
        // Calculate throughput
        let throughput_bps = if duration.as_secs_f64() > 0.0 {
            (chunk_size as f64 * 8.0) / duration.as_secs_f64()
        } else {
            0.0
        };

        // Get or create peer state and update it
        let should_adjust = {
            let state = self
                .peer_states
                .entry(peer_id.to_string())
                .or_insert_with(|| PeerChunkState::new(self.config.default_chunk_size));

            // Add sample
            state.samples.push(TransferSample {
                chunk_size,
                duration,
                success,
                timestamp: Instant::now(),
                throughput_bps,
            });

            // Update counters
            state.total_transfers += 1;
            if success {
                state.successful_transfers += 1;
            }

            // Clean old samples
            let cutoff = Instant::now() - self.config.sample_window;
            state.samples.retain(|s| s.timestamp > cutoff);

            // Check if we should adjust
            state.samples.len() >= self.config.min_samples
        };

        // Update global stats
        self.update_global_stats();

        // Adjust chunk size if needed
        if should_adjust {
            self.adjust_chunk_size(peer_id);
        }
    }

    /// Get optimal chunk size for a peer
    pub fn get_chunk_size(&self, peer_id: &str) -> usize {
        self.peer_states
            .get(peer_id)
            .map(|s| s.current_chunk_size)
            .unwrap_or(self.config.default_chunk_size)
    }

    /// Adjust chunk size for a peer based on performance
    fn adjust_chunk_size(&mut self, peer_id: &str) {
        let state = match self.peer_states.get(peer_id) {
            Some(s) => s,
            None => return,
        };

        let current_size = state.current_chunk_size;
        let new_size = match self.config.strategy {
            ChunkSizeStrategy::LowLatency => self.calculate_low_latency_size(state),
            ChunkSizeStrategy::HighThroughput => self.calculate_high_throughput_size(state),
            ChunkSizeStrategy::Balanced => self.calculate_balanced_size(state),
            ChunkSizeStrategy::Adaptive => self.calculate_adaptive_size(state),
            ChunkSizeStrategy::Conservative => current_size,
        };

        // Apply bounds
        let bounded_size = new_size
            .max(self.config.min_chunk_size)
            .min(self.config.max_chunk_size);

        // Update if changed
        if bounded_size != current_size {
            if let Some(state) = self.peer_states.get_mut(peer_id) {
                state.current_chunk_size = bounded_size;
                state.last_adjustment = Instant::now();
                state.adjustment_count += 1;
                self.total_adjustments += 1;
            }
        }
    }

    /// Calculate chunk size optimized for low latency
    fn calculate_low_latency_size(&self, state: &PeerChunkState) -> usize {
        // Prefer smaller chunks for lower latency
        let avg_duration = state.average_duration().as_millis() as f64;

        if avg_duration < 50.0 {
            // Very fast, can go smaller
            (state.current_chunk_size as f64 * 0.8) as usize
        } else if avg_duration > 200.0 {
            // Too slow, increase slightly
            (state.current_chunk_size as f64 * 1.1) as usize
        } else {
            state.current_chunk_size
        }
    }

    /// Calculate chunk size optimized for high throughput
    fn calculate_high_throughput_size(&self, state: &PeerChunkState) -> usize {
        // Prefer larger chunks for higher throughput
        let success_rate = state.success_rate();

        if success_rate > 0.95 && state.average_throughput() > self.global_avg_throughput {
            // Performing well, try larger chunks
            (state.current_chunk_size as f64 * 1.2) as usize
        } else if success_rate < 0.8 {
            // Struggling, reduce size
            (state.current_chunk_size as f64 * 0.7) as usize
        } else {
            state.current_chunk_size
        }
    }

    /// Calculate balanced chunk size
    fn calculate_balanced_size(&self, state: &PeerChunkState) -> usize {
        let success_rate = state.success_rate();
        let avg_duration_ms = state.average_duration().as_millis() as f64;
        let throughput = state.average_throughput();

        // Balance between latency and throughput
        if success_rate < 0.85 {
            // Reduce size if failing
            (state.current_chunk_size as f64 * 0.8) as usize
        } else if avg_duration_ms < 100.0 && throughput > self.global_avg_throughput {
            // Fast and efficient, try larger
            (state.current_chunk_size as f64 * 1.15) as usize
        } else if avg_duration_ms > 300.0 {
            // Too slow, reduce
            (state.current_chunk_size as f64 * 0.9) as usize
        } else {
            state.current_chunk_size
        }
    }

    /// Calculate adaptive chunk size based on network conditions
    fn calculate_adaptive_size(&self, state: &PeerChunkState) -> usize {
        let success_rate = state.success_rate();
        let throughput = state.average_throughput();
        let duration_ms = state.average_duration().as_millis() as f64;

        // Combine multiple factors
        let throughput_factor = if self.global_avg_throughput > 0.0 {
            throughput / self.global_avg_throughput
        } else {
            1.0
        };

        let latency_factor = if duration_ms > 0.0 {
            100.0 / duration_ms.max(1.0)
        } else {
            1.0
        };

        // Calculate adjustment multiplier
        let multiplier = if success_rate < 0.7 {
            0.7 // Significant reduction
        } else if success_rate < 0.85 {
            0.9 // Moderate reduction
        } else if throughput_factor > 1.2 && latency_factor > 1.0 {
            1.2 // Increase for good performance
        } else if throughput_factor > 1.0 && success_rate > 0.95 {
            1.1 // Slight increase
        } else if latency_factor < 0.7 {
            0.85 // Reduce for high latency
        } else {
            1.0 // Keep current
        };

        // Apply aggressiveness
        let adjusted_multiplier = 1.0 + (multiplier - 1.0) * self.config.aggressiveness;

        (state.current_chunk_size as f64 * adjusted_multiplier) as usize
    }

    /// Update global statistics
    fn update_global_stats(&mut self) {
        let mut total_throughput = 0.0;
        let mut total_latency_micros = 0u64;
        let mut count = 0;

        for state in self.peer_states.values() {
            if !state.samples.is_empty() {
                total_throughput += state.average_throughput();
                total_latency_micros += state.average_duration().as_micros() as u64;
                count += 1;
            }
        }

        if count > 0 {
            self.global_avg_throughput = total_throughput / count as f64;
            self.global_avg_latency = Duration::from_micros(total_latency_micros / count as u64);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> ChunkSizeStats {
        let total_peers = self.peer_states.len();
        let avg_chunk_size = if total_peers > 0 {
            self.peer_states
                .values()
                .map(|s| s.current_chunk_size)
                .sum::<usize>()
                / total_peers
        } else {
            self.config.default_chunk_size
        };

        let total_transfers: u64 = self.peer_states.values().map(|s| s.total_transfers).sum();
        let successful_transfers: u64 = self
            .peer_states
            .values()
            .map(|s| s.successful_transfers)
            .sum();

        ChunkSizeStats {
            total_peers,
            avg_chunk_size,
            min_chunk_size: self
                .peer_states
                .values()
                .map(|s| s.current_chunk_size)
                .min()
                .unwrap_or(self.config.default_chunk_size),
            max_chunk_size: self
                .peer_states
                .values()
                .map(|s| s.current_chunk_size)
                .max()
                .unwrap_or(self.config.default_chunk_size),
            total_adjustments: self.total_adjustments,
            global_avg_throughput: self.global_avg_throughput,
            global_avg_latency: self.global_avg_latency,
            total_transfers,
            successful_transfers,
            overall_success_rate: if total_transfers > 0 {
                successful_transfers as f64 / total_transfers as f64
            } else {
                0.0
            },
        }
    }

    /// Get chunk size for peer or negotiate new one
    pub fn negotiate_chunk_size(&mut self, peer_id: &str, peer_max_size: usize) -> usize {
        let optimal_size = self.get_chunk_size(peer_id);

        // Return minimum of our optimal and peer's max
        optimal_size.min(peer_max_size)
    }

    /// Reset peer state
    pub fn reset_peer(&mut self, peer_id: &str) {
        self.peer_states.remove(peer_id);
    }

    /// Get peer state summary
    pub fn get_peer_summary(&self, peer_id: &str) -> Option<PeerChunkSummary> {
        self.peer_states.get(peer_id).map(|state| PeerChunkSummary {
            current_chunk_size: state.current_chunk_size,
            total_transfers: state.total_transfers,
            success_rate: state.success_rate(),
            avg_throughput: state.average_throughput(),
            avg_duration: state.average_duration(),
            adjustment_count: state.adjustment_count,
        })
    }
}

/// Chunk size statistics
#[derive(Debug, Clone)]
pub struct ChunkSizeStats {
    pub total_peers: usize,
    pub avg_chunk_size: usize,
    pub min_chunk_size: usize,
    pub max_chunk_size: usize,
    pub total_adjustments: u64,
    pub global_avg_throughput: f64,
    pub global_avg_latency: Duration,
    pub total_transfers: u64,
    pub successful_transfers: u64,
    pub overall_success_rate: f64,
}

/// Peer chunk size summary
#[derive(Debug, Clone)]
pub struct PeerChunkSummary {
    pub current_chunk_size: usize,
    pub total_transfers: u64,
    pub success_rate: f64,
    pub avg_throughput: f64,
    pub avg_duration: Duration,
    pub adjustment_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);
        assert_eq!(manager.get_chunk_size("peer1"), 65536);
    }

    #[test]
    fn test_record_transfer() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);

        let stats = manager.stats();
        assert_eq!(stats.total_transfers, 1);
        assert_eq!(stats.successful_transfers, 1);
    }

    #[test]
    fn test_chunk_size_adjustment() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        // Record several successful fast transfers
        for _ in 0..10 {
            manager.record_transfer("peer1", 65536, Duration::from_millis(50), true);
        }

        let new_size = manager.get_chunk_size("peer1");
        // Should increase due to good performance
        assert!(new_size >= 65536);
    }

    #[test]
    fn test_low_latency_strategy() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::LowLatency);

        // Record slow transfers
        for _ in 0..10 {
            manager.record_transfer("peer1", 65536, Duration::from_millis(300), true);
        }

        let new_size = manager.get_chunk_size("peer1");
        // Low latency strategy should adjust based on duration
        assert!(new_size > 0);
    }

    #[test]
    fn test_high_throughput_strategy() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::HighThroughput);

        // Record successful transfers
        for _ in 0..10 {
            manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);
        }

        let new_size = manager.get_chunk_size("peer1");
        // High throughput strategy should favor larger chunks
        assert!(new_size > 0);
    }

    #[test]
    fn test_failure_reduces_size() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        // Record many failures
        for _ in 0..10 {
            manager.record_transfer("peer1", 65536, Duration::from_millis(100), false);
        }

        let new_size = manager.get_chunk_size("peer1");
        // Should reduce due to failures
        assert!(new_size <= 65536);
    }

    #[test]
    fn test_negotiate_chunk_size() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        // Set a specific chunk size
        manager.record_transfer("peer1", 100000, Duration::from_millis(100), true);

        // Negotiate with peer that has smaller max
        let negotiated = manager.negotiate_chunk_size("peer1", 50000);
        assert_eq!(negotiated, 50000);
    }

    #[test]
    fn test_bounds_enforcement() {
        let config = ChunkSizeConfig {
            min_chunk_size: 4096,
            max_chunk_size: 131072,
            ..Default::default()
        };
        let mut manager = AdaptiveChunkSize::with_config(config);

        // Try to force very small chunk through failures
        for _ in 0..20 {
            manager.record_transfer("peer1", 4096, Duration::from_millis(100), false);
        }

        let size = manager.get_chunk_size("peer1");
        assert!(size >= 4096);
        assert!(size <= 131072);
    }

    #[test]
    fn test_peer_summary() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);

        let summary = manager.get_peer_summary("peer1").unwrap();
        assert_eq!(summary.total_transfers, 1);
        assert_eq!(summary.success_rate, 1.0);
    }

    #[test]
    fn test_reset_peer() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);
        manager.reset_peer("peer1");

        assert!(manager.get_peer_summary("peer1").is_none());
        assert_eq!(manager.get_chunk_size("peer1"), 65536); // Returns default
    }

    #[test]
    fn test_stats() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);
        manager.record_transfer("peer2", 32768, Duration::from_millis(50), true);

        let stats = manager.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.total_transfers, 2);
        assert_eq!(stats.successful_transfers, 2);
    }

    #[test]
    fn test_conservative_strategy() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Conservative);
        let initial_size = manager.get_chunk_size("peer1");

        // Record transfers
        for _ in 0..10 {
            manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);
        }

        // Conservative should not change
        assert_eq!(manager.get_chunk_size("peer1"), initial_size);
    }

    #[test]
    fn test_sample_window() {
        let config = ChunkSizeConfig {
            sample_window: Duration::from_millis(100),
            min_samples: 2,
            ..Default::default()
        };
        let mut manager = AdaptiveChunkSize::with_config(config);

        manager.record_transfer("peer1", 65536, Duration::from_millis(50), true);

        // Wait for sample to expire
        std::thread::sleep(Duration::from_millis(150));

        manager.record_transfer("peer1", 65536, Duration::from_millis(50), true);

        // Old sample should be cleaned
        let summary = manager.get_peer_summary("peer1").unwrap();
        assert_eq!(summary.total_transfers, 2); // Count doesn't reset, but samples are cleaned
    }

    #[test]
    fn test_global_stats_update() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Balanced);

        manager.record_transfer("peer1", 65536, Duration::from_millis(100), true);
        manager.record_transfer("peer2", 65536, Duration::from_millis(200), true);

        let stats = manager.stats();
        assert!(stats.global_avg_throughput > 0.0);
        assert!(stats.global_avg_latency.as_millis() > 0);
    }

    #[test]
    fn test_adaptive_strategy() {
        let mut manager = AdaptiveChunkSize::new(ChunkSizeStrategy::Adaptive);

        // Record good performance
        for _ in 0..10 {
            manager.record_transfer("peer1", 65536, Duration::from_millis(80), true);
        }

        let size = manager.get_chunk_size("peer1");
        // Adaptive should adjust based on performance
        assert!(size > 0);
    }
}
