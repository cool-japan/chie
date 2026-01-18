//! Unified peer scoring system.
//!
//! This module aggregates multiple scoring metrics (reputation, bandwidth, latency, reliability)
//! into a single unified score for peer selection and ranking.
//!
//! # Example
//! ```
//! use chie_p2p::peer_scoring::{PeerScorer, ScorerConfig, ScoreWeights};
//! use std::time::Duration;
//!
//! let config = ScorerConfig {
//!     weights: ScoreWeights {
//!         reputation: 0.3,
//!         bandwidth: 0.25,
//!         latency: 0.25,
//!         reliability: 0.2,
//!     },
//!     min_interactions: 5,
//!     decay_factor: 0.95,
//! };
//!
//! let mut scorer = PeerScorer::new(config);
//!
//! // Record peer metrics
//! scorer.record_bandwidth("peer1".to_string(), 1_000_000); // 1 Mbps
//! scorer.record_latency("peer1".to_string(), Duration::from_millis(50));
//! scorer.record_success("peer1".to_string());
//!
//! // Get unified score
//! let score = scorer.get_score(&"peer1".to_string());
//! println!("Peer score: {}", score);
//! ```

use std::collections::HashMap;
use std::time::Duration;

/// Peer identifier
pub type PeerId = String;

/// Score weights for different metrics
#[derive(Debug, Clone, Copy)]
pub struct ScoreWeights {
    /// Weight for reputation (0.0-1.0)
    pub reputation: f64,
    /// Weight for bandwidth (0.0-1.0)
    pub bandwidth: f64,
    /// Weight for latency (0.0-1.0)
    pub latency: f64,
    /// Weight for reliability (0.0-1.0)
    pub reliability: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            reputation: 0.3,
            bandwidth: 0.25,
            latency: 0.25,
            reliability: 0.2,
        }
    }
}

impl ScoreWeights {
    /// Normalize weights to sum to 1.0
    pub fn normalize(&self) -> Self {
        let sum = self.reputation + self.bandwidth + self.latency + self.reliability;
        if sum == 0.0 {
            return Self::default();
        }

        Self {
            reputation: self.reputation / sum,
            bandwidth: self.bandwidth / sum,
            latency: self.latency / sum,
            reliability: self.reliability / sum,
        }
    }

    /// Validate that weights are in valid range
    pub fn is_valid(&self) -> bool {
        self.reputation >= 0.0
            && self.bandwidth >= 0.0
            && self.latency >= 0.0
            && self.reliability >= 0.0
    }
}

/// Peer metrics
#[derive(Debug, Clone)]
pub struct PeerMetrics {
    /// Peer ID
    pub peer_id: PeerId,
    /// Reputation score (0.0-1.0)
    pub reputation: f64,
    /// Bandwidth score (normalized, 0.0-1.0)
    pub bandwidth_score: f64,
    /// Latency score (normalized, 0.0-1.0, lower latency = higher score)
    pub latency_score: f64,
    /// Reliability score (0.0-1.0)
    pub reliability: f64,
    /// Unified score
    pub unified_score: f64,
    /// Total interactions
    pub total_interactions: u64,
    /// Successful interactions
    pub successful_interactions: u64,
    /// Failed interactions
    pub failed_interactions: u64,
    /// Average bandwidth (bytes/sec)
    pub avg_bandwidth: u64,
    /// Average latency
    pub avg_latency: Duration,
    /// Bandwidth samples
    bandwidth_samples: Vec<u64>,
    /// Latency samples
    latency_samples: Vec<Duration>,
}

impl PeerMetrics {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            reputation: 0.5, // Start neutral
            bandwidth_score: 0.0,
            latency_score: 0.0,
            reliability: 0.5, // Start neutral
            unified_score: 0.0,
            total_interactions: 0,
            successful_interactions: 0,
            failed_interactions: 0,
            avg_bandwidth: 0,
            avg_latency: Duration::ZERO,
            bandwidth_samples: Vec::new(),
            latency_samples: Vec::new(),
        }
    }

    /// Calculate reliability score
    fn calculate_reliability(&self) -> f64 {
        if self.total_interactions == 0 {
            return 0.5; // Neutral for new peers
        }

        self.successful_interactions as f64 / self.total_interactions as f64
    }

    /// Calculate bandwidth score (normalized)
    fn calculate_bandwidth_score(&self, max_bandwidth: u64) -> f64 {
        if max_bandwidth == 0 {
            return 0.0;
        }

        (self.avg_bandwidth as f64 / max_bandwidth as f64).min(1.0)
    }

    /// Calculate latency score (lower is better)
    fn calculate_latency_score(&self, max_latency: Duration) -> f64 {
        if max_latency.is_zero() {
            return 1.0;
        }

        let latency_ratio = self.avg_latency.as_secs_f64() / max_latency.as_secs_f64();
        (1.0 - latency_ratio).max(0.0)
    }
}

/// Peer scorer configuration
#[derive(Debug, Clone)]
pub struct ScorerConfig {
    /// Score weights
    pub weights: ScoreWeights,
    /// Minimum interactions before scoring is reliable
    pub min_interactions: u64,
    /// Decay factor for old samples (0.0-1.0)
    pub decay_factor: f64,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            weights: ScoreWeights::default(),
            min_interactions: 10,
            decay_factor: 0.95,
        }
    }
}

/// Unified peer scorer
pub struct PeerScorer {
    /// Configuration
    config: ScorerConfig,
    /// Peer metrics
    metrics: HashMap<PeerId, PeerMetrics>,
    /// Maximum observed bandwidth (for normalization)
    max_bandwidth: u64,
    /// Maximum observed latency (for normalization)
    max_latency: Duration,
    /// Total peers scored
    total_peers: usize,
}

impl PeerScorer {
    /// Create a new peer scorer
    pub fn new(config: ScorerConfig) -> Self {
        let config = ScorerConfig {
            weights: config.weights.normalize(),
            ..config
        };

        Self {
            config,
            metrics: HashMap::new(),
            max_bandwidth: 10_000_000,           // 10 Mbps default
            max_latency: Duration::from_secs(1), // 1 second default
            total_peers: 0,
        }
    }

    /// Get or create peer metrics
    fn get_or_create_metrics(&mut self, peer_id: PeerId) -> &mut PeerMetrics {
        if !self.metrics.contains_key(&peer_id) {
            self.total_peers += 1;
        }

        self.metrics
            .entry(peer_id.clone())
            .or_insert_with(|| PeerMetrics::new(peer_id))
    }

    /// Record bandwidth measurement
    pub fn record_bandwidth(&mut self, peer_id: PeerId, bandwidth: u64) {
        let peer_id_copy = peer_id.clone();
        let metrics = self.get_or_create_metrics(peer_id);

        metrics.bandwidth_samples.push(bandwidth);

        // Keep only recent samples
        if metrics.bandwidth_samples.len() > 100 {
            metrics.bandwidth_samples.remove(0);
        }

        // Update average
        if !metrics.bandwidth_samples.is_empty() {
            let sum: u64 = metrics.bandwidth_samples.iter().sum();
            metrics.avg_bandwidth = sum / metrics.bandwidth_samples.len() as u64;
        }

        // Update max bandwidth
        if bandwidth > self.max_bandwidth {
            self.max_bandwidth = bandwidth;
        }

        self.update_score(&peer_id_copy);
    }

    /// Record latency measurement
    pub fn record_latency(&mut self, peer_id: PeerId, latency: Duration) {
        let peer_id_copy = peer_id.clone();
        let metrics = self.get_or_create_metrics(peer_id);

        metrics.latency_samples.push(latency);

        // Keep only recent samples
        if metrics.latency_samples.len() > 100 {
            metrics.latency_samples.remove(0);
        }

        // Update average
        if !metrics.latency_samples.is_empty() {
            let sum: Duration = metrics.latency_samples.iter().sum();
            metrics.avg_latency = sum / metrics.latency_samples.len() as u32;
        }

        // Update max latency
        if latency > self.max_latency {
            self.max_latency = latency;
        }

        self.update_score(&peer_id_copy);
    }

    /// Record successful interaction
    pub fn record_success(&mut self, peer_id: PeerId) {
        let peer_id_copy = peer_id.clone();
        let metrics = self.get_or_create_metrics(peer_id);

        metrics.total_interactions += 1;
        metrics.successful_interactions += 1;

        // Update reputation (gradually increase)
        metrics.reputation = (metrics.reputation + 0.1).min(1.0);

        self.update_score(&peer_id_copy);
    }

    /// Record failed interaction
    pub fn record_failure(&mut self, peer_id: PeerId) {
        let peer_id_copy = peer_id.clone();
        let metrics = self.get_or_create_metrics(peer_id);

        metrics.total_interactions += 1;
        metrics.failed_interactions += 1;

        // Update reputation (gradually decrease)
        metrics.reputation = (metrics.reputation - 0.15).max(0.0);

        self.update_score(&peer_id_copy);
    }

    /// Update unified score for a peer
    fn update_score(&mut self, peer_id: &PeerId) {
        if let Some(metrics) = self.metrics.get_mut(peer_id) {
            // Calculate component scores
            metrics.reliability = metrics.calculate_reliability();
            metrics.bandwidth_score = metrics.calculate_bandwidth_score(self.max_bandwidth);
            metrics.latency_score = metrics.calculate_latency_score(self.max_latency);

            // Calculate unified score
            let weights = &self.config.weights;
            metrics.unified_score = metrics.reputation * weights.reputation
                + metrics.bandwidth_score * weights.bandwidth
                + metrics.latency_score * weights.latency
                + metrics.reliability * weights.reliability;

            // Apply confidence adjustment for new peers
            if metrics.total_interactions < self.config.min_interactions {
                let confidence =
                    metrics.total_interactions as f64 / self.config.min_interactions as f64;
                metrics.unified_score *= confidence;
            }
        }
    }

    /// Get unified score for a peer
    pub fn get_score(&self, peer_id: &PeerId) -> f64 {
        self.metrics
            .get(peer_id)
            .map(|m| m.unified_score)
            .unwrap_or(0.0)
    }

    /// Get peer metrics
    pub fn get_metrics(&self, peer_id: &PeerId) -> Option<&PeerMetrics> {
        self.metrics.get(peer_id)
    }

    /// Get all metrics
    pub fn get_all_metrics(&self) -> Vec<&PeerMetrics> {
        self.metrics.values().collect()
    }

    /// Get top N peers by score
    pub fn get_top_peers(&self, n: usize) -> Vec<&PeerMetrics> {
        let mut peers: Vec<_> = self.metrics.values().collect();
        peers.sort_by(|a, b| {
            b.unified_score
                .partial_cmp(&a.unified_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        peers.into_iter().take(n).collect()
    }

    /// Get peers above threshold
    pub fn get_peers_above_threshold(&self, threshold: f64) -> Vec<&PeerMetrics> {
        self.metrics
            .values()
            .filter(|m| m.unified_score >= threshold)
            .collect()
    }

    /// Apply decay to all peer scores
    pub fn apply_decay(&mut self) {
        for metrics in self.metrics.values_mut() {
            metrics.reputation *= self.config.decay_factor;
            metrics.unified_score *= self.config.decay_factor;
        }
    }

    /// Remove peer
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        self.metrics.remove(peer_id).is_some()
    }

    /// Clear all peers
    pub fn clear(&mut self) {
        self.metrics.clear();
        self.total_peers = 0;
    }

    /// Get statistics
    pub fn stats(&self) -> ScorerStats {
        let avg_score = if !self.metrics.is_empty() {
            self.metrics.values().map(|m| m.unified_score).sum::<f64>() / self.metrics.len() as f64
        } else {
            0.0
        };

        let max_score = self
            .metrics
            .values()
            .map(|m| m.unified_score)
            .fold(0.0f64, f64::max);

        let min_score = self
            .metrics
            .values()
            .map(|m| m.unified_score)
            .fold(1.0f64, f64::min);

        ScorerStats {
            total_peers: self.metrics.len(),
            avg_score,
            max_score,
            min_score,
        }
    }
}

/// Scorer statistics
#[derive(Debug, Clone)]
pub struct ScorerStats {
    /// Total peers tracked
    pub total_peers: usize,
    /// Average unified score
    pub avg_score: f64,
    /// Maximum score
    pub max_score: f64,
    /// Minimum score
    pub min_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_weights_normalize() {
        let weights = ScoreWeights {
            reputation: 1.0,
            bandwidth: 1.0,
            latency: 1.0,
            reliability: 1.0,
        };

        let normalized = weights.normalize();
        assert!((normalized.reputation - 0.25).abs() < 0.001);
        assert!((normalized.bandwidth - 0.25).abs() < 0.001);
        assert!((normalized.latency - 0.25).abs() < 0.001);
        assert!((normalized.reliability - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_score_weights_validation() {
        let valid = ScoreWeights::default();
        assert!(valid.is_valid());

        let invalid = ScoreWeights {
            reputation: -1.0,
            ..Default::default()
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_record_success() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        scorer.record_success("peer1".to_string());

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert_eq!(metrics.total_interactions, 1);
        assert_eq!(metrics.successful_interactions, 1);
        assert!(metrics.reputation > 0.5); // Should increase from neutral
    }

    #[test]
    fn test_record_failure() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        scorer.record_failure("peer1".to_string());

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert_eq!(metrics.total_interactions, 1);
        assert_eq!(metrics.failed_interactions, 1);
        assert!(metrics.reputation < 0.5); // Should decrease from neutral
    }

    #[test]
    fn test_record_bandwidth() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        scorer.record_bandwidth("peer1".to_string(), 1_000_000);

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert_eq!(metrics.avg_bandwidth, 1_000_000);
        assert!(metrics.bandwidth_score > 0.0);
    }

    #[test]
    fn test_record_latency() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        scorer.record_latency("peer1".to_string(), Duration::from_millis(50));

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert_eq!(metrics.avg_latency, Duration::from_millis(50));
        assert!(metrics.latency_score > 0.0);
    }

    #[test]
    fn test_unified_score_calculation() {
        let config = ScorerConfig {
            min_interactions: 0, // Disable confidence adjustment
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        scorer.record_success("peer1".to_string());
        scorer.record_bandwidth("peer1".to_string(), 5_000_000);
        scorer.record_latency("peer1".to_string(), Duration::from_millis(50));

        let score = scorer.get_score(&"peer1".to_string());
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_reliability_calculation() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        for _ in 0..8 {
            scorer.record_success("peer1".to_string());
        }
        for _ in 0..2 {
            scorer.record_failure("peer1".to_string());
        }

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert_eq!(metrics.reliability, 0.8);
    }

    #[test]
    fn test_get_top_peers() {
        let config = ScorerConfig {
            min_interactions: 0,
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        // Create peers with different scores
        for _ in 0..5 {
            scorer.record_success("peer1".to_string());
        }
        for _ in 0..3 {
            scorer.record_success("peer2".to_string());
        }
        scorer.record_success("peer3".to_string());

        let top = scorer.get_top_peers(2);
        assert_eq!(top.len(), 2);
        assert!(top[0].unified_score >= top[1].unified_score);
    }

    #[test]
    fn test_get_peers_above_threshold() {
        let config = ScorerConfig {
            min_interactions: 0,
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        for _ in 0..5 {
            scorer.record_success("peer1".to_string());
        }
        scorer.record_failure("peer2".to_string());
        scorer.record_failure("peer2".to_string());

        let above = scorer.get_peers_above_threshold(0.5);
        assert!(!above.is_empty());
        for metrics in above {
            assert!(metrics.unified_score >= 0.5);
        }
    }

    #[test]
    fn test_apply_decay() {
        let config = ScorerConfig {
            min_interactions: 0,
            decay_factor: 0.9,
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        scorer.record_success("peer1".to_string());
        let score_before = scorer.get_score(&"peer1".to_string());

        scorer.apply_decay();
        let score_after = scorer.get_score(&"peer1".to_string());

        assert!(score_after < score_before);
    }

    #[test]
    fn test_remove_peer() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        scorer.record_success("peer1".to_string());
        assert!(scorer.remove_peer(&"peer1".to_string()));
        assert!(!scorer.remove_peer(&"peer1".to_string()));
        assert!(scorer.get_metrics(&"peer1".to_string()).is_none());
    }

    #[test]
    fn test_clear() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        scorer.record_success("peer1".to_string());
        scorer.record_success("peer2".to_string());

        scorer.clear();
        assert_eq!(scorer.stats().total_peers, 0);
    }

    #[test]
    fn test_stats() {
        let config = ScorerConfig {
            min_interactions: 0,
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        for _ in 0..5 {
            scorer.record_success("peer1".to_string());
        }
        for _ in 0..3 {
            scorer.record_success("peer2".to_string());
        }

        let stats = scorer.stats();
        assert_eq!(stats.total_peers, 2);
        assert!(stats.avg_score > 0.0);
        assert!(stats.max_score >= stats.min_score);
    }

    #[test]
    fn test_confidence_adjustment() {
        let config = ScorerConfig {
            min_interactions: 10,
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        // Record 5 interactions (50% of min)
        for _ in 0..5 {
            scorer.record_success("peer1".to_string());
        }

        let score_with_few = scorer.get_score(&"peer1".to_string());

        // Record 5 more interactions (100% of min)
        for _ in 0..5 {
            scorer.record_success("peer1".to_string());
        }

        let score_with_enough = scorer.get_score(&"peer1".to_string());

        // Score should be higher with more interactions
        assert!(score_with_enough > score_with_few);
    }

    #[test]
    fn test_bandwidth_samples_limit() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        // Record more than 100 samples
        for i in 0..150 {
            scorer.record_bandwidth("peer1".to_string(), (i + 1) * 1000);
        }

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert!(metrics.bandwidth_samples.len() <= 100);
    }

    #[test]
    fn test_latency_samples_limit() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        // Record more than 100 samples
        for i in 0..150 {
            scorer.record_latency("peer1".to_string(), Duration::from_millis((i + 1) * 10));
        }

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert!(metrics.latency_samples.len() <= 100);
    }

    #[test]
    fn test_multiple_peers() {
        let config = ScorerConfig {
            min_interactions: 0,
            ..Default::default()
        };
        let mut scorer = PeerScorer::new(config);

        scorer.record_success("peer1".to_string());
        scorer.record_bandwidth("peer1".to_string(), 2_000_000);

        scorer.record_success("peer2".to_string());
        scorer.record_bandwidth("peer2".to_string(), 5_000_000);

        let score1 = scorer.get_score(&"peer1".to_string());
        let score2 = scorer.get_score(&"peer2".to_string());

        // peer2 should have higher score due to higher bandwidth
        assert!(score2 > score1);
    }

    #[test]
    fn test_reputation_bounds() {
        let config = ScorerConfig::default();
        let mut scorer = PeerScorer::new(config);

        // Test upper bound
        for _ in 0..20 {
            scorer.record_success("peer1".to_string());
        }

        let metrics = scorer.get_metrics(&"peer1".to_string()).unwrap();
        assert!(metrics.reputation <= 1.0);

        // Test lower bound
        for _ in 0..20 {
            scorer.record_failure("peer2".to_string());
        }

        let metrics = scorer.get_metrics(&"peer2".to_string()).unwrap();
        assert!(metrics.reputation >= 0.0);
    }
}
