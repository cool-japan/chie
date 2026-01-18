//! Intelligent peer selection strategies for optimal P2P performance.
//!
//! This module provides:
//! - Multiple selection strategies (latency, bandwidth, reputation, random)
//! - Composite scoring with weighted criteria
//! - Geographic proximity awareness
//! - Load-aware selection
//! - Blacklist/whitelist integration

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Peer selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionStrategy {
    /// Select peer with lowest latency
    LowestLatency,
    /// Select peer with highest bandwidth
    HighestBandwidth,
    /// Select peer with highest reputation
    HighestReputation,
    /// Random selection
    Random,
    /// Composite score (weighted combination)
    #[default]
    Composite,
    /// Round-robin selection
    RoundRobin,
    /// Least loaded peer
    LeastLoaded,
}

/// Peer quality metrics
#[derive(Debug, Clone)]
pub struct PeerQuality {
    /// Peer ID
    pub peer_id: PeerId,
    /// Average latency in milliseconds
    pub latency_ms: f64,
    /// Average bandwidth in bytes/sec
    pub bandwidth_bps: f64,
    /// Reputation score (0.0 - 1.0)
    pub reputation: f64,
    /// Current load (0.0 - 1.0, where 1.0 is fully loaded)
    pub load: f64,
    /// Number of successful transfers
    pub success_count: u64,
    /// Number of failed transfers
    pub failure_count: u64,
    /// Geographic distance estimate (arbitrary units)
    pub geo_distance: f64,
}

impl PeerQuality {
    /// Create new peer quality metrics
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            latency_ms: 0.0,
            bandwidth_bps: 0.0,
            reputation: 0.5,
            load: 0.0,
            success_count: 0,
            failure_count: 0,
            geo_distance: 0.0,
        }
    }

    /// Calculate success rate
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            return 0.5; // Neutral for new peers
        }
        self.success_count as f64 / total as f64
    }

    /// Calculate composite score with weights
    pub fn composite_score(&self, weights: &SelectionWeights) -> f64 {
        let latency_score = if self.latency_ms > 0.0 {
            // Lower latency is better, normalize to 0-1
            (1.0 / (1.0 + self.latency_ms / 100.0)).min(1.0)
        } else {
            0.5
        };

        let bandwidth_score = if self.bandwidth_bps > 0.0 {
            // Higher bandwidth is better, normalize to 0-1
            (self.bandwidth_bps / 1_000_000.0).min(1.0)
        } else {
            0.5
        };

        let load_score = 1.0 - self.load; // Lower load is better
        let geo_score = if self.geo_distance > 0.0 {
            (1.0 / (1.0 + self.geo_distance / 1000.0)).min(1.0)
        } else {
            0.5
        };

        // Weighted average
        latency_score * weights.latency_weight
            + bandwidth_score * weights.bandwidth_weight
            + self.reputation * weights.reputation_weight
            + load_score * weights.load_weight
            + self.success_rate() * weights.success_rate_weight
            + geo_score * weights.geo_weight
    }
}

/// Weights for composite scoring
#[derive(Debug, Clone)]
pub struct SelectionWeights {
    pub latency_weight: f64,
    pub bandwidth_weight: f64,
    pub reputation_weight: f64,
    pub load_weight: f64,
    pub success_rate_weight: f64,
    pub geo_weight: f64,
}

impl Default for SelectionWeights {
    fn default() -> Self {
        Self {
            latency_weight: 0.25,
            bandwidth_weight: 0.20,
            reputation_weight: 0.20,
            load_weight: 0.15,
            success_rate_weight: 0.15,
            geo_weight: 0.05,
        }
    }
}

impl SelectionWeights {
    /// Create weights optimized for low-latency applications
    pub fn low_latency() -> Self {
        Self {
            latency_weight: 0.50,
            bandwidth_weight: 0.15,
            reputation_weight: 0.15,
            load_weight: 0.10,
            success_rate_weight: 0.05,
            geo_weight: 0.05,
        }
    }

    /// Create weights optimized for high-bandwidth transfers
    pub fn high_bandwidth() -> Self {
        Self {
            latency_weight: 0.10,
            bandwidth_weight: 0.50,
            reputation_weight: 0.15,
            load_weight: 0.15,
            success_rate_weight: 0.05,
            geo_weight: 0.05,
        }
    }

    /// Create weights optimized for reliability
    pub fn high_reliability() -> Self {
        Self {
            latency_weight: 0.10,
            bandwidth_weight: 0.10,
            reputation_weight: 0.40,
            load_weight: 0.10,
            success_rate_weight: 0.25,
            geo_weight: 0.05,
        }
    }
}

/// Peer selector for intelligent peer selection
#[derive(Clone)]
pub struct PeerSelector {
    inner: Arc<RwLock<PeerSelectorInner>>,
}

struct PeerSelectorInner {
    /// Peer quality metrics
    peers: HashMap<PeerId, PeerQuality>,
    /// Selection strategy
    strategy: SelectionStrategy,
    /// Composite scoring weights
    weights: SelectionWeights,
    /// Round-robin counter
    round_robin_index: usize,
    /// Minimum number of peers to consider
    #[allow(dead_code)]
    min_candidates: usize,
}

impl Default for PeerSelector {
    fn default() -> Self {
        Self::new(SelectionStrategy::Composite)
    }
}

impl PeerSelector {
    /// Create a new peer selector
    pub fn new(strategy: SelectionStrategy) -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerSelectorInner {
                peers: HashMap::new(),
                strategy,
                weights: SelectionWeights::default(),
                round_robin_index: 0,
                min_candidates: 1,
            })),
        }
    }

    /// Set selection strategy
    pub fn set_strategy(&self, strategy: SelectionStrategy) {
        if let Ok(mut inner) = self.inner.write() {
            inner.strategy = strategy;
        }
    }

    /// Set composite scoring weights
    pub fn set_weights(&self, weights: SelectionWeights) {
        if let Ok(mut inner) = self.inner.write() {
            inner.weights = weights;
        }
    }

    /// Update peer quality metrics
    pub fn update_peer(&self, peer_id: PeerId, quality: PeerQuality) {
        if let Ok(mut inner) = self.inner.write() {
            inner.peers.insert(peer_id, quality);
        }
    }

    /// Update peer latency
    pub fn update_latency(&self, peer_id: PeerId, latency: Duration) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peers
                .entry(peer_id)
                .or_insert_with(|| PeerQuality::new(peer_id))
                .latency_ms = latency.as_millis() as f64;
        }
    }

    /// Update peer bandwidth
    pub fn update_bandwidth(&self, peer_id: PeerId, bytes_per_sec: f64) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peers
                .entry(peer_id)
                .or_insert_with(|| PeerQuality::new(peer_id))
                .bandwidth_bps = bytes_per_sec;
        }
    }

    /// Update peer reputation
    pub fn update_reputation(&self, peer_id: PeerId, reputation: f64) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peers
                .entry(peer_id)
                .or_insert_with(|| PeerQuality::new(peer_id))
                .reputation = reputation.clamp(0.0, 1.0);
        }
    }

    /// Update peer load
    pub fn update_load(&self, peer_id: PeerId, load: f64) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .peers
                .entry(peer_id)
                .or_insert_with(|| PeerQuality::new(peer_id))
                .load = load.clamp(0.0, 1.0);
        }
    }

    /// Record successful transfer
    pub fn record_success(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                peer.success_count += 1;
            }
        }
    }

    /// Record failed transfer
    pub fn record_failure(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                peer.failure_count += 1;
            }
        }
    }

    /// Select best peer from candidates
    pub fn select_peer(&self, candidates: &[PeerId]) -> Option<PeerId> {
        if candidates.is_empty() {
            return None;
        }

        let Ok(mut inner) = self.inner.write() else {
            return None;
        };

        match inner.strategy {
            SelectionStrategy::LowestLatency => {
                self.select_by_metric(candidates, &inner, |p| -p.latency_ms)
            }
            SelectionStrategy::HighestBandwidth => {
                self.select_by_metric(candidates, &inner, |p| p.bandwidth_bps)
            }
            SelectionStrategy::HighestReputation => {
                self.select_by_metric(candidates, &inner, |p| p.reputation)
            }
            SelectionStrategy::Random => {
                use std::collections::hash_map::RandomState;
                use std::hash::BuildHasher;
                let hasher = RandomState::new();
                let idx =
                    (hasher.hash_one(std::time::SystemTime::now()) as usize) % candidates.len();
                Some(candidates[idx])
            }
            SelectionStrategy::Composite => {
                self.select_by_metric(candidates, &inner, |p| p.composite_score(&inner.weights))
            }
            SelectionStrategy::RoundRobin => {
                if candidates.is_empty() {
                    return None;
                }
                let idx = inner.round_robin_index % candidates.len();
                inner.round_robin_index = (inner.round_robin_index + 1) % candidates.len();
                Some(candidates[idx])
            }
            SelectionStrategy::LeastLoaded => {
                self.select_by_metric(candidates, &inner, |p| -(p.load))
            }
        }
    }

    /// Select peer by metric function
    fn select_by_metric<F>(
        &self,
        candidates: &[PeerId],
        inner: &PeerSelectorInner,
        metric_fn: F,
    ) -> Option<PeerId>
    where
        F: Fn(&PeerQuality) -> f64,
    {
        candidates
            .iter()
            .filter_map(|peer_id| {
                inner
                    .peers
                    .get(peer_id)
                    .map(|quality| (*peer_id, metric_fn(quality)))
            })
            .max_by(|(_, score_a), (_, score_b)| {
                score_a
                    .partial_cmp(score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(peer_id, _)| peer_id)
            .or_else(|| candidates.first().copied())
    }

    /// Select multiple peers
    pub fn select_multiple(&self, candidates: &[PeerId], count: usize) -> Vec<PeerId> {
        if candidates.is_empty() || count == 0 {
            return Vec::new();
        }

        let Ok(inner) = self.inner.read() else {
            return Vec::new();
        };

        let mut scored_peers: Vec<_> = candidates
            .iter()
            .map(|peer_id| {
                let quality = inner
                    .peers
                    .get(peer_id)
                    .cloned()
                    .unwrap_or_else(|| PeerQuality::new(*peer_id));
                let score = quality.composite_score(&inner.weights);
                (*peer_id, score)
            })
            .collect();

        // Sort by score descending
        scored_peers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_peers
            .into_iter()
            .take(count)
            .map(|(peer_id, _)| peer_id)
            .collect()
    }

    /// Get peer quality metrics
    pub fn get_quality(&self, peer_id: &PeerId) -> Option<PeerQuality> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.peers.get(peer_id).cloned())
    }

    /// Get all tracked peers
    pub fn tracked_peers(&self) -> Vec<PeerId> {
        self.inner
            .read()
            .map(|inner| inner.peers.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Remove peer from tracking
    pub fn remove_peer(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.peers.remove(peer_id);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> SelectorStats {
        let Ok(inner) = self.inner.read() else {
            return SelectorStats::default();
        };

        let total_peers = inner.peers.len();
        let avg_latency = if total_peers > 0 {
            inner.peers.values().map(|p| p.latency_ms).sum::<f64>() / total_peers as f64
        } else {
            0.0
        };

        let avg_reputation = if total_peers > 0 {
            inner.peers.values().map(|p| p.reputation).sum::<f64>() / total_peers as f64
        } else {
            0.0
        };

        SelectorStats {
            total_peers,
            strategy: inner.strategy,
            avg_latency_ms: avg_latency,
            avg_reputation,
        }
    }
}

/// Peer selector statistics
#[derive(Debug, Clone, Default)]
pub struct SelectorStats {
    pub total_peers: usize,
    pub strategy: SelectionStrategy,
    pub avg_latency_ms: f64,
    pub avg_reputation: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_quality_creation() {
        let peer_id = PeerId::random();
        let quality = PeerQuality::new(peer_id);
        assert_eq!(quality.peer_id, peer_id);
        assert_eq!(quality.success_rate(), 0.5);
    }

    #[test]
    fn test_success_rate() {
        let mut quality = PeerQuality::new(PeerId::random());
        quality.success_count = 7;
        quality.failure_count = 3;
        assert_eq!(quality.success_rate(), 0.7);
    }

    #[test]
    fn test_composite_score() {
        let mut quality = PeerQuality::new(PeerId::random());
        quality.latency_ms = 50.0;
        quality.bandwidth_bps = 1_000_000.0;
        quality.reputation = 0.8;
        quality.load = 0.3;

        let weights = SelectionWeights::default();
        let score = quality.composite_score(&weights);
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_selection_strategies() {
        let selector = PeerSelector::new(SelectionStrategy::Composite);

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut q1 = PeerQuality::new(peer1);
        q1.latency_ms = 100.0;
        selector.update_peer(peer1, q1);

        let mut q2 = PeerQuality::new(peer2);
        q2.latency_ms = 50.0;
        selector.update_peer(peer2, q2);

        let mut q3 = PeerQuality::new(peer3);
        q3.latency_ms = 200.0;
        selector.update_peer(peer3, q3);

        let candidates = vec![peer1, peer2, peer3];

        // Test lowest latency
        selector.set_strategy(SelectionStrategy::LowestLatency);
        let selected = selector.select_peer(&candidates);
        assert_eq!(selected, Some(peer2)); // peer2 has lowest latency
    }

    #[test]
    fn test_update_metrics() {
        let selector = PeerSelector::new(SelectionStrategy::Composite);
        let peer_id = PeerId::random();

        selector.update_latency(peer_id, Duration::from_millis(100));
        selector.update_bandwidth(peer_id, 5_000_000.0);
        selector.update_reputation(peer_id, 0.9);
        selector.update_load(peer_id, 0.2);

        let quality = selector.get_quality(&peer_id).unwrap();
        assert_eq!(quality.latency_ms, 100.0);
        assert_eq!(quality.bandwidth_bps, 5_000_000.0);
        assert_eq!(quality.reputation, 0.9);
        assert_eq!(quality.load, 0.2);
    }

    #[test]
    fn test_record_success_failure() {
        let selector = PeerSelector::new(SelectionStrategy::Composite);
        let peer_id = PeerId::random();

        selector.update_peer(peer_id, PeerQuality::new(peer_id));
        selector.record_success(&peer_id);
        selector.record_success(&peer_id);
        selector.record_failure(&peer_id);

        let quality = selector.get_quality(&peer_id).unwrap();
        assert_eq!(quality.success_count, 2);
        assert_eq!(quality.failure_count, 1);
    }

    #[test]
    fn test_select_multiple() {
        let selector = PeerSelector::new(SelectionStrategy::Composite);

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let mut q1 = PeerQuality::new(peer1);
        q1.reputation = 0.9;
        selector.update_peer(peer1, q1);

        let mut q2 = PeerQuality::new(peer2);
        q2.reputation = 0.5;
        selector.update_peer(peer2, q2);

        let mut q3 = PeerQuality::new(peer3);
        q3.reputation = 0.7;
        selector.update_peer(peer3, q3);

        let candidates = vec![peer1, peer2, peer3];
        let selected = selector.select_multiple(&candidates, 2);

        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&peer1)); // Highest reputation should be selected
    }

    #[test]
    fn test_round_robin() {
        let selector = PeerSelector::new(SelectionStrategy::RoundRobin);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        let candidates = vec![peer1, peer2, peer3];

        let s1 = selector.select_peer(&candidates);
        let s2 = selector.select_peer(&candidates);
        let s3 = selector.select_peer(&candidates);

        assert_eq!(s1, Some(peer1));
        assert_eq!(s2, Some(peer2));
        assert_eq!(s3, Some(peer3));
    }

    #[test]
    fn test_remove_peer() {
        let selector = PeerSelector::new(SelectionStrategy::Composite);
        let peer_id = PeerId::random();

        selector.update_peer(peer_id, PeerQuality::new(peer_id));
        assert!(selector.get_quality(&peer_id).is_some());

        selector.remove_peer(&peer_id);
        assert!(selector.get_quality(&peer_id).is_none());
    }

    #[test]
    fn test_stats() {
        let selector = PeerSelector::new(SelectionStrategy::Composite);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        let mut q1 = PeerQuality::new(peer1);
        q1.latency_ms = 100.0;
        q1.reputation = 0.8;
        selector.update_peer(peer1, q1);

        let mut q2 = PeerQuality::new(peer2);
        q2.latency_ms = 200.0;
        q2.reputation = 0.6;
        selector.update_peer(peer2, q2);

        let stats = selector.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.avg_latency_ms, 150.0);
        assert_eq!(stats.avg_reputation, 0.7);
    }

    #[test]
    fn test_preset_weights() {
        let low_lat = SelectionWeights::low_latency();
        assert_eq!(low_lat.latency_weight, 0.50);

        let high_bw = SelectionWeights::high_bandwidth();
        assert_eq!(high_bw.bandwidth_weight, 0.50);

        let reliable = SelectionWeights::high_reliability();
        assert_eq!(reliable.reputation_weight, 0.40);
    }
}
