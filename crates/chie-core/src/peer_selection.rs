//! Intelligent peer selection module for optimizing content delivery.
//!
//! This module provides smart peer selection algorithms that combine multiple
//! factors including reputation scores, network quality, load balancing, and
//! geographical proximity to select the best peers for content requests.
//!
//! # Example
//!
//! ```
//! use chie_core::{PeerSelector, SelectionStrategy, PeerCandidate};
//!
//! # async fn example() {
//! let mut selector = PeerSelector::new();
//!
//! // Add peer candidates with various metrics
//! selector.add_candidate(PeerCandidate {
//!     peer_id: "peer1".to_string(),
//!     reputation_score: 0.95,
//!     network_health: 0.90,
//!     current_load: 0.3,
//!     latency_ms: 50.0,
//!     bandwidth_mbps: 100.0,
//!     distance_km: Some(100.0),
//!     last_seen: std::time::SystemTime::now(),
//! });
//!
//! // Select the best peer using weighted scoring
//! if let Some(best_peer) = selector.select_best() {
//!     println!("Selected peer: {}", best_peer.peer_id);
//! }
//!
//! // Get top N peers for redundancy
//! let top_peers = selector.select_top_n(3);
//! # }
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Represents a peer candidate for content delivery.
#[derive(Debug, Clone)]
pub struct PeerCandidate {
    /// Unique peer identifier
    pub peer_id: String,
    /// Reputation score (0.0 to 1.0)
    pub reputation_score: f64,
    /// Network health score (0.0 to 1.0)
    pub network_health: f64,
    /// Current load percentage (0.0 to 1.0)
    pub current_load: f64,
    /// Average latency in milliseconds
    pub latency_ms: f64,
    /// Available bandwidth in Mbps
    pub bandwidth_mbps: f64,
    /// Geographic distance in kilometers (if known)
    pub distance_km: Option<f64>,
    /// Last seen timestamp
    pub last_seen: SystemTime,
}

/// Peer selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Select the single best peer based on weighted score
    Best,
    /// Weighted random selection (higher scores more likely)
    WeightedRandom,
    /// Round-robin among top peers
    RoundRobin,
    /// Least loaded peer
    LeastLoaded,
    /// Lowest latency peer
    LowestLatency,
}

/// Weights for different factors in peer selection.
#[derive(Debug, Clone)]
pub struct SelectionWeights {
    /// Weight for reputation score (default: 0.3)
    pub reputation: f64,
    /// Weight for network health (default: 0.25)
    pub network_health: f64,
    /// Weight for load (inverted - lower is better) (default: 0.2)
    pub load: f64,
    /// Weight for latency (inverted - lower is better) (default: 0.15)
    pub latency: f64,
    /// Weight for bandwidth (default: 0.1)
    pub bandwidth: f64,
    /// Weight for distance (inverted - closer is better) (default: 0.0)
    pub distance: f64,
}

impl Default for SelectionWeights {
    fn default() -> Self {
        Self {
            reputation: 0.3,
            network_health: 0.25,
            load: 0.2,
            latency: 0.15,
            bandwidth: 0.1,
            distance: 0.0,
        }
    }
}

/// Peer selector for intelligent peer ranking and selection.
pub struct PeerSelector {
    candidates: Vec<PeerCandidate>,
    weights: SelectionWeights,
    strategy: SelectionStrategy,
    round_robin_index: usize,
    peer_request_counts: HashMap<String, u64>,
    stale_threshold: Duration,
}

impl PeerSelector {
    /// Create a new peer selector with default settings.
    #[must_use]
    #[inline]
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
            weights: SelectionWeights::default(),
            strategy: SelectionStrategy::Best,
            round_robin_index: 0,
            peer_request_counts: HashMap::new(),
            stale_threshold: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a peer selector with custom weights.
    #[must_use]
    #[inline]
    pub fn with_weights(weights: SelectionWeights) -> Self {
        Self {
            weights,
            ..Self::new()
        }
    }

    /// Set the selection strategy.
    #[inline]
    pub fn set_strategy(&mut self, strategy: SelectionStrategy) {
        self.strategy = strategy;
    }

    /// Set the stale threshold for removing old peers.
    #[inline]
    pub fn set_stale_threshold(&mut self, threshold: Duration) {
        self.stale_threshold = threshold;
    }

    /// Add a peer candidate.
    pub fn add_candidate(&mut self, candidate: PeerCandidate) {
        // Remove existing entry for this peer if present
        self.candidates.retain(|c| c.peer_id != candidate.peer_id);
        self.candidates.push(candidate);
    }

    /// Remove a peer candidate.
    #[inline]
    pub fn remove_candidate(&mut self, peer_id: &str) {
        self.candidates.retain(|c| c.peer_id != peer_id);
        self.peer_request_counts.remove(peer_id);
    }

    /// Remove stale peers based on last_seen timestamp.
    pub fn remove_stale_peers(&mut self) -> usize {
        let now = SystemTime::now();
        let initial_count = self.candidates.len();

        self.candidates.retain(|c| {
            if let Ok(duration) = now.duration_since(c.last_seen) {
                duration < self.stale_threshold
            } else {
                true // Keep if we can't determine age
            }
        });

        initial_count - self.candidates.len()
    }

    /// Calculate weighted score for a peer.
    #[inline]
    fn calculate_score(&self, peer: &PeerCandidate) -> f64 {
        let mut score = 0.0;

        // Add reputation component
        score += peer.reputation_score * self.weights.reputation;

        // Add network health component
        score += peer.network_health * self.weights.network_health;

        // Add load component (inverted - lower load is better)
        score += (1.0 - peer.current_load) * self.weights.load;

        // Add latency component (inverted - lower latency is better)
        // Normalize latency: assume 0-500ms range
        let normalized_latency = 1.0 - (peer.latency_ms.min(500.0) / 500.0);
        score += normalized_latency * self.weights.latency;

        // Add bandwidth component
        // Normalize bandwidth: assume 0-1000 Mbps range
        let normalized_bandwidth = peer.bandwidth_mbps.min(1000.0) / 1000.0;
        score += normalized_bandwidth * self.weights.bandwidth;

        // Add distance component if available (inverted - closer is better)
        if let Some(distance) = peer.distance_km {
            // Normalize distance: assume 0-10000km range
            let normalized_distance = 1.0 - (distance.min(10000.0) / 10000.0);
            score += normalized_distance * self.weights.distance;
        }

        score
    }

    /// Select the best peer based on the current strategy.
    #[must_use]
    pub fn select_best(&mut self) -> Option<PeerCandidate> {
        if self.candidates.is_empty() {
            return None;
        }

        match self.strategy {
            SelectionStrategy::Best => self.select_highest_score(),
            SelectionStrategy::WeightedRandom => self.select_weighted_random(),
            SelectionStrategy::RoundRobin => self.select_round_robin(),
            SelectionStrategy::LeastLoaded => self.select_least_loaded(),
            SelectionStrategy::LowestLatency => self.select_lowest_latency(),
        }
    }

    /// Select the peer with the highest score.
    fn select_highest_score(&mut self) -> Option<PeerCandidate> {
        let mut scored: Vec<_> = self
            .candidates
            .iter()
            .map(|c| (c.clone(), self.calculate_score(c)))
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored.first().map(|(peer, _)| {
            *self
                .peer_request_counts
                .entry(peer.peer_id.clone())
                .or_insert(0) += 1;
            peer.clone()
        })
    }

    /// Select a peer using weighted random selection.
    fn select_weighted_random(&mut self) -> Option<PeerCandidate> {
        use rand::RngExt as _;

        let scores: Vec<_> = self
            .candidates
            .iter()
            .map(|c| self.calculate_score(c))
            .collect();

        let total_score: f64 = scores.iter().sum();
        if total_score == 0.0 {
            return self.candidates.first().cloned();
        }

        let mut rng = rand::rng();
        let mut random_value = rng.random_range(0.0..total_score);

        for (i, score) in scores.iter().enumerate() {
            random_value -= score;
            if random_value <= 0.0 {
                let peer = self.candidates[i].clone();
                *self
                    .peer_request_counts
                    .entry(peer.peer_id.clone())
                    .or_insert(0) += 1;
                return Some(peer);
            }
        }

        // Fallback to last candidate
        self.candidates.last().cloned()
    }

    /// Select the next peer in round-robin order.
    fn select_round_robin(&mut self) -> Option<PeerCandidate> {
        if self.candidates.is_empty() {
            return None;
        }

        let peer = self.candidates[self.round_robin_index % self.candidates.len()].clone();
        self.round_robin_index = (self.round_robin_index + 1) % self.candidates.len();
        *self
            .peer_request_counts
            .entry(peer.peer_id.clone())
            .or_insert(0) += 1;
        Some(peer)
    }

    /// Select the peer with the lowest current load.
    fn select_least_loaded(&mut self) -> Option<PeerCandidate> {
        let mut sorted = self.candidates.clone();
        sorted.sort_by(|a, b| {
            a.current_load
                .partial_cmp(&b.current_load)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        sorted.first().map(|peer| {
            *self
                .peer_request_counts
                .entry(peer.peer_id.clone())
                .or_insert(0) += 1;
            peer.clone()
        })
    }

    /// Select the peer with the lowest latency.
    fn select_lowest_latency(&mut self) -> Option<PeerCandidate> {
        let mut sorted = self.candidates.clone();
        sorted.sort_by(|a, b| {
            a.latency_ms
                .partial_cmp(&b.latency_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        sorted.first().map(|peer| {
            *self
                .peer_request_counts
                .entry(peer.peer_id.clone())
                .or_insert(0) += 1;
            peer.clone()
        })
    }

    /// Select the top N peers based on score.
    #[must_use]
    #[inline]
    pub fn select_top_n(&self, n: usize) -> Vec<PeerCandidate> {
        let mut scored: Vec<_> = self
            .candidates
            .iter()
            .map(|c| (c.clone(), self.calculate_score(c)))
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored.into_iter().take(n).map(|(peer, _)| peer).collect()
    }

    /// Get peers with score above a threshold.
    #[must_use]
    #[inline]
    pub fn get_qualified_peers(&self, min_score: f64) -> Vec<PeerCandidate> {
        self.candidates
            .iter()
            .filter(|c| self.calculate_score(c) >= min_score)
            .cloned()
            .collect()
    }

    /// Get the number of candidates.
    #[must_use]
    #[inline]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Get all candidates.
    #[must_use]
    #[inline]
    pub fn candidates(&self) -> &[PeerCandidate] {
        &self.candidates
    }

    /// Clear all candidates.
    #[inline]
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.peer_request_counts.clear();
        self.round_robin_index = 0;
    }

    /// Get request count for a peer.
    #[must_use]
    #[inline]
    pub fn get_request_count(&self, peer_id: &str) -> u64 {
        self.peer_request_counts.get(peer_id).copied().unwrap_or(0)
    }

    /// Get statistics about peer selection.
    #[must_use]
    #[inline]
    pub fn get_statistics(&self) -> PeerSelectionStats {
        if self.candidates.is_empty() {
            return PeerSelectionStats::default();
        }

        let scores: Vec<f64> = self
            .candidates
            .iter()
            .map(|c| self.calculate_score(c))
            .collect();

        let total_score: f64 = scores.iter().sum();
        let avg_score = total_score / scores.len() as f64;
        let max_score = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let min_score = scores.iter().cloned().fold(f64::INFINITY, f64::min);

        let total_requests: u64 = self.peer_request_counts.values().sum();

        PeerSelectionStats {
            total_candidates: self.candidates.len(),
            average_score: avg_score,
            max_score,
            min_score,
            total_requests,
        }
    }
}

impl Default for PeerSelector {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about peer selection.
#[derive(Debug, Clone, Default)]
pub struct PeerSelectionStats {
    /// Total number of peer candidates
    pub total_candidates: usize,
    /// Average score across all candidates
    pub average_score: f64,
    /// Maximum score among candidates
    pub max_score: f64,
    /// Minimum score among candidates
    pub min_score: f64,
    /// Total number of selection requests
    pub total_requests: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer(peer_id: &str, reputation: f64, health: f64, load: f64) -> PeerCandidate {
        PeerCandidate {
            peer_id: peer_id.to_string(),
            reputation_score: reputation,
            network_health: health,
            current_load: load,
            latency_ms: 100.0,
            bandwidth_mbps: 100.0,
            distance_km: None,
            last_seen: SystemTime::now(),
        }
    }

    #[test]
    fn test_peer_selection_best_strategy() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.5, 0.5, 0.8));
        selector.add_candidate(create_test_peer("peer2", 0.9, 0.9, 0.2));
        selector.add_candidate(create_test_peer("peer3", 0.7, 0.7, 0.5));

        selector.set_strategy(SelectionStrategy::Best);
        let best = selector.select_best().unwrap();
        assert_eq!(best.peer_id, "peer2");
    }

    #[test]
    fn test_peer_selection_least_loaded() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.9, 0.9, 0.8));
        selector.add_candidate(create_test_peer("peer2", 0.5, 0.5, 0.1));
        selector.add_candidate(create_test_peer("peer3", 0.7, 0.7, 0.5));

        selector.set_strategy(SelectionStrategy::LeastLoaded);
        let best = selector.select_best().unwrap();
        assert_eq!(best.peer_id, "peer2");
    }

    #[test]
    fn test_peer_selection_top_n() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.5, 0.5, 0.8));
        selector.add_candidate(create_test_peer("peer2", 0.9, 0.9, 0.2));
        selector.add_candidate(create_test_peer("peer3", 0.7, 0.7, 0.5));

        let top_2 = selector.select_top_n(2);
        assert_eq!(top_2.len(), 2);
        assert_eq!(top_2[0].peer_id, "peer2");
        assert_eq!(top_2[1].peer_id, "peer3");
    }

    #[test]
    fn test_peer_selection_round_robin() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.5, 0.5, 0.5));
        selector.add_candidate(create_test_peer("peer2", 0.5, 0.5, 0.5));
        selector.add_candidate(create_test_peer("peer3", 0.5, 0.5, 0.5));

        selector.set_strategy(SelectionStrategy::RoundRobin);

        assert_eq!(selector.select_best().unwrap().peer_id, "peer1");
        assert_eq!(selector.select_best().unwrap().peer_id, "peer2");
        assert_eq!(selector.select_best().unwrap().peer_id, "peer3");
        assert_eq!(selector.select_best().unwrap().peer_id, "peer1");
    }

    #[test]
    fn test_remove_candidate() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.5, 0.5, 0.5));
        selector.add_candidate(create_test_peer("peer2", 0.5, 0.5, 0.5));

        assert_eq!(selector.candidate_count(), 2);

        selector.remove_candidate("peer1");
        assert_eq!(selector.candidate_count(), 1);
        assert_eq!(selector.candidates()[0].peer_id, "peer2");
    }

    #[test]
    fn test_custom_weights() {
        let weights = SelectionWeights {
            reputation: 1.0,
            network_health: 0.0,
            load: 0.0,
            latency: 0.0,
            bandwidth: 0.0,
            distance: 0.0,
        };

        let mut selector = PeerSelector::with_weights(weights);

        selector.add_candidate(create_test_peer("peer1", 0.5, 1.0, 0.0));
        selector.add_candidate(create_test_peer("peer2", 1.0, 0.0, 1.0));

        selector.set_strategy(SelectionStrategy::Best);
        let best = selector.select_best().unwrap();
        assert_eq!(best.peer_id, "peer2"); // Higher reputation
    }

    #[test]
    fn test_qualified_peers() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.3, 0.3, 0.9));
        selector.add_candidate(create_test_peer("peer2", 0.9, 0.9, 0.1));
        selector.add_candidate(create_test_peer("peer3", 0.7, 0.7, 0.5));

        let qualified = selector.get_qualified_peers(0.5);
        assert!(qualified.len() >= 2);
    }

    #[test]
    fn test_statistics() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.5, 0.5, 0.5));
        selector.add_candidate(create_test_peer("peer2", 0.9, 0.9, 0.2));
        selector.add_candidate(create_test_peer("peer3", 0.7, 0.7, 0.5));

        let _ = selector.select_best();
        let _ = selector.select_best();

        let stats = selector.get_statistics();
        assert_eq!(stats.total_candidates, 3);
        assert!(stats.average_score > 0.0);
        assert_eq!(stats.total_requests, 2);
    }

    #[test]
    fn test_stale_peer_removal() {
        let mut selector = PeerSelector::new();
        selector.set_stale_threshold(Duration::from_secs(1));

        let mut old_peer = create_test_peer("peer1", 0.5, 0.5, 0.5);
        old_peer.last_seen = SystemTime::now() - Duration::from_secs(5);

        selector.add_candidate(old_peer);
        selector.add_candidate(create_test_peer("peer2", 0.5, 0.5, 0.5));

        assert_eq!(selector.candidate_count(), 2);

        let removed = selector.remove_stale_peers();
        assert_eq!(removed, 1);
        assert_eq!(selector.candidate_count(), 1);
    }

    #[test]
    fn test_request_counting() {
        let mut selector = PeerSelector::new();

        selector.add_candidate(create_test_peer("peer1", 0.9, 0.9, 0.1));

        selector.set_strategy(SelectionStrategy::Best);
        let _ = selector.select_best();
        let _ = selector.select_best();
        let _ = selector.select_best();

        assert_eq!(selector.get_request_count("peer1"), 3);
        assert_eq!(selector.get_request_count("peer2"), 0);
    }
}
