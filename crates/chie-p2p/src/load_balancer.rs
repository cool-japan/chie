//! Load balancing for distributing requests across available peers.
//!
//! This module provides:
//! - Multiple load balancing algorithms
//! - Request tracking and peer load monitoring
//! - Weighted load distribution
//! - Health-aware balancing
//! - Session affinity support

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Load balancing algorithm
///
/// # Examples
///
/// ```
/// use chie_p2p::{LoadBalancer, LoadBalancingAlgorithm};
///
/// // Create a load balancer with round-robin algorithm
/// let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
/// // Load balancer is ready to distribute requests
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancingAlgorithm {
    /// Round-robin distribution
    RoundRobin,
    /// Least connections
    #[default]
    LeastConnections,
    /// Weighted round-robin
    WeightedRoundRobin,
    /// Random selection
    Random,
    /// Least response time
    LeastResponseTime,
    /// Resource-based (CPU/memory)
    ResourceBased,
}

/// Peer load information
#[derive(Debug, Clone)]
pub struct PeerLoad {
    /// Peer ID
    pub peer_id: PeerId,
    /// Current active connections
    pub active_connections: usize,
    /// Total requests handled
    pub total_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time
    pub avg_response_time_ms: f64,
    /// Weight for weighted algorithms (0.0 - 1.0)
    pub weight: f64,
    /// Resource utilization (0.0 - 1.0)
    pub resource_utilization: f64,
    /// Is peer healthy
    pub is_healthy: bool,
    /// Last health check time
    pub last_health_check: Instant,
}

impl PeerLoad {
    /// Create new peer load info
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            active_connections: 0,
            total_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            weight: 1.0,
            resource_utilization: 0.0,
            is_healthy: true,
            last_health_check: Instant::now(),
        }
    }

    /// Calculate effective load score (lower is better)
    pub fn load_score(&self) -> f64 {
        if !self.is_healthy {
            return f64::MAX;
        }

        let connection_factor = self.active_connections as f64;
        let response_factor = self.avg_response_time_ms / 100.0;
        let resource_factor = self.resource_utilization * 10.0;
        let weight_factor = 1.0 / self.weight.max(0.1);

        connection_factor + response_factor + resource_factor + weight_factor
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 1.0;
        }
        let successful = self.total_requests - self.failed_requests;
        successful as f64 / self.total_requests as f64
    }
}

/// Session affinity configuration
#[derive(Debug, Clone)]
pub struct SessionAffinity {
    /// Session timeout duration
    pub timeout: Duration,
    /// Enable session affinity
    pub enabled: bool,
}

impl Default for SessionAffinity {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes
            enabled: false,
        }
    }
}

/// Session information
#[derive(Debug, Clone)]
struct Session {
    peer_id: PeerId,
    #[allow(dead_code)]
    created_at: Instant,
    last_accessed: Instant,
}

/// Load balancer for peer requests
#[derive(Clone)]
pub struct LoadBalancer {
    inner: Arc<RwLock<LoadBalancerInner>>,
}

struct LoadBalancerInner {
    /// Peer load information
    peers: HashMap<PeerId, PeerLoad>,
    /// Load balancing algorithm
    algorithm: LoadBalancingAlgorithm,
    /// Round-robin counter
    round_robin_index: usize,
    /// Weighted round-robin current weights
    current_weights: HashMap<PeerId, f64>,
    /// Session affinity configuration
    session_affinity: SessionAffinity,
    /// Active sessions (session_id -> peer_id)
    sessions: HashMap<String, Session>,
    /// Health check interval
    #[allow(dead_code)]
    health_check_interval: Duration,
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new(LoadBalancingAlgorithm::LeastConnections)
    }
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(algorithm: LoadBalancingAlgorithm) -> Self {
        Self {
            inner: Arc::new(RwLock::new(LoadBalancerInner {
                peers: HashMap::new(),
                algorithm,
                round_robin_index: 0,
                current_weights: HashMap::new(),
                session_affinity: SessionAffinity::default(),
                sessions: HashMap::new(),
                health_check_interval: Duration::from_secs(30),
            })),
        }
    }

    /// Set load balancing algorithm
    pub fn set_algorithm(&self, algorithm: LoadBalancingAlgorithm) {
        if let Ok(mut inner) = self.inner.write() {
            inner.algorithm = algorithm;
        }
    }

    /// Enable/disable session affinity
    pub fn set_session_affinity(&self, enabled: bool, timeout: Duration) {
        if let Ok(mut inner) = self.inner.write() {
            inner.session_affinity.enabled = enabled;
            inner.session_affinity.timeout = timeout;
        }
    }

    /// Add or update peer
    pub fn add_peer(&self, peer_id: PeerId, weight: f64) {
        if let Ok(mut inner) = self.inner.write() {
            let mut load = inner
                .peers
                .get(&peer_id)
                .cloned()
                .unwrap_or_else(|| PeerLoad::new(peer_id));
            load.weight = weight.clamp(0.1, 10.0);
            inner.peers.insert(peer_id, load);
            inner.current_weights.insert(peer_id, 0.0);
        }
    }

    /// Remove peer
    pub fn remove_peer(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.peers.remove(peer_id);
            inner.current_weights.remove(peer_id);
        }
    }

    /// Mark peer as healthy/unhealthy
    pub fn set_peer_health(&self, peer_id: &PeerId, healthy: bool) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                peer.is_healthy = healthy;
                peer.last_health_check = Instant::now();
            }
        }
    }

    /// Select next peer for request
    pub fn select_peer(&self, session_id: Option<&str>) -> Option<PeerId> {
        let Ok(mut inner) = self.inner.write() else {
            return None;
        };

        // Check session affinity first
        if let Some(sid) = session_id {
            if inner.session_affinity.enabled {
                let timeout = inner.session_affinity.timeout;
                if let Some(session) = inner.sessions.get_mut(sid) {
                    if session.last_accessed.elapsed() < timeout {
                        session.last_accessed = Instant::now();
                        return Some(session.peer_id);
                    }
                }
            }
        }

        // Get healthy peers
        let healthy_peers: Vec<&PeerId> = inner
            .peers
            .values()
            .filter(|p| p.is_healthy)
            .map(|p| &p.peer_id)
            .collect();

        if healthy_peers.is_empty() {
            return None;
        }

        let algorithm = inner.algorithm;
        let selected = match algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                let peer_count = healthy_peers.len();
                let idx = inner.round_robin_index % peer_count;
                let selected_peer = *healthy_peers[idx];
                inner.round_robin_index = (inner.round_robin_index + 1) % peer_count;
                Some(selected_peer)
            }
            LoadBalancingAlgorithm::LeastConnections => healthy_peers
                .iter()
                .min_by_key(|&&peer_id| {
                    inner
                        .peers
                        .get(peer_id)
                        .map(|p| p.active_connections)
                        .unwrap_or(usize::MAX)
                })
                .copied()
                .copied(),
            LoadBalancingAlgorithm::WeightedRoundRobin => {
                let healthy_peer_ids: Vec<PeerId> =
                    healthy_peers.iter().copied().copied().collect();
                self.select_weighted_round_robin(&mut inner, &healthy_peer_ids)
            }
            LoadBalancingAlgorithm::Random => {
                use std::collections::hash_map::RandomState;
                use std::hash::BuildHasher;
                let hasher = RandomState::new();
                let idx =
                    (hasher.hash_one(std::time::SystemTime::now()) as usize) % healthy_peers.len();
                Some(*healthy_peers[idx])
            }
            LoadBalancingAlgorithm::LeastResponseTime => healthy_peers
                .iter()
                .min_by(|&&a, &&b| {
                    let time_a = inner
                        .peers
                        .get(a)
                        .map(|p| p.avg_response_time_ms)
                        .unwrap_or(f64::MAX);
                    let time_b = inner
                        .peers
                        .get(b)
                        .map(|p| p.avg_response_time_ms)
                        .unwrap_or(f64::MAX);
                    time_a
                        .partial_cmp(&time_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied()
                .copied(),
            LoadBalancingAlgorithm::ResourceBased => healthy_peers
                .iter()
                .min_by(|&&a, &&b| {
                    let score_a = inner
                        .peers
                        .get(a)
                        .map(|p| p.load_score())
                        .unwrap_or(f64::MAX);
                    let score_b = inner
                        .peers
                        .get(b)
                        .map(|p| p.load_score())
                        .unwrap_or(f64::MAX);
                    score_a
                        .partial_cmp(&score_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .copied()
                .copied(),
        };

        // Create session if affinity is enabled
        if let (Some(peer_id), Some(sid)) = (selected, session_id) {
            if inner.session_affinity.enabled {
                inner.sessions.insert(
                    sid.to_string(),
                    Session {
                        peer_id,
                        created_at: Instant::now(),
                        last_accessed: Instant::now(),
                    },
                );
            }
        }

        selected
    }

    /// Weighted round-robin selection
    fn select_weighted_round_robin(
        &self,
        inner: &mut LoadBalancerInner,
        healthy_peers: &[PeerId],
    ) -> Option<PeerId> {
        if healthy_peers.is_empty() {
            return None;
        }

        // Find peer with highest current weight
        let selected = healthy_peers
            .iter()
            .max_by(|&a, &b| {
                let weight_a = inner.current_weights.get(a).copied().unwrap_or(0.0);
                let weight_b = inner.current_weights.get(b).copied().unwrap_or(0.0);
                weight_a
                    .partial_cmp(&weight_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied();

        if let Some(peer_id) = selected {
            // Update weights
            let total_weight: f64 = healthy_peers
                .iter()
                .filter_map(|pid| inner.peers.get(pid).map(|p| p.weight))
                .sum();

            for &pid in healthy_peers {
                let current = inner.current_weights.entry(pid).or_insert(0.0);
                let peer_weight = inner.peers.get(&pid).map(|p| p.weight).unwrap_or(1.0);

                if pid == peer_id {
                    *current = *current - total_weight + peer_weight;
                } else {
                    *current += peer_weight;
                }
            }
        }

        selected
    }

    /// Record request start (increment active connections)
    pub fn request_start(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                peer.active_connections += 1;
                peer.total_requests += 1;
            }
        }
    }

    /// Record request end (decrement active connections)
    pub fn request_end(&self, peer_id: &PeerId, duration: Duration, success: bool) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                peer.active_connections = peer.active_connections.saturating_sub(1);

                if !success {
                    peer.failed_requests += 1;
                }

                // Update average response time (exponential moving average)
                let response_time_ms = duration.as_millis() as f64;
                if peer.avg_response_time_ms == 0.0 {
                    peer.avg_response_time_ms = response_time_ms;
                } else {
                    peer.avg_response_time_ms =
                        0.7 * peer.avg_response_time_ms + 0.3 * response_time_ms;
                }
            }
        }
    }

    /// Update peer resource utilization
    pub fn update_resource_utilization(&self, peer_id: &PeerId, utilization: f64) {
        if let Ok(mut inner) = self.inner.write() {
            if let Some(peer) = inner.peers.get_mut(peer_id) {
                peer.resource_utilization = utilization.clamp(0.0, 1.0);
            }
        }
    }

    /// Clean up expired sessions
    pub fn cleanup_sessions(&self) -> usize {
        let Ok(mut inner) = self.inner.write() else {
            return 0;
        };

        let timeout = inner.session_affinity.timeout;
        let before_count = inner.sessions.len();

        inner
            .sessions
            .retain(|_, session| session.last_accessed.elapsed() < timeout);

        before_count - inner.sessions.len()
    }

    /// Get load balancer statistics
    pub fn stats(&self) -> LoadBalancerStats {
        let Ok(inner) = self.inner.read() else {
            return LoadBalancerStats::default();
        };

        let total_peers = inner.peers.len();
        let healthy_peers = inner.peers.values().filter(|p| p.is_healthy).count();
        let total_connections: usize = inner.peers.values().map(|p| p.active_connections).sum();
        let total_requests: u64 = inner.peers.values().map(|p| p.total_requests).sum();
        let active_sessions = inner.sessions.len();

        LoadBalancerStats {
            total_peers,
            healthy_peers,
            total_connections,
            total_requests,
            active_sessions,
            algorithm: inner.algorithm,
        }
    }

    /// Get peer load information
    pub fn get_peer_load(&self, peer_id: &PeerId) -> Option<PeerLoad> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.peers.get(peer_id).cloned())
    }

    /// Get all peer loads
    pub fn all_peer_loads(&self) -> Vec<PeerLoad> {
        self.inner
            .read()
            .map(|inner| inner.peers.values().cloned().collect())
            .unwrap_or_default()
    }
}

/// Load balancer statistics
#[derive(Debug, Clone, Default)]
pub struct LoadBalancerStats {
    pub total_peers: usize,
    pub healthy_peers: usize,
    pub total_connections: usize,
    pub total_requests: u64,
    pub active_sessions: usize,
    pub algorithm: LoadBalancingAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_load_creation() {
        let peer_id = PeerId::random();
        let load = PeerLoad::new(peer_id);
        assert_eq!(load.peer_id, peer_id);
        assert_eq!(load.active_connections, 0);
        assert!(load.is_healthy);
    }

    #[test]
    fn test_load_score() {
        let mut load = PeerLoad::new(PeerId::random());
        load.active_connections = 5;
        load.avg_response_time_ms = 100.0;
        load.resource_utilization = 0.5;
        load.weight = 1.0;

        let score = load.load_score();
        assert!(score > 0.0);

        load.is_healthy = false;
        assert_eq!(load.load_score(), f64::MAX);
    }

    #[test]
    fn test_add_remove_peer() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        let peer_id = PeerId::random();

        lb.add_peer(peer_id, 1.0);
        assert!(lb.get_peer_load(&peer_id).is_some());

        lb.remove_peer(&peer_id);
        assert!(lb.get_peer_load(&peer_id).is_none());
    }

    #[test]
    fn test_round_robin() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        lb.add_peer(peer1, 1.0);
        lb.add_peer(peer2, 1.0);
        lb.add_peer(peer3, 1.0);

        let s1 = lb.select_peer(None);
        let s2 = lb.select_peer(None);
        let s3 = lb.select_peer(None);

        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
    }

    #[test]
    fn test_least_connections() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::LeastConnections);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        lb.add_peer(peer1, 1.0);
        lb.add_peer(peer2, 1.0);

        lb.request_start(&peer1);
        lb.request_start(&peer1);
        lb.request_start(&peer2);

        // peer2 has fewer connections, should be selected
        let selected = lb.select_peer(None);
        assert_eq!(selected, Some(peer2));
    }

    #[test]
    fn test_request_tracking() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::LeastConnections);
        let peer_id = PeerId::random();

        lb.add_peer(peer_id, 1.0);
        lb.request_start(&peer_id);

        let load = lb.get_peer_load(&peer_id).unwrap();
        assert_eq!(load.active_connections, 1);
        assert_eq!(load.total_requests, 1);

        lb.request_end(&peer_id, Duration::from_millis(50), true);

        let load = lb.get_peer_load(&peer_id).unwrap();
        assert_eq!(load.active_connections, 0);
        assert!(load.avg_response_time_ms > 0.0);
    }

    #[test]
    fn test_health_filtering() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        lb.add_peer(peer1, 1.0);
        lb.add_peer(peer2, 1.0);

        lb.set_peer_health(&peer1, false);

        // Only healthy peer should be selected
        let selected = lb.select_peer(None);
        assert_eq!(selected, Some(peer2));
    }

    #[test]
    fn test_session_affinity() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        lb.set_session_affinity(true, Duration::from_secs(60));

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        lb.add_peer(peer1, 1.0);
        lb.add_peer(peer2, 1.0);

        let session_id = "test-session";
        let first = lb.select_peer(Some(session_id));
        let second = lb.select_peer(Some(session_id));

        // Should get same peer for same session
        assert_eq!(first, second);
    }

    #[test]
    fn test_weighted_round_robin() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::WeightedRoundRobin);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        lb.add_peer(peer1, 2.0); // Higher weight
        lb.add_peer(peer2, 1.0);

        let mut peer1_count = 0;
        let mut peer2_count = 0;

        for _ in 0..30 {
            match lb.select_peer(None) {
                Some(p) if p == peer1 => peer1_count += 1,
                Some(p) if p == peer2 => peer2_count += 1,
                _ => {}
            }
        }

        // peer1 should be selected more often due to higher weight
        assert!(peer1_count > peer2_count);
    }

    #[test]
    fn test_stats() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        lb.add_peer(peer1, 1.0);
        lb.add_peer(peer2, 1.0);
        lb.request_start(&peer1);

        let stats = lb.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.healthy_peers, 2);
        assert_eq!(stats.total_connections, 1);
    }

    #[test]
    fn test_cleanup_sessions() {
        let lb = LoadBalancer::new(LoadBalancingAlgorithm::RoundRobin);
        lb.set_session_affinity(true, Duration::from_millis(50));

        let peer_id = PeerId::random();
        lb.add_peer(peer_id, 1.0);

        lb.select_peer(Some("session1"));
        lb.select_peer(Some("session2"));

        std::thread::sleep(Duration::from_millis(100));
        let cleaned = lb.cleanup_sessions();
        assert_eq!(cleaned, 2);
    }
}
