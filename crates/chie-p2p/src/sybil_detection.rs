//! Sybil attack detection for identifying malicious peer networks.
//!
//! This module implements detection mechanisms for Sybil attacks, where an
//! attacker creates many fake identities to gain disproportionate influence
//! in the P2P network. Detection is based on behavioral analysis, connection
//! patterns, and peer clustering.
//!
//! # Example
//!
//! ```
//! use chie_p2p::sybil_detection::{SybilDetector, DetectionConfig};
//! use std::time::Duration;
//!
//! let config = DetectionConfig {
//!     max_peers_per_ip: 3,
//!     suspicious_threshold: 0.7,
//!     ..Default::default()
//! };
//!
//! let mut detector = SybilDetector::with_config(config);
//!
//! // Register peer connections
//! detector.register_peer("peer-1", Some("192.168.1.100".to_string()));
//! detector.register_peer("peer-2", Some("192.168.1.100".to_string()));
//! detector.register_peer("peer-3", Some("192.168.1.100".to_string()));
//! detector.register_peer("peer-4", Some("192.168.1.100".to_string())); // Suspicious!
//!
//! // Check if a peer is suspicious
//! if detector.is_suspicious("peer-4") {
//!     println!("Peer-4 is part of a suspected Sybil attack!");
//! }
//!
//! // Get Sybil groups
//! let groups = detector.get_sybil_groups();
//! for group in groups {
//!     println!("Sybil group: {:?}", group.peer_ids);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Configuration for Sybil attack detection
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    /// Maximum number of peers allowed from the same IP address
    pub max_peers_per_ip: usize,
    /// Threshold for suspicious behavior (0.0 to 1.0)
    pub suspicious_threshold: f64,
    /// Time window for behavioral analysis
    pub analysis_window: Duration,
    /// Minimum peer age before evaluation (new peers are given grace period)
    pub min_peer_age: Duration,
    /// Maximum allowed connection rate (connections per minute)
    pub max_connection_rate: f64,
    /// Behavioral similarity threshold for clustering
    pub similarity_threshold: f64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            max_peers_per_ip: 3,
            suspicious_threshold: 0.7,
            analysis_window: Duration::from_secs(3600), // 1 hour
            min_peer_age: Duration::from_secs(300),     // 5 minutes
            max_connection_rate: 10.0,                  // 10 connections/minute
            similarity_threshold: 0.8,
        }
    }
}

/// Peer information for Sybil detection
#[derive(Debug, Clone)]
struct PeerInfo {
    #[allow(dead_code)]
    peer_id: String,
    #[allow(dead_code)]
    ip_address: Option<String>,
    first_seen: Instant,
    last_seen: Instant,
    connection_count: u32,
    behavior_score: f64,
    suspicious_flags: HashSet<SuspiciousFlag>,
}

/// Flags indicating suspicious behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuspiciousFlag {
    /// Multiple peers from same IP
    SharedIp,
    /// High connection rate
    HighConnectionRate,
    /// Similar behavior patterns
    SimilarBehavior,
    /// Short peer lifetime
    ShortLifetime,
    /// Coordinated activity
    CoordinatedActivity,
}

/// Detected Sybil group
#[derive(Debug, Clone)]
pub struct SybilGroup {
    /// Peer IDs in the group
    pub peer_ids: Vec<String>,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Detection reason
    pub reason: Vec<SuspiciousFlag>,
    /// Common IP address if applicable
    pub common_ip: Option<String>,
}

/// Sybil attack detector
pub struct SybilDetector {
    config: DetectionConfig,
    peers: HashMap<String, PeerInfo>,
    ip_to_peers: HashMap<String, HashSet<String>>,
    sybil_groups: Vec<SybilGroup>,
    total_connections: u64,
    last_analysis: Instant,
}

impl SybilDetector {
    /// Creates a new Sybil detector with default configuration
    pub fn new() -> Self {
        Self::with_config(DetectionConfig::default())
    }

    /// Creates a new Sybil detector with custom configuration
    pub fn with_config(config: DetectionConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            ip_to_peers: HashMap::new(),
            sybil_groups: Vec::new(),
            total_connections: 0,
            last_analysis: Instant::now(),
        }
    }

    /// Registers a new peer connection
    pub fn register_peer(&mut self, peer_id: impl Into<String>, ip_address: Option<String>) {
        let peer_id = peer_id.into();
        let now = Instant::now();

        self.total_connections += 1;

        let peer_info = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| PeerInfo {
                peer_id: peer_id.clone(),
                ip_address: ip_address.clone(),
                first_seen: now,
                last_seen: now,
                connection_count: 0,
                behavior_score: 0.5, // Neutral start
                suspicious_flags: HashSet::new(),
            });

        peer_info.connection_count += 1;
        peer_info.last_seen = now;

        // Track IP associations
        if let Some(ref ip) = ip_address {
            self.ip_to_peers
                .entry(ip.clone())
                .or_default()
                .insert(peer_id.clone());

            // Check for shared IP violations
            if let Some(peers_on_ip) = self.ip_to_peers.get(ip) {
                if peers_on_ip.len() > self.config.max_peers_per_ip {
                    for peer in peers_on_ip {
                        if let Some(p) = self.peers.get_mut(peer) {
                            p.suspicious_flags.insert(SuspiciousFlag::SharedIp);
                        }
                    }
                }
            }
        }

        // Periodic analysis
        if now.duration_since(self.last_analysis) >= self.config.analysis_window {
            self.analyze_sybil_groups();
        }
    }

    /// Records peer behavior for analysis
    pub fn record_behavior(&mut self, peer_id: &str, behavior_score: f64) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            // Update behavior score with exponential moving average
            peer.behavior_score = 0.7 * peer.behavior_score + 0.3 * behavior_score;
        }
    }

    /// Checks if a peer is suspicious
    pub fn is_suspicious(&self, peer_id: &str) -> bool {
        if let Some(peer) = self.peers.get(peer_id) {
            let suspicion_score = self.calculate_suspicion_score(peer);
            suspicion_score >= self.config.suspicious_threshold
        } else {
            false
        }
    }

    /// Gets the suspicion score for a peer (0.0 to 1.0)
    pub fn suspicion_score(&self, peer_id: &str) -> Option<f64> {
        self.peers
            .get(peer_id)
            .map(|peer| self.calculate_suspicion_score(peer))
    }

    /// Gets all detected Sybil groups
    pub fn get_sybil_groups(&self) -> &[SybilGroup] {
        &self.sybil_groups
    }

    /// Gets all suspicious peers
    pub fn get_suspicious_peers(&self) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, peer)| {
                self.calculate_suspicion_score(peer) >= self.config.suspicious_threshold
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Blocks a peer as confirmed Sybil
    pub fn mark_as_sybil(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.behavior_score = 0.0;
            peer.suspicious_flags
                .insert(SuspiciousFlag::CoordinatedActivity);
        }
    }

    /// Clears a peer's suspicious flags (false positive)
    pub fn clear_suspicion(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.suspicious_flags.clear();
            peer.behavior_score = 0.7; // Slightly elevated trust
        }
    }

    /// Gets statistics about detection
    pub fn stats(&self) -> DetectionStats {
        let suspicious_count = self.get_suspicious_peers().len();
        let total_flags: usize = self.peers.values().map(|p| p.suspicious_flags.len()).sum();

        DetectionStats {
            total_peers: self.peers.len(),
            suspicious_peers: suspicious_count,
            sybil_groups: self.sybil_groups.len(),
            total_connections: self.total_connections,
            total_suspicious_flags: total_flags,
        }
    }

    /// Clears all detection data
    pub fn clear(&mut self) {
        self.peers.clear();
        self.ip_to_peers.clear();
        self.sybil_groups.clear();
        self.total_connections = 0;
        self.last_analysis = Instant::now();
    }

    // Private helper methods

    fn calculate_suspicion_score(&self, peer: &PeerInfo) -> f64 {
        let now = Instant::now();
        let age = now.duration_since(peer.first_seen);

        // Grace period for new peers
        if age < self.config.min_peer_age {
            return 0.0;
        }

        let mut score = 0.0;

        // Factor 1: Number of suspicious flags (0.0 to 0.4)
        let flags_score = (peer.suspicious_flags.len() as f64 * 0.1).min(0.4);
        score += flags_score;

        // Factor 2: Behavior score (0.0 to 0.3)
        let behavior_score = (1.0 - peer.behavior_score) * 0.3;
        score += behavior_score;

        // Factor 3: Connection rate (0.0 to 0.3)
        let age_minutes = age.as_secs_f64() / 60.0;
        if age_minutes > 0.0 {
            let conn_rate = peer.connection_count as f64 / age_minutes;
            if conn_rate > self.config.max_connection_rate {
                score += 0.3;
            }
        }

        score.min(1.0)
    }

    fn analyze_sybil_groups(&mut self) {
        self.sybil_groups.clear();

        // Group 1: Peers sharing IPs
        for (ip, peer_ids) in &self.ip_to_peers {
            if peer_ids.len() > self.config.max_peers_per_ip {
                let confidence =
                    (peer_ids.len() as f64 / self.config.max_peers_per_ip as f64 - 1.0).min(1.0);

                self.sybil_groups.push(SybilGroup {
                    peer_ids: peer_ids.iter().cloned().collect(),
                    confidence,
                    reason: vec![SuspiciousFlag::SharedIp],
                    common_ip: Some(ip.clone()),
                });
            }
        }

        // Group 2: Peers with similar behavior patterns
        self.detect_behavioral_clusters();

        self.last_analysis = Instant::now();
    }

    fn detect_behavioral_clusters(&mut self) {
        // Simple behavioral clustering based on behavior scores
        let mut score_groups: HashMap<u32, Vec<String>> = HashMap::new();

        for (peer_id, peer) in &self.peers {
            // Discretize behavior score into buckets
            let bucket = (peer.behavior_score * 10.0) as u32;
            score_groups
                .entry(bucket)
                .or_default()
                .push(peer_id.clone());
        }

        // Identify suspiciously large groups with similar behavior
        for (_, peer_ids) in score_groups {
            if peer_ids.len() >= 5 {
                // At least 5 peers with very similar behavior
                let confidence = (peer_ids.len() as f64 / 10.0).min(0.9);

                self.sybil_groups.push(SybilGroup {
                    peer_ids,
                    confidence,
                    reason: vec![SuspiciousFlag::SimilarBehavior],
                    common_ip: None,
                });
            }
        }
    }
}

impl Default for SybilDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about Sybil detection
#[derive(Debug, Clone)]
pub struct DetectionStats {
    pub total_peers: usize,
    pub suspicious_peers: usize,
    pub sybil_groups: usize,
    pub total_connections: u64,
    pub total_suspicious_flags: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_new() {
        let detector = SybilDetector::new();
        assert_eq!(detector.peers.len(), 0);
        assert_eq!(detector.sybil_groups.len(), 0);
    }

    #[test]
    fn test_register_peer() {
        let mut detector = SybilDetector::new();
        detector.register_peer("peer-1", Some("192.168.1.1".to_string()));

        assert_eq!(detector.peers.len(), 1);
        assert_eq!(detector.total_connections, 1);
    }

    #[test]
    fn test_shared_ip_detection() {
        let config = DetectionConfig {
            max_peers_per_ip: 2,
            ..Default::default()
        };
        let mut detector = SybilDetector::with_config(config);

        detector.register_peer("peer-1", Some("192.168.1.1".to_string()));
        detector.register_peer("peer-2", Some("192.168.1.1".to_string()));
        detector.register_peer("peer-3", Some("192.168.1.1".to_string())); // Exceeds limit

        // All peers on this IP should be flagged
        assert!(
            detector
                .peers
                .get("peer-1")
                .unwrap()
                .suspicious_flags
                .contains(&SuspiciousFlag::SharedIp)
        );
        assert!(
            detector
                .peers
                .get("peer-2")
                .unwrap()
                .suspicious_flags
                .contains(&SuspiciousFlag::SharedIp)
        );
        assert!(
            detector
                .peers
                .get("peer-3")
                .unwrap()
                .suspicious_flags
                .contains(&SuspiciousFlag::SharedIp)
        );
    }

    #[test]
    fn test_is_suspicious() {
        let mut detector = SybilDetector::new();

        detector.register_peer("peer-1", Some("192.168.1.1".to_string()));

        // New peer shouldn't be suspicious yet (grace period)
        assert!(!detector.is_suspicious("peer-1"));
    }

    #[test]
    fn test_record_behavior() {
        let mut detector = SybilDetector::new();
        detector.register_peer("peer-1", None);

        detector.record_behavior("peer-1", 0.2); // Bad behavior

        let peer = detector.peers.get("peer-1").unwrap();
        assert!(peer.behavior_score < 0.5); // Should decrease from initial 0.5
    }

    #[test]
    fn test_suspicion_score() {
        let mut detector = SybilDetector::new();
        detector.register_peer("peer-1", None);

        let score = detector.suspicion_score("peer-1");
        assert!(score.is_some());
        assert!(score.unwrap() >= 0.0 && score.unwrap() <= 1.0);
    }

    #[test]
    fn test_suspicion_score_nonexistent() {
        let detector = SybilDetector::new();
        assert!(detector.suspicion_score("nonexistent").is_none());
    }

    #[test]
    fn test_mark_as_sybil() {
        let mut detector = SybilDetector::new();
        detector.register_peer("peer-1", None);

        detector.mark_as_sybil("peer-1");

        let peer = detector.peers.get("peer-1").unwrap();
        assert_eq!(peer.behavior_score, 0.0);
        assert!(
            peer.suspicious_flags
                .contains(&SuspiciousFlag::CoordinatedActivity)
        );
    }

    #[test]
    fn test_clear_suspicion() {
        let mut detector = SybilDetector::new();
        detector.register_peer("peer-1", None);
        detector.mark_as_sybil("peer-1");

        detector.clear_suspicion("peer-1");

        let peer = detector.peers.get("peer-1").unwrap();
        assert!(peer.suspicious_flags.is_empty());
        assert!(peer.behavior_score > 0.0);
    }

    #[test]
    fn test_get_suspicious_peers() {
        let config = DetectionConfig {
            max_peers_per_ip: 1,
            suspicious_threshold: 0.5,
            min_peer_age: Duration::from_secs(0), // No grace period for testing
            ..Default::default()
        };
        let mut detector = SybilDetector::with_config(config);

        detector.register_peer("peer-1", Some("192.168.1.1".to_string()));
        detector.register_peer("peer-2", Some("192.168.1.1".to_string())); // Suspicious
        detector.register_peer("peer-3", Some("192.168.1.2".to_string())); // OK

        let suspicious = detector.get_suspicious_peers();
        assert!(!suspicious.is_empty());
    }

    #[test]
    fn test_sybil_group_detection() {
        let config = DetectionConfig {
            max_peers_per_ip: 2,
            ..Default::default()
        };
        let mut detector = SybilDetector::with_config(config);

        // Create a Sybil group with shared IP
        for i in 0..5 {
            detector.register_peer(format!("peer-{}", i), Some("192.168.1.1".to_string()));
        }

        detector.analyze_sybil_groups();
        let groups = detector.get_sybil_groups();

        assert!(!groups.is_empty());
        let group = &groups[0];
        assert_eq!(group.peer_ids.len(), 5);
        assert!(group.reason.contains(&SuspiciousFlag::SharedIp));
    }

    #[test]
    fn test_stats() {
        let mut detector = SybilDetector::new();

        detector.register_peer("peer-1", None);
        detector.register_peer("peer-2", None);

        let stats = detector.stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.total_connections, 2);
    }

    #[test]
    fn test_clear() {
        let mut detector = SybilDetector::new();

        detector.register_peer("peer-1", None);
        detector.register_peer("peer-2", None);

        detector.clear();

        assert_eq!(detector.peers.len(), 0);
        assert_eq!(detector.total_connections, 0);
    }

    #[test]
    fn test_multiple_connections_same_peer() {
        let mut detector = SybilDetector::new();

        detector.register_peer("peer-1", None);
        detector.register_peer("peer-1", None);
        detector.register_peer("peer-1", None);

        let peer = detector.peers.get("peer-1").unwrap();
        assert_eq!(peer.connection_count, 3);
    }

    #[test]
    fn test_behavioral_clustering() {
        let mut detector = SybilDetector::new();

        // Create multiple peers with similar bad behavior
        for i in 0..6 {
            detector.register_peer(format!("peer-{}", i), None);
            detector.record_behavior(&format!("peer-{}", i), 0.1);
        }

        detector.analyze_sybil_groups();
        let groups = detector.get_sybil_groups();

        // Should detect behavioral cluster
        let behavioral_groups: Vec<_> = groups
            .iter()
            .filter(|g| g.reason.contains(&SuspiciousFlag::SimilarBehavior))
            .collect();

        assert!(!behavioral_groups.is_empty());
    }

    #[test]
    fn test_grace_period() {
        let config = DetectionConfig {
            min_peer_age: Duration::from_secs(300),
            suspicious_threshold: 0.5,
            ..Default::default()
        };
        let mut detector = SybilDetector::with_config(config);

        detector.register_peer("peer-1", None);
        detector.record_behavior("peer-1", 0.0); // Very bad behavior

        // Should not be suspicious due to grace period
        assert!(!detector.is_suspicious("peer-1"));
    }

    #[test]
    fn test_ip_to_peers_tracking() {
        let mut detector = SybilDetector::new();

        detector.register_peer("peer-1", Some("192.168.1.1".to_string()));
        detector.register_peer("peer-2", Some("192.168.1.1".to_string()));
        detector.register_peer("peer-3", Some("192.168.1.2".to_string()));

        assert_eq!(detector.ip_to_peers.get("192.168.1.1").unwrap().len(), 2);
        assert_eq!(detector.ip_to_peers.get("192.168.1.2").unwrap().len(), 1);
    }

    #[test]
    fn test_confidence_scaling() {
        let config = DetectionConfig {
            max_peers_per_ip: 2,
            ..Default::default()
        };
        let mut detector = SybilDetector::with_config(config);

        // More peers = higher confidence
        for i in 0..10 {
            detector.register_peer(format!("peer-{}", i), Some("192.168.1.1".to_string()));
        }

        detector.analyze_sybil_groups();
        let groups = detector.get_sybil_groups();

        assert!(!groups.is_empty());
        assert!(groups[0].confidence > 0.5);
    }
}
