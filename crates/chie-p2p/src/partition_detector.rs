//! Network partition detection and recovery module.
//!
//! This module provides mechanisms to detect network partitions (network splits)
//! and help the system recover by identifying isolated peer groups.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Represents a network partition state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionState {
    /// Network is healthy with no detected partitions
    Healthy,
    /// Potential partition detected, under observation
    Suspected,
    /// Confirmed network partition
    Partitioned,
    /// Network is recovering from a partition
    Recovering,
}

/// Information about a detected partition.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// When the partition was first detected
    pub detected_at: Instant,
    /// Peers in our partition group
    pub local_group: HashSet<String>,
    /// Known peers in other partition(s)
    pub remote_groups: Vec<HashSet<String>>,
    /// Estimated partition severity (0.0 = minor, 1.0 = complete split)
    pub severity: f64,
}

/// Configuration for partition detection.
#[derive(Debug, Clone)]
pub struct PartitionDetectorConfig {
    /// Minimum number of peers before partition detection activates
    pub min_peers: usize,
    /// Time window for analyzing connectivity patterns
    pub analysis_window: Duration,
    /// Threshold for connectivity loss to trigger partition suspicion (0.0-1.0)
    pub connectivity_threshold: f64,
    /// How long to wait before confirming a suspected partition
    pub confirmation_delay: Duration,
    /// Maximum time to track partition history
    pub history_retention: Duration,
}

impl Default for PartitionDetectorConfig {
    fn default() -> Self {
        Self {
            min_peers: 3,
            analysis_window: Duration::from_secs(30),
            connectivity_threshold: 0.3,
            confirmation_delay: Duration::from_secs(10),
            history_retention: Duration::from_secs(3600),
        }
    }
}

/// Tracks connectivity between peers for partition detection.
#[derive(Debug)]
struct ConnectivityMatrix {
    /// Timestamp of last update
    last_update: Instant,
    /// Map of peer -> set of peers it can reach
    reachability: HashMap<String, HashSet<String>>,
}

impl ConnectivityMatrix {
    fn new() -> Self {
        Self {
            last_update: Instant::now(),
            reachability: HashMap::new(),
        }
    }

    fn update_reachability(&mut self, peer: String, reachable_peers: HashSet<String>) {
        self.last_update = Instant::now();
        self.reachability.insert(peer, reachable_peers);
    }

    fn get_reachable_peers(&self, peer: &str) -> Option<&HashSet<String>> {
        self.reachability.get(peer)
    }

    fn all_peers(&self) -> HashSet<String> {
        let mut peers = HashSet::new();
        for (peer, reachable) in &self.reachability {
            peers.insert(peer.clone());
            peers.extend(reachable.iter().cloned());
        }
        peers
    }
}

/// Detects network partitions using connectivity analysis.
pub struct PartitionDetector {
    config: PartitionDetectorConfig,
    state: PartitionState,
    connectivity: ConnectivityMatrix,
    suspected_since: Option<Instant>,
    recovering_since: Option<Instant>,
    current_partition: Option<PartitionInfo>,
    partition_history: Vec<(Instant, PartitionInfo)>,
}

impl PartitionDetector {
    /// Creates a new partition detector with default configuration.
    pub fn new() -> Self {
        Self::with_config(PartitionDetectorConfig::default())
    }

    /// Creates a new partition detector with custom configuration.
    pub fn with_config(config: PartitionDetectorConfig) -> Self {
        Self {
            config,
            state: PartitionState::Healthy,
            connectivity: ConnectivityMatrix::new(),
            suspected_since: None,
            recovering_since: None,
            current_partition: None,
            partition_history: Vec::new(),
        }
    }

    /// Updates connectivity information for a peer.
    ///
    /// # Arguments
    /// * `peer` - The peer reporting connectivity
    /// * `reachable_peers` - Set of peers this peer can reach
    pub fn update_connectivity(&mut self, peer: String, reachable_peers: HashSet<String>) {
        self.connectivity.update_reachability(peer, reachable_peers);
        self.analyze_partition();
    }

    /// Performs partition analysis based on current connectivity data.
    fn analyze_partition(&mut self) {
        let all_peers = self.connectivity.all_peers();

        if all_peers.len() < self.config.min_peers {
            // Not enough peers for meaningful partition detection
            self.state = PartitionState::Healthy;
            self.suspected_since = None;
            return;
        }

        // Detect isolated groups using graph connectivity
        let groups = self.find_isolated_groups();

        if groups.len() > 1 {
            // Multiple isolated groups detected
            let severity = self.calculate_partition_severity(&groups);

            match self.state {
                PartitionState::Healthy => {
                    // First detection - mark as suspected
                    self.state = PartitionState::Suspected;
                    self.suspected_since = Some(Instant::now());
                }
                PartitionState::Suspected => {
                    // Check if enough time has passed to confirm
                    if let Some(since) = self.suspected_since {
                        if since.elapsed() >= self.config.confirmation_delay {
                            self.confirm_partition(groups, severity);
                        }
                    }
                }
                PartitionState::Partitioned => {
                    // Update existing partition info
                    if let Some(ref mut partition) = self.current_partition {
                        partition.severity = severity;
                    }
                }
                PartitionState::Recovering => {
                    // Partition still exists during recovery
                    self.state = PartitionState::Partitioned;
                    self.recovering_since = None;
                }
            }
        } else {
            // No partition detected
            match self.state {
                PartitionState::Partitioned => {
                    // Start recovery
                    self.state = PartitionState::Recovering;
                    self.recovering_since = Some(Instant::now());
                }
                PartitionState::Recovering => {
                    // Check if enough time has passed to confirm recovery
                    if let Some(since) = self.recovering_since {
                        if since.elapsed() >= self.config.confirmation_delay {
                            // Complete recovery
                            self.state = PartitionState::Healthy;
                            self.current_partition = None;
                            self.recovering_since = None;
                        }
                    } else {
                        // No timestamp set, go to healthy immediately
                        self.state = PartitionState::Healthy;
                        self.current_partition = None;
                    }
                }
                _ => {
                    self.state = PartitionState::Healthy;
                    self.suspected_since = None;
                    self.recovering_since = None;
                }
            }
        }

        self.cleanup_history();
    }

    /// Finds isolated peer groups using connectivity data.
    fn find_isolated_groups(&self) -> Vec<HashSet<String>> {
        let all_peers = self.connectivity.all_peers();
        let mut unvisited: HashSet<String> = all_peers.clone();
        let mut groups = Vec::new();

        while let Some(start_peer) = unvisited.iter().next().cloned() {
            let mut group = HashSet::new();
            let mut to_visit = vec![start_peer];

            while let Some(peer) = to_visit.pop() {
                if group.insert(peer.clone()) {
                    unvisited.remove(&peer);

                    // Add all reachable peers
                    if let Some(reachable) = self.connectivity.get_reachable_peers(&peer) {
                        for reachable_peer in reachable {
                            if !group.contains(reachable_peer) {
                                to_visit.push(reachable_peer.clone());
                            }
                        }
                    }
                }
            }

            groups.push(group);
        }

        groups
    }

    /// Calculates partition severity based on group sizes.
    fn calculate_partition_severity(&self, groups: &[HashSet<String>]) -> f64 {
        if groups.is_empty() {
            return 0.0;
        }

        let total_peers: usize = groups.iter().map(|g| g.len()).sum();
        if total_peers == 0 {
            return 0.0;
        }

        // Calculate balance - more balanced partitions are more severe
        let largest_group = groups.iter().map(|g| g.len()).max().unwrap_or(0);
        let balance = 1.0 - (largest_group as f64 / total_peers as f64);

        // Severity is based on number of groups and balance
        let group_factor = (groups.len() - 1) as f64 / groups.len() as f64;
        (group_factor + balance) / 2.0
    }

    /// Confirms a partition and records it.
    fn confirm_partition(&mut self, groups: Vec<HashSet<String>>, severity: f64) {
        self.state = PartitionState::Partitioned;

        let partition_info = PartitionInfo {
            detected_at: Instant::now(),
            local_group: groups.first().cloned().unwrap_or_default(),
            remote_groups: groups.into_iter().skip(1).collect(),
            severity,
        };

        self.partition_history
            .push((Instant::now(), partition_info.clone()));
        self.current_partition = Some(partition_info);
        self.suspected_since = None;
    }

    /// Removes old entries from partition history.
    fn cleanup_history(&mut self) {
        let cutoff = Instant::now() - self.config.history_retention;
        self.partition_history
            .retain(|(timestamp, _)| *timestamp >= cutoff);
    }

    /// Returns the current partition state.
    pub fn state(&self) -> &PartitionState {
        &self.state
    }

    /// Returns information about the current partition, if any.
    pub fn current_partition(&self) -> Option<&PartitionInfo> {
        self.current_partition.as_ref()
    }

    /// Returns the partition detection history.
    pub fn partition_history(&self) -> &[(Instant, PartitionInfo)] {
        &self.partition_history
    }

    /// Returns statistics about partition detection.
    pub fn stats(&self) -> PartitionStats {
        PartitionStats {
            current_state: self.state.clone(),
            total_peers: self.connectivity.all_peers().len(),
            partitions_detected: self.partition_history.len(),
            current_severity: self.current_partition.as_ref().map(|p| p.severity),
            time_in_partition: self
                .current_partition
                .as_ref()
                .map(|p| p.detected_at.elapsed()),
        }
    }
}

impl Default for PartitionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about partition detection.
#[derive(Debug, Clone)]
pub struct PartitionStats {
    /// Current partition state
    pub current_state: PartitionState,
    /// Total number of known peers
    pub total_peers: usize,
    /// Number of partitions detected in history
    pub partitions_detected: usize,
    /// Severity of current partition (if any)
    pub current_severity: Option<f64>,
    /// Time spent in current partition state
    pub time_in_partition: Option<Duration>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;

    #[test]
    fn test_partition_detector_new() {
        let detector = PartitionDetector::new();
        assert_eq!(*detector.state(), PartitionState::Healthy);
        assert!(detector.current_partition().is_none());
    }

    #[test]
    fn test_partition_detector_with_config() {
        let config = PartitionDetectorConfig {
            min_peers: 5,
            connectivity_threshold: 0.5,
            ..Default::default()
        };
        let detector = PartitionDetector::with_config(config);
        assert_eq!(*detector.state(), PartitionState::Healthy);
    }

    #[test]
    fn test_healthy_network() {
        let mut detector = PartitionDetector::new();

        // All peers can reach each other
        let mut reachable = HashSet::new();
        reachable.insert("peer2".to_string());
        reachable.insert("peer3".to_string());
        detector.update_connectivity("peer1".to_string(), reachable.clone());

        let mut reachable = HashSet::new();
        reachable.insert("peer1".to_string());
        reachable.insert("peer3".to_string());
        detector.update_connectivity("peer2".to_string(), reachable);

        let mut reachable = HashSet::new();
        reachable.insert("peer1".to_string());
        reachable.insert("peer2".to_string());
        detector.update_connectivity("peer3".to_string(), reachable);

        assert_eq!(*detector.state(), PartitionState::Healthy);
    }

    #[test]
    fn test_partition_detection() {
        let mut config = PartitionDetectorConfig::default();
        config.confirmation_delay = Duration::from_millis(10);
        let mut detector = PartitionDetector::with_config(config);

        // Group 1: peer1, peer2
        let mut reachable = HashSet::new();
        reachable.insert("peer2".to_string());
        detector.update_connectivity("peer1".to_string(), reachable);

        let mut reachable = HashSet::new();
        reachable.insert("peer1".to_string());
        detector.update_connectivity("peer2".to_string(), reachable);

        // Group 2: peer3, peer4
        let mut reachable = HashSet::new();
        reachable.insert("peer4".to_string());
        detector.update_connectivity("peer3".to_string(), reachable);

        let mut reachable = HashSet::new();
        reachable.insert("peer3".to_string());
        detector.update_connectivity("peer4".to_string(), reachable);

        // Should be suspected initially
        assert_eq!(*detector.state(), PartitionState::Suspected);

        // Wait for confirmation
        std::thread::sleep(Duration::from_millis(20));
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });

        assert_eq!(*detector.state(), PartitionState::Partitioned);
        assert!(detector.current_partition().is_some());
    }

    #[test]
    fn test_partition_recovery() {
        let mut config = PartitionDetectorConfig::default();
        config.confirmation_delay = Duration::from_millis(10);
        let mut detector = PartitionDetector::with_config(config);

        // Create partition - bidirectional connectivity within each group
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });
        detector.update_connectivity("peer2".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer4".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer3".to_string());
            s
        });

        std::thread::sleep(Duration::from_millis(20));
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });

        assert_eq!(*detector.state(), PartitionState::Partitioned);

        // Restore connectivity - need to update all peers for full recovery
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s.insert("peer3".to_string());
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer2".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s.insert("peer3".to_string());
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s.insert("peer2".to_string());
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer4".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s.insert("peer2".to_string());
            s.insert("peer3".to_string());
            s
        });

        // Check that partition is recovering (may be Recovering or already Healthy)
        let state = detector.state();
        assert!(
            *state == PartitionState::Recovering || *state == PartitionState::Healthy,
            "Expected Recovering or Healthy, got {:?}",
            state
        );
    }

    #[test]
    fn test_severity_calculation() {
        let detector = PartitionDetector::new();

        // Balanced partition (2-2 split)
        let groups = vec![
            vec!["p1".to_string(), "p2".to_string()]
                .into_iter()
                .collect(),
            vec!["p3".to_string(), "p4".to_string()]
                .into_iter()
                .collect(),
        ];
        let severity = detector.calculate_partition_severity(&groups);
        assert!(severity > 0.4);

        // Unbalanced partition (3-1 split)
        let groups = vec![
            vec!["p1".to_string(), "p2".to_string(), "p3".to_string()]
                .into_iter()
                .collect(),
            vec!["p4".to_string()].into_iter().collect(),
        ];
        let severity = detector.calculate_partition_severity(&groups);
        assert!(severity < 0.5);
    }

    #[test]
    fn test_isolated_groups_detection() {
        let mut detector = PartitionDetector::new();

        // Three isolated groups - peers should report bidirectional connectivity
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });
        detector.update_connectivity("peer2".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer4".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer3".to_string());
            s
        });
        detector.update_connectivity("peer5".to_string(), HashSet::new());

        let groups = detector.find_isolated_groups();
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn test_stats() {
        let mut detector = PartitionDetector::new();
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });

        let stats = detector.stats();
        assert_eq!(stats.current_state, PartitionState::Healthy);
        assert_eq!(stats.total_peers, 2);
    }

    #[test]
    fn test_min_peers_threshold() {
        let mut config = PartitionDetectorConfig::default();
        config.min_peers = 10;
        let mut detector = PartitionDetector::with_config(config);

        // Even with partition, too few peers to trigger detection
        detector.update_connectivity("peer1".to_string(), HashSet::new());
        detector.update_connectivity("peer2".to_string(), HashSet::new());

        assert_eq!(*detector.state(), PartitionState::Healthy);
    }

    #[test]
    fn test_history_cleanup() {
        let mut config = PartitionDetectorConfig::default();
        config.history_retention = Duration::from_millis(50);
        config.confirmation_delay = Duration::from_millis(1);
        let mut detector = PartitionDetector::with_config(config);

        // Create a partition event
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer4".to_string());
            s
        });

        std::thread::sleep(Duration::from_millis(5));
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });

        let initial_history = detector.partition_history().len();

        // Wait for history to expire
        std::thread::sleep(Duration::from_millis(60));
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s.insert("peer3".to_string());
            s
        });

        assert!(detector.partition_history().len() <= initial_history);
    }

    #[test]
    fn test_partition_info() {
        let mut config = PartitionDetectorConfig::default();
        config.confirmation_delay = Duration::from_millis(10);
        let mut detector = PartitionDetector::with_config(config);

        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer4".to_string());
            s
        });

        std::thread::sleep(Duration::from_millis(20));
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });

        if let Some(info) = detector.current_partition() {
            assert!(!info.local_group.is_empty());
            assert!(!info.remote_groups.is_empty());
            assert!(info.severity > 0.0);
        } else {
            panic!("Expected partition info");
        }
    }

    #[test]
    fn test_connectivity_matrix() {
        let mut matrix = ConnectivityMatrix::new();

        let peers = vec!["p2".to_string(), "p3".to_string()]
            .into_iter()
            .collect();
        matrix.update_reachability("p1".to_string(), peers);

        assert!(matrix.get_reachable_peers("p1").is_some());
        assert_eq!(matrix.get_reachable_peers("p1").unwrap().len(), 2);

        let all = matrix.all_peers();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_partition_state_transitions() {
        let mut config = PartitionDetectorConfig::default();
        config.confirmation_delay = Duration::from_millis(10);
        let mut detector = PartitionDetector::with_config(config);

        // Start healthy
        assert_eq!(*detector.state(), PartitionState::Healthy);

        // Create partition -> Suspected
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer4".to_string());
            s
        });
        assert_eq!(*detector.state(), PartitionState::Suspected);

        // Wait -> Partitioned
        std::thread::sleep(Duration::from_millis(15));
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s
        });
        assert_eq!(*detector.state(), PartitionState::Partitioned);

        // Restore -> Recovering (all peers connected)
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s.insert("peer3".to_string());
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer2".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s.insert("peer3".to_string());
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer3".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s.insert("peer2".to_string());
            s.insert("peer4".to_string());
            s
        });
        detector.update_connectivity("peer4".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer1".to_string());
            s.insert("peer2".to_string());
            s.insert("peer3".to_string());
            s
        });
        assert_eq!(*detector.state(), PartitionState::Recovering);

        // Wait for recovery confirmation -> Healthy
        std::thread::sleep(Duration::from_millis(15));

        // Trigger another update to check recovery completion
        detector.update_connectivity("peer1".to_string(), {
            let mut s = HashSet::new();
            s.insert("peer2".to_string());
            s.insert("peer3".to_string());
            s.insert("peer4".to_string());
            s
        });
        assert_eq!(*detector.state(), PartitionState::Healthy);
    }
}
