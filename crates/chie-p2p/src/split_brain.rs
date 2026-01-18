// SPDX-License-Identifier: MIT OR Apache-2.0
//! Split-brain prevention module for network partitions
//!
//! This module provides mechanisms to prevent split-brain scenarios where network
//! partitions could lead to inconsistent state across different parts of the network.
//!
//! # Features
//!
//! - Quorum-based consensus for critical operations
//! - Leader election during partitions
//! - Read-only mode enforcement for minority partitions
//! - Automatic partition healing detection
//! - Conflict resolution strategies
//!
//! # Example
//!
//! ```
//! use chie_p2p::split_brain::{SplitBrainPrevention, QuorumConfig, ConflictResolution, NetworkMode};
//!
//! let config = QuorumConfig {
//!     min_quorum_size: 3,
//!     quorum_percentage: 0.51,
//!     ..Default::default()
//! };
//!
//! let mut sbp = SplitBrainPrevention::new(config);
//!
//! // Add peers to track quorum - add enough peers at once to maintain quorum
//! sbp.add_peer("peer1");
//! sbp.add_peer("peer2");
//! sbp.add_peer("peer3");
//! sbp.add_peer("peer4");
//! sbp.add_peer("peer5");
//!
//! // With 5 peers, we have quorum
//! assert!(sbp.has_quorum());
//! ```

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Configuration for quorum-based split-brain prevention
#[derive(Debug, Clone)]
pub struct QuorumConfig {
    /// Minimum number of peers required for quorum
    pub min_quorum_size: usize,
    /// Percentage of total network required for quorum (0.0-1.0)
    pub quorum_percentage: f64,
    /// Timeout for leader election
    pub election_timeout: Duration,
    /// Heartbeat interval for leader
    pub heartbeat_interval: Duration,
    /// Maximum time to wait for partition healing
    pub partition_heal_timeout: Duration,
    /// Enable automatic read-only mode when quorum is lost
    pub auto_readonly_mode: bool,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            min_quorum_size: 3,
            quorum_percentage: 0.51, // 51% majority
            election_timeout: Duration::from_secs(5),
            heartbeat_interval: Duration::from_secs(1),
            partition_heal_timeout: Duration::from_secs(30),
            auto_readonly_mode: true,
        }
    }
}

/// Network mode based on partition status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Normal operation with quorum
    Normal,
    /// Read-only mode (quorum lost)
    ReadOnly,
    /// Recovery mode (partition healing)
    Recovery,
    /// Partitioned (minority side)
    Partitioned,
}

/// Leader election state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaderState {
    /// Following a leader
    Follower,
    /// Candidate for leadership
    Candidate,
    /// Current leader
    Leader,
    /// No leader elected
    None,
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Last write wins (based on timestamp)
    LastWriteWins,
    /// Highest peer ID wins
    HighestPeerWins,
    /// Keep both versions (require manual merge)
    KeepBoth,
    /// Reject conflicts (require manual resolution)
    RejectConflict,
}

/// Partition event
#[derive(Debug, Clone)]
pub struct PartitionEvent {
    /// Timestamp of event
    pub timestamp: Instant,
    /// Peers in our partition
    pub our_peers: HashSet<String>,
    /// Total network size before partition
    pub total_network_size: usize,
    /// Whether we have quorum
    pub has_quorum: bool,
}

/// Split-brain prevention manager
#[derive(Debug)]
pub struct SplitBrainPrevention {
    config: QuorumConfig,
    /// All known peers in the network
    known_peers: HashSet<String>,
    /// Currently reachable peers
    reachable_peers: HashSet<String>,
    /// Current network mode
    mode: NetworkMode,
    /// Leader election state
    leader_state: LeaderState,
    /// Current leader ID
    current_leader: Option<String>,
    /// Last heartbeat from leader
    last_leader_heartbeat: Option<Instant>,
    /// Election term number
    term: u64,
    /// Votes received in current term
    votes_received: HashSet<String>,
    /// Partition history
    partition_events: Vec<PartitionEvent>,
    /// Conflict resolution strategy
    conflict_resolution: ConflictResolution,
    /// Operations blocked count
    operations_blocked: u64,
    /// Conflicts detected count
    conflicts_detected: u64,
    /// Last mode change
    last_mode_change: Instant,
}

impl SplitBrainPrevention {
    /// Create a new split-brain prevention manager
    pub fn new(config: QuorumConfig) -> Self {
        Self {
            config,
            known_peers: HashSet::new(),
            reachable_peers: HashSet::new(),
            mode: NetworkMode::Normal,
            leader_state: LeaderState::None,
            current_leader: None,
            last_leader_heartbeat: None,
            term: 0,
            votes_received: HashSet::new(),
            partition_events: Vec::new(),
            conflict_resolution: ConflictResolution::LastWriteWins,
            operations_blocked: 0,
            conflicts_detected: 0,
            last_mode_change: Instant::now(),
        }
    }

    /// Add a peer to the known peers set
    pub fn add_peer(&mut self, peer_id: impl Into<String>) {
        let peer_id = peer_id.into();
        self.known_peers.insert(peer_id.clone());
        self.reachable_peers.insert(peer_id);
        self.update_network_mode();
    }

    /// Remove a peer from known peers
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.known_peers.remove(peer_id);
        self.reachable_peers.remove(peer_id);
        self.update_network_mode();
    }

    /// Mark a peer as unreachable
    pub fn mark_unreachable(&mut self, peer_id: &str) {
        self.reachable_peers.remove(peer_id);
        self.update_network_mode();
    }

    /// Mark a peer as reachable
    pub fn mark_reachable(&mut self, peer_id: &str) {
        if self.known_peers.contains(peer_id) {
            self.reachable_peers.insert(peer_id.to_string());
            self.update_network_mode();
        }
    }

    /// Check if we can accept write operations
    pub fn can_accept_writes(&self) -> bool {
        matches!(self.mode, NetworkMode::Normal)
    }

    /// Check if we can accept read operations
    pub fn can_accept_reads(&self) -> bool {
        !matches!(self.mode, NetworkMode::Partitioned)
    }

    /// Get current network mode
    pub fn mode(&self) -> NetworkMode {
        self.mode
    }

    /// Get leader state
    pub fn leader_state(&self) -> LeaderState {
        self.leader_state
    }

    /// Get current leader
    pub fn current_leader(&self) -> Option<&str> {
        self.current_leader.as_deref()
    }

    /// Check if we have quorum
    pub fn has_quorum(&self) -> bool {
        let reachable_count = self.reachable_peers.len();
        let total_count = self.known_peers.len().max(1);

        let percentage = reachable_count as f64 / total_count as f64;

        reachable_count >= self.config.min_quorum_size
            && percentage >= self.config.quorum_percentage
    }

    /// Update network mode based on current state
    fn update_network_mode(&mut self) {
        let has_quorum = self.has_quorum();
        let old_mode = self.mode;

        self.mode = if has_quorum {
            match old_mode {
                NetworkMode::Partitioned | NetworkMode::ReadOnly => {
                    // Partition healing detected
                    NetworkMode::Recovery
                }
                _ => NetworkMode::Normal,
            }
        } else if self.config.auto_readonly_mode {
            NetworkMode::ReadOnly
        } else {
            NetworkMode::Partitioned
        };

        if old_mode != self.mode {
            self.last_mode_change = Instant::now();

            // Record partition event only if we transitioned from a healthy state to partitioned
            // and we have enough peers (don't record during initial setup)
            let was_healthy = matches!(old_mode, NetworkMode::Normal | NetworkMode::Recovery);
            let is_partitioned =
                matches!(self.mode, NetworkMode::ReadOnly | NetworkMode::Partitioned);
            let has_enough_peers = self.known_peers.len() >= self.config.min_quorum_size;

            if !has_quorum && was_healthy && is_partitioned && has_enough_peers {
                self.partition_events.push(PartitionEvent {
                    timestamp: Instant::now(),
                    our_peers: self.reachable_peers.clone(),
                    total_network_size: self.known_peers.len(),
                    has_quorum,
                });
            }
        }
    }

    /// Start leader election
    pub fn start_election(&mut self, our_peer_id: impl Into<String>) {
        self.term += 1;
        self.leader_state = LeaderState::Candidate;
        self.votes_received.clear();
        let our_peer_id = our_peer_id.into();
        self.votes_received.insert(our_peer_id); // Vote for ourselves
    }

    /// Record a vote for current election
    pub fn record_vote(&mut self, voter_id: impl Into<String>) -> bool {
        self.votes_received.insert(voter_id.into());

        // Check if we won the election
        let votes = self.votes_received.len();
        let total = self.reachable_peers.len().max(1);

        if votes as f64 / total as f64 > 0.5 {
            self.leader_state = LeaderState::Leader;
            true
        } else {
            false
        }
    }

    /// Process heartbeat from leader
    pub fn process_leader_heartbeat(&mut self, leader_id: impl Into<String>, term: u64) {
        let leader_id = leader_id.into();

        if term >= self.term {
            self.term = term;
            self.leader_state = LeaderState::Follower;
            self.current_leader = Some(leader_id);
            self.last_leader_heartbeat = Some(Instant::now());
        }
    }

    /// Check if leader heartbeat has timed out
    pub fn is_leader_timeout(&self) -> bool {
        if let Some(last_hb) = self.last_leader_heartbeat {
            last_hb.elapsed() > self.config.election_timeout
        } else {
            true
        }
    }

    /// Attempt to resolve conflict
    pub fn resolve_conflict(
        &mut self,
        value1: &str,
        timestamp1: Instant,
        value2: &str,
        timestamp2: Instant,
    ) -> Result<String, &'static str> {
        self.conflicts_detected += 1;

        match self.conflict_resolution {
            ConflictResolution::LastWriteWins => Ok(if timestamp1 > timestamp2 {
                value1.to_string()
            } else {
                value2.to_string()
            }),
            ConflictResolution::HighestPeerWins => Ok(if value1 > value2 {
                value1.to_string()
            } else {
                value2.to_string()
            }),
            ConflictResolution::KeepBoth => Err("Manual merge required"),
            ConflictResolution::RejectConflict => Err("Conflict detected, operation rejected"),
        }
    }

    /// Set conflict resolution strategy
    pub fn set_conflict_resolution(&mut self, strategy: ConflictResolution) {
        self.conflict_resolution = strategy;
    }

    /// Get partition history
    pub fn partition_history(&self) -> &[PartitionEvent] {
        &self.partition_events
    }

    /// Get number of operations blocked
    pub fn operations_blocked(&self) -> u64 {
        self.operations_blocked
    }

    /// Get number of conflicts detected
    pub fn conflicts_detected(&self) -> u64 {
        self.conflicts_detected
    }

    /// Record a blocked operation
    pub fn record_blocked_operation(&mut self) {
        self.operations_blocked += 1;
    }

    /// Complete recovery and return to normal mode
    pub fn complete_recovery(&mut self) {
        if self.mode == NetworkMode::Recovery && self.has_quorum() {
            self.mode = NetworkMode::Normal;
            self.last_mode_change = Instant::now();
        }
    }

    /// Get time since last mode change
    pub fn time_since_mode_change(&self) -> Duration {
        self.last_mode_change.elapsed()
    }

    /// Get reachable peers count
    pub fn reachable_peers_count(&self) -> usize {
        self.reachable_peers.len()
    }

    /// Get total known peers count
    pub fn total_peers_count(&self) -> usize {
        self.known_peers.len()
    }

    /// Get current election term
    pub fn current_term(&self) -> u64 {
        self.term
    }

    /// Check if partition has healed
    pub fn is_partition_healed(&self) -> bool {
        matches!(self.mode, NetworkMode::Recovery | NetworkMode::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_split_brain_prevention() {
        let config = QuorumConfig::default();
        let sbp = SplitBrainPrevention::new(config);

        assert_eq!(sbp.mode(), NetworkMode::Normal);
        assert_eq!(sbp.leader_state(), LeaderState::None);
        assert!(sbp.current_leader().is_none());
    }

    #[test]
    fn test_add_remove_peers() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        assert_eq!(sbp.total_peers_count(), 2);
        assert_eq!(sbp.reachable_peers_count(), 2);

        sbp.remove_peer("peer1");
        assert_eq!(sbp.total_peers_count(), 1);
        assert_eq!(sbp.reachable_peers_count(), 1);
    }

    #[test]
    fn test_quorum_check() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            min_quorum_size: 2,
            quorum_percentage: 0.51,
            ..Default::default()
        });

        sbp.add_peer("peer1");
        assert!(!sbp.has_quorum()); // Only 1 peer, need 2

        sbp.add_peer("peer2");
        assert!(sbp.has_quorum()); // 2 peers, meets minimum

        sbp.add_peer("peer3");
        assert!(sbp.has_quorum()); // 3 peers, good quorum

        sbp.mark_unreachable("peer2");
        assert!(sbp.has_quorum()); // 2/3 = 67% > 51%

        sbp.mark_unreachable("peer3");
        assert!(!sbp.has_quorum()); // Only 1 reachable, below minimum
    }

    #[test]
    fn test_network_mode_transitions() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            min_quorum_size: 2,
            quorum_percentage: 0.51,
            auto_readonly_mode: true,
            ..Default::default()
        });

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        sbp.add_peer("peer3");
        assert_eq!(sbp.mode(), NetworkMode::Normal);

        // Lose quorum
        sbp.mark_unreachable("peer2");
        sbp.mark_unreachable("peer3");
        assert_eq!(sbp.mode(), NetworkMode::ReadOnly);

        // Regain quorum
        sbp.mark_reachable("peer2");
        assert_eq!(sbp.mode(), NetworkMode::Recovery);

        // Complete recovery
        sbp.complete_recovery();
        assert_eq!(sbp.mode(), NetworkMode::Normal);
    }

    #[test]
    fn test_can_accept_operations() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            min_quorum_size: 2,
            quorum_percentage: 0.51,
            auto_readonly_mode: true,
            ..Default::default()
        });

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        sbp.add_peer("peer3");

        assert!(sbp.can_accept_writes());
        assert!(sbp.can_accept_reads());

        // Lose quorum
        sbp.mark_unreachable("peer2");
        sbp.mark_unreachable("peer3");

        assert!(!sbp.can_accept_writes()); // No writes in read-only mode
        assert!(sbp.can_accept_reads()); // Can still read
    }

    #[test]
    fn test_leader_election() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        sbp.add_peer("peer3");

        assert_eq!(sbp.leader_state(), LeaderState::None);

        sbp.start_election("peer1");
        assert_eq!(sbp.leader_state(), LeaderState::Candidate);
        assert_eq!(sbp.current_term(), 1);

        // Receive votes
        let won = sbp.record_vote("peer2");
        assert!(won); // 2/3 votes = won
        assert_eq!(sbp.leader_state(), LeaderState::Leader);
    }

    #[test]
    fn test_leader_heartbeat() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");

        sbp.process_leader_heartbeat("peer2", 1);
        assert_eq!(sbp.leader_state(), LeaderState::Follower);
        assert_eq!(sbp.current_leader(), Some("peer2"));
        assert!(!sbp.is_leader_timeout());
    }

    #[test]
    fn test_leader_timeout() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            election_timeout: Duration::from_millis(50),
            ..Default::default()
        });

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");

        sbp.process_leader_heartbeat("peer2", 1);
        assert!(!sbp.is_leader_timeout());

        thread::sleep(Duration::from_millis(60));
        assert!(sbp.is_leader_timeout());
    }

    #[test]
    fn test_conflict_resolution_last_write_wins() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());
        sbp.set_conflict_resolution(ConflictResolution::LastWriteWins);

        let t1 = Instant::now();
        thread::sleep(Duration::from_millis(10));
        let t2 = Instant::now();

        let result = sbp.resolve_conflict("value1", t1, "value2", t2);
        assert_eq!(result.unwrap(), "value2"); // t2 is later
        assert_eq!(sbp.conflicts_detected(), 1);
    }

    #[test]
    fn test_conflict_resolution_highest_peer_wins() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());
        sbp.set_conflict_resolution(ConflictResolution::HighestPeerWins);

        let t1 = Instant::now();
        let t2 = Instant::now();

        let result = sbp.resolve_conflict("peer1", t1, "peer2", t2);
        assert_eq!(result.unwrap(), "peer2"); // "peer2" > "peer1"
    }

    #[test]
    fn test_conflict_resolution_reject() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());
        sbp.set_conflict_resolution(ConflictResolution::RejectConflict);

        let t1 = Instant::now();
        let t2 = Instant::now();

        let result = sbp.resolve_conflict("value1", t1, "value2", t2);
        assert!(result.is_err());
    }

    #[test]
    fn test_partition_history() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            min_quorum_size: 2,
            quorum_percentage: 0.51,
            auto_readonly_mode: true,
            ..Default::default()
        });

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        sbp.add_peer("peer3");

        assert_eq!(sbp.partition_history().len(), 0);

        // Cause partition
        sbp.mark_unreachable("peer2");
        sbp.mark_unreachable("peer3");

        assert_eq!(sbp.partition_history().len(), 1);
        let event = &sbp.partition_history()[0];
        assert_eq!(event.total_network_size, 3);
        assert!(!event.has_quorum);
    }

    #[test]
    fn test_operations_blocked() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig::default());

        assert_eq!(sbp.operations_blocked(), 0);

        sbp.record_blocked_operation();
        sbp.record_blocked_operation();

        assert_eq!(sbp.operations_blocked(), 2);
    }

    #[test]
    fn test_partition_healing() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            min_quorum_size: 2,
            quorum_percentage: 0.51,
            auto_readonly_mode: true,
            ..Default::default()
        });

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        sbp.add_peer("peer3");

        // Partition
        sbp.mark_unreachable("peer2");
        sbp.mark_unreachable("peer3");
        assert!(!sbp.is_partition_healed());

        // Heal
        sbp.mark_reachable("peer2");
        assert_eq!(sbp.mode(), NetworkMode::Recovery);
        assert!(sbp.is_partition_healed());

        sbp.complete_recovery();
        assert_eq!(sbp.mode(), NetworkMode::Normal);
    }

    #[test]
    fn test_time_since_mode_change() {
        let mut sbp = SplitBrainPrevention::new(QuorumConfig {
            min_quorum_size: 2,
            quorum_percentage: 0.51,
            auto_readonly_mode: true,
            ..Default::default()
        });

        sbp.add_peer("peer1");
        sbp.add_peer("peer2");
        sbp.add_peer("peer3");

        thread::sleep(Duration::from_millis(50));

        // Mode change
        sbp.mark_unreachable("peer2");
        sbp.mark_unreachable("peer3");

        let elapsed = sbp.time_since_mode_change();
        assert!(elapsed < Duration::from_millis(100));
    }
}
