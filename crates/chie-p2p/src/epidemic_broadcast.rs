//! Epidemic-style content propagation for efficient P2P dissemination.
//!
//! This module implements epidemic broadcast protocols (gossip protocols) for
//! efficient content dissemination in P2P CDN networks. Provides fast, reliable,
//! and scalable content propagation with minimal overhead.
//!
//! # Features
//!
//! - Multiple epidemic strategies (Push, Pull, Push-Pull)
//! - Probabilistic forwarding to control overhead
//! - Anti-entropy mechanisms for consistency
//! - Infection tracking and convergence detection
//! - Fanout control for optimal propagation speed
//! - Duplicate suppression
//! - TTL-based message expiration
//! - Propagation statistics and monitoring
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::epidemic_broadcast::{EpidemicBroadcaster, BroadcastConfig, EpidemicStrategy};
//!
//! let config = BroadcastConfig {
//!     strategy: EpidemicStrategy::PushPull,
//!     fanout: 6,
//!     forward_probability: 0.8,
//!     ..Default::default()
//! };
//!
//! let mut broadcaster = EpidemicBroadcaster::new(config);
//!
//! // Add peers to the network
//! broadcaster.add_peer("peer1");
//! broadcaster.add_peer("peer2");
//! broadcaster.add_peer("peer3");
//!
//! // Initiate content broadcast
//! let message_id = broadcaster.broadcast(b"content_hash_123", b"metadata");
//!
//! // Get peers to forward to
//! if let Some(peers) = broadcaster.select_forward_peers(&message_id) {
//!     for peer in peers {
//!         println!("Forward to: {}", peer);
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Epidemic broadcast configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastConfig {
    /// Epidemic strategy to use
    pub strategy: EpidemicStrategy,
    /// Number of peers to forward to (fanout)
    pub fanout: usize,
    /// Probability of forwarding (0.0-1.0)
    pub forward_probability: f64,
    /// Maximum message age (seconds)
    pub max_message_age: u64,
    /// Maximum number of stored messages
    pub max_stored_messages: usize,
    /// Enable anti-entropy
    pub enable_anti_entropy: bool,
    /// Anti-entropy interval (seconds)
    pub anti_entropy_interval: u64,
    /// Maximum forwarding hops
    pub max_hops: u32,
    /// Enable push
    pub enable_push: bool,
    /// Enable pull
    pub enable_pull: bool,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            strategy: EpidemicStrategy::PushPull,
            fanout: 6,
            forward_probability: 0.8,
            max_message_age: 300, // 5 minutes
            max_stored_messages: 10000,
            enable_anti_entropy: true,
            anti_entropy_interval: 60,
            max_hops: 10,
            enable_push: true,
            enable_pull: true,
        }
    }
}

/// Epidemic broadcast strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpidemicStrategy {
    /// Push-based: infected nodes actively push to neighbors
    Push,
    /// Pull-based: susceptible nodes actively pull from neighbors
    Pull,
    /// Push-Pull: combination of push and pull
    PushPull,
}

/// Message state in epidemic model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageState {
    /// Not yet received
    Susceptible,
    /// Received and being forwarded
    Infected,
    /// Received but no longer forwarding
    Removed,
}

/// Epidemic message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpidemicMessage {
    /// Unique message identifier
    pub id: String,
    /// Content identifier (hash)
    pub content_id: Vec<u8>,
    /// Message payload/metadata
    pub payload: Vec<u8>,
    /// Number of hops from origin
    pub hops: u32,
    /// Timestamp when created
    #[serde(skip, default = "Instant::now")]
    pub created_at: Instant,
    /// Peers that have been infected
    pub infected_peers: HashSet<String>,
    /// Current state
    pub state: MessageState,
}

/// Peer information in epidemic model
#[derive(Debug, Clone)]
struct PeerInfo {
    id: String,
    messages_received: HashSet<String>,
    messages_sent: HashSet<String>,
    last_contact: Instant,
    is_active: bool,
}

/// Broadcast statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastStats {
    /// Total messages broadcast
    pub total_broadcasts: usize,
    /// Total messages received
    pub total_received: usize,
    /// Total messages forwarded
    pub total_forwarded: usize,
    /// Total duplicates detected
    pub duplicates_detected: usize,
    /// Average propagation time (ms)
    pub avg_propagation_time: f64,
    /// Total peers infected
    pub total_peers_infected: usize,
    /// Current active messages
    pub active_messages: usize,
    /// Messages expired
    pub messages_expired: usize,
}

/// Epidemic broadcaster
pub struct EpidemicBroadcaster {
    config: BroadcastConfig,
    peers: HashMap<String, PeerInfo>,
    messages: HashMap<String, EpidemicMessage>,
    message_order: VecDeque<String>,
    stats: BroadcastStats,
    last_anti_entropy: Instant,
    rng_state: u64,
}

impl EpidemicBroadcaster {
    /// Create a new epidemic broadcaster
    pub fn new(config: BroadcastConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            messages: HashMap::new(),
            message_order: VecDeque::new(),
            stats: BroadcastStats {
                total_broadcasts: 0,
                total_received: 0,
                total_forwarded: 0,
                duplicates_detected: 0,
                avg_propagation_time: 0.0,
                total_peers_infected: 0,
                active_messages: 0,
                messages_expired: 0,
            },
            last_anti_entropy: Instant::now(),
            rng_state: 0x123456789abcdef0,
        }
    }

    /// Add a peer to the network
    pub fn add_peer(&mut self, peer_id: &str) {
        self.peers.insert(
            peer_id.to_string(),
            PeerInfo {
                id: peer_id.to_string(),
                messages_received: HashSet::new(),
                messages_sent: HashSet::new(),
                last_contact: Instant::now(),
                is_active: true,
            },
        );
    }

    /// Remove a peer from the network
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peers.remove(peer_id);
    }

    /// Broadcast a new message
    pub fn broadcast(&mut self, content_id: &[u8], payload: &[u8]) -> String {
        let message_id = format!(
            "msg_{}_{}",
            Self::encode_hex(content_id),
            self.stats.total_broadcasts
        );

        let message = EpidemicMessage {
            id: message_id.clone(),
            content_id: content_id.to_vec(),
            payload: payload.to_vec(),
            hops: 0,
            created_at: Instant::now(),
            infected_peers: HashSet::new(),
            state: MessageState::Infected,
        };

        self.messages.insert(message_id.clone(), message);
        self.message_order.push_back(message_id.clone());
        self.stats.total_broadcasts += 1;
        self.stats.active_messages += 1;

        // Cleanup old messages
        self.cleanup_old_messages();

        message_id
    }

    /// Receive a message from a peer
    pub fn receive_message(
        &mut self,
        peer_id: &str,
        content_id: &[u8],
        payload: &[u8],
        hops: u32,
    ) -> Result<String, String> {
        // Check if we've seen this message before
        let message_id = format!("msg_{}_{}", Self::encode_hex(content_id), 0);

        if self.messages.contains_key(&message_id) {
            self.stats.duplicates_detected += 1;
            return Err("Duplicate message".to_string());
        }

        // Check hop limit
        if hops >= self.config.max_hops {
            return Err("Max hops exceeded".to_string());
        }

        // Create message
        let message = EpidemicMessage {
            id: message_id.clone(),
            content_id: content_id.to_vec(),
            payload: payload.to_vec(),
            hops: hops + 1,
            created_at: Instant::now(),
            infected_peers: HashSet::new(),
            state: MessageState::Infected,
        };

        self.messages.insert(message_id.clone(), message);
        self.message_order.push_back(message_id.clone());
        self.stats.total_received += 1;
        self.stats.active_messages += 1;

        // Update peer info
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.messages_received.insert(message_id.clone());
            peer.last_contact = Instant::now();
        }

        // Cleanup
        self.cleanup_old_messages();

        Ok(message_id)
    }

    /// Select peers to forward a message to
    pub fn select_forward_peers(&mut self, message_id: &str) -> Option<Vec<String>> {
        // Check if should forward based on probability
        if !self.should_forward() {
            return None;
        }

        // Get infected peers set first
        let infected_peers = self.messages.get(message_id)?.infected_peers.clone();

        // Get active peers that haven't been infected
        let available_peers: Vec<String> = self
            .peers
            .values()
            .filter(|p| p.is_active && !infected_peers.contains(&p.id))
            .map(|p| p.id.clone())
            .collect();

        if available_peers.is_empty() {
            return None;
        }

        // Select fanout peers randomly
        let count = self.config.fanout.min(available_peers.len());
        let selected = self.random_sample(&available_peers, count);

        // Mark as forwarded
        self.stats.total_forwarded += 1;

        // Update message with infected peers
        if let Some(msg) = self.messages.get_mut(message_id) {
            for peer_id in &selected {
                msg.infected_peers.insert(peer_id.clone());
                self.stats.total_peers_infected += 1;

                // Update peer info
                if let Some(peer) = self.peers.get_mut(peer_id) {
                    peer.messages_sent.insert(message_id.to_string());
                }
            }
        }

        Some(selected)
    }

    /// Check if a message should be forwarded based on probability
    fn should_forward(&mut self) -> bool {
        self.random_f64() < self.config.forward_probability
    }

    /// Random sampling without replacement
    fn random_sample(&mut self, items: &[String], count: usize) -> Vec<String> {
        let mut result = Vec::new();
        let mut available: Vec<String> = items.to_vec();

        for _ in 0..count {
            if available.is_empty() {
                break;
            }

            let idx = (self.random_u64() as usize) % available.len();
            result.push(available.remove(idx));
        }

        result
    }

    /// Simple LCG random number generator for deterministic sampling
    fn random_u64(&mut self) -> u64 {
        self.rng_state = self
            .rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.rng_state
    }

    /// Generate random f64 in [0, 1)
    fn random_f64(&mut self) -> f64 {
        (self.random_u64() as f64) / (u64::MAX as f64)
    }

    /// Cleanup old messages
    fn cleanup_old_messages(&mut self) {
        let max_age = Duration::from_secs(self.config.max_message_age);
        let now = Instant::now();

        // Remove expired messages
        while let Some(msg_id) = self.message_order.front() {
            let should_remove = if let Some(msg) = self.messages.get(msg_id) {
                now.duration_since(msg.created_at) > max_age
            } else {
                true
            };

            if should_remove {
                if let Some(msg_id) = self.message_order.pop_front() {
                    self.messages.remove(&msg_id);
                    self.stats.messages_expired += 1;
                    self.stats.active_messages = self.stats.active_messages.saturating_sub(1);
                }
            } else {
                break;
            }
        }

        // Enforce max message limit
        while self.messages.len() > self.config.max_stored_messages {
            if let Some(msg_id) = self.message_order.pop_front() {
                self.messages.remove(&msg_id);
                self.stats.active_messages = self.stats.active_messages.saturating_sub(1);
            }
        }
    }

    /// Perform anti-entropy (synchronization)
    pub fn anti_entropy(&mut self) -> Vec<(String, Vec<String>)> {
        if !self.config.enable_anti_entropy {
            return Vec::new();
        }

        let now = Instant::now();
        if now.duration_since(self.last_anti_entropy).as_secs() < self.config.anti_entropy_interval
        {
            return Vec::new();
        }

        self.last_anti_entropy = now;

        // For each peer, find messages they might be missing
        let mut sync_requests = Vec::new();

        for (peer_id, peer_info) in &self.peers {
            let mut missing_messages = Vec::new();

            for (msg_id, message) in &self.messages {
                if message.state == MessageState::Infected
                    && !peer_info.messages_received.contains(msg_id)
                    && !peer_info.messages_sent.contains(msg_id)
                {
                    missing_messages.push(msg_id.clone());
                }
            }

            if !missing_messages.is_empty() {
                sync_requests.push((peer_id.clone(), missing_messages));
            }
        }

        sync_requests
    }

    /// Mark a message as removed (no longer forwarding)
    pub fn mark_removed(&mut self, message_id: &str) {
        if let Some(message) = self.messages.get_mut(message_id) {
            message.state = MessageState::Removed;
        }
    }

    /// Get convergence status
    pub fn get_convergence(&self, message_id: &str) -> Option<f64> {
        let message = self.messages.get(message_id)?;

        if self.peers.is_empty() {
            return Some(1.0);
        }

        let infected_count = message.infected_peers.len();
        Some(infected_count as f64 / self.peers.len() as f64)
    }

    /// Get message information
    pub fn get_message(&self, message_id: &str) -> Option<&EpidemicMessage> {
        self.messages.get(message_id)
    }

    /// Get all active messages
    pub fn active_messages(&self) -> Vec<String> {
        self.messages
            .iter()
            .filter(|(_, msg)| msg.state == MessageState::Infected)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &BroadcastStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = BroadcastStats {
            total_broadcasts: 0,
            total_received: 0,
            total_forwarded: 0,
            duplicates_detected: 0,
            avg_propagation_time: 0.0,
            total_peers_infected: 0,
            active_messages: self.messages.len(),
            messages_expired: 0,
        };
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Simple hex encoding helper
    fn encode_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcaster_creation() {
        let config = BroadcastConfig::default();
        let broadcaster = EpidemicBroadcaster::new(config);
        assert_eq!(broadcaster.peer_count(), 0);
    }

    #[test]
    fn test_add_remove_peer() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.add_peer("peer1");
        assert_eq!(broadcaster.peer_count(), 1);

        broadcaster.remove_peer("peer1");
        assert_eq!(broadcaster.peer_count(), 0);
    }

    #[test]
    fn test_broadcast_message() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        let msg_id = broadcaster.broadcast(b"content123", b"metadata");
        assert!(broadcaster.get_message(&msg_id).is_some());
        assert_eq!(broadcaster.stats().total_broadcasts, 1);
    }

    #[test]
    fn test_receive_message() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.add_peer("peer1");
        let result = broadcaster.receive_message("peer1", b"content123", b"payload", 0);
        assert!(result.is_ok());
        assert_eq!(broadcaster.stats().total_received, 1);
    }

    #[test]
    fn test_duplicate_detection() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.add_peer("peer1");
        let _msg_id = broadcaster.broadcast(b"content123", b"metadata");

        // Try to receive the same message again
        let result = broadcaster.receive_message("peer1", b"content123", b"metadata", 0);
        assert!(result.is_err());
        assert_eq!(broadcaster.stats().duplicates_detected, 1);
    }

    #[test]
    fn test_select_forward_peers() {
        let config = BroadcastConfig {
            fanout: 3,
            forward_probability: 1.0, // Always forward
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        // Add peers
        for i in 0..10 {
            broadcaster.add_peer(&format!("peer{}", i));
        }

        let msg_id = broadcaster.broadcast(b"content123", b"metadata");

        if let Some(peers) = broadcaster.select_forward_peers(&msg_id) {
            assert!(peers.len() <= 3);
        }
    }

    #[test]
    fn test_max_hops() {
        let config = BroadcastConfig {
            max_hops: 5,
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.add_peer("peer1");

        // Message with hops at limit
        let result = broadcaster.receive_message("peer1", b"content123", b"payload", 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_convergence() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        // Add 10 peers
        for i in 0..10 {
            broadcaster.add_peer(&format!("peer{}", i));
        }

        let _msg_id = broadcaster.broadcast(b"content123", b"metadata");

        // Initially, convergence should be 0
        let conv = broadcaster.get_convergence(&_msg_id).unwrap();
        assert_eq!(conv, 0.0);
    }

    #[test]
    fn test_message_removal() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        let msg_id = broadcaster.broadcast(b"content123", b"metadata");
        broadcaster.mark_removed(&msg_id);

        let msg = broadcaster.get_message(&msg_id).unwrap();
        assert_eq!(msg.state, MessageState::Removed);
    }

    #[test]
    fn test_active_messages() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        let msg_id1 = broadcaster.broadcast(b"content1", b"meta1");
        let _msg_id2 = broadcaster.broadcast(b"content2", b"meta2");

        broadcaster.mark_removed(&msg_id1);

        let active = broadcaster.active_messages();
        assert_eq!(active.len(), 1);
        assert!(active.contains(&_msg_id2));
    }

    #[test]
    fn test_anti_entropy() {
        let config = BroadcastConfig {
            enable_anti_entropy: true,
            anti_entropy_interval: 0, // Immediate
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.add_peer("peer1");
        broadcaster.add_peer("peer2");

        broadcaster.broadcast(b"content123", b"metadata");

        let sync_requests = broadcaster.anti_entropy();
        assert!(!sync_requests.is_empty());
    }

    #[test]
    fn test_reset_stats() {
        let config = BroadcastConfig::default();
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.broadcast(b"content123", b"metadata");
        broadcaster.reset_stats();

        assert_eq!(broadcaster.stats().total_broadcasts, 0);
    }

    #[test]
    fn test_fanout_limit() {
        let config = BroadcastConfig {
            fanout: 100, // More than available peers
            forward_probability: 1.0,
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        // Add only 5 peers
        for i in 0..5 {
            broadcaster.add_peer(&format!("peer{}", i));
        }

        let msg_id = broadcaster.broadcast(b"content123", b"metadata");

        if let Some(peers) = broadcaster.select_forward_peers(&msg_id) {
            assert!(peers.len() <= 5); // Can't exceed available peers
        }
    }

    #[test]
    fn test_forward_probability() {
        let config = BroadcastConfig {
            forward_probability: 0.0, // Never forward
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.add_peer("peer1");
        let msg_id = broadcaster.broadcast(b"content123", b"metadata");

        // Should not forward
        let result = broadcaster.select_forward_peers(&msg_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_cleanup_old_messages() {
        let config = BroadcastConfig {
            max_message_age: 0, // Expire immediately
            max_stored_messages: 1000,
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        broadcaster.broadcast(b"content123", b"metadata");
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Trigger cleanup by broadcasting another message
        broadcaster.broadcast(b"content456", b"metadata");

        // Both messages may be expired depending on timing
        assert!(broadcaster.stats().messages_expired >= 1);
    }

    #[test]
    fn test_max_stored_messages() {
        let config = BroadcastConfig {
            max_stored_messages: 5,
            ..Default::default()
        };
        let mut broadcaster = EpidemicBroadcaster::new(config);

        // Broadcast more than max
        for i in 0..10 {
            broadcaster.broadcast(format!("content{}", i).as_bytes(), b"metadata");
        }

        // Should only keep max_stored_messages
        assert!(broadcaster.messages.len() <= 5);
    }
}
