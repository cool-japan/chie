//! Peer Exchange (PEX) protocol for CHIE Network.
//!
//! PEX allows nodes to share their known peers with each other,
//! improving peer discovery especially in scenarios where DHT
//! bootstrapping is slow or unavailable.
//!
//! Features:
//! - Periodic peer list exchange
//! - Reputation-based peer sharing (share high-reputation peers first)
//! - Rate limiting to prevent PEX flooding
//! - Support for both TCP and QUIC addresses

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Maximum number of peers to share in a single PEX message.
pub const MAX_PEERS_PER_MESSAGE: usize = 50;

/// Maximum number of addresses per peer in PEX messages.
pub const MAX_ADDRS_PER_PEER: usize = 5;

/// Default PEX interval.
pub const DEFAULT_PEX_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes

/// Default minimum interval between PEX exchanges with the same peer.
pub const MIN_PEX_INTERVAL_PER_PEER: Duration = Duration::from_secs(60);

/// PEX message types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PexMessageType {
    /// Request peers from the recipient.
    Request,
    /// Response with peer list.
    Response,
    /// Unsolicited peer advertisement (push).
    Advertisement,
}

/// A peer entry in PEX messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexPeerEntry {
    /// Peer ID (base58 encoded).
    pub peer_id: String,
    /// Known addresses for this peer.
    pub addresses: Vec<String>,
    /// Peer reputation score (0-100, optional).
    pub reputation: Option<u8>,
    /// When this peer was last seen (Unix timestamp).
    pub last_seen: u64,
    /// Connection type hints.
    pub hints: PexHints,
}

/// Hints about peer connectivity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PexHints {
    /// Peer supports QUIC.
    pub quic: bool,
    /// Peer is NAT'd (may need relay).
    pub natted: bool,
    /// Peer is a relay node.
    pub relay: bool,
    /// Peer is a long-running node.
    pub stable: bool,
}

/// A PEX protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PexMessage {
    /// Message type.
    pub message_type: PexMessageType,
    /// Protocol version.
    pub version: u8,
    /// List of peers.
    pub peers: Vec<PexPeerEntry>,
    /// Unix timestamp of the message.
    pub timestamp: u64,
    /// Optional: number of peers requested (for requests).
    pub count_requested: Option<usize>,
}

impl PexMessage {
    /// Create a PEX request message.
    pub fn request(count: usize) -> Self {
        Self {
            message_type: PexMessageType::Request,
            version: 1,
            peers: vec![],
            timestamp: current_timestamp(),
            count_requested: Some(count),
        }
    }

    /// Create a PEX response message.
    pub fn response(peers: Vec<PexPeerEntry>) -> Self {
        Self {
            message_type: PexMessageType::Response,
            version: 1,
            peers,
            timestamp: current_timestamp(),
            count_requested: None,
        }
    }

    /// Create a PEX advertisement message.
    pub fn advertisement(peers: Vec<PexPeerEntry>) -> Self {
        Self {
            message_type: PexMessageType::Advertisement,
            version: 1,
            peers,
            timestamp: current_timestamp(),
            count_requested: None,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PexError> {
        crate::serde_helpers::encode(self).map_err(|e| PexError::SerializationFailed(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PexError> {
        crate::serde_helpers::decode(bytes)
            .map_err(|e| PexError::DeserializationFailed(e.to_string()))
    }
}

/// PEX-related errors.
#[derive(Debug, thiserror::Error)]
pub enum PexError {
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Message too large")]
    MessageTooLarge,
}

/// Configuration for the PEX system.
#[derive(Debug, Clone)]
pub struct PexConfig {
    /// Interval between PEX exchanges.
    pub pex_interval: Duration,
    /// Minimum interval between PEX exchanges with the same peer.
    pub min_interval_per_peer: Duration,
    /// Maximum peers to share per message.
    pub max_peers_per_message: usize,
    /// Maximum addresses per peer.
    pub max_addrs_per_peer: usize,
    /// Prefer sharing high-reputation peers.
    pub reputation_based: bool,
    /// Share only recently-seen peers.
    pub recency_threshold: Duration,
    /// Enable PEX advertisements (push mode).
    pub enable_advertisements: bool,
}

impl Default for PexConfig {
    fn default() -> Self {
        Self {
            pex_interval: DEFAULT_PEX_INTERVAL,
            min_interval_per_peer: MIN_PEX_INTERVAL_PER_PEER,
            max_peers_per_message: MAX_PEERS_PER_MESSAGE,
            max_addrs_per_peer: MAX_ADDRS_PER_PEER,
            reputation_based: true,
            recency_threshold: Duration::from_secs(3600), // 1 hour
            enable_advertisements: true,
        }
    }
}

/// Peer information for PEX.
#[derive(Debug, Clone)]
pub struct PexPeerInfo {
    /// Peer ID.
    pub peer_id: PeerId,
    /// Known addresses.
    pub addresses: Vec<Multiaddr>,
    /// Reputation score (0-100).
    pub reputation: u8,
    /// Last seen time.
    pub last_seen: Instant,
    /// Connection hints.
    pub hints: PexHints,
    /// Whether this peer was discovered via PEX.
    pub from_pex: bool,
}

/// Manager for Peer Exchange.
pub struct PexManager {
    /// Configuration.
    config: PexConfig,
    /// Known peers eligible for PEX.
    known_peers: HashMap<PeerId, PexPeerInfo>,
    /// Last PEX exchange time per peer.
    last_exchange: HashMap<PeerId, Instant>,
    /// Peers received from PEX (for tracking).
    pex_discovered: HashSet<PeerId>,
    /// Our peer ID.
    local_peer_id: PeerId,
}

impl PexManager {
    /// Create a new PEX manager.
    pub fn new(local_peer_id: PeerId, config: PexConfig) -> Self {
        Self {
            config,
            known_peers: HashMap::new(),
            last_exchange: HashMap::new(),
            pex_discovered: HashSet::new(),
            local_peer_id,
        }
    }

    /// Add or update a known peer.
    pub fn add_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>, reputation: u8) {
        if peer_id == self.local_peer_id {
            return;
        }

        let entry = self.known_peers.entry(peer_id).or_insert(PexPeerInfo {
            peer_id,
            addresses: vec![],
            reputation: 50,
            last_seen: Instant::now(),
            hints: PexHints::default(),
            from_pex: false,
        });

        // Update addresses (add new ones, keep existing)
        for addr in addresses {
            if !entry.addresses.contains(&addr) {
                entry.addresses.push(addr);
            }
        }

        // Limit addresses per peer
        if entry.addresses.len() > self.config.max_addrs_per_peer {
            entry.addresses.truncate(self.config.max_addrs_per_peer);
        }

        entry.reputation = reputation;
        entry.last_seen = Instant::now();
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.known_peers.remove(peer_id);
        self.last_exchange.remove(peer_id);
    }

    /// Update peer hints.
    pub fn update_hints(&mut self, peer_id: &PeerId, hints: PexHints) {
        if let Some(peer) = self.known_peers.get_mut(peer_id) {
            peer.hints = hints;
        }
    }

    /// Mark peer as seen.
    pub fn mark_seen(&mut self, peer_id: &PeerId) {
        if let Some(peer) = self.known_peers.get_mut(peer_id) {
            peer.last_seen = Instant::now();
        }
    }

    /// Check if we can exchange PEX with a peer (rate limiting).
    pub fn can_exchange(&self, peer_id: &PeerId) -> bool {
        match self.last_exchange.get(peer_id) {
            Some(last) => last.elapsed() >= self.config.min_interval_per_peer,
            None => true,
        }
    }

    /// Record a PEX exchange with a peer.
    pub fn record_exchange(&mut self, peer_id: PeerId) {
        self.last_exchange.insert(peer_id, Instant::now());
    }

    /// Get peers to share (respects reputation and recency).
    pub fn get_peers_to_share(&self, count: usize, exclude: Option<&PeerId>) -> Vec<PexPeerEntry> {
        let now = Instant::now();
        let mut eligible: Vec<_> = self
            .known_peers
            .values()
            .filter(|p| {
                // Filter out excluded peer
                if let Some(ex) = exclude {
                    if p.peer_id == *ex {
                        return false;
                    }
                }
                // Filter out stale peers
                now.duration_since(p.last_seen) < self.config.recency_threshold
            })
            .collect();

        // Sort by reputation if enabled
        if self.config.reputation_based {
            eligible.sort_by(|a, b| b.reputation.cmp(&a.reputation));
        }

        eligible
            .into_iter()
            .take(count.min(self.config.max_peers_per_message))
            .map(peer_info_to_entry)
            .collect()
    }

    /// Process a received PEX message.
    pub fn process_message(
        &mut self,
        from: PeerId,
        message: PexMessage,
    ) -> Result<PexResponse, PexError> {
        // Rate limit check
        if !self.can_exchange(&from) {
            return Err(PexError::RateLimited(format!(
                "PEX exchange with {} too frequent",
                from
            )));
        }

        self.record_exchange(from);

        match message.message_type {
            PexMessageType::Request => {
                let count = message.count_requested.unwrap_or(20);
                let peers = self.get_peers_to_share(count, Some(&from));
                debug!(
                    "Responding to PEX request from {} with {} peers",
                    from,
                    peers.len()
                );
                Ok(PexResponse::SendPeers(PexMessage::response(peers)))
            }
            PexMessageType::Response | PexMessageType::Advertisement => {
                let added = self.process_peer_entries(&message.peers)?;
                info!(
                    "Received {} peers from {} via PEX, added {}",
                    message.peers.len(),
                    from,
                    added.len()
                );
                Ok(PexResponse::PeersDiscovered(added))
            }
        }
    }

    /// Process peer entries from a PEX message.
    fn process_peer_entries(&mut self, entries: &[PexPeerEntry]) -> Result<Vec<PeerId>, PexError> {
        let mut added = Vec::new();

        for entry in entries {
            // Parse peer ID
            let peer_id: PeerId = entry
                .peer_id
                .parse()
                .map_err(|_| PexError::InvalidPeerId(entry.peer_id.clone()))?;

            // Skip self
            if peer_id == self.local_peer_id {
                continue;
            }

            // Parse addresses
            let mut addresses = Vec::new();
            for addr_str in &entry.addresses {
                match addr_str.parse::<Multiaddr>() {
                    Ok(addr) => addresses.push(addr),
                    Err(_) => {
                        warn!("Invalid address in PEX: {}", addr_str);
                    }
                }
            }

            if addresses.is_empty() {
                continue;
            }

            // Add or update peer
            let is_new = !self.known_peers.contains_key(&peer_id);
            let reputation = entry.reputation.unwrap_or(50);

            self.add_peer(peer_id, addresses, reputation);

            if is_new {
                if let Some(peer) = self.known_peers.get_mut(&peer_id) {
                    peer.from_pex = true;
                    peer.hints = entry.hints.clone();
                }
                self.pex_discovered.insert(peer_id);
                added.push(peer_id);
            }
        }

        Ok(added)
    }

    /// Create a PEX request message.
    pub fn create_request(&self, count: usize) -> PexMessage {
        PexMessage::request(count)
    }

    /// Create a PEX advertisement for newly connected peers.
    pub fn create_advertisement(&self) -> Option<PexMessage> {
        if !self.config.enable_advertisements {
            return None;
        }

        let peers = self.get_peers_to_share(10, None);
        if peers.is_empty() {
            return None;
        }

        Some(PexMessage::advertisement(peers))
    }

    /// Get peers that need PEX exchange (based on interval).
    pub fn get_peers_for_exchange(&self) -> Vec<PeerId> {
        let now = Instant::now();

        self.known_peers
            .keys()
            .filter(|peer_id| {
                match self.last_exchange.get(*peer_id) {
                    Some(last) => now.duration_since(*last) >= self.config.pex_interval,
                    None => true, // Never exchanged
                }
            })
            .cloned()
            .collect()
    }

    /// Get statistics.
    pub fn stats(&self) -> PexStats {
        PexStats {
            known_peers: self.known_peers.len(),
            pex_discovered: self.pex_discovered.len(),
            recent_exchanges: self
                .last_exchange
                .values()
                .filter(|t| t.elapsed() < Duration::from_secs(3600))
                .count(),
        }
    }

    /// Cleanup stale entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let threshold = self.config.recency_threshold * 2;

        self.known_peers
            .retain(|_, p| now.duration_since(p.last_seen) < threshold);
        self.last_exchange
            .retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
    }
}

/// Response from processing a PEX message.
#[derive(Debug)]
pub enum PexResponse {
    /// Send these peers to the requester.
    SendPeers(PexMessage),
    /// New peers were discovered.
    PeersDiscovered(Vec<PeerId>),
}

/// PEX statistics.
#[derive(Debug, Clone, Default)]
pub struct PexStats {
    /// Number of known peers.
    pub known_peers: usize,
    /// Number of peers discovered via PEX.
    pub pex_discovered: usize,
    /// Number of recent PEX exchanges.
    pub recent_exchanges: usize,
}

/// Convert PexPeerInfo to PexPeerEntry for transmission.
fn peer_info_to_entry(info: &PexPeerInfo) -> PexPeerEntry {
    PexPeerEntry {
        peer_id: info.peer_id.to_base58(),
        addresses: info.addresses.iter().map(|a| a.to_string()).collect(),
        reputation: Some(info.reputation),
        last_seen: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| {
                d.as_secs()
                    .saturating_sub(info.last_seen.elapsed().as_secs())
            })
            .unwrap_or(0),
        hints: info.hints.clone(),
    }
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_peer_id() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_pex_message_serialization() {
        let entry = PexPeerEntry {
            peer_id: random_peer_id().to_base58(),
            addresses: vec!["/ip4/127.0.0.1/tcp/4001".to_string()],
            reputation: Some(80),
            last_seen: current_timestamp(),
            hints: PexHints::default(),
        };

        let msg = PexMessage::response(vec![entry]);
        let bytes = msg.to_bytes().unwrap();
        let restored = PexMessage::from_bytes(&bytes).unwrap();

        assert_eq!(restored.message_type, PexMessageType::Response);
        assert_eq!(restored.peers.len(), 1);
    }

    #[test]
    fn test_pex_manager_add_peer() {
        let local = random_peer_id();
        let mut manager = PexManager::new(local, PexConfig::default());

        let peer = random_peer_id();
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/4001".parse().unwrap();

        manager.add_peer(peer, vec![addr.clone()], 75);

        assert!(manager.known_peers.contains_key(&peer));
        assert_eq!(manager.known_peers.get(&peer).unwrap().reputation, 75);
    }

    #[test]
    fn test_pex_manager_rate_limiting() {
        let local = random_peer_id();
        let mut manager = PexManager::new(local, PexConfig::default());

        let peer = random_peer_id();

        assert!(manager.can_exchange(&peer));

        manager.record_exchange(peer);

        assert!(!manager.can_exchange(&peer));
    }

    #[test]
    fn test_pex_manager_get_peers() {
        let local = random_peer_id();
        let mut manager = PexManager::new(local, PexConfig::default());

        for i in 0..5 {
            let peer = random_peer_id();
            let addr: Multiaddr = format!("/ip4/192.168.1.{}/tcp/4001", i).parse().unwrap();
            manager.add_peer(peer, vec![addr], 50 + i * 10);
        }

        let peers = manager.get_peers_to_share(3, None);
        assert_eq!(peers.len(), 3);

        // Should be sorted by reputation (highest first)
        assert!(peers[0].reputation >= peers[1].reputation);
    }

    #[test]
    fn test_pex_exclude_self() {
        let local = random_peer_id();
        let mut manager = PexManager::new(local, PexConfig::default());

        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        manager.add_peer(local, vec![addr], 100);

        // Should not add self
        assert!(!manager.known_peers.contains_key(&local));
    }
}
