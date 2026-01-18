//! Peer persistence for saving and loading known good peers.
//!
//! This module allows saving peer information to disk so that nodes
//! can quickly reconnect to known good peers on restart.

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can occur during peer persistence operations.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] oxicode::error::Error),
    /// Invalid peer data.
    #[error("Invalid peer data: {0}")]
    InvalidData(String),
}

/// Result type for persistence operations.
pub type PersistenceResult<T> = Result<T, PersistenceError>;

/// Persisted peer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPeer {
    /// Peer ID.
    pub peer_id: String,
    /// Known addresses for this peer.
    pub addresses: Vec<String>,
    /// Last seen timestamp (Unix epoch seconds).
    pub last_seen: u64,
    /// Success count (successful transfers).
    pub success_count: u32,
    /// Failure count (failed transfers).
    pub failure_count: u32,
    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<f64>,
    /// Reputation score.
    pub reputation_score: Option<f64>,
}

impl PersistedPeer {
    /// Create a new persisted peer.
    pub fn new(peer_id: PeerId, addresses: Vec<Multiaddr>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            peer_id: peer_id.to_base58(),
            addresses: addresses.iter().map(|a| a.to_string()).collect(),
            last_seen: now,
            success_count: 0,
            failure_count: 0,
            avg_latency_ms: None,
            reputation_score: None,
        }
    }

    /// Convert to libp2p types.
    pub fn to_libp2p(&self) -> PersistenceResult<(PeerId, Vec<Multiaddr>)> {
        let peer_id = PeerId::from_bytes(
            &bs58::decode(&self.peer_id)
                .into_vec()
                .map_err(|e| PersistenceError::InvalidData(format!("Invalid peer ID: {}", e)))?,
        )
        .map_err(|e| PersistenceError::InvalidData(format!("Invalid peer ID: {}", e)))?;

        let addresses: Result<Vec<Multiaddr>, _> =
            self.addresses.iter().map(|a| a.parse()).collect();
        let addresses = addresses
            .map_err(|e| PersistenceError::InvalidData(format!("Invalid address: {}", e)))?;

        Ok((peer_id, addresses))
    }

    /// Check if this peer is stale (not seen recently).
    pub fn is_stale(&self, max_age: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(self.last_seen) > max_age.as_secs()
    }

    /// Update last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Record a successful transfer.
    pub fn record_success(&mut self, latency_ms: f64) {
        self.success_count = self.success_count.saturating_add(1);
        self.touch();

        // Update average latency with exponential moving average
        self.avg_latency_ms = Some(match self.avg_latency_ms {
            Some(avg) => avg * 0.8 + latency_ms * 0.2,
            None => latency_ms,
        });
    }

    /// Record a failed transfer.
    pub fn record_failure(&mut self) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.touch();
    }

    /// Calculate success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 {
            0.0
        } else {
            self.success_count as f64 / total as f64
        }
    }
}

/// Peer store for persisting peer information.
pub struct PeerStore {
    peers: HashMap<String, PersistedPeer>,
    file_path: PathBuf,
    max_peers: usize,
    max_age: Duration,
}

impl PeerStore {
    /// Create a new peer store with the given file path.
    pub fn new(file_path: PathBuf, max_peers: usize, max_age: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            file_path,
            max_peers,
            max_age,
        }
    }

    /// Load peers from disk.
    pub fn load(&mut self) -> PersistenceResult<usize> {
        if !self.file_path.exists() {
            debug!("Peer store file does not exist, starting fresh");
            return Ok(0);
        }

        let data = std::fs::read(&self.file_path)?;
        let peers: Vec<PersistedPeer> = crate::serde_helpers::decode(&data)?;

        let mut loaded = 0;
        for peer in peers {
            if !peer.is_stale(self.max_age) {
                self.peers.insert(peer.peer_id.clone(), peer);
                loaded += 1;
            }
        }

        info!("Loaded {} peers from disk", loaded);
        Ok(loaded)
    }

    /// Save peers to disk.
    pub fn save(&self) -> PersistenceResult<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let peers: Vec<_> = self.peers.values().cloned().collect();
        let data = crate::serde_helpers::encode(&peers)?;
        std::fs::write(&self.file_path, data)?;

        debug!("Saved {} peers to disk", peers.len());
        Ok(())
    }

    /// Add or update a peer.
    pub fn upsert_peer(&mut self, peer: PersistedPeer) {
        self.peers.insert(peer.peer_id.clone(), peer);
        self.prune_if_needed();
    }

    /// Get a peer by ID.
    pub fn get_peer(&self, peer_id: &str) -> Option<&PersistedPeer> {
        self.peers.get(peer_id)
    }

    /// Get a mutable reference to a peer.
    pub fn get_peer_mut(&mut self, peer_id: &str) -> Option<&mut PersistedPeer> {
        self.peers.get_mut(peer_id)
    }

    /// Get all peers.
    pub fn get_all_peers(&self) -> Vec<&PersistedPeer> {
        self.peers.values().collect()
    }

    /// Get top peers by success rate.
    pub fn get_top_peers(&self, limit: usize) -> Vec<&PersistedPeer> {
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by(|a, b| {
            b.success_rate()
                .partial_cmp(&a.success_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        peers.into_iter().take(limit).collect()
    }

    /// Remove stale peers.
    pub fn prune_stale(&mut self) -> usize {
        let before = self.peers.len();
        self.peers.retain(|_, peer| !peer.is_stale(self.max_age));
        let pruned = before - self.peers.len();

        if pruned > 0 {
            debug!("Pruned {} stale peers", pruned);
        }

        pruned
    }

    /// Prune peers if we exceed max_peers limit.
    fn prune_if_needed(&mut self) {
        if self.peers.len() <= self.max_peers {
            return;
        }

        // Sort by success rate and keep the best ones
        let mut peers: Vec<_> = self.peers.values().cloned().collect();
        peers.sort_by(|a, b| {
            b.success_rate()
                .partial_cmp(&a.success_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Keep only max_peers best peers
        self.peers.clear();
        for peer in peers.into_iter().take(self.max_peers) {
            self.peers.insert(peer.peer_id.clone(), peer);
        }

        debug!("Pruned peer store to {} peers", self.peers.len());
    }

    /// Get the number of stored peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Clear all peers.
    pub fn clear(&mut self) {
        self.peers.clear();
    }

    /// Get statistics about the peer store.
    pub fn stats(&self) -> PeerStoreStats {
        let total_success: u32 = self.peers.values().map(|p| p.success_count).sum();
        let total_failure: u32 = self.peers.values().map(|p| p.failure_count).sum();

        let avg_latency = {
            let latencies: Vec<f64> = self
                .peers
                .values()
                .filter_map(|p| p.avg_latency_ms)
                .collect();
            if latencies.is_empty() {
                None
            } else {
                Some(latencies.iter().sum::<f64>() / latencies.len() as f64)
            }
        };

        PeerStoreStats {
            total_peers: self.peers.len(),
            total_success,
            total_failure,
            avg_latency_ms: avg_latency,
        }
    }
}

/// Statistics about the peer store.
#[derive(Debug, Clone)]
pub struct PeerStoreStats {
    /// Total number of stored peers.
    pub total_peers: usize,
    /// Total successful transfers across all peers.
    pub total_success: u32,
    /// Total failed transfers across all peers.
    pub total_failure: u32,
    /// Average latency across all peers.
    pub avg_latency_ms: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn temp_file() -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("test_peer_store_{}.bin", rand::random::<u64>()));
        path
    }

    #[test]
    fn test_persisted_peer_creation() {
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let peer = PersistedPeer::new(peer_id, vec![addr]);

        assert_eq!(peer.success_count, 0);
        assert_eq!(peer.failure_count, 0);
        assert!(peer.avg_latency_ms.is_none());
    }

    #[test]
    fn test_record_success() {
        let peer_id = PeerId::random();
        let mut peer = PersistedPeer::new(peer_id, vec![]);

        peer.record_success(100.0);
        assert_eq!(peer.success_count, 1);
        assert_eq!(peer.avg_latency_ms, Some(100.0));

        peer.record_success(200.0);
        assert_eq!(peer.success_count, 2);
        // EMA: 100 * 0.8 + 200 * 0.2 = 120
        assert!((peer.avg_latency_ms.unwrap() - 120.0).abs() < 0.01);
    }

    #[test]
    fn test_record_failure() {
        let peer_id = PeerId::random();
        let mut peer = PersistedPeer::new(peer_id, vec![]);

        peer.record_failure();
        assert_eq!(peer.failure_count, 1);
    }

    #[test]
    fn test_success_rate() {
        let peer_id = PeerId::random();
        let mut peer = PersistedPeer::new(peer_id, vec![]);

        assert_eq!(peer.success_rate(), 0.0);

        peer.record_success(100.0);
        peer.record_success(100.0);
        peer.record_failure();

        assert!((peer.success_rate() - 0.666666).abs() < 0.001);
    }

    #[test]
    fn test_peer_store_save_load() {
        let path = temp_file();
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();

        {
            let mut store = PeerStore::new(path.clone(), 100, Duration::from_secs(86400));
            let mut peer = PersistedPeer::new(peer_id, vec![addr.clone()]);
            peer.record_success(150.0);
            store.upsert_peer(peer);
            store.save().unwrap();
        }

        {
            let mut store = PeerStore::new(path.clone(), 100, Duration::from_secs(86400));
            let loaded = store.load().unwrap();
            assert_eq!(loaded, 1);
            assert_eq!(store.len(), 1);
        }

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_prune_stale() {
        let path = temp_file();
        let mut store = PeerStore::new(path.clone(), 100, Duration::from_secs(1));

        let peer_id = PeerId::random();
        let mut peer = PersistedPeer::new(peer_id, vec![]);
        peer.last_seen = 0; // Very old timestamp
        store.upsert_peer(peer);

        assert_eq!(store.len(), 1);
        let pruned = store.prune_stale();
        assert_eq!(pruned, 1);
        assert_eq!(store.len(), 0);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_max_peers_limit() {
        let path = temp_file();
        let mut store = PeerStore::new(path.clone(), 3, Duration::from_secs(86400));

        // Add 5 peers
        for i in 0..5 {
            let peer_id = PeerId::random();
            let mut peer = PersistedPeer::new(peer_id, vec![]);
            // Give different success rates
            for _ in 0..i {
                peer.record_success(100.0);
            }
            store.upsert_peer(peer);
        }

        // Should only keep 3 best peers
        assert_eq!(store.len(), 3);

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_get_top_peers() {
        let path = temp_file();
        let mut store = PeerStore::new(path.clone(), 100, Duration::from_secs(86400));

        for i in 0..5 {
            let peer_id = PeerId::random();
            let mut peer = PersistedPeer::new(peer_id, vec![]);
            for _ in 0..i {
                peer.record_success(100.0);
            }
            if i > 0 {
                peer.record_failure();
            }
            store.upsert_peer(peer);
        }

        let top = store.get_top_peers(3);
        assert_eq!(top.len(), 3);

        // Top peer should have highest success rate
        assert!(top[0].success_rate() >= top[1].success_rate());
        assert!(top[1].success_rate() >= top[2].success_rate());

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_stats() {
        let path = temp_file();
        let mut store = PeerStore::new(path.clone(), 100, Duration::from_secs(86400));

        for _ in 0..3 {
            let peer_id = PeerId::random();
            let mut peer = PersistedPeer::new(peer_id, vec![]);
            peer.record_success(100.0);
            peer.record_failure();
            store.upsert_peer(peer);
        }

        let stats = store.stats();
        assert_eq!(stats.total_peers, 3);
        assert_eq!(stats.total_success, 3);
        assert_eq!(stats.total_failure, 3);
        assert!(stats.avg_latency_ms.is_some());

        std::fs::remove_file(path).ok();
    }
}
