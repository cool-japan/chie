//! Peer capability advertisement and discovery.
//!
//! This module allows peers to advertise their capabilities and discover
//! peers with specific capabilities for efficient content distribution.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Peer capability types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// Can serve content
    ContentProvider,
    /// Can relay connections
    Relay,
    /// Supports DHT operations
    DHT,
    /// Has high bandwidth
    HighBandwidth,
    /// Has high storage capacity
    HighStorage,
    /// Supports WebRTC
    WebRTC,
    /// Supports QUIC transport
    QUIC,
    /// Can act as bootstrap node
    Bootstrap,
    /// Supports gossip protocol
    Gossip,
    /// Supports NAT traversal
    NATTraversal,
}

impl Capability {
    /// Get all capability types
    pub fn all() -> Vec<Capability> {
        vec![
            Self::ContentProvider,
            Self::Relay,
            Self::DHT,
            Self::HighBandwidth,
            Self::HighStorage,
            Self::WebRTC,
            Self::QUIC,
            Self::Bootstrap,
            Self::Gossip,
            Self::NATTraversal,
        ]
    }

    /// Get capability name
    pub fn name(&self) -> &'static str {
        match self {
            Self::ContentProvider => "content_provider",
            Self::Relay => "relay",
            Self::DHT => "dht",
            Self::HighBandwidth => "high_bandwidth",
            Self::HighStorage => "high_storage",
            Self::WebRTC => "webrtc",
            Self::QUIC => "quic",
            Self::Bootstrap => "bootstrap",
            Self::Gossip => "gossip",
            Self::NATTraversal => "nat_traversal",
        }
    }
}

/// Capability metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityMetadata {
    /// Capability type
    pub capability: Capability,
    /// Version (e.g., protocol version)
    pub version: String,
    /// Additional properties
    pub properties: HashMap<String, String>,
    /// Capability level (0.0-1.0, e.g., bandwidth as fraction of max)
    pub level: f64,
}

/// Peer capabilities advertisement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Peer ID
    pub peer_id: String,
    /// Advertised capabilities with metadata
    pub capabilities: Vec<CapabilityMetadata>,
    /// Advertisement timestamp
    pub timestamp: u64,
    /// Advertisement TTL in seconds
    pub ttl: u64,
}

impl PeerCapabilities {
    /// Check if has capability
    pub fn has_capability(&self, capability: Capability) -> bool {
        self.capabilities.iter().any(|c| c.capability == capability)
    }

    /// Get capability metadata
    pub fn get_metadata(&self, capability: Capability) -> Option<&CapabilityMetadata> {
        self.capabilities
            .iter()
            .find(|c| c.capability == capability)
    }

    /// Get capability level
    pub fn get_level(&self, capability: Capability) -> Option<f64> {
        self.get_metadata(capability).map(|m| m.level)
    }
}

/// Capability requirement for peer selection
#[derive(Debug, Clone)]
pub struct CapabilityRequirement {
    pub capability: Capability,
    pub min_level: Option<f64>,
    pub min_version: Option<String>,
    pub required_properties: HashMap<String, String>,
}

impl CapabilityRequirement {
    /// Create a simple requirement (just capability type)
    pub fn simple(capability: Capability) -> Self {
        Self {
            capability,
            min_level: None,
            min_version: None,
            required_properties: HashMap::new(),
        }
    }

    /// With minimum level
    pub fn with_min_level(mut self, level: f64) -> Self {
        self.min_level = Some(level);
        self
    }

    /// With minimum version
    pub fn with_min_version(mut self, version: String) -> Self {
        self.min_version = Some(version);
        self
    }

    /// Check if metadata satisfies requirement
    pub fn is_satisfied_by(&self, metadata: &CapabilityMetadata) -> bool {
        if metadata.capability != self.capability {
            return false;
        }

        // Check level
        if let Some(min_level) = self.min_level {
            if metadata.level < min_level {
                return false;
            }
        }

        // Check version (simple string comparison)
        if let Some(ref min_version) = self.min_version {
            if &metadata.version < min_version {
                return false;
            }
        }

        // Check required properties
        for (key, value) in &self.required_properties {
            if metadata.properties.get(key) != Some(value) {
                return false;
            }
        }

        true
    }
}

/// Capability discovery configuration
#[derive(Debug, Clone)]
pub struct CapabilityConfig {
    /// Advertisement TTL
    pub advertisement_ttl: Duration,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Maximum peers per capability to track
    pub max_peers_per_capability: usize,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            advertisement_ttl: Duration::from_secs(3600), // 1 hour
            cleanup_interval: Duration::from_secs(300),   // 5 minutes
            max_peers_per_capability: 1000,
        }
    }
}

/// Peer capability info
#[derive(Debug, Clone)]
struct PeerCapabilityInfo {
    capabilities: Vec<CapabilityMetadata>,
    advertised_at: Instant,
    ttl: Duration,
}

impl PeerCapabilityInfo {
    fn is_expired(&self) -> bool {
        self.advertised_at.elapsed() > self.ttl
    }
}

/// Capability manager
pub struct CapabilityManager {
    config: CapabilityConfig,
    peer_capabilities: Arc<RwLock<HashMap<PeerId, PeerCapabilityInfo>>>,
    capability_index: Arc<RwLock<HashMap<Capability, HashSet<PeerId>>>>,
    last_cleanup: Arc<RwLock<Instant>>,
}

impl CapabilityManager {
    /// Create a new capability manager
    pub fn new(config: CapabilityConfig) -> Self {
        Self {
            config,
            peer_capabilities: Arc::new(RwLock::new(HashMap::new())),
            capability_index: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Advertise capabilities for a peer
    pub fn advertise(&self, peer_id: PeerId, capabilities: Vec<CapabilityMetadata>) {
        let info = PeerCapabilityInfo {
            capabilities: capabilities.clone(),
            advertised_at: Instant::now(),
            ttl: self.config.advertisement_ttl,
        };

        self.peer_capabilities
            .write()
            .unwrap()
            .insert(peer_id, info);

        // Update index
        let mut index = self.capability_index.write().unwrap();
        for cap_meta in capabilities {
            index
                .entry(cap_meta.capability)
                .or_default()
                .insert(peer_id);
        }
    }

    /// Get capabilities for a peer
    pub fn get_capabilities(&self, peer_id: &PeerId) -> Option<Vec<CapabilityMetadata>> {
        let caps = self.peer_capabilities.read().unwrap();
        caps.get(peer_id)
            .filter(|info| !info.is_expired())
            .map(|info| info.capabilities.clone())
    }

    /// Check if peer has capability
    pub fn has_capability(&self, peer_id: &PeerId, capability: Capability) -> bool {
        if let Some(caps) = self.get_capabilities(peer_id) {
            caps.iter().any(|c| c.capability == capability)
        } else {
            false
        }
    }

    /// Find peers with capability
    pub fn find_peers_with_capability(&self, capability: Capability) -> Vec<PeerId> {
        let index = self.capability_index.read().unwrap();
        let caps = self.peer_capabilities.read().unwrap();

        index
            .get(&capability)
            .map(|peers| {
                peers
                    .iter()
                    .filter(|peer_id| {
                        caps.get(peer_id)
                            .map(|info| !info.is_expired())
                            .unwrap_or(false)
                    })
                    .copied()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find peers matching requirements
    pub fn find_peers_with_requirements(
        &self,
        requirements: &[CapabilityRequirement],
    ) -> Vec<PeerId> {
        if requirements.is_empty() {
            return Vec::new();
        }

        // Start with peers having the first capability
        let mut candidates: HashSet<PeerId> = self
            .find_peers_with_capability(requirements[0].capability)
            .into_iter()
            .collect();

        // Filter by remaining requirements
        let caps = self.peer_capabilities.read().unwrap();

        candidates.retain(|peer_id| {
            if let Some(info) = caps.get(peer_id) {
                if info.is_expired() {
                    return false;
                }

                // Check all requirements
                requirements.iter().all(|req| {
                    info.capabilities
                        .iter()
                        .any(|meta| req.is_satisfied_by(meta))
                })
            } else {
                false
            }
        });

        candidates.into_iter().collect()
    }

    /// Get peers ranked by capability level
    pub fn rank_peers_by_level(&self, capability: Capability) -> Vec<(PeerId, f64)> {
        let mut ranked: Vec<(PeerId, f64)> = self
            .find_peers_with_capability(capability)
            .into_iter()
            .filter_map(|peer_id| {
                let caps = self.get_capabilities(&peer_id)?;
                let metadata = caps.iter().find(|c| c.capability == capability)?;
                Some((peer_id, metadata.level))
            })
            .collect();

        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        ranked
    }

    /// Remove peer capabilities
    pub fn remove_peer(&self, peer_id: &PeerId) {
        // Remove from index
        if let Some(info) = self.peer_capabilities.write().unwrap().remove(peer_id) {
            let mut index = self.capability_index.write().unwrap();
            for cap_meta in info.capabilities {
                if let Some(peers) = index.get_mut(&cap_meta.capability) {
                    peers.remove(peer_id);
                }
            }
        }
    }

    /// Cleanup expired advertisements
    pub fn cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.write().unwrap();
        if last_cleanup.elapsed() < self.config.cleanup_interval {
            return;
        }
        *last_cleanup = Instant::now();
        drop(last_cleanup);

        // Find expired peers
        let expired: Vec<PeerId> = self
            .peer_capabilities
            .read()
            .unwrap()
            .iter()
            .filter(|(_, info)| info.is_expired())
            .map(|(peer_id, _)| *peer_id)
            .collect();

        // Remove expired
        for peer_id in expired {
            self.remove_peer(&peer_id);
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> CapabilityStats {
        let caps = self.peer_capabilities.read().unwrap();
        let index = self.capability_index.read().unwrap();

        let total_peers = caps.len();
        let active_peers = caps.values().filter(|info| !info.is_expired()).count();

        let mut peers_per_capability: HashMap<Capability, usize> = HashMap::new();
        for (cap, peers) in index.iter() {
            let active_count = peers
                .iter()
                .filter(|peer_id| {
                    caps.get(peer_id)
                        .map(|info| !info.is_expired())
                        .unwrap_or(false)
                })
                .count();
            peers_per_capability.insert(*cap, active_count);
        }

        CapabilityStats {
            total_peers,
            active_peers,
            peers_per_capability,
        }
    }
}

/// Capability statistics
#[derive(Debug, Clone)]
pub struct CapabilityStats {
    pub total_peers: usize,
    pub active_peers: usize,
    pub peers_per_capability: HashMap<Capability, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    fn create_test_capability(cap: Capability, level: f64) -> CapabilityMetadata {
        CapabilityMetadata {
            capability: cap,
            version: "1.0".to_string(),
            properties: HashMap::new(),
            level,
        }
    }

    #[test]
    fn test_capability_name() {
        assert_eq!(Capability::ContentProvider.name(), "content_provider");
        assert_eq!(Capability::DHT.name(), "dht");
    }

    #[test]
    fn test_capability_all() {
        let all = Capability::all();
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_peer_capabilities_has_capability() {
        let peer = create_test_peer();
        let caps = PeerCapabilities {
            peer_id: peer.to_base58(),
            capabilities: vec![create_test_capability(Capability::DHT, 1.0)],
            timestamp: 0,
            ttl: 3600,
        };

        assert!(caps.has_capability(Capability::DHT));
        assert!(!caps.has_capability(Capability::Relay));
    }

    #[test]
    fn test_peer_capabilities_get_level() {
        let peer = create_test_peer();
        let caps = PeerCapabilities {
            peer_id: peer.to_base58(),
            capabilities: vec![create_test_capability(Capability::HighBandwidth, 0.8)],
            timestamp: 0,
            ttl: 3600,
        };

        assert_eq!(caps.get_level(Capability::HighBandwidth), Some(0.8));
        assert_eq!(caps.get_level(Capability::Relay), None);
    }

    #[test]
    fn test_capability_requirement_simple() {
        let req = CapabilityRequirement::simple(Capability::DHT);
        let metadata = create_test_capability(Capability::DHT, 1.0);

        assert!(req.is_satisfied_by(&metadata));
    }

    #[test]
    fn test_capability_requirement_min_level() {
        let req = CapabilityRequirement::simple(Capability::HighBandwidth).with_min_level(0.5);

        let high_level = create_test_capability(Capability::HighBandwidth, 0.8);
        let low_level = create_test_capability(Capability::HighBandwidth, 0.3);

        assert!(req.is_satisfied_by(&high_level));
        assert!(!req.is_satisfied_by(&low_level));
    }

    #[test]
    fn test_capability_requirement_version() {
        let req =
            CapabilityRequirement::simple(Capability::WebRTC).with_min_version("2.0".to_string());

        let mut new_version = create_test_capability(Capability::WebRTC, 1.0);
        new_version.version = "2.5".to_string();

        let mut old_version = create_test_capability(Capability::WebRTC, 1.0);
        old_version.version = "1.0".to_string();

        assert!(req.is_satisfied_by(&new_version));
        assert!(!req.is_satisfied_by(&old_version));
    }

    #[test]
    fn test_manager_new() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);
        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_advertise() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer = create_test_peer();
        let caps = vec![
            create_test_capability(Capability::DHT, 1.0),
            create_test_capability(Capability::Relay, 1.0),
        ];

        manager.advertise(peer, caps);

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 1);
    }

    #[test]
    fn test_get_capabilities() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer = create_test_peer();
        let caps = vec![create_test_capability(Capability::DHT, 1.0)];

        manager.advertise(peer, caps.clone());

        let retrieved = manager.get_capabilities(&peer);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 1);
    }

    #[test]
    fn test_has_capability() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer = create_test_peer();
        manager.advertise(peer, vec![create_test_capability(Capability::DHT, 1.0)]);

        assert!(manager.has_capability(&peer, Capability::DHT));
        assert!(!manager.has_capability(&peer, Capability::Relay));
    }

    #[test]
    fn test_find_peers_with_capability() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        manager.advertise(peer1, vec![create_test_capability(Capability::DHT, 1.0)]);
        manager.advertise(peer2, vec![create_test_capability(Capability::DHT, 1.0)]);
        manager.advertise(peer3, vec![create_test_capability(Capability::Relay, 1.0)]);

        let dht_peers = manager.find_peers_with_capability(Capability::DHT);
        assert_eq!(dht_peers.len(), 2);
    }

    #[test]
    fn test_find_peers_with_requirements() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager.advertise(
            peer1,
            vec![
                create_test_capability(Capability::DHT, 1.0),
                create_test_capability(Capability::HighBandwidth, 0.8),
            ],
        );
        manager.advertise(
            peer2,
            vec![
                create_test_capability(Capability::DHT, 1.0),
                create_test_capability(Capability::HighBandwidth, 0.3),
            ],
        );

        let requirements = vec![
            CapabilityRequirement::simple(Capability::DHT),
            CapabilityRequirement::simple(Capability::HighBandwidth).with_min_level(0.5),
        ];

        let matches = manager.find_peers_with_requirements(&requirements);
        assert_eq!(matches.len(), 1); // Only peer1 meets bandwidth requirement
    }

    #[test]
    fn test_rank_peers_by_level() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        manager.advertise(
            peer1,
            vec![create_test_capability(Capability::HighBandwidth, 0.5)],
        );
        manager.advertise(
            peer2,
            vec![create_test_capability(Capability::HighBandwidth, 0.9)],
        );
        manager.advertise(
            peer3,
            vec![create_test_capability(Capability::HighBandwidth, 0.7)],
        );

        let ranked = manager.rank_peers_by_level(Capability::HighBandwidth);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].1, 0.9); // peer2 first
        assert_eq!(ranked[1].1, 0.7); // peer3 second
        assert_eq!(ranked[2].1, 0.5); // peer1 last
    }

    #[test]
    fn test_remove_peer() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer = create_test_peer();
        manager.advertise(peer, vec![create_test_capability(Capability::DHT, 1.0)]);

        assert_eq!(manager.get_stats().total_peers, 1);

        manager.remove_peer(&peer);
        assert_eq!(manager.get_stats().total_peers, 0);
    }

    #[test]
    fn test_cleanup_expired() {
        let config = CapabilityConfig {
            advertisement_ttl: Duration::from_millis(10),
            cleanup_interval: Duration::from_millis(0),
            ..Default::default()
        };

        let manager = CapabilityManager::new(config);

        let peer = create_test_peer();
        manager.advertise(peer, vec![create_test_capability(Capability::DHT, 1.0)]);

        std::thread::sleep(Duration::from_millis(20));
        manager.cleanup();

        let stats = manager.get_stats();
        assert_eq!(stats.active_peers, 0);
    }

    #[test]
    fn test_stats() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager.advertise(peer1, vec![create_test_capability(Capability::DHT, 1.0)]);
        manager.advertise(
            peer2,
            vec![
                create_test_capability(Capability::DHT, 1.0),
                create_test_capability(Capability::Relay, 1.0),
            ],
        );

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.active_peers, 2);
        assert_eq!(stats.peers_per_capability.get(&Capability::DHT), Some(&2));
        assert_eq!(stats.peers_per_capability.get(&Capability::Relay), Some(&1));
    }

    #[test]
    fn test_config_default() {
        let config = CapabilityConfig::default();
        assert_eq!(config.advertisement_ttl, Duration::from_secs(3600));
        assert_eq!(config.cleanup_interval, Duration::from_secs(300));
    }

    #[test]
    fn test_empty_requirements() {
        let config = CapabilityConfig::default();
        let manager = CapabilityManager::new(config);

        let peer = create_test_peer();
        manager.advertise(peer, vec![create_test_capability(Capability::DHT, 1.0)]);

        let matches = manager.find_peers_with_requirements(&[]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_multiple_capabilities() {
        let peer = create_test_peer();
        let caps = PeerCapabilities {
            peer_id: peer.to_base58(),
            capabilities: vec![
                create_test_capability(Capability::DHT, 1.0),
                create_test_capability(Capability::Relay, 0.8),
                create_test_capability(Capability::HighBandwidth, 0.9),
            ],
            timestamp: 0,
            ttl: 3600,
        };

        assert!(caps.has_capability(Capability::DHT));
        assert!(caps.has_capability(Capability::Relay));
        assert!(caps.has_capability(Capability::HighBandwidth));
        assert!(!caps.has_capability(Capability::Bootstrap));
    }
}
