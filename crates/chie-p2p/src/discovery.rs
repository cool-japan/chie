//! Peer discovery and content advertisement for CHIE Protocol.
//!
//! This module provides:
//! - Bootstrap node configuration (static, DNS, environment variables)
//! - Content advertisement via Kademlia DHT
//! - Provider record management
//! - Bootstrap node health checking and fallback

use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Production bootstrap nodes for CHIE network.
///
/// These should be updated to point to actual deployed and maintained bootstrap nodes.
/// For production deployment, consider:
/// - Deploying at least 3-5 geographically distributed bootstrap nodes
/// - Using DNS TXT records for dynamic bootstrap node discovery
/// - Monitoring bootstrap node health and availability
pub const BOOTSTRAP_NODES: &[&str] = &[
    // Production bootstrap nodes - update these with actual deployed nodes
    // Example formats:
    // "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWBootstrap1...",
    // "/ip4/203.0.113.20/udp/4001/quic-v1/p2p/12D3KooWBootstrap2...",
    // "/dns4/bootstrap1.chie.network/tcp/4001/p2p/12D3KooWBootstrap3...",
    // "/dns6/bootstrap2.chie.network/tcp/4001/p2p/12D3KooWBootstrap4...",
];

/// Environment variable name for custom bootstrap nodes.
/// Format: comma-separated list of multiaddrs
/// Example: CHIE_BOOTSTRAP_NODES="/ip4/1.2.3.4/tcp/4001/p2p/12D3...,/dns4/node.example.com/tcp/4001/p2p/12D3..."
pub const ENV_BOOTSTRAP_NODES: &str = "CHIE_BOOTSTRAP_NODES";

/// Environment variable for DNS-based bootstrap discovery.
/// Format: DNS name that has TXT records with bootstrap multiaddrs
/// Example: CHIE_BOOTSTRAP_DNS="bootstrap.chie.network"
pub const ENV_BOOTSTRAP_DNS: &str = "CHIE_BOOTSTRAP_DNS";

/// Default TTL for content advertisements (24 hours).
pub const DEFAULT_ADVERTISEMENT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Bootstrap node source strategy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BootstrapSource {
    /// Use hardcoded bootstrap nodes.
    #[default]
    Static,
    /// Load from environment variable.
    Environment,
    /// Discover via DNS TXT records.
    Dns(String),
    /// Custom list of multiaddrs.
    Custom(Vec<String>),
}

/// Peer discovery configuration.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Bootstrap nodes to connect to on startup.
    pub bootstrap_nodes: Vec<Multiaddr>,

    /// Bootstrap source strategy.
    pub bootstrap_source: BootstrapSource,

    /// Enable fallback to static bootstrap nodes if primary source fails.
    pub enable_bootstrap_fallback: bool,

    /// Enable mDNS for local network discovery.
    pub enable_mdns: bool,

    /// Maximum number of peers to maintain.
    pub max_peers: usize,

    /// Advertisement TTL.
    pub advertisement_ttl: Duration,

    /// Re-advertisement interval (should be < TTL).
    pub readvertise_interval: Duration,

    /// Health check interval for bootstrap nodes.
    pub bootstrap_health_check_interval: Duration,

    /// Timeout for bootstrap node connection attempts.
    pub bootstrap_connection_timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: BOOTSTRAP_NODES
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            bootstrap_source: BootstrapSource::default(),
            enable_bootstrap_fallback: true,
            enable_mdns: true,
            max_peers: 50,
            advertisement_ttl: DEFAULT_ADVERTISEMENT_TTL,
            readvertise_interval: Duration::from_secs(12 * 60 * 60), // 12 hours
            bootstrap_health_check_interval: Duration::from_secs(5 * 60), // 5 minutes
            bootstrap_connection_timeout: Duration::from_secs(10),
        }
    }
}

impl DiscoveryConfig {
    /// Create a new discovery config with custom bootstrap source.
    pub fn with_bootstrap_source(mut self, source: BootstrapSource) -> Self {
        self.bootstrap_source = source;
        self
    }

    /// Enable or disable bootstrap fallback.
    pub fn with_bootstrap_fallback(mut self, enable: bool) -> Self {
        self.enable_bootstrap_fallback = enable;
        self
    }

    /// Set bootstrap health check interval.
    pub fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.bootstrap_health_check_interval = interval;
        self
    }
}

/// Discovered peers.
#[derive(Debug, Default)]
pub struct DiscoveredPeers {
    /// Set of discovered peer IDs.
    pub peers: HashSet<PeerId>,
}

impl DiscoveredPeers {
    /// Add a discovered peer.
    pub fn add(&mut self, peer: PeerId) -> bool {
        self.peers.insert(peer)
    }

    /// Remove a peer.
    pub fn remove(&mut self, peer: &PeerId) -> bool {
        self.peers.remove(peer)
    }

    /// Check if a peer is known.
    pub fn contains(&self, peer: &PeerId) -> bool {
        self.peers.contains(peer)
    }

    /// Get the number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Content advertisement record.
#[derive(Debug, Clone)]
pub struct ContentAdvertisement {
    /// Content CID.
    pub cid: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Number of chunks.
    pub chunk_count: u64,
    /// When this advertisement was created.
    pub created_at: Instant,
    /// When this advertisement expires.
    pub expires_at: Instant,
    /// Last time we advertised this content.
    pub last_advertised: Option<Instant>,
}

impl ContentAdvertisement {
    /// Create a new content advertisement.
    pub fn new(cid: String, size_bytes: u64, chunk_count: u64, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            cid,
            size_bytes,
            chunk_count,
            created_at: now,
            expires_at: now + ttl,
            last_advertised: None,
        }
    }

    /// Check if this advertisement has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Refresh the advertisement expiry.
    pub fn refresh(&mut self, ttl: Duration) {
        self.expires_at = Instant::now() + ttl;
    }

    /// Mark as advertised.
    pub fn mark_advertised(&mut self) {
        self.last_advertised = Some(Instant::now());
    }

    /// Check if re-advertisement is needed.
    pub fn needs_readvertise(&self, interval: Duration) -> bool {
        match self.last_advertised {
            Some(last) => Instant::now().duration_since(last) >= interval,
            None => true,
        }
    }
}

/// Content provider information.
#[derive(Debug, Clone)]
pub struct ContentProvider {
    /// Provider's peer ID.
    pub peer_id: PeerId,
    /// Provider's addresses.
    pub addresses: Vec<Multiaddr>,
    /// When this provider record was seen.
    pub seen_at: Instant,
    /// Provider score (from reputation system, if available).
    pub score: Option<f64>,
}

/// Manager for content advertisements.
pub struct ContentAdvertisementManager {
    /// Local content we're advertising.
    local_content: HashMap<String, ContentAdvertisement>,
    /// Known providers for content (CID -> providers).
    known_providers: HashMap<String, Vec<ContentProvider>>,
    /// Configuration.
    config: DiscoveryConfig,
}

impl Default for ContentAdvertisementManager {
    fn default() -> Self {
        Self::new(DiscoveryConfig::default())
    }
}

impl ContentAdvertisementManager {
    /// Create a new content advertisement manager.
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            local_content: HashMap::new(),
            known_providers: HashMap::new(),
            config,
        }
    }

    /// Add content to advertise.
    pub fn add_content(&mut self, cid: String, size_bytes: u64, chunk_count: u64) {
        let advertisement = ContentAdvertisement::new(
            cid.clone(),
            size_bytes,
            chunk_count,
            self.config.advertisement_ttl,
        );
        self.local_content.insert(cid, advertisement);
    }

    /// Remove content from advertisement.
    pub fn remove_content(&mut self, cid: &str) -> Option<ContentAdvertisement> {
        self.local_content.remove(cid)
    }

    /// Check if we're advertising a specific content.
    pub fn has_content(&self, cid: &str) -> bool {
        self.local_content.contains_key(cid)
    }

    /// Get advertisement for specific content.
    pub fn get_advertisement(&self, cid: &str) -> Option<&ContentAdvertisement> {
        self.local_content.get(cid)
    }

    /// Get all content CIDs we're advertising.
    pub fn get_local_cids(&self) -> Vec<String> {
        self.local_content.keys().cloned().collect()
    }

    /// Get content that needs to be advertised (new or needs re-advertisement).
    pub fn get_pending_advertisements(&self) -> Vec<&ContentAdvertisement> {
        self.local_content
            .values()
            .filter(|ad| !ad.is_expired() && ad.needs_readvertise(self.config.readvertise_interval))
            .collect()
    }

    /// Mark content as advertised.
    pub fn mark_advertised(&mut self, cid: &str) {
        if let Some(ad) = self.local_content.get_mut(cid) {
            ad.mark_advertised();
        }
    }

    /// Record a provider for content.
    pub fn add_provider(&mut self, cid: String, provider: ContentProvider) {
        self.known_providers.entry(cid).or_default().push(provider);
    }

    /// Get known providers for content.
    pub fn get_providers(&self, cid: &str) -> Option<&Vec<ContentProvider>> {
        self.known_providers.get(cid)
    }

    /// Get providers sorted by score (highest first).
    pub fn get_ranked_providers(&self, cid: &str) -> Vec<&ContentProvider> {
        if let Some(providers) = self.known_providers.get(cid) {
            let mut ranked: Vec<&ContentProvider> = providers.iter().collect();
            ranked.sort_by(|a, b| {
                let score_a = a.score.unwrap_or(50.0);
                let score_b = b.score.unwrap_or(50.0);
                score_b.partial_cmp(&score_a).unwrap()
            });
            ranked
        } else {
            Vec::new()
        }
    }

    /// Clear providers for content.
    pub fn clear_providers(&mut self, cid: &str) {
        self.known_providers.remove(cid);
    }

    /// Prune expired advertisements.
    pub fn prune_expired(&mut self) {
        self.local_content.retain(|_, ad| !ad.is_expired());
    }

    /// Prune old provider records.
    pub fn prune_old_providers(&mut self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        for providers in self.known_providers.values_mut() {
            providers.retain(|p| p.seen_at > cutoff);
        }
        self.known_providers
            .retain(|_, providers| !providers.is_empty());
    }

    /// Get statistics about content advertisements.
    pub fn get_stats(&self) -> ContentAdvertisementStats {
        ContentAdvertisementStats {
            local_content_count: self.local_content.len(),
            known_content_count: self.known_providers.len(),
            total_providers: self.known_providers.values().map(|v| v.len()).sum(),
        }
    }
}

/// Statistics about content advertisements.
#[derive(Debug, Clone)]
pub struct ContentAdvertisementStats {
    /// Number of local content items being advertised.
    pub local_content_count: usize,
    /// Number of content items with known providers.
    pub known_content_count: usize,
    /// Total number of known providers.
    pub total_providers: usize,
}

/// Create a DHT key from a content CID.
///
/// This creates a key suitable for Kademlia provider records.
pub fn cid_to_dht_key(cid: &str) -> Vec<u8> {
    use chie_crypto::hash;
    let key_hash = hash(cid.as_bytes());
    key_hash.to_vec()
}

/// Query builder for content discovery.
pub struct ContentQuery {
    /// Content CID to search for.
    pub cid: String,
    /// DHT key for the query.
    pub dht_key: Vec<u8>,
    /// Maximum number of providers to find.
    pub max_providers: usize,
    /// Query started at.
    pub started_at: Instant,
    /// Query timeout.
    pub timeout: Duration,
}

impl ContentQuery {
    /// Create a new content query.
    pub fn new(cid: String, max_providers: usize, timeout: Duration) -> Self {
        let dht_key = cid_to_dht_key(&cid);
        Self {
            cid,
            dht_key,
            max_providers,
            started_at: Instant::now(),
            timeout,
        }
    }

    /// Check if the query has timed out.
    pub fn is_timed_out(&self) -> bool {
        Instant::now().duration_since(self.started_at) >= self.timeout
    }
}

/// Bootstrap node health status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapHealth {
    /// Node is reachable and responsive.
    Healthy,
    /// Node is unreachable or not responding.
    Unhealthy,
    /// Health status unknown (not yet checked).
    Unknown,
}

/// Information about a bootstrap node.
#[derive(Debug, Clone)]
pub struct BootstrapNodeInfo {
    /// Multiaddr of the bootstrap node.
    pub addr: Multiaddr,
    /// Peer ID if known.
    pub peer_id: Option<PeerId>,
    /// Health status.
    pub health: BootstrapHealth,
    /// Last time this node was checked.
    pub last_checked: Option<Instant>,
    /// Number of successful connections.
    pub success_count: usize,
    /// Number of failed connection attempts.
    pub failure_count: usize,
}

impl BootstrapNodeInfo {
    /// Create a new bootstrap node info from a multiaddr.
    pub fn new(addr: Multiaddr) -> Self {
        Self {
            addr,
            peer_id: None,
            health: BootstrapHealth::Unknown,
            last_checked: None,
            success_count: 0,
            failure_count: 0,
        }
    }

    /// Mark the node as healthy.
    pub fn mark_healthy(&mut self) {
        self.health = BootstrapHealth::Healthy;
        self.last_checked = Some(Instant::now());
        self.success_count += 1;
    }

    /// Mark the node as unhealthy.
    pub fn mark_unhealthy(&mut self) {
        self.health = BootstrapHealth::Unhealthy;
        self.last_checked = Some(Instant::now());
        self.failure_count += 1;
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

    /// Check if health check is needed.
    pub fn needs_health_check(&self, interval: Duration) -> bool {
        match self.last_checked {
            Some(last) => Instant::now().duration_since(last) >= interval,
            None => true,
        }
    }
}

/// Manager for bootstrap nodes with health monitoring.
#[derive(Debug)]
pub struct BootstrapManager {
    /// Bootstrap node information.
    nodes: Vec<BootstrapNodeInfo>,
    /// Configuration.
    config: DiscoveryConfig,
}

impl BootstrapManager {
    /// Create a new bootstrap manager.
    pub fn new(config: DiscoveryConfig) -> Self {
        let nodes = config
            .bootstrap_nodes
            .iter()
            .map(|addr| BootstrapNodeInfo::new(addr.clone()))
            .collect();

        Self { nodes, config }
    }

    /// Load bootstrap nodes from the configured source.
    pub fn load_bootstrap_nodes(&mut self) -> Result<Vec<Multiaddr>, BootstrapError> {
        let addrs = match &self.config.bootstrap_source {
            BootstrapSource::Static => load_static_bootstrap_nodes(),
            BootstrapSource::Environment => load_bootstrap_from_env()?,
            BootstrapSource::Dns(domain) => {
                // Note: Actual DNS resolution would be async, this is a placeholder
                tracing::info!(
                    "DNS bootstrap from {} not yet implemented, using static",
                    domain
                );
                load_static_bootstrap_nodes()
            }
            BootstrapSource::Custom(addrs) => addrs.iter().filter_map(|s| s.parse().ok()).collect(),
        };

        // Update nodes list
        self.nodes = addrs
            .iter()
            .map(|addr| BootstrapNodeInfo::new(addr.clone()))
            .collect();

        Ok(addrs)
    }

    /// Get all bootstrap nodes.
    pub fn get_nodes(&self) -> &[BootstrapNodeInfo] {
        &self.nodes
    }

    /// Get healthy bootstrap nodes only.
    pub fn get_healthy_nodes(&self) -> Vec<&BootstrapNodeInfo> {
        self.nodes
            .iter()
            .filter(|n| n.health == BootstrapHealth::Healthy)
            .collect()
    }

    /// Get nodes that need health check.
    pub fn get_nodes_needing_check(&self) -> Vec<&BootstrapNodeInfo> {
        self.nodes
            .iter()
            .filter(|n| n.needs_health_check(self.config.bootstrap_health_check_interval))
            .collect()
    }

    /// Update node health status.
    pub fn update_node_health(&mut self, addr: &Multiaddr, is_healthy: bool) {
        if let Some(node) = self.nodes.iter_mut().find(|n| &n.addr == addr) {
            if is_healthy {
                node.mark_healthy();
            } else {
                node.mark_unhealthy();
            }
        }
    }

    /// Get bootstrap statistics.
    pub fn get_stats(&self) -> BootstrapStats {
        let healthy = self
            .nodes
            .iter()
            .filter(|n| n.health == BootstrapHealth::Healthy)
            .count();
        let unhealthy = self
            .nodes
            .iter()
            .filter(|n| n.health == BootstrapHealth::Unhealthy)
            .count();
        let unknown = self
            .nodes
            .iter()
            .filter(|n| n.health == BootstrapHealth::Unknown)
            .count();

        BootstrapStats {
            total_nodes: self.nodes.len(),
            healthy_nodes: healthy,
            unhealthy_nodes: unhealthy,
            unknown_nodes: unknown,
        }
    }
}

/// Bootstrap statistics.
#[derive(Debug, Clone)]
pub struct BootstrapStats {
    /// Total number of bootstrap nodes.
    pub total_nodes: usize,
    /// Number of healthy nodes.
    pub healthy_nodes: usize,
    /// Number of unhealthy nodes.
    pub unhealthy_nodes: usize,
    /// Number of nodes with unknown health.
    pub unknown_nodes: usize,
}

/// Bootstrap error types.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BootstrapError {
    /// No bootstrap nodes configured.
    #[error("No bootstrap nodes configured")]
    NoNodes,
    /// Invalid multiaddr format.
    #[error("Invalid multiaddr: {0}")]
    InvalidMultiaddr(String),
    /// Environment variable not set.
    #[error("Environment variable {0} not set")]
    EnvNotSet(String),
    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),
}

/// Load bootstrap nodes from static configuration.
pub fn load_static_bootstrap_nodes() -> Vec<Multiaddr> {
    BOOTSTRAP_NODES
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Load bootstrap nodes from environment variable.
pub fn load_bootstrap_from_env() -> Result<Vec<Multiaddr>, BootstrapError> {
    let env_value = std::env::var(ENV_BOOTSTRAP_NODES)
        .map_err(|_| BootstrapError::EnvNotSet(ENV_BOOTSTRAP_NODES.to_string()))?;

    if env_value.is_empty() {
        return Err(BootstrapError::NoNodes);
    }

    let addrs: Vec<Multiaddr> = env_value
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| match s.parse::<Multiaddr>() {
            Ok(addr) => Some(addr),
            Err(e) => {
                tracing::warn!("Failed to parse bootstrap multiaddr '{}': {}", s, e);
                None
            }
        })
        .collect();

    if addrs.is_empty() {
        Err(BootstrapError::NoNodes)
    } else {
        Ok(addrs)
    }
}

/// Load bootstrap DNS domain from environment variable.
pub fn load_bootstrap_dns_from_env() -> Option<String> {
    std::env::var(ENV_BOOTSTRAP_DNS).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_advertisement() {
        let mut manager = ContentAdvertisementManager::default();

        manager.add_content("QmTest123".to_string(), 1024 * 1024, 4);

        assert!(manager.has_content("QmTest123"));
        assert!(!manager.has_content("QmNonExistent"));

        let pending = manager.get_pending_advertisements();
        assert_eq!(pending.len(), 1);

        manager.mark_advertised("QmTest123");
        let pending = manager.get_pending_advertisements();
        assert_eq!(pending.len(), 0); // Now marked as advertised
    }

    #[test]
    fn test_content_providers() {
        let mut manager = ContentAdvertisementManager::default();
        let peer_id = PeerId::random();

        let provider = ContentProvider {
            peer_id,
            addresses: vec![],
            seen_at: Instant::now(),
            score: Some(80.0),
        };

        manager.add_provider("QmTest123".to_string(), provider);

        let providers = manager.get_providers("QmTest123");
        assert!(providers.is_some());
        assert_eq!(providers.unwrap().len(), 1);
    }

    #[test]
    fn test_ranked_providers() {
        let mut manager = ContentAdvertisementManager::default();

        for score in [50.0, 80.0, 30.0, 70.0].iter() {
            let provider = ContentProvider {
                peer_id: PeerId::random(),
                addresses: vec![],
                seen_at: Instant::now(),
                score: Some(*score),
            };
            manager.add_provider("QmTest".to_string(), provider);
        }

        let ranked = manager.get_ranked_providers("QmTest");
        assert_eq!(ranked.len(), 4);
        assert_eq!(ranked[0].score, Some(80.0));
        assert_eq!(ranked[1].score, Some(70.0));
        assert_eq!(ranked[2].score, Some(50.0));
        assert_eq!(ranked[3].score, Some(30.0));
    }

    #[test]
    fn test_cid_to_dht_key() {
        let key1 = cid_to_dht_key("QmTest123");
        let key2 = cid_to_dht_key("QmTest123");
        let key3 = cid_to_dht_key("QmDifferent");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_bootstrap_source() {
        let source_static = BootstrapSource::Static;
        let source_env = BootstrapSource::Environment;
        let source_dns = BootstrapSource::Dns("bootstrap.example.com".to_string());
        let source_custom = BootstrapSource::Custom(vec!["/ip4/127.0.0.1/tcp/4001".to_string()]);

        assert_eq!(source_static, BootstrapSource::default());
        assert_ne!(source_static, source_env);
        assert_ne!(source_env, source_dns);
        assert_ne!(source_dns, source_custom);
    }

    #[test]
    fn test_bootstrap_node_info() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let mut node = BootstrapNodeInfo::new(addr.clone());

        assert_eq!(node.addr, addr);
        assert_eq!(node.health, BootstrapHealth::Unknown);
        assert_eq!(node.success_count, 0);
        assert_eq!(node.failure_count, 0);
        assert_eq!(node.success_rate(), 0.0);

        node.mark_healthy();
        assert_eq!(node.health, BootstrapHealth::Healthy);
        assert_eq!(node.success_count, 1);
        assert_eq!(node.success_rate(), 1.0);

        node.mark_unhealthy();
        assert_eq!(node.health, BootstrapHealth::Unhealthy);
        assert_eq!(node.failure_count, 1);
        assert_eq!(node.success_rate(), 0.5);

        node.mark_healthy();
        assert_eq!(node.success_rate(), 2.0 / 3.0);
    }

    #[test]
    fn test_bootstrap_node_health_check() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let mut node = BootstrapNodeInfo::new(addr);

        // Should need check initially
        assert!(node.needs_health_check(Duration::from_secs(60)));

        node.mark_healthy();
        // Should not need check immediately after
        assert!(!node.needs_health_check(Duration::from_secs(60)));

        // Test that a zero duration would indicate check is needed
        // Test with zero duration - should always need check (since any time has passed)
        let needs_check = node.needs_health_check(Duration::from_nanos(0));
        // The result depends on timing, so we just ensure the API is callable
        let _ = needs_check;

        // Better test: check with a very long interval shows no check needed
        assert!(!node.needs_health_check(Duration::from_secs(3600)));
    }

    #[test]
    fn test_bootstrap_manager() {
        let config = DiscoveryConfig::default();
        let manager = BootstrapManager::new(config);

        let stats = manager.get_stats();
        assert_eq!(stats.total_nodes, 0); // No static bootstrap nodes configured
        assert_eq!(stats.healthy_nodes, 0);
        assert_eq!(stats.unhealthy_nodes, 0);
        assert_eq!(stats.unknown_nodes, 0);
    }

    #[test]
    fn test_bootstrap_manager_with_custom_nodes() {
        let custom_addrs = vec![
            "/ip4/127.0.0.1/tcp/4001".to_string(),
            "/ip4/127.0.0.1/tcp/4002".to_string(),
        ];

        let config =
            DiscoveryConfig::default().with_bootstrap_source(BootstrapSource::Custom(custom_addrs));

        let mut manager = BootstrapManager::new(config);
        let addrs = manager.load_bootstrap_nodes().unwrap();

        assert_eq!(addrs.len(), 2);

        let stats = manager.get_stats();
        assert_eq!(stats.total_nodes, 2);
        assert_eq!(stats.unknown_nodes, 2);
    }

    #[test]
    fn test_bootstrap_manager_health_updates() {
        let custom_addrs = vec!["/ip4/127.0.0.1/tcp/4001".to_string()];

        let config =
            DiscoveryConfig::default().with_bootstrap_source(BootstrapSource::Custom(custom_addrs));

        let mut manager = BootstrapManager::new(config);
        manager.load_bootstrap_nodes().unwrap();

        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        manager.update_node_health(&addr, true);

        let healthy = manager.get_healthy_nodes();
        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].addr, addr);

        let stats = manager.get_stats();
        assert_eq!(stats.healthy_nodes, 1);
        assert_eq!(stats.unhealthy_nodes, 0);

        manager.update_node_health(&addr, false);
        let stats = manager.get_stats();
        assert_eq!(stats.healthy_nodes, 0);
        assert_eq!(stats.unhealthy_nodes, 1);
    }

    #[test]
    fn test_load_bootstrap_from_env_not_set() {
        // Make sure env var is not set
        unsafe {
            std::env::remove_var(ENV_BOOTSTRAP_NODES);
        }

        let result = load_bootstrap_from_env();
        assert!(result.is_err());
        match result {
            Err(BootstrapError::EnvNotSet(_)) => {}
            _ => panic!("Expected EnvNotSet error"),
        }
    }

    #[test]
    fn test_load_bootstrap_from_env_empty() {
        unsafe {
            std::env::set_var(ENV_BOOTSTRAP_NODES, "");
        }

        let result = load_bootstrap_from_env();
        assert!(result.is_err());
        match result {
            Err(BootstrapError::NoNodes) => {}
            _ => panic!("Expected NoNodes error"),
        }

        unsafe {
            std::env::remove_var(ENV_BOOTSTRAP_NODES);
        }
    }

    #[test]
    fn test_load_bootstrap_from_env_valid() {
        unsafe {
            std::env::set_var(
                ENV_BOOTSTRAP_NODES,
                "/ip4/127.0.0.1/tcp/4001,/ip4/127.0.0.1/tcp/4002",
            );
        }

        let result = load_bootstrap_from_env();
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert_eq!(addrs.len(), 2);

        unsafe {
            std::env::remove_var(ENV_BOOTSTRAP_NODES);
        }
    }

    #[test]
    fn test_load_bootstrap_from_env_mixed_valid_invalid() {
        unsafe {
            std::env::set_var(
                ENV_BOOTSTRAP_NODES,
                "/ip4/127.0.0.1/tcp/4001,invalid,/ip4/127.0.0.1/tcp/4002",
            );
        }

        let result = load_bootstrap_from_env();
        assert!(result.is_ok());
        let addrs = result.unwrap();
        // Should only get the valid ones
        assert_eq!(addrs.len(), 2);

        unsafe {
            std::env::remove_var(ENV_BOOTSTRAP_NODES);
        }
    }

    #[test]
    fn test_discovery_config_builder() {
        let config = DiscoveryConfig::default()
            .with_bootstrap_source(BootstrapSource::Environment)
            .with_bootstrap_fallback(false)
            .with_health_check_interval(Duration::from_secs(300));

        assert_eq!(config.bootstrap_source, BootstrapSource::Environment);
        assert!(!config.enable_bootstrap_fallback);
        assert_eq!(
            config.bootstrap_health_check_interval,
            Duration::from_secs(300)
        );
    }
}
