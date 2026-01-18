//! NAT traversal utilities for CHIE Protocol.
//!
//! This module provides:
//! - NAT type detection
//! - Circuit relay client configuration
//! - Hole punching support configuration
//! - External address discovery

use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// NAT type detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT detected (public IP).
    Public,
    /// Full cone NAT (most permissive).
    FullCone,
    /// Restricted cone NAT.
    RestrictedCone,
    /// Port restricted cone NAT.
    PortRestrictedCone,
    /// Symmetric NAT (most restrictive).
    Symmetric,
    /// NAT type unknown.
    Unknown,
}

impl NatType {
    /// Check if direct connections are likely to work.
    pub fn supports_direct(&self) -> bool {
        matches!(
            self,
            NatType::Public | NatType::FullCone | NatType::RestrictedCone
        )
    }

    /// Check if hole punching is likely to work.
    pub fn supports_hole_punching(&self) -> bool {
        !matches!(self, NatType::Symmetric)
    }

    /// Check if relay is required for incoming connections.
    pub fn requires_relay(&self) -> bool {
        matches!(
            self,
            NatType::PortRestrictedCone | NatType::Symmetric | NatType::Unknown
        )
    }
}

/// Configuration for NAT traversal.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Enable automatic relay usage.
    pub enable_relay: bool,
    /// Enable hole punching attempts.
    pub enable_hole_punching: bool,
    /// Enable UPnP port mapping.
    pub enable_upnp: bool,
    /// Maximum number of relay servers to use.
    pub max_relay_servers: usize,
    /// Timeout for NAT detection.
    pub detection_timeout: Duration,
    /// How often to refresh NAT status.
    pub refresh_interval: Duration,
    /// Reserved relay servers (known good relays).
    pub reserved_relays: Vec<(PeerId, Multiaddr)>,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_relay: true,
            enable_hole_punching: true,
            enable_upnp: false, // Disabled by default for security
            max_relay_servers: 3,
            detection_timeout: Duration::from_secs(30),
            refresh_interval: Duration::from_secs(300), // 5 minutes
            reserved_relays: Vec::new(),
        }
    }
}

/// External address information.
#[derive(Debug, Clone)]
pub struct ExternalAddress {
    /// The external address.
    pub address: Multiaddr,
    /// When this address was discovered.
    pub discovered_at: Instant,
    /// How many peers confirmed this address.
    pub confirmations: u32,
    /// Source of this address discovery.
    pub source: AddressSource,
}

/// Source of address discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSource {
    /// Discovered via identify protocol.
    Identify,
    /// Discovered via STUN.
    Stun,
    /// Discovered via UPnP.
    Upnp,
    /// Manually configured.
    Manual,
    /// Discovered via relay.
    Relay,
}

/// NAT status tracker.
pub struct NatStatus {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Our known external addresses.
    external_addresses: Vec<ExternalAddress>,
    /// Active relay connections.
    relay_connections: HashSet<PeerId>,
    /// Last NAT detection time.
    last_detection: Option<Instant>,
    /// Configuration.
    config: NatConfig,
}

impl Default for NatStatus {
    fn default() -> Self {
        Self::new(NatConfig::default())
    }
}

impl NatStatus {
    /// Create a new NAT status tracker.
    pub fn new(config: NatConfig) -> Self {
        Self {
            nat_type: NatType::Unknown,
            external_addresses: Vec::new(),
            relay_connections: HashSet::new(),
            last_detection: None,
            config,
        }
    }

    /// Add an external address.
    pub fn add_external_address(&mut self, address: Multiaddr, source: AddressSource) {
        // Check if we already have this address
        if let Some(existing) = self
            .external_addresses
            .iter_mut()
            .find(|a| a.address == address)
        {
            existing.confirmations += 1;
            return;
        }

        self.external_addresses.push(ExternalAddress {
            address,
            discovered_at: Instant::now(),
            confirmations: 1,
            source,
        });
    }

    /// Get confirmed external addresses (with multiple confirmations).
    pub fn confirmed_addresses(&self) -> Vec<&ExternalAddress> {
        self.external_addresses
            .iter()
            .filter(|a| a.confirmations >= 2)
            .collect()
    }

    /// Get all external addresses.
    pub fn all_addresses(&self) -> &[ExternalAddress] {
        &self.external_addresses
    }

    /// Update NAT type.
    pub fn set_nat_type(&mut self, nat_type: NatType) {
        self.nat_type = nat_type;
        self.last_detection = Some(Instant::now());
    }

    /// Check if NAT detection needs refresh.
    pub fn needs_refresh(&self) -> bool {
        match self.last_detection {
            Some(t) => Instant::now().duration_since(t) >= self.config.refresh_interval,
            None => true,
        }
    }

    /// Add a relay connection.
    pub fn add_relay(&mut self, peer: PeerId) -> bool {
        if self.relay_connections.len() >= self.config.max_relay_servers {
            return false;
        }
        self.relay_connections.insert(peer)
    }

    /// Remove a relay connection.
    pub fn remove_relay(&mut self, peer: &PeerId) -> bool {
        self.relay_connections.remove(peer)
    }

    /// Get active relay connections.
    pub fn relay_connections(&self) -> &HashSet<PeerId> {
        &self.relay_connections
    }

    /// Check if we should use relay.
    pub fn should_use_relay(&self) -> bool {
        self.config.enable_relay && self.nat_type.requires_relay()
    }

    /// Check if we should attempt hole punching.
    pub fn should_hole_punch(&self) -> bool {
        self.config.enable_hole_punching && self.nat_type.supports_hole_punching()
    }

    /// Get the configuration.
    pub fn config(&self) -> &NatConfig {
        &self.config
    }

    /// Get a summary of NAT status.
    pub fn summary(&self) -> NatSummary {
        NatSummary {
            nat_type: self.nat_type,
            external_address_count: self.external_addresses.len(),
            relay_count: self.relay_connections.len(),
            supports_direct: self.nat_type.supports_direct(),
            supports_hole_punching: self.nat_type.supports_hole_punching(),
            requires_relay: self.nat_type.requires_relay(),
        }
    }
}

/// Summary of NAT status for monitoring.
#[derive(Debug, Clone)]
pub struct NatSummary {
    /// Detected NAT type.
    pub nat_type: NatType,
    /// Number of known external addresses.
    pub external_address_count: usize,
    /// Number of active relay connections.
    pub relay_count: usize,
    /// Whether direct connections are supported.
    pub supports_direct: bool,
    /// Whether hole punching is supported.
    pub supports_hole_punching: bool,
    /// Whether relay is required.
    pub requires_relay: bool,
}

/// Relay server information.
#[derive(Debug, Clone)]
pub struct RelayServer {
    /// Peer ID of the relay server.
    pub peer_id: PeerId,
    /// Addresses of the relay server.
    pub addresses: Vec<Multiaddr>,
    /// Whether this relay is currently connected.
    pub connected: bool,
    /// Last successful connection time.
    pub last_connected: Option<Instant>,
    /// Number of times we've used this relay.
    pub usage_count: u64,
    /// Average latency to this relay (ms).
    pub avg_latency_ms: Option<u32>,
}

impl RelayServer {
    /// Create a new relay server entry.
    pub fn new(peer_id: PeerId, addresses: Vec<Multiaddr>) -> Self {
        Self {
            peer_id,
            addresses,
            connected: false,
            last_connected: None,
            usage_count: 0,
            avg_latency_ms: None,
        }
    }

    /// Mark as connected.
    pub fn mark_connected(&mut self) {
        self.connected = true;
        self.last_connected = Some(Instant::now());
    }

    /// Mark as disconnected.
    pub fn mark_disconnected(&mut self) {
        self.connected = false;
    }

    /// Record usage.
    pub fn record_usage(&mut self, latency_ms: u32) {
        self.usage_count += 1;
        self.avg_latency_ms = Some(match self.avg_latency_ms {
            Some(avg) => (avg + latency_ms) / 2,
            None => latency_ms,
        });
    }
}

/// Relay server manager.
pub struct RelayManager {
    /// Known relay servers.
    servers: Vec<RelayServer>,
    /// Configuration.
    #[allow(dead_code)]
    config: NatConfig,
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new(NatConfig::default())
    }
}

impl RelayManager {
    /// Create a new relay manager.
    pub fn new(config: NatConfig) -> Self {
        let mut servers = Vec::new();

        // Add reserved relays from config
        for (peer_id, addr) in &config.reserved_relays {
            servers.push(RelayServer::new(*peer_id, vec![addr.clone()]));
        }

        Self { servers, config }
    }

    /// Add a relay server.
    pub fn add_server(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        if self.servers.iter().any(|s| s.peer_id == peer_id) {
            return;
        }
        self.servers.push(RelayServer::new(peer_id, addresses));
    }

    /// Remove a relay server.
    pub fn remove_server(&mut self, peer_id: &PeerId) {
        self.servers.retain(|s| &s.peer_id != peer_id);
    }

    /// Get a relay server by peer ID.
    pub fn get_server(&self, peer_id: &PeerId) -> Option<&RelayServer> {
        self.servers.iter().find(|s| &s.peer_id == peer_id)
    }

    /// Get a mutable relay server by peer ID.
    pub fn get_server_mut(&mut self, peer_id: &PeerId) -> Option<&mut RelayServer> {
        self.servers.iter_mut().find(|s| &s.peer_id == peer_id)
    }

    /// Get connected relay servers.
    pub fn connected_servers(&self) -> Vec<&RelayServer> {
        self.servers.iter().filter(|s| s.connected).collect()
    }

    /// Get the best relay server (lowest latency, connected).
    pub fn best_server(&self) -> Option<&RelayServer> {
        self.servers
            .iter()
            .filter(|s| s.connected)
            .min_by_key(|s| s.avg_latency_ms.unwrap_or(u32::MAX))
    }

    /// Get relay servers sorted by quality.
    pub fn servers_by_quality(&self) -> Vec<&RelayServer> {
        let mut servers: Vec<&RelayServer> = self.servers.iter().collect();
        servers.sort_by(|a, b| {
            // Connected servers first
            match (a.connected, b.connected) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    // Then by latency
                    let lat_a = a.avg_latency_ms.unwrap_or(u32::MAX);
                    let lat_b = b.avg_latency_ms.unwrap_or(u32::MAX);
                    lat_a.cmp(&lat_b)
                }
            }
        });
        servers
    }

    /// Get the number of relay servers.
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// Get the number of connected relay servers.
    pub fn connected_count(&self) -> usize {
        self.servers.iter().filter(|s| s.connected).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_type_properties() {
        assert!(NatType::Public.supports_direct());
        assert!(NatType::Public.supports_hole_punching());
        assert!(!NatType::Public.requires_relay());

        assert!(!NatType::Symmetric.supports_direct());
        assert!(!NatType::Symmetric.supports_hole_punching());
        assert!(NatType::Symmetric.requires_relay());
    }

    #[test]
    fn test_nat_status() {
        let mut status = NatStatus::default();

        assert_eq!(status.nat_type, NatType::Unknown);
        assert!(status.needs_refresh());

        status.set_nat_type(NatType::FullCone);
        assert_eq!(status.nat_type, NatType::FullCone);
        assert!(!status.needs_refresh());
    }

    #[test]
    fn test_external_address() {
        let mut status = NatStatus::default();
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();

        status.add_external_address(addr.clone(), AddressSource::Identify);
        assert_eq!(status.all_addresses().len(), 1);

        // Add same address again
        status.add_external_address(addr.clone(), AddressSource::Stun);
        assert_eq!(status.all_addresses().len(), 1);
        assert_eq!(status.all_addresses()[0].confirmations, 2);

        // Should be confirmed now
        assert_eq!(status.confirmed_addresses().len(), 1);
    }

    #[test]
    fn test_relay_manager() {
        let mut manager = RelayManager::default();
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/4001".parse().unwrap();

        manager.add_server(peer_id, vec![addr]);
        assert_eq!(manager.server_count(), 1);
        assert_eq!(manager.connected_count(), 0);

        manager.get_server_mut(&peer_id).unwrap().mark_connected();
        assert_eq!(manager.connected_count(), 1);

        assert!(manager.best_server().is_some());
    }
}
