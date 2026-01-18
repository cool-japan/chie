//! Enhanced peer discovery strategies with quality scoring, geographic proximity,
//! topology awareness, and intelligent peer replacement.
//!
//! This module provides advanced peer discovery capabilities beyond basic DHT and mDNS,
//! including network topology analysis and smart peer selection based on multiple factors.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Geographic location information for a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,
    /// City name
    pub city: Option<String>,
    /// Autonomous System Number
    pub asn: Option<u32>,
}

impl GeoLocation {
    /// Calculate distance to another location in kilometers using Haversine formula
    pub fn distance_to(&self, other: &GeoLocation) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }

    /// Check if two peers are in the same AS (Autonomous System)
    pub fn same_as(&self, other: &GeoLocation) -> bool {
        match (self.asn, other.asn) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

/// Network topology position of a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyPosition {
    /// Number of direct connections
    pub degree: usize,
    /// Betweenness centrality (0.0 to 1.0)
    pub betweenness: f64,
    /// Clustering coefficient (0.0 to 1.0)
    pub clustering: f64,
    /// Distance to network core (hop count)
    pub core_distance: usize,
    /// Whether this peer is a hub (high degree)
    pub is_hub: bool,
}

/// Comprehensive peer quality metrics
#[derive(Debug, Clone)]
pub struct PeerQuality {
    /// Overall quality score (0.0 to 1.0)
    pub overall_score: f64,
    /// Connection success rate (0.0 to 1.0)
    pub success_rate: f64,
    /// Average latency in milliseconds
    pub avg_latency_ms: f64,
    /// Average bandwidth in bytes per second
    pub avg_bandwidth_bps: u64,
    /// Uptime percentage (0.0 to 1.0)
    pub uptime_ratio: f64,
    /// Number of successful transfers
    pub successful_transfers: u64,
    /// Number of failed transfers
    pub failed_transfers: u64,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Time since first seen
    pub age: Duration,
}

impl PeerQuality {
    /// Create a new peer quality with default values
    pub fn new() -> Self {
        Self {
            overall_score: 0.5,
            success_rate: 1.0,
            avg_latency_ms: 0.0,
            avg_bandwidth_bps: 0,
            uptime_ratio: 1.0,
            successful_transfers: 0,
            failed_transfers: 0,
            last_seen: Instant::now(),
            age: Duration::from_secs(0),
        }
    }

    /// Update quality metrics after a transfer
    pub fn record_transfer(&mut self, success: bool, latency_ms: f64, bandwidth_bps: u64) {
        if success {
            self.successful_transfers += 1;
        } else {
            self.failed_transfers += 1;
        }

        let total = self.successful_transfers + self.failed_transfers;
        self.success_rate = self.successful_transfers as f64 / total as f64;

        // Update latency using exponential moving average
        if self.avg_latency_ms == 0.0 {
            self.avg_latency_ms = latency_ms;
        } else {
            self.avg_latency_ms = 0.7 * self.avg_latency_ms + 0.3 * latency_ms;
        }

        // Update bandwidth using exponential moving average
        if self.avg_bandwidth_bps == 0 {
            self.avg_bandwidth_bps = bandwidth_bps;
        } else {
            self.avg_bandwidth_bps =
                (0.7 * self.avg_bandwidth_bps as f64 + 0.3 * bandwidth_bps as f64) as u64;
        }

        self.last_seen = Instant::now();
        self.calculate_overall_score();
    }

    /// Calculate overall quality score from all metrics
    fn calculate_overall_score(&mut self) {
        // Weighted combination of factors
        let latency_score = if self.avg_latency_ms > 0.0 {
            (1000.0 / (self.avg_latency_ms + 100.0)).min(1.0)
        } else {
            0.5
        };

        let bandwidth_score = (self.avg_bandwidth_bps as f64 / 10_000_000.0).min(1.0);

        self.overall_score = 0.4 * self.success_rate
            + 0.3 * latency_score
            + 0.2 * bandwidth_score
            + 0.1 * self.uptime_ratio;
    }

    /// Check if peer is considered healthy
    pub fn is_healthy(&self) -> bool {
        self.overall_score > 0.5
            && self.success_rate > 0.7
            && self.last_seen.elapsed() < Duration::from_secs(300)
    }
}

impl Default for PeerQuality {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced peer information combining multiple dimensions
#[derive(Debug, Clone)]
pub struct EnhancedPeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// IP address
    pub ip_addr: IpAddr,
    /// Geographic location
    pub geo_location: Option<GeoLocation>,
    /// Network topology position
    pub topology: Option<TopologyPosition>,
    /// Quality metrics
    pub quality: PeerQuality,
    /// When this peer was first discovered
    pub discovered_at: Instant,
}

/// Strategy for selecting peers based on different criteria
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionStrategy {
    /// Prefer geographically close peers
    Geographic,
    /// Prefer high-quality peers
    Quality,
    /// Prefer topologically central peers
    Topology,
    /// Balanced combination of all factors
    Balanced,
}

/// Peer replacement strategy when peer limit is reached
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplacementStrategy {
    /// Replace lowest quality peer
    LowestQuality,
    /// Replace most distant peer
    MostDistant,
    /// Replace least recently seen
    LeastRecentlySeen,
    /// Replace based on balanced score
    Balanced,
}

/// Enhanced peer discovery manager
pub struct DiscoveryEnhanced {
    /// Known peers with enhanced information
    peers: HashMap<PeerId, EnhancedPeerInfo>,
    /// Our own geographic location
    own_location: Option<GeoLocation>,
    /// Maximum number of peers to maintain
    max_peers: usize,
    /// Selection strategy
    selection_strategy: SelectionStrategy,
    /// Replacement strategy
    replacement_strategy: ReplacementStrategy,
    /// Statistics
    stats: DiscoveryStats,
}

/// Discovery statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryStats {
    /// Total peers discovered
    pub total_discovered: u64,
    /// Peers replaced
    pub peers_replaced: u64,
    /// Average peer quality
    pub avg_quality: f64,
    /// Geographic diversity (unique countries)
    pub geographic_diversity: usize,
    /// Topology diversity (unique AS numbers)
    pub topology_diversity: usize,
}

impl DiscoveryEnhanced {
    /// Create a new enhanced discovery manager
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            own_location: None,
            max_peers,
            selection_strategy: SelectionStrategy::Balanced,
            replacement_strategy: ReplacementStrategy::Balanced,
            stats: DiscoveryStats::default(),
        }
    }

    /// Set our own geographic location
    pub fn set_own_location(&mut self, location: GeoLocation) {
        self.own_location = Some(location);
    }

    /// Set selection strategy
    pub fn set_selection_strategy(&mut self, strategy: SelectionStrategy) {
        self.selection_strategy = strategy;
    }

    /// Set replacement strategy
    pub fn set_replacement_strategy(&mut self, strategy: ReplacementStrategy) {
        self.replacement_strategy = strategy;
    }

    /// Add or update a peer
    pub fn add_peer(
        &mut self,
        peer_id: PeerId,
        ip_addr: IpAddr,
        geo_location: Option<GeoLocation>,
        topology: Option<TopologyPosition>,
    ) -> bool {
        // Check if we already have this peer
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            // Update existing peer
            if let Some(geo) = geo_location {
                peer.geo_location = Some(geo);
            }
            if let Some(topo) = topology {
                peer.topology = Some(topo);
            }
            peer.quality.last_seen = Instant::now();
            return true;
        }

        // Check if we're at capacity
        if self.peers.len() >= self.max_peers {
            // Try to replace a peer
            if !self.try_replace_peer(&peer_id, &ip_addr, &geo_location, &topology) {
                return false;
            }
        }

        // Add new peer
        let peer_info = EnhancedPeerInfo {
            peer_id,
            ip_addr,
            geo_location,
            topology,
            quality: PeerQuality::new(),
            discovered_at: Instant::now(),
        };

        self.peers.insert(peer_id, peer_info);
        self.stats.total_discovered += 1;
        self.update_stats();

        true
    }

    /// Try to replace an existing peer with a new candidate
    fn try_replace_peer(
        &mut self,
        _new_peer_id: &PeerId,
        _new_ip: &IpAddr,
        new_geo: &Option<GeoLocation>,
        new_topo: &Option<TopologyPosition>,
    ) -> bool {
        let candidate_to_replace = match self.replacement_strategy {
            ReplacementStrategy::LowestQuality => self.find_lowest_quality_peer(),
            ReplacementStrategy::MostDistant => self.find_most_distant_peer(),
            ReplacementStrategy::LeastRecentlySeen => self.find_least_recently_seen_peer(),
            ReplacementStrategy::Balanced => self.find_balanced_replacement_peer(new_geo, new_topo),
        };

        if let Some(peer_to_replace) = candidate_to_replace {
            self.peers.remove(&peer_to_replace);
            self.stats.peers_replaced += 1;
            true
        } else {
            false
        }
    }

    /// Find peer with lowest quality score
    fn find_lowest_quality_peer(&self) -> Option<PeerId> {
        self.peers
            .iter()
            .min_by(|(_, a), (_, b)| {
                a.quality
                    .overall_score
                    .partial_cmp(&b.quality.overall_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| *id)
    }

    /// Find most geographically distant peer
    fn find_most_distant_peer(&self) -> Option<PeerId> {
        let own_loc = self.own_location.as_ref()?;

        self.peers
            .iter()
            .filter_map(|(id, peer)| {
                peer.geo_location
                    .as_ref()
                    .map(|loc| (*id, own_loc.distance_to(loc)))
            })
            .max_by(|(_, dist_a), (_, dist_b)| {
                dist_a
                    .partial_cmp(dist_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id)
    }

    /// Find least recently seen peer
    fn find_least_recently_seen_peer(&self) -> Option<PeerId> {
        self.peers
            .iter()
            .min_by_key(|(_, peer)| peer.quality.last_seen)
            .map(|(id, _)| *id)
    }

    /// Find peer to replace using balanced scoring
    #[allow(dead_code)]
    fn find_balanced_replacement_peer(
        &self,
        _new_geo: &Option<GeoLocation>,
        _new_topo: &Option<TopologyPosition>,
    ) -> Option<PeerId> {
        // Calculate replacement score (lower is more replaceable)
        self.peers
            .iter()
            .map(|(id, peer)| {
                let quality_score = peer.quality.overall_score;
                let age_score = (peer.discovered_at.elapsed().as_secs() as f64 / 3600.0).min(1.0);
                let recency_score =
                    1.0 - (peer.quality.last_seen.elapsed().as_secs() as f64 / 300.0).min(1.0);

                let replacement_score = 0.5 * quality_score + 0.3 * recency_score + 0.2 * age_score;

                (*id, replacement_score)
            })
            .min_by(|(_, score_a), (_, score_b)| {
                score_a
                    .partial_cmp(score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(id, _)| id)
    }

    /// Select best peers according to strategy
    pub fn select_peers(&self, count: usize) -> Vec<PeerId> {
        let mut peers: Vec<_> = self.peers.values().collect();

        // Sort according to selection strategy
        match self.selection_strategy {
            SelectionStrategy::Geographic => {
                if let Some(own_loc) = &self.own_location {
                    peers.sort_by(|a, b| {
                        let dist_a = a
                            .geo_location
                            .as_ref()
                            .map(|loc| own_loc.distance_to(loc))
                            .unwrap_or(f64::MAX);
                        let dist_b = b
                            .geo_location
                            .as_ref()
                            .map(|loc| own_loc.distance_to(loc))
                            .unwrap_or(f64::MAX);
                        dist_a
                            .partial_cmp(&dist_b)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                }
            }
            SelectionStrategy::Quality => {
                peers.sort_by(|a, b| {
                    b.quality
                        .overall_score
                        .partial_cmp(&a.quality.overall_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            SelectionStrategy::Topology => {
                peers.sort_by(|a, b| {
                    let score_a = a.topology.as_ref().map(|t| t.betweenness).unwrap_or(0.0);
                    let score_b = b.topology.as_ref().map(|t| t.betweenness).unwrap_or(0.0);
                    score_b
                        .partial_cmp(&score_a)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            SelectionStrategy::Balanced => {
                peers.sort_by(|a, b| {
                    let score_a = self.calculate_balanced_score(a);
                    let score_b = self.calculate_balanced_score(b);
                    score_b
                        .partial_cmp(&score_a)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        peers.into_iter().take(count).map(|p| p.peer_id).collect()
    }

    /// Calculate balanced selection score for a peer
    fn calculate_balanced_score(&self, peer: &EnhancedPeerInfo) -> f64 {
        let quality_score = peer.quality.overall_score;

        let distance_score =
            if let (Some(own_loc), Some(peer_loc)) = (&self.own_location, &peer.geo_location) {
                let distance = own_loc.distance_to(peer_loc);
                (1.0 / (1.0 + distance / 1000.0)).min(1.0)
            } else {
                0.5
            };

        let topology_score = peer
            .topology
            .as_ref()
            .map(|t| t.betweenness * 0.5 + (1.0 - t.clustering) * 0.5)
            .unwrap_or(0.5);

        0.5 * quality_score + 0.3 * distance_score + 0.2 * topology_score
    }

    /// Record a transfer for peer quality tracking
    pub fn record_transfer(
        &mut self,
        peer_id: &PeerId,
        success: bool,
        latency_ms: f64,
        bandwidth_bps: u64,
    ) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.quality
                .record_transfer(success, latency_ms, bandwidth_bps);
            self.update_stats();
        }
    }

    /// Update topology information for a peer
    pub fn update_topology(&mut self, peer_id: &PeerId, topology: TopologyPosition) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.topology = Some(topology);
        }
    }

    /// Get peer information
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&EnhancedPeerInfo> {
        self.peers.get(peer_id)
    }

    /// Get all peers
    pub fn get_all_peers(&self) -> Vec<&EnhancedPeerInfo> {
        self.peers.values().collect()
    }

    /// Get healthy peers only
    pub fn get_healthy_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, peer)| peer.quality.is_healthy())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> &DiscoveryStats {
        &self.stats
    }

    /// Update statistics
    fn update_stats(&mut self) {
        let total = self.peers.len();
        if total == 0 {
            self.stats.avg_quality = 0.0;
            self.stats.geographic_diversity = 0;
            self.stats.topology_diversity = 0;
            return;
        }

        let quality_sum: f64 = self.peers.values().map(|p| p.quality.overall_score).sum();
        self.stats.avg_quality = quality_sum / total as f64;

        let unique_countries: std::collections::HashSet<_> = self
            .peers
            .values()
            .filter_map(|p| p.geo_location.as_ref()?.country.as_ref())
            .collect();
        self.stats.geographic_diversity = unique_countries.len();

        let unique_asns: std::collections::HashSet<_> = self
            .peers
            .values()
            .filter_map(|p| p.geo_location.as_ref()?.asn)
            .collect();
        self.stats.topology_diversity = unique_asns.len();
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        if self.peers.remove(peer_id).is_some() {
            self.update_stats();
            true
        } else {
            false
        }
    }

    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_location_distance() {
        let tokyo = GeoLocation {
            latitude: 35.6762,
            longitude: 139.6503,
            country: Some("JP".to_string()),
            city: Some("Tokyo".to_string()),
            asn: Some(2516),
        };

        let london = GeoLocation {
            latitude: 51.5074,
            longitude: -0.1278,
            country: Some("GB".to_string()),
            city: Some("London".to_string()),
            asn: Some(5400),
        };

        let distance = tokyo.distance_to(&london);
        // Tokyo to London is approximately 9,500 km
        assert!(distance > 9000.0 && distance < 10000.0);
    }

    #[test]
    fn test_geo_location_same_as() {
        let peer1 = GeoLocation {
            latitude: 35.6762,
            longitude: 139.6503,
            country: Some("JP".to_string()),
            city: Some("Tokyo".to_string()),
            asn: Some(2516),
        };

        let peer2 = GeoLocation {
            latitude: 35.6895,
            longitude: 139.6917,
            country: Some("JP".to_string()),
            city: Some("Tokyo".to_string()),
            asn: Some(2516),
        };

        assert!(peer1.same_as(&peer2));
    }

    #[test]
    fn test_peer_quality_new() {
        let quality = PeerQuality::new();
        assert_eq!(quality.overall_score, 0.5);
        assert_eq!(quality.success_rate, 1.0);
        assert_eq!(quality.successful_transfers, 0);
        assert_eq!(quality.failed_transfers, 0);
    }

    #[test]
    fn test_peer_quality_record_transfer() {
        let mut quality = PeerQuality::new();

        quality.record_transfer(true, 50.0, 1_000_000);
        assert_eq!(quality.successful_transfers, 1);
        assert_eq!(quality.success_rate, 1.0);
        assert_eq!(quality.avg_latency_ms, 50.0);

        quality.record_transfer(false, 100.0, 500_000);
        assert_eq!(quality.failed_transfers, 1);
        assert_eq!(quality.success_rate, 0.5);
    }

    #[test]
    fn test_peer_quality_is_healthy() {
        let mut quality = PeerQuality::new();
        quality.record_transfer(true, 50.0, 5_000_000);
        quality.record_transfer(true, 60.0, 6_000_000);

        assert!(quality.is_healthy());
    }

    #[test]
    fn test_discovery_enhanced_new() {
        let discovery = DiscoveryEnhanced::new(100);
        assert_eq!(discovery.max_peers, 100);
        assert_eq!(discovery.peer_count(), 0);
        assert_eq!(discovery.selection_strategy, SelectionStrategy::Balanced);
    }

    #[test]
    fn test_discovery_add_peer() {
        let mut discovery = DiscoveryEnhanced::new(10);
        let peer_id = PeerId::random();
        let ip = "192.168.1.1".parse().unwrap();

        let result = discovery.add_peer(peer_id, ip, None, None);
        assert!(result);
        assert_eq!(discovery.peer_count(), 1);
        assert_eq!(discovery.stats().total_discovered, 1);
    }

    #[test]
    fn test_discovery_add_duplicate_peer() {
        let mut discovery = DiscoveryEnhanced::new(10);
        let peer_id = PeerId::random();
        let ip = "192.168.1.1".parse().unwrap();

        discovery.add_peer(peer_id, ip, None, None);
        let result = discovery.add_peer(peer_id, ip, None, None);

        assert!(result);
        assert_eq!(discovery.peer_count(), 1);
    }

    #[test]
    fn test_discovery_max_peers() {
        let mut discovery = DiscoveryEnhanced::new(5);

        for _ in 0..5 {
            let peer_id = PeerId::random();
            let ip = "192.168.1.1".parse().unwrap();
            discovery.add_peer(peer_id, ip, None, None);
        }

        assert_eq!(discovery.peer_count(), 5);
    }

    #[test]
    fn test_discovery_record_transfer() {
        let mut discovery = DiscoveryEnhanced::new(10);
        let peer_id = PeerId::random();
        let ip = "192.168.1.1".parse().unwrap();

        discovery.add_peer(peer_id, ip, None, None);
        discovery.record_transfer(&peer_id, true, 50.0, 1_000_000);

        let peer = discovery.get_peer(&peer_id).unwrap();
        assert_eq!(peer.quality.successful_transfers, 1);
    }

    #[test]
    fn test_discovery_remove_peer() {
        let mut discovery = DiscoveryEnhanced::new(10);
        let peer_id = PeerId::random();
        let ip = "192.168.1.1".parse().unwrap();

        discovery.add_peer(peer_id, ip, None, None);
        assert_eq!(discovery.peer_count(), 1);

        let result = discovery.remove_peer(&peer_id);
        assert!(result);
        assert_eq!(discovery.peer_count(), 0);
    }

    #[test]
    fn test_discovery_select_peers() {
        let mut discovery = DiscoveryEnhanced::new(10);

        for _ in 0..5 {
            let peer_id = PeerId::random();
            let ip = "192.168.1.1".parse().unwrap();
            discovery.add_peer(peer_id, ip, None, None);
        }

        let selected = discovery.select_peers(3);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn test_discovery_get_healthy_peers() {
        let mut discovery = DiscoveryEnhanced::new(10);

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let ip = "192.168.1.1".parse().unwrap();

        discovery.add_peer(peer1, ip, None, None);
        discovery.add_peer(peer2, ip, None, None);

        discovery.record_transfer(&peer1, true, 50.0, 5_000_000);
        discovery.record_transfer(&peer1, true, 60.0, 6_000_000);

        let healthy = discovery.get_healthy_peers();
        assert!(healthy.contains(&peer1));
    }

    #[test]
    fn test_discovery_set_strategies() {
        let mut discovery = DiscoveryEnhanced::new(10);

        discovery.set_selection_strategy(SelectionStrategy::Quality);
        assert_eq!(discovery.selection_strategy, SelectionStrategy::Quality);

        discovery.set_replacement_strategy(ReplacementStrategy::LowestQuality);
        assert_eq!(
            discovery.replacement_strategy,
            ReplacementStrategy::LowestQuality
        );
    }

    #[test]
    fn test_discovery_stats() {
        let mut discovery = DiscoveryEnhanced::new(10);

        for _ in 0..3 {
            let peer_id = PeerId::random();
            let ip = "192.168.1.1".parse().unwrap();
            discovery.add_peer(peer_id, ip, None, None);
        }

        let stats = discovery.stats();
        assert_eq!(stats.total_discovered, 3);
    }
}
