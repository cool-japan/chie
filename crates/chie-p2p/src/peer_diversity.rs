//! Automatic peer diversity maintenance for network resilience.
//!
//! This module ensures that the peer set maintains diversity across
//! geographic regions, autonomous systems, and network characteristics
//! to prevent single points of failure and improve content availability.

use libp2p::PeerId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Diversity dimension
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiversityDimension {
    /// Geographic region
    Geographic,
    /// Autonomous System (AS) number
    AutonomousSystem,
    /// IP subnet (/24 for IPv4, /48 for IPv6)
    Subnet,
    /// Network latency class
    LatencyClass,
    /// Bandwidth class
    BandwidthClass,
}

/// Geographic region
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GeographicRegion {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Asia,
    Africa,
    Oceania,
    Unknown,
}

impl GeographicRegion {
    /// Determine region from coordinates
    pub fn from_coordinates(latitude: f64, longitude: f64) -> Self {
        match (latitude, longitude) {
            (lat, lon) if (15.0..=72.0).contains(&lat) && (-168.0..=-52.0).contains(&lon) => {
                Self::NorthAmerica
            }
            (lat, lon) if (-56.0..15.0).contains(&lat) && (-82.0..=-34.0).contains(&lon) => {
                Self::SouthAmerica
            }
            (lat, lon) if (36.0..=71.0).contains(&lat) && (-10.0..=40.0).contains(&lon) => {
                Self::Europe
            }
            (lat, lon) if (-10.0..=55.0).contains(&lat) && (26.0..=180.0).contains(&lon) => {
                Self::Asia
            }
            (lat, lon) if (-35.0..=37.0).contains(&lat) && (-18.0..=52.0).contains(&lon) => {
                Self::Africa
            }
            (lat, lon) if (-47.0..=-10.0).contains(&lat) && (110.0..=180.0).contains(&lon) => {
                Self::Oceania
            }
            _ => Self::Unknown,
        }
    }
}

/// Latency class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LatencyClass {
    VeryLow,  // < 20ms
    Low,      // 20-50ms
    Medium,   // 50-150ms
    High,     // 150-300ms
    VeryHigh, // > 300ms
}

impl LatencyClass {
    pub fn from_latency(latency: Duration) -> Self {
        let ms = latency.as_millis() as u64;
        match ms {
            0..=20 => Self::VeryLow,
            21..=50 => Self::Low,
            51..=150 => Self::Medium,
            151..=300 => Self::High,
            _ => Self::VeryHigh,
        }
    }
}

/// Bandwidth class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BandwidthClass {
    VeryLow,  // < 1 MB/s
    Low,      // 1-10 MB/s
    Medium,   // 10-50 MB/s
    High,     // 50-100 MB/s
    VeryHigh, // > 100 MB/s
}

impl BandwidthClass {
    pub fn from_bandwidth(bandwidth_bps: f64) -> Self {
        let mbps = bandwidth_bps / 1_000_000.0;
        if mbps < 1.0 {
            Self::VeryLow
        } else if mbps < 10.0 {
            Self::Low
        } else if mbps < 50.0 {
            Self::Medium
        } else if mbps < 100.0 {
            Self::High
        } else {
            Self::VeryHigh
        }
    }
}

/// Peer diversity attributes
#[derive(Debug, Clone)]
pub struct PeerDiversityInfo {
    pub peer_id: PeerId,
    pub region: GeographicRegion,
    pub as_number: Option<u32>,
    pub ip_addr: Option<IpAddr>,
    pub latency_class: LatencyClass,
    pub bandwidth_class: BandwidthClass,
    pub last_updated: Instant,
}

/// Diversity maintenance configuration
#[derive(Debug, Clone)]
pub struct DiversityConfig {
    /// Target number of different regions
    pub target_regions: usize,
    /// Target number of different AS
    pub target_as_count: usize,
    /// Target number of different subnets
    pub target_subnets: usize,
    /// Minimum peers per region
    pub min_peers_per_region: usize,
    /// Maximum peers from same AS
    pub max_peers_same_as: usize,
    /// Maximum peers from same subnet
    pub max_peers_same_subnet: usize,
    /// Diversity check interval
    pub check_interval: Duration,
}

impl Default for DiversityConfig {
    fn default() -> Self {
        Self {
            target_regions: 3,
            target_as_count: 5,
            target_subnets: 10,
            min_peers_per_region: 2,
            max_peers_same_as: 5,
            max_peers_same_subnet: 3,
            check_interval: Duration::from_secs(60),
        }
    }
}

/// Diversity recommendation
#[derive(Debug, Clone)]
pub enum DiversityRecommendation {
    /// Add peer from specific region
    AddFromRegion(GeographicRegion),
    /// Add peer from different AS
    AddFromDifferentAS,
    /// Add peer from different subnet
    AddFromDifferentSubnet,
    /// Remove peer (too many from same region/AS/subnet)
    RemovePeer(PeerId, String),
    /// No action needed
    NoAction,
}

/// Peer diversity manager
pub struct PeerDiversityManager {
    config: DiversityConfig,
    peers: Arc<RwLock<HashMap<PeerId, PeerDiversityInfo>>>,
    last_check: Arc<RwLock<Instant>>,
}

impl PeerDiversityManager {
    /// Create a new diversity manager
    pub fn new(config: DiversityConfig) -> Self {
        // Initialize last_check to past so initial should_check() returns true
        let check_interval = config.check_interval;
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            last_check: Arc::new(RwLock::new(Instant::now() - check_interval)),
        }
    }

    /// Add or update peer diversity info
    pub fn update_peer(
        &self,
        peer_id: PeerId,
        region: GeographicRegion,
        as_number: Option<u32>,
        ip_addr: Option<IpAddr>,
        latency: Duration,
        bandwidth_bps: f64,
    ) {
        let info = PeerDiversityInfo {
            peer_id,
            region,
            as_number,
            ip_addr,
            latency_class: LatencyClass::from_latency(latency),
            bandwidth_class: BandwidthClass::from_bandwidth(bandwidth_bps),
            last_updated: Instant::now(),
        };

        self.peers.write().unwrap().insert(peer_id, info);
    }

    /// Remove peer
    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().unwrap().remove(peer_id);
    }

    /// Check diversity and get recommendations
    pub fn check_diversity(&self) -> Vec<DiversityRecommendation> {
        let mut recommendations = Vec::new();
        let peers = self.peers.read().unwrap();

        // Check geographic diversity
        let region_counts = self.count_by_region(&peers);
        for region in [
            GeographicRegion::NorthAmerica,
            GeographicRegion::Europe,
            GeographicRegion::Asia,
        ] {
            let count = region_counts.get(&region).copied().unwrap_or(0);
            if count < self.config.min_peers_per_region {
                recommendations.push(DiversityRecommendation::AddFromRegion(region));
            }
        }

        // Check AS diversity
        let as_counts = self.count_by_as(&peers);
        for (as_num, count) in as_counts.iter() {
            if *count > self.config.max_peers_same_as {
                // Find peers from this AS to potentially remove
                if let Some(peer_id) = peers
                    .values()
                    .find(|p| p.as_number == Some(*as_num))
                    .map(|p| p.peer_id)
                {
                    recommendations.push(DiversityRecommendation::RemovePeer(
                        peer_id,
                        format!("Too many peers from AS {}", as_num),
                    ));
                }
            }
        }

        // Check subnet diversity
        let subnet_counts = self.count_by_subnet(&peers);
        for (subnet, count) in subnet_counts.iter() {
            if *count > self.config.max_peers_same_subnet {
                if let Some(peer_id) = peers
                    .values()
                    .find(|p| Self::get_subnet(&p.ip_addr).as_ref() == Some(subnet))
                    .map(|p| p.peer_id)
                {
                    recommendations.push(DiversityRecommendation::RemovePeer(
                        peer_id,
                        format!("Too many peers from subnet {}", subnet),
                    ));
                }
            }
        }

        // Update last check time
        *self.last_check.write().unwrap() = Instant::now();

        if recommendations.is_empty() {
            vec![DiversityRecommendation::NoAction]
        } else {
            recommendations
        }
    }

    /// Count peers by region
    fn count_by_region(
        &self,
        peers: &HashMap<PeerId, PeerDiversityInfo>,
    ) -> HashMap<GeographicRegion, usize> {
        let mut counts = HashMap::new();
        for peer in peers.values() {
            *counts.entry(peer.region).or_insert(0) += 1;
        }
        counts
    }

    /// Count peers by AS
    fn count_by_as(&self, peers: &HashMap<PeerId, PeerDiversityInfo>) -> HashMap<u32, usize> {
        let mut counts = HashMap::new();
        for peer in peers.values() {
            if let Some(as_num) = peer.as_number {
                *counts.entry(as_num).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Count peers by subnet
    fn count_by_subnet(
        &self,
        peers: &HashMap<PeerId, PeerDiversityInfo>,
    ) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for peer in peers.values() {
            if let Some(subnet) = Self::get_subnet(&peer.ip_addr) {
                *counts.entry(subnet).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Get subnet prefix from IP address
    fn get_subnet(ip_addr: &Option<IpAddr>) -> Option<String> {
        ip_addr.as_ref().map(|addr| match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
            }
        })
    }

    /// Calculate diversity score (0.0-1.0)
    pub fn calculate_diversity_score(&self) -> f64 {
        let peers = self.peers.read().unwrap();
        if peers.is_empty() {
            return 0.0;
        }

        let mut score = 0.0;
        let mut dimensions = 0;

        // Region diversity
        let region_counts = self.count_by_region(&peers);
        let region_diversity = region_counts.len() as f64 / self.config.target_regions as f64;
        score += region_diversity.min(1.0);
        dimensions += 1;

        // AS diversity
        let as_counts = self.count_by_as(&peers);
        let as_diversity = as_counts.len() as f64 / self.config.target_as_count as f64;
        score += as_diversity.min(1.0);
        dimensions += 1;

        // Subnet diversity
        let subnet_counts = self.count_by_subnet(&peers);
        let subnet_diversity = subnet_counts.len() as f64 / self.config.target_subnets as f64;
        score += subnet_diversity.min(1.0);
        dimensions += 1;

        score / dimensions as f64
    }

    /// Get peers by dimension
    pub fn get_peers_by_dimension(
        &self,
        dimension: DiversityDimension,
    ) -> HashMap<String, Vec<PeerId>> {
        let peers = self.peers.read().unwrap();
        let mut result: HashMap<String, Vec<PeerId>> = HashMap::new();

        for peer in peers.values() {
            let key = match dimension {
                DiversityDimension::Geographic => format!("{:?}", peer.region),
                DiversityDimension::AutonomousSystem => peer
                    .as_number
                    .map(|as_num| format!("AS{}", as_num))
                    .unwrap_or_else(|| "Unknown".to_string()),
                DiversityDimension::Subnet => {
                    Self::get_subnet(&peer.ip_addr).unwrap_or_else(|| "Unknown".to_string())
                }
                DiversityDimension::LatencyClass => format!("{:?}", peer.latency_class),
                DiversityDimension::BandwidthClass => format!("{:?}", peer.bandwidth_class),
            };

            result.entry(key).or_default().push(peer.peer_id);
        }

        result
    }

    /// Get underrepresented regions
    pub fn get_underrepresented_regions(&self) -> Vec<GeographicRegion> {
        let peers = self.peers.read().unwrap();
        let region_counts = self.count_by_region(&peers);

        [
            GeographicRegion::NorthAmerica,
            GeographicRegion::SouthAmerica,
            GeographicRegion::Europe,
            GeographicRegion::Asia,
            GeographicRegion::Africa,
            GeographicRegion::Oceania,
        ]
        .iter()
        .filter(|region| {
            let count = region_counts.get(region).copied().unwrap_or(0);
            count < self.config.min_peers_per_region
        })
        .copied()
        .collect()
    }

    /// Get overrepresented AS numbers
    pub fn get_overrepresented_as(&self) -> Vec<u32> {
        let peers = self.peers.read().unwrap();
        let as_counts = self.count_by_as(&peers);

        as_counts
            .iter()
            .filter(|(_, count)| **count > self.config.max_peers_same_as)
            .map(|(as_num, _)| *as_num)
            .collect()
    }

    /// Get diversity statistics
    pub fn get_stats(&self) -> DiversityStats {
        let peers = self.peers.read().unwrap();
        let total_peers = peers.len();
        let region_counts = self.count_by_region(&peers);
        let as_counts = self.count_by_as(&peers);
        let subnet_counts = self.count_by_subnet(&peers);

        DiversityStats {
            total_peers,
            unique_regions: region_counts.len(),
            unique_as: as_counts.len(),
            unique_subnets: subnet_counts.len(),
            diversity_score: self.calculate_diversity_score(),
        }
    }

    /// Should check diversity now
    pub fn should_check(&self) -> bool {
        self.last_check.read().unwrap().elapsed() >= self.config.check_interval
    }
}

/// Diversity statistics
#[derive(Debug, Clone)]
pub struct DiversityStats {
    pub total_peers: usize,
    pub unique_regions: usize,
    pub unique_as: usize,
    pub unique_subnets: usize,
    pub diversity_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_geographic_region_from_coordinates() {
        assert_eq!(
            GeographicRegion::from_coordinates(40.0, -74.0),
            GeographicRegion::NorthAmerica
        );
        assert_eq!(
            GeographicRegion::from_coordinates(51.5, -0.1),
            GeographicRegion::Europe
        );
        assert_eq!(
            GeographicRegion::from_coordinates(35.6, 139.6),
            GeographicRegion::Asia
        );
    }

    #[test]
    fn test_latency_class_from_latency() {
        assert_eq!(
            LatencyClass::from_latency(Duration::from_millis(10)),
            LatencyClass::VeryLow
        );
        assert_eq!(
            LatencyClass::from_latency(Duration::from_millis(30)),
            LatencyClass::Low
        );
        assert_eq!(
            LatencyClass::from_latency(Duration::from_millis(100)),
            LatencyClass::Medium
        );
        assert_eq!(
            LatencyClass::from_latency(Duration::from_millis(200)),
            LatencyClass::High
        );
        assert_eq!(
            LatencyClass::from_latency(Duration::from_millis(500)),
            LatencyClass::VeryHigh
        );
    }

    #[test]
    fn test_bandwidth_class_from_bandwidth() {
        assert_eq!(
            BandwidthClass::from_bandwidth(500_000.0),
            BandwidthClass::VeryLow
        );
        assert_eq!(
            BandwidthClass::from_bandwidth(5_000_000.0),
            BandwidthClass::Low
        );
        assert_eq!(
            BandwidthClass::from_bandwidth(20_000_000.0),
            BandwidthClass::Medium
        );
        assert_eq!(
            BandwidthClass::from_bandwidth(75_000_000.0),
            BandwidthClass::High
        );
        assert_eq!(
            BandwidthClass::from_bandwidth(150_000_000.0),
            BandwidthClass::VeryHigh
        );
    }

    #[test]
    fn test_diversity_manager_new() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);
        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_update_peer() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);

        let peer = create_test_peer();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        manager.update_peer(
            peer,
            GeographicRegion::NorthAmerica,
            Some(12345),
            Some(ip),
            Duration::from_millis(50),
            10_000_000.0,
        );

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 1);
    }

    #[test]
    fn test_remove_peer() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);

        let peer = create_test_peer();
        manager.update_peer(
            peer,
            GeographicRegion::Europe,
            None,
            None,
            Duration::from_millis(50),
            10_000_000.0,
        );

        assert_eq!(manager.get_stats().total_peers, 1);

        manager.remove_peer(&peer);
        assert_eq!(manager.get_stats().total_peers, 0);
    }

    #[test]
    fn test_diversity_score() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);

        // Add peers from different regions
        for i in 0..3 {
            let peer = create_test_peer();
            let region = match i {
                0 => GeographicRegion::NorthAmerica,
                1 => GeographicRegion::Europe,
                _ => GeographicRegion::Asia,
            };
            manager.update_peer(
                peer,
                region,
                Some(i as u32),
                None,
                Duration::from_millis(50),
                10_000_000.0,
            );
        }

        let score = manager.calculate_diversity_score();
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_check_diversity_add_region() {
        let config = DiversityConfig {
            min_peers_per_region: 2,
            ..Default::default()
        };

        let manager = PeerDiversityManager::new(config);

        // Add only one peer from North America
        let peer = create_test_peer();
        manager.update_peer(
            peer,
            GeographicRegion::NorthAmerica,
            None,
            None,
            Duration::from_millis(50),
            10_000_000.0,
        );

        let recommendations = manager.check_diversity();
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_check_diversity_remove_as() {
        let config = DiversityConfig {
            max_peers_same_as: 2,
            ..Default::default()
        };

        let manager = PeerDiversityManager::new(config);

        // Add too many peers from same AS
        for _ in 0..3 {
            let peer = create_test_peer();
            manager.update_peer(
                peer,
                GeographicRegion::NorthAmerica,
                Some(12345),
                None,
                Duration::from_millis(50),
                10_000_000.0,
            );
        }

        let recommendations = manager.check_diversity();
        let has_remove = recommendations
            .iter()
            .any(|r| matches!(r, DiversityRecommendation::RemovePeer(_, _)));
        assert!(has_remove);
    }

    #[test]
    fn test_check_diversity_subnet() {
        let config = DiversityConfig {
            max_peers_same_subnet: 2,
            ..Default::default()
        };

        let manager = PeerDiversityManager::new(config);

        // Add too many peers from same subnet
        for i in 0..3 {
            let peer = create_test_peer();
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            manager.update_peer(
                peer,
                GeographicRegion::NorthAmerica,
                None,
                Some(ip),
                Duration::from_millis(50),
                10_000_000.0,
            );
        }

        let recommendations = manager.check_diversity();
        let has_remove = recommendations
            .iter()
            .any(|r| matches!(r, DiversityRecommendation::RemovePeer(_, _)));
        assert!(has_remove);
    }

    #[test]
    fn test_get_peers_by_dimension() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager.update_peer(
            peer1,
            GeographicRegion::NorthAmerica,
            None,
            None,
            Duration::from_millis(50),
            10_000_000.0,
        );
        manager.update_peer(
            peer2,
            GeographicRegion::Europe,
            None,
            None,
            Duration::from_millis(50),
            10_000_000.0,
        );

        let by_region = manager.get_peers_by_dimension(DiversityDimension::Geographic);
        assert_eq!(by_region.len(), 2);
    }

    #[test]
    fn test_get_underrepresented_regions() {
        let config = DiversityConfig {
            min_peers_per_region: 2,
            ..Default::default()
        };

        let manager = PeerDiversityManager::new(config);

        let peer = create_test_peer();
        manager.update_peer(
            peer,
            GeographicRegion::NorthAmerica,
            None,
            None,
            Duration::from_millis(50),
            10_000_000.0,
        );

        let underrep = manager.get_underrepresented_regions();
        assert!(underrep.contains(&GeographicRegion::Europe));
        assert!(underrep.contains(&GeographicRegion::Asia));
    }

    #[test]
    fn test_get_overrepresented_as() {
        let config = DiversityConfig {
            max_peers_same_as: 2,
            ..Default::default()
        };

        let manager = PeerDiversityManager::new(config);

        for _ in 0..3 {
            let peer = create_test_peer();
            manager.update_peer(
                peer,
                GeographicRegion::NorthAmerica,
                Some(12345),
                None,
                Duration::from_millis(50),
                10_000_000.0,
            );
        }

        let overrep = manager.get_overrepresented_as();
        assert!(overrep.contains(&12345));
    }

    #[test]
    fn test_get_subnet() {
        let ip_v4 = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        let subnet = PeerDiversityManager::get_subnet(&ip_v4);
        assert_eq!(subnet, Some("192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_diversity_stats() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);

        for i in 0..5 {
            let peer = create_test_peer();
            let region = match i % 3 {
                0 => GeographicRegion::NorthAmerica,
                1 => GeographicRegion::Europe,
                _ => GeographicRegion::Asia,
            };
            manager.update_peer(
                peer,
                region,
                Some(i as u32),
                None,
                Duration::from_millis(50),
                10_000_000.0,
            );
        }

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 5);
        assert_eq!(stats.unique_regions, 3);
        assert_eq!(stats.unique_as, 5);
    }

    #[test]
    fn test_should_check() {
        let config = DiversityConfig {
            check_interval: Duration::from_millis(100),
            ..Default::default()
        };

        let manager = PeerDiversityManager::new(config);

        // Initially should check
        assert!(manager.should_check());

        manager.check_diversity();

        // Immediately after check, should not check
        assert!(!manager.should_check());
    }

    #[test]
    fn test_latency_class_ordering() {
        assert!(LatencyClass::VeryLow < LatencyClass::Low);
        assert!(LatencyClass::Low < LatencyClass::Medium);
        assert!(LatencyClass::Medium < LatencyClass::High);
        assert!(LatencyClass::High < LatencyClass::VeryHigh);
    }

    #[test]
    fn test_bandwidth_class_ordering() {
        assert!(BandwidthClass::VeryLow < BandwidthClass::Low);
        assert!(BandwidthClass::Low < BandwidthClass::Medium);
        assert!(BandwidthClass::Medium < BandwidthClass::High);
        assert!(BandwidthClass::High < BandwidthClass::VeryHigh);
    }

    #[test]
    fn test_empty_diversity_score() {
        let config = DiversityConfig::default();
        let manager = PeerDiversityManager::new(config);
        assert_eq!(manager.calculate_diversity_score(), 0.0);
    }

    #[test]
    fn test_diversity_config_default() {
        let config = DiversityConfig::default();
        assert_eq!(config.target_regions, 3);
        assert_eq!(config.target_as_count, 5);
        assert_eq!(config.min_peers_per_region, 2);
    }
}
