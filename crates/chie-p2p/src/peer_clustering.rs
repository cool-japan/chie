//! Peer clustering by geographic region and network characteristics.
//!
//! This module provides functionality to cluster peers based on geographic location,
//! network latency, and other characteristics for optimal content distribution.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Geographic coordinate (latitude, longitude)
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoCoordinate {
    pub latitude: f64,
    pub longitude: f64,
}

impl GeoCoordinate {
    /// Create a new geographic coordinate
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
        }
    }

    /// Calculate distance to another coordinate using Haversine formula (in kilometers)
    pub fn distance_to(&self, other: &GeoCoordinate) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = self.latitude.to_radians();
        let lat2_rad = other.latitude.to_radians();
        let dlat = (other.latitude - self.latitude).to_radians();
        let dlon = (other.longitude - self.longitude).to_radians();

        let a = (dlat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }
}

/// Clustering method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClusteringMethod {
    /// Geographic region-based clustering
    Geographic,
    /// Network latency-based clustering
    Latency,
    /// Hybrid (geographic + latency)
    Hybrid,
    /// AS number (Autonomous System)
    AutonomousSystem,
}

/// Peer cluster information
#[derive(Debug, Clone)]
pub struct PeerCluster {
    /// Cluster ID
    pub id: String,
    /// Cluster name/label
    pub name: String,
    /// Peers in this cluster
    pub peers: Vec<PeerId>,
    /// Geographic center (if applicable)
    pub geo_center: Option<GeoCoordinate>,
    /// Average latency within cluster
    pub avg_latency: Option<Duration>,
    /// Cluster quality score (0.0-1.0)
    pub quality: f64,
    /// Creation time
    pub created_at: Instant,
    /// Last updated
    pub updated_at: Instant,
}

impl PeerCluster {
    /// Create a new cluster
    pub fn new(id: String, name: String) -> Self {
        let now = Instant::now();
        Self {
            id,
            name,
            peers: Vec::new(),
            geo_center: None,
            avg_latency: None,
            quality: 1.0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a peer to the cluster
    pub fn add_peer(&mut self, peer_id: PeerId) {
        if !self.peers.contains(&peer_id) {
            self.peers.push(peer_id);
            self.updated_at = Instant::now();
        }
    }

    /// Remove a peer from the cluster
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        if let Some(pos) = self.peers.iter().position(|p| p == peer_id) {
            self.peers.swap_remove(pos);
            self.updated_at = Instant::now();
            true
        } else {
            false
        }
    }

    /// Get cluster size
    pub fn size(&self) -> usize {
        self.peers.len()
    }

    /// Update cluster center from peer locations
    pub fn update_center(&mut self, peer_locations: &HashMap<PeerId, GeoCoordinate>) {
        let coords: Vec<&GeoCoordinate> = self
            .peers
            .iter()
            .filter_map(|p| peer_locations.get(p))
            .collect();

        if !coords.is_empty() {
            let avg_lat = coords.iter().map(|c| c.latitude).sum::<f64>() / coords.len() as f64;
            let avg_lon = coords.iter().map(|c| c.longitude).sum::<f64>() / coords.len() as f64;
            self.geo_center = Some(GeoCoordinate::new(avg_lat, avg_lon));
            self.updated_at = Instant::now();
        }
    }
}

/// Clustering configuration
#[derive(Debug, Clone)]
pub struct ClusteringConfig {
    /// Clustering method
    pub method: ClusteringMethod,
    /// Maximum cluster size
    pub max_cluster_size: usize,
    /// Minimum cluster size (clusters below this may be merged)
    pub min_cluster_size: usize,
    /// Maximum distance for geographic clustering (km)
    pub max_geo_distance: f64,
    /// Maximum latency difference for latency clustering
    pub max_latency_diff: Duration,
    /// Hybrid weight: geographic vs latency (0.0-1.0, higher = more geographic)
    pub hybrid_geo_weight: f64,
}

impl Default for ClusteringConfig {
    fn default() -> Self {
        Self {
            method: ClusteringMethod::Hybrid,
            max_cluster_size: 50,
            min_cluster_size: 3,
            max_geo_distance: 500.0, // 500 km
            max_latency_diff: Duration::from_millis(50),
            hybrid_geo_weight: 0.6,
        }
    }
}

/// Peer location info
#[derive(Debug, Clone)]
pub struct PeerLocationInfo {
    pub location: GeoCoordinate,
    pub latency: Duration,
    pub as_number: Option<u32>,
    pub last_updated: Instant,
}

/// Peer clustering manager
pub struct PeerClusteringManager {
    config: ClusteringConfig,
    clusters: Arc<RwLock<HashMap<String, PeerCluster>>>,
    peer_locations: Arc<RwLock<HashMap<PeerId, PeerLocationInfo>>>,
    peer_to_cluster: Arc<RwLock<HashMap<PeerId, String>>>,
}

impl PeerClusteringManager {
    /// Create a new clustering manager
    pub fn new(config: ClusteringConfig) -> Self {
        Self {
            config,
            clusters: Arc::new(RwLock::new(HashMap::new())),
            peer_locations: Arc::new(RwLock::new(HashMap::new())),
            peer_to_cluster: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add peer location info
    pub fn add_peer_location(
        &self,
        peer_id: PeerId,
        location: GeoCoordinate,
        latency: Duration,
        as_number: Option<u32>,
    ) {
        let info = PeerLocationInfo {
            location,
            latency,
            as_number,
            last_updated: Instant::now(),
        };
        self.peer_locations.write().unwrap().insert(peer_id, info);
    }

    /// Perform clustering
    pub fn recluster(&self) {
        match self.config.method {
            ClusteringMethod::Geographic => self.cluster_geographic(),
            ClusteringMethod::Latency => self.cluster_latency(),
            ClusteringMethod::Hybrid => self.cluster_hybrid(),
            ClusteringMethod::AutonomousSystem => self.cluster_as(),
        }
    }

    /// Geographic clustering
    fn cluster_geographic(&self) {
        let mut clusters: HashMap<String, PeerCluster> = HashMap::new();
        let mut peer_to_cluster: HashMap<PeerId, String> = HashMap::new();
        let locations = self.peer_locations.read().unwrap();

        let peers: Vec<(PeerId, &PeerLocationInfo)> =
            locations.iter().map(|(p, i)| (*p, i)).collect();

        for (peer_id, info) in peers {
            // Try to find a nearby cluster
            let mut assigned = false;
            for cluster in clusters.values_mut() {
                if cluster.size() >= self.config.max_cluster_size {
                    continue;
                }

                if let Some(center) = cluster.geo_center {
                    let distance = info.location.distance_to(&center);
                    if distance <= self.config.max_geo_distance {
                        cluster.add_peer(peer_id);
                        peer_to_cluster.insert(peer_id, cluster.id.clone());
                        assigned = true;
                        break;
                    }
                }
            }

            // Create a new cluster if not assigned
            if !assigned {
                let cluster_id = format!("geo-{}", clusters.len());
                let mut cluster = PeerCluster::new(
                    cluster_id.clone(),
                    format!("Geographic Cluster {}", clusters.len()),
                );
                cluster.geo_center = Some(info.location);
                cluster.add_peer(peer_id);
                peer_to_cluster.insert(peer_id, cluster_id.clone());
                clusters.insert(cluster_id, cluster);
            }
        }

        // Update cluster centers
        let location_map: HashMap<PeerId, GeoCoordinate> =
            locations.iter().map(|(p, i)| (*p, i.location)).collect();
        for cluster in clusters.values_mut() {
            cluster.update_center(&location_map);
        }

        *self.clusters.write().unwrap() = clusters;
        *self.peer_to_cluster.write().unwrap() = peer_to_cluster;
    }

    /// Latency-based clustering
    fn cluster_latency(&self) {
        let mut clusters: HashMap<String, PeerCluster> = HashMap::new();
        let mut peer_to_cluster: HashMap<PeerId, String> = HashMap::new();
        let locations = self.peer_locations.read().unwrap();

        let mut peers: Vec<(PeerId, Duration)> =
            locations.iter().map(|(p, i)| (*p, i.latency)).collect();
        peers.sort_by_key(|(_, lat)| *lat);

        for (peer_id, latency) in peers {
            let mut assigned = false;
            for cluster in clusters.values_mut() {
                if cluster.size() >= self.config.max_cluster_size {
                    continue;
                }

                if let Some(avg_lat) = cluster.avg_latency {
                    let diff = latency
                        .saturating_sub(avg_lat)
                        .max(avg_lat.saturating_sub(latency));

                    if diff <= self.config.max_latency_diff {
                        cluster.add_peer(peer_id);
                        peer_to_cluster.insert(peer_id, cluster.id.clone());
                        // Recalculate average latency
                        let total_lat: Duration = cluster
                            .peers
                            .iter()
                            .filter_map(|p| locations.get(p).map(|i| i.latency))
                            .sum();
                        cluster.avg_latency = Some(total_lat / cluster.peers.len() as u32);
                        assigned = true;
                        break;
                    }
                }
            }

            if !assigned {
                let cluster_id = format!("lat-{}", clusters.len());
                let mut cluster = PeerCluster::new(
                    cluster_id.clone(),
                    format!("Latency Cluster {}", clusters.len()),
                );
                cluster.avg_latency = Some(latency);
                cluster.add_peer(peer_id);
                peer_to_cluster.insert(peer_id, cluster_id.clone());
                clusters.insert(cluster_id, cluster);
            }
        }

        *self.clusters.write().unwrap() = clusters;
        *self.peer_to_cluster.write().unwrap() = peer_to_cluster;
    }

    /// Hybrid clustering (geographic + latency)
    fn cluster_hybrid(&self) {
        let mut clusters: HashMap<String, PeerCluster> = HashMap::new();
        let mut peer_to_cluster: HashMap<PeerId, String> = HashMap::new();
        let locations = self.peer_locations.read().unwrap();

        let peers: Vec<(PeerId, &PeerLocationInfo)> =
            locations.iter().map(|(p, i)| (*p, i)).collect();

        for (peer_id, info) in peers {
            let mut best_cluster: Option<String> = None;
            let mut best_score = f64::MIN;

            for cluster in clusters.values() {
                if cluster.size() >= self.config.max_cluster_size {
                    continue;
                }

                let mut score = 0.0;

                // Geographic similarity
                if let Some(center) = cluster.geo_center {
                    let distance = info.location.distance_to(&center);
                    let geo_similarity = 1.0 - (distance / self.config.max_geo_distance).min(1.0);
                    score += geo_similarity * self.config.hybrid_geo_weight;
                }

                // Latency similarity
                if let Some(avg_lat) = cluster.avg_latency {
                    let diff = info
                        .latency
                        .saturating_sub(avg_lat)
                        .max(avg_lat.saturating_sub(info.latency));
                    let lat_similarity = 1.0
                        - (diff.as_millis() as f64
                            / self.config.max_latency_diff.as_millis() as f64)
                            .min(1.0);
                    score += lat_similarity * (1.0 - self.config.hybrid_geo_weight);
                }

                if score > best_score {
                    best_score = score;
                    best_cluster = Some(cluster.id.clone());
                }
            }

            if let Some(cluster_id) = best_cluster {
                if best_score > 0.5 {
                    // Only assign if similarity is above threshold
                    if let Some(cluster) = clusters.get_mut(&cluster_id) {
                        cluster.add_peer(peer_id);
                        peer_to_cluster.insert(peer_id, cluster_id);

                        // Update cluster center
                        let location_map: HashMap<PeerId, GeoCoordinate> =
                            locations.iter().map(|(p, i)| (*p, i.location)).collect();
                        cluster.update_center(&location_map);

                        // Update average latency
                        let total_lat: Duration = cluster
                            .peers
                            .iter()
                            .filter_map(|p| locations.get(p).map(|i| i.latency))
                            .sum();
                        cluster.avg_latency = Some(total_lat / cluster.peers.len() as u32);
                    }
                    continue;
                }
            }

            // Create new cluster
            let cluster_id = format!("hybrid-{}", clusters.len());
            let mut cluster = PeerCluster::new(
                cluster_id.clone(),
                format!("Hybrid Cluster {}", clusters.len()),
            );
            cluster.geo_center = Some(info.location);
            cluster.avg_latency = Some(info.latency);
            cluster.add_peer(peer_id);
            peer_to_cluster.insert(peer_id, cluster_id.clone());
            clusters.insert(cluster_id, cluster);
        }

        *self.clusters.write().unwrap() = clusters;
        *self.peer_to_cluster.write().unwrap() = peer_to_cluster;
    }

    /// AS-based clustering
    fn cluster_as(&self) {
        let mut clusters: HashMap<String, PeerCluster> = HashMap::new();
        let mut peer_to_cluster: HashMap<PeerId, String> = HashMap::new();
        let locations = self.peer_locations.read().unwrap();

        for (peer_id, info) in locations.iter() {
            if let Some(as_num) = info.as_number {
                let cluster_id = format!("as-{}", as_num);
                clusters
                    .entry(cluster_id.clone())
                    .or_insert_with(|| {
                        PeerCluster::new(cluster_id.clone(), format!("AS {}", as_num))
                    })
                    .add_peer(*peer_id);
                peer_to_cluster.insert(*peer_id, cluster_id);
            }
        }

        *self.clusters.write().unwrap() = clusters;
        *self.peer_to_cluster.write().unwrap() = peer_to_cluster;
    }

    /// Get cluster for a peer
    pub fn get_peer_cluster(&self, peer_id: &PeerId) -> Option<String> {
        self.peer_to_cluster.read().unwrap().get(peer_id).cloned()
    }

    /// Get all clusters
    pub fn get_clusters(&self) -> Vec<PeerCluster> {
        self.clusters.read().unwrap().values().cloned().collect()
    }

    /// Get peers in the same cluster as the given peer
    pub fn get_cluster_peers(&self, peer_id: &PeerId) -> Vec<PeerId> {
        if let Some(cluster_id) = self.get_peer_cluster(peer_id) {
            if let Some(cluster) = self.clusters.read().unwrap().get(&cluster_id) {
                return cluster.peers.clone();
            }
        }
        Vec::new()
    }

    /// Get cluster statistics
    pub fn get_stats(&self) -> ClusteringStats {
        let clusters = self.clusters.read().unwrap();
        let total_clusters = clusters.len();
        let total_peers = self.peer_locations.read().unwrap().len();
        let avg_cluster_size = if total_clusters > 0 {
            total_peers as f64 / total_clusters as f64
        } else {
            0.0
        };

        let cluster_sizes: Vec<usize> = clusters.values().map(|c| c.size()).collect();
        let max_cluster_size = cluster_sizes.iter().max().copied().unwrap_or(0);
        let min_cluster_size = cluster_sizes.iter().min().copied().unwrap_or(0);

        ClusteringStats {
            total_clusters,
            total_peers,
            avg_cluster_size,
            max_cluster_size,
            min_cluster_size,
        }
    }
}

/// Clustering statistics
#[derive(Debug, Clone)]
pub struct ClusteringStats {
    pub total_clusters: usize,
    pub total_peers: usize,
    pub avg_cluster_size: f64,
    pub max_cluster_size: usize,
    pub min_cluster_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_geo_coordinate_distance() {
        // New York to London
        let ny = GeoCoordinate::new(40.7128, -74.0060);
        let london = GeoCoordinate::new(51.5074, -0.1278);
        let distance = ny.distance_to(&london);
        // Approximate distance is 5,570 km, allow 10% tolerance
        assert!((distance - 5570.0).abs() < 557.0);
    }

    #[test]
    fn test_peer_cluster_new() {
        let cluster = PeerCluster::new("test-1".to_string(), "Test Cluster".to_string());
        assert_eq!(cluster.id, "test-1");
        assert_eq!(cluster.name, "Test Cluster");
        assert_eq!(cluster.size(), 0);
    }

    #[test]
    fn test_peer_cluster_add_remove() {
        let mut cluster = PeerCluster::new("test-1".to_string(), "Test".to_string());
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        cluster.add_peer(peer1);
        assert_eq!(cluster.size(), 1);

        cluster.add_peer(peer2);
        assert_eq!(cluster.size(), 2);

        // Add duplicate
        cluster.add_peer(peer1);
        assert_eq!(cluster.size(), 2);

        assert!(cluster.remove_peer(&peer1));
        assert_eq!(cluster.size(), 1);

        assert!(!cluster.remove_peer(&peer1));
    }

    #[test]
    fn test_cluster_update_center() {
        let mut cluster = PeerCluster::new("test-1".to_string(), "Test".to_string());
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        cluster.add_peer(peer1);
        cluster.add_peer(peer2);

        let mut locations = HashMap::new();
        locations.insert(peer1, GeoCoordinate::new(40.0, -74.0));
        locations.insert(peer2, GeoCoordinate::new(42.0, -72.0));

        cluster.update_center(&locations);

        assert!(cluster.geo_center.is_some());
        let center = cluster.geo_center.unwrap();
        assert!((center.latitude - 41.0).abs() < 0.01);
        assert!((center.longitude + 73.0).abs() < 0.01);
    }

    #[test]
    fn test_clustering_manager_new() {
        let config = ClusteringConfig::default();
        let manager = PeerClusteringManager::new(config);
        let stats = manager.get_stats();
        assert_eq!(stats.total_clusters, 0);
        assert_eq!(stats.total_peers, 0);
    }

    #[test]
    fn test_add_peer_location() {
        let config = ClusteringConfig::default();
        let manager = PeerClusteringManager::new(config);

        let peer = create_test_peer();
        let location = GeoCoordinate::new(40.7128, -74.0060);
        manager.add_peer_location(peer, location, Duration::from_millis(50), Some(12345));

        let locations = manager.peer_locations.read().unwrap();
        assert!(locations.contains_key(&peer));
    }

    #[test]
    fn test_geographic_clustering() {
        let config = ClusteringConfig {
            method: ClusteringMethod::Geographic,
            max_geo_distance: 1000.0,
            ..Default::default()
        };

        let manager = PeerClusteringManager::new(config);

        // Add peers in two geographic regions
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();
        let peer4 = create_test_peer();

        manager.add_peer_location(
            peer1,
            GeoCoordinate::new(40.0, -74.0),
            Duration::from_millis(10),
            None,
        );
        manager.add_peer_location(
            peer2,
            GeoCoordinate::new(40.5, -73.5),
            Duration::from_millis(15),
            None,
        );
        manager.add_peer_location(
            peer3,
            GeoCoordinate::new(51.5, -0.1),
            Duration::from_millis(50),
            None,
        );
        manager.add_peer_location(
            peer4,
            GeoCoordinate::new(51.3, -0.3),
            Duration::from_millis(55),
            None,
        );

        manager.recluster();

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 4);
        assert!(stats.total_clusters >= 2); // At least 2 clusters for 2 regions
    }

    #[test]
    fn test_latency_clustering() {
        let config = ClusteringConfig {
            method: ClusteringMethod::Latency,
            max_latency_diff: Duration::from_millis(20),
            ..Default::default()
        };

        let manager = PeerClusteringManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();
        let peer4 = create_test_peer();

        manager.add_peer_location(
            peer1,
            GeoCoordinate::new(40.0, -74.0),
            Duration::from_millis(10),
            None,
        );
        manager.add_peer_location(
            peer2,
            GeoCoordinate::new(40.5, -73.5),
            Duration::from_millis(15),
            None,
        );
        manager.add_peer_location(
            peer3,
            GeoCoordinate::new(51.5, -0.1),
            Duration::from_millis(100),
            None,
        );
        manager.add_peer_location(
            peer4,
            GeoCoordinate::new(51.3, -0.3),
            Duration::from_millis(105),
            None,
        );

        manager.recluster();

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 4);
        assert!(stats.total_clusters >= 2); // Should have at least 2 latency clusters
    }

    #[test]
    fn test_hybrid_clustering() {
        let config = ClusteringConfig {
            method: ClusteringMethod::Hybrid,
            ..Default::default()
        };

        let manager = PeerClusteringManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager.add_peer_location(
            peer1,
            GeoCoordinate::new(40.0, -74.0),
            Duration::from_millis(10),
            None,
        );
        manager.add_peer_location(
            peer2,
            GeoCoordinate::new(40.5, -73.5),
            Duration::from_millis(15),
            None,
        );

        manager.recluster();

        let cluster_id = manager.get_peer_cluster(&peer1);
        assert!(cluster_id.is_some());
    }

    #[test]
    fn test_as_clustering() {
        let config = ClusteringConfig {
            method: ClusteringMethod::AutonomousSystem,
            ..Default::default()
        };

        let manager = PeerClusteringManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();
        let peer3 = create_test_peer();

        manager.add_peer_location(
            peer1,
            GeoCoordinate::new(40.0, -74.0),
            Duration::from_millis(10),
            Some(12345),
        );
        manager.add_peer_location(
            peer2,
            GeoCoordinate::new(40.5, -73.5),
            Duration::from_millis(15),
            Some(12345),
        );
        manager.add_peer_location(
            peer3,
            GeoCoordinate::new(51.5, -0.1),
            Duration::from_millis(50),
            Some(67890),
        );

        manager.recluster();

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 3);
        assert_eq!(stats.total_clusters, 2); // Two AS numbers

        let cluster1 = manager.get_peer_cluster(&peer1);
        let cluster2 = manager.get_peer_cluster(&peer2);
        assert_eq!(cluster1, cluster2); // Same AS
    }

    #[test]
    fn test_get_cluster_peers() {
        let config = ClusteringConfig::default();
        let manager = PeerClusteringManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager.add_peer_location(
            peer1,
            GeoCoordinate::new(40.0, -74.0),
            Duration::from_millis(10),
            None,
        );
        manager.add_peer_location(
            peer2,
            GeoCoordinate::new(40.1, -74.1),
            Duration::from_millis(11),
            None,
        );

        manager.recluster();

        let cluster_peers = manager.get_cluster_peers(&peer1);
        assert!(!cluster_peers.is_empty());
    }

    #[test]
    fn test_get_clusters() {
        let config = ClusteringConfig::default();
        let manager = PeerClusteringManager::new(config);

        let peer1 = create_test_peer();
        manager.add_peer_location(
            peer1,
            GeoCoordinate::new(40.0, -74.0),
            Duration::from_millis(10),
            None,
        );

        manager.recluster();

        let clusters = manager.get_clusters();
        assert!(!clusters.is_empty());
    }

    #[test]
    fn test_clustering_config_default() {
        let config = ClusteringConfig::default();
        assert_eq!(config.method, ClusteringMethod::Hybrid);
        assert_eq!(config.max_cluster_size, 50);
        assert_eq!(config.min_cluster_size, 3);
    }

    #[test]
    fn test_max_cluster_size_limit() {
        let config = ClusteringConfig {
            max_cluster_size: 2,
            max_geo_distance: 10000.0, // Large distance
            ..Default::default()
        };

        let manager = PeerClusteringManager::new(config);

        for _ in 0..5 {
            let peer = create_test_peer();
            manager.add_peer_location(
                peer,
                GeoCoordinate::new(40.0, -74.0),
                Duration::from_millis(10),
                None,
            );
        }

        manager.recluster();

        let clusters = manager.get_clusters();
        for cluster in clusters {
            assert!(cluster.size() <= 2);
        }
    }

    #[test]
    fn test_stats_accuracy() {
        let config = ClusteringConfig::default();
        let manager = PeerClusteringManager::new(config);

        for _ in 0..10 {
            let peer = create_test_peer();
            manager.add_peer_location(
                peer,
                GeoCoordinate::new(40.0, -74.0),
                Duration::from_millis(10),
                None,
            );
        }

        manager.recluster();

        let stats = manager.get_stats();
        assert_eq!(stats.total_peers, 10);
        assert!(stats.avg_cluster_size > 0.0);
    }
}
