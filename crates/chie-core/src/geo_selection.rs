//! Geographic-aware peer selection for optimal content delivery.
//!
//! This module provides geographic intelligence for peer selection, including:
//! - Haversine distance calculation between geographic coordinates
//! - Region-based peer grouping
//! - Geographic diversity scoring
//! - Proximity-based peer ranking
//!
//! # Example
//!
//! ```rust
//! use chie_core::geo_selection::{GeoLocation, GeoPeer, GeoSelector, GeoConfig};
//!
//! # fn example() {
//! let config = GeoConfig::default();
//! let mut selector = GeoSelector::new(config);
//!
//! // Add peers with geographic locations
//! selector.add_peer(GeoPeer {
//!     peer_id: "peer1".to_string(),
//!     location: GeoLocation::new(37.7749, -122.4194), // San Francisco
//!     region: "us-west".to_string(),
//!     latency_ms: 50.0,
//!     bandwidth_mbps: 100.0,
//! });
//!
//! selector.add_peer(GeoPeer {
//!     peer_id: "peer2".to_string(),
//!     location: GeoLocation::new(40.7128, -74.0060), // New York
//!     region: "us-east".to_string(),
//!     latency_ms: 120.0,
//!     bandwidth_mbps: 100.0,
//! });
//!
//! // Find nearest peer to a location
//! let target = GeoLocation::new(37.3382, -121.8863); // San Jose
//! let nearest = selector.find_nearest(&target, 5);
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Earth's radius in kilometers.
const EARTH_RADIUS_KM: f64 = 6371.0;

/// Geographic location with latitude and longitude.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Latitude in degrees (-90 to 90).
    pub latitude: f64,
    /// Longitude in degrees (-180 to 180).
    pub longitude: f64,
}

impl GeoLocation {
    /// Create a new geographic location.
    ///
    /// # Panics
    ///
    /// Panics if latitude is not in range [-90, 90] or longitude is not in range [-180, 180].
    #[must_use]
    pub fn new(latitude: f64, longitude: f64) -> Self {
        assert!(
            (-90.0..=90.0).contains(&latitude),
            "Latitude must be between -90 and 90 degrees"
        );
        assert!(
            (-180.0..=180.0).contains(&longitude),
            "Longitude must be between -180 and 180 degrees"
        );

        Self {
            latitude,
            longitude,
        }
    }

    /// Calculate the great-circle distance to another location using the Haversine formula.
    ///
    /// Returns the distance in kilometers.
    #[must_use]
    #[inline]
    pub fn distance_to(&self, other: &GeoLocation) -> f64 {
        haversine_distance(self, other)
    }

    /// Check if this location is within a certain radius of another location.
    #[must_use]
    #[inline]
    pub fn is_within(&self, other: &GeoLocation, radius_km: f64) -> bool {
        self.distance_to(other) <= radius_km
    }

    /// Get the bearing (direction) to another location in degrees (0-360).
    #[must_use]
    #[inline]
    pub fn bearing_to(&self, other: &GeoLocation) -> f64 {
        let lat1 = self.latitude.to_radians();
        let lat2 = other.latitude.to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let y = delta_lon.sin() * lat2.cos();
        let x = lat1.cos() * lat2.sin() - lat1.sin() * lat2.cos() * delta_lon.cos();

        let bearing = y.atan2(x).to_degrees();
        (bearing + 360.0) % 360.0
    }
}

/// Calculate the Haversine distance between two geographic locations.
///
/// Returns the distance in kilometers.
#[must_use]
pub fn haversine_distance(loc1: &GeoLocation, loc2: &GeoLocation) -> f64 {
    let lat1 = loc1.latitude.to_radians();
    let lat2 = loc2.latitude.to_radians();
    let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
    let delta_lon = (loc2.longitude - loc1.longitude).to_radians();

    let a =
        (delta_lat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (delta_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    EARTH_RADIUS_KM * c
}

/// A peer with geographic location information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoPeer {
    /// Peer identifier.
    pub peer_id: String,
    /// Geographic location of the peer.
    pub location: GeoLocation,
    /// Region identifier (e.g., "us-west", "eu-central").
    pub region: String,
    /// Average latency in milliseconds.
    pub latency_ms: f64,
    /// Available bandwidth in Mbps.
    pub bandwidth_mbps: f64,
}

impl GeoPeer {
    /// Calculate distance to a target location.
    #[must_use]
    #[inline]
    pub fn distance_to(&self, target: &GeoLocation) -> f64 {
        self.location.distance_to(target)
    }

    /// Calculate a geographic score (lower distance and latency = higher score).
    #[must_use]
    #[inline]
    pub fn geo_score(&self, target: &GeoLocation) -> f64 {
        let distance = self.distance_to(target);
        let distance_score = 1.0 / (1.0 + distance / 1000.0); // Normalize by 1000km
        let latency_score = 1.0 / (1.0 + self.latency_ms / 100.0); // Normalize by 100ms

        // Weighted combination
        0.6 * distance_score + 0.4 * latency_score
    }
}

/// Configuration for geographic peer selection.
#[derive(Debug, Clone)]
pub struct GeoConfig {
    /// Prefer peers within this radius (km).
    pub preferred_radius_km: f64,
    /// Maximum acceptable distance (km).
    pub max_distance_km: f64,
    /// Whether to enable region-based grouping.
    pub enable_region_grouping: bool,
    /// Minimum number of peers to select from different regions (for diversity).
    pub min_region_diversity: usize,
    /// Weight for distance vs latency (0.0 = all latency, 1.0 = all distance).
    pub distance_weight: f64,
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            preferred_radius_km: 500.0, // 500 km preferred
            max_distance_km: 10000.0,   // 10,000 km max
            enable_region_grouping: true,
            min_region_diversity: 2, // At least 2 different regions
            distance_weight: 0.6,    // 60% distance, 40% latency
        }
    }
}

/// Geographic peer selector.
pub struct GeoSelector {
    /// Configuration.
    config: GeoConfig,
    /// Map of peer ID to peer info.
    peers: HashMap<String, GeoPeer>,
    /// Map of region to peer IDs.
    regions: HashMap<String, Vec<String>>,
}

impl GeoSelector {
    /// Create a new geographic peer selector.
    #[must_use]
    pub fn new(config: GeoConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            regions: HashMap::new(),
        }
    }

    /// Add a peer to the selector.
    pub fn add_peer(&mut self, peer: GeoPeer) {
        // Update region mapping
        self.regions
            .entry(peer.region.clone())
            .or_default()
            .push(peer.peer_id.clone());

        // Add peer
        self.peers.insert(peer.peer_id.clone(), peer);
    }

    /// Remove a peer from the selector.
    pub fn remove_peer(&mut self, peer_id: &str) -> Option<GeoPeer> {
        if let Some(peer) = self.peers.remove(peer_id) {
            // Remove from region mapping
            if let Some(region_peers) = self.regions.get_mut(&peer.region) {
                region_peers.retain(|id| id != peer_id);
                if region_peers.is_empty() {
                    self.regions.remove(&peer.region);
                }
            }
            Some(peer)
        } else {
            None
        }
    }

    /// Find the N nearest peers to a target location.
    #[must_use]
    #[inline]
    pub fn find_nearest(&self, target: &GeoLocation, n: usize) -> Vec<GeoPeer> {
        let mut peers_with_distance: Vec<(GeoPeer, f64)> = self
            .peers
            .values()
            .map(|peer| {
                let distance = peer.distance_to(target);
                (peer.clone(), distance)
            })
            .collect();

        // Sort by distance
        peers_with_distance.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Take top N
        peers_with_distance
            .into_iter()
            .take(n)
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Find peers within a specific radius.
    #[must_use]
    #[inline]
    pub fn find_within_radius(&self, target: &GeoLocation, radius_km: f64) -> Vec<GeoPeer> {
        self.peers
            .values()
            .filter(|peer| peer.distance_to(target) <= radius_km)
            .cloned()
            .collect()
    }

    /// Select best peers based on geographic score.
    #[must_use]
    #[inline]
    pub fn select_best(&self, target: &GeoLocation, n: usize) -> Vec<GeoPeer> {
        let mut peers_with_score: Vec<(GeoPeer, f64)> = self
            .peers
            .values()
            .map(|peer| {
                let score = peer.geo_score(target);
                (peer.clone(), score)
            })
            .collect();

        // Sort by score (descending)
        peers_with_score.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        peers_with_score
            .into_iter()
            .take(n)
            .map(|(peer, _)| peer)
            .collect()
    }

    /// Select peers with geographic diversity (from different regions).
    #[must_use]
    #[inline]
    pub fn select_diverse(&self, target: &GeoLocation, n: usize) -> Vec<GeoPeer> {
        if !self.config.enable_region_grouping {
            return self.select_best(target, n);
        }

        let mut selected = Vec::new();
        let mut used_regions = std::collections::HashSet::new();

        // Get all peers sorted by score
        let mut peers_with_score: Vec<(GeoPeer, f64)> = self
            .peers
            .values()
            .map(|peer| {
                let score = peer.geo_score(target);
                (peer.clone(), score)
            })
            .collect();

        peers_with_score.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // First, select best peer from each region
        for (peer, _) in &peers_with_score {
            if !used_regions.contains(&peer.region) {
                selected.push(peer.clone());
                used_regions.insert(peer.region.clone());

                if selected.len() >= n {
                    return selected;
                }
            }
        }

        // Then fill remaining slots with best peers
        for (peer, _) in peers_with_score {
            if selected.iter().any(|p| p.peer_id == peer.peer_id) {
                continue;
            }
            selected.push(peer);
            if selected.len() >= n {
                break;
            }
        }

        selected
    }

    /// Get peers grouped by region.
    #[must_use]
    #[inline]
    pub fn get_peers_by_region(&self, region: &str) -> Vec<GeoPeer> {
        if let Some(peer_ids) = self.regions.get(region) {
            peer_ids
                .iter()
                .filter_map(|id| self.peers.get(id))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all available regions.
    #[must_use]
    #[inline]
    pub fn get_regions(&self) -> Vec<String> {
        self.regions.keys().cloned().collect()
    }

    /// Get statistics about geographic distribution.
    #[must_use]
    pub fn get_geo_stats(&self) -> GeoStats {
        let mut region_counts = HashMap::new();
        for (region, peers) in &self.regions {
            region_counts.insert(region.clone(), peers.len());
        }

        let total_peers = self.peers.len();
        let total_regions = self.regions.len();

        GeoStats {
            total_peers,
            total_regions,
            peers_per_region: region_counts,
            avg_peers_per_region: if total_regions > 0 {
                total_peers as f64 / total_regions as f64
            } else {
                0.0
            },
        }
    }

    /// Get peer count.
    #[must_use]
    #[inline]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get a peer by ID.
    #[must_use]
    #[inline]
    pub fn get_peer(&self, peer_id: &str) -> Option<&GeoPeer> {
        self.peers.get(peer_id)
    }
}

/// Geographic distribution statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoStats {
    /// Total number of peers.
    pub total_peers: usize,
    /// Total number of regions.
    pub total_regions: usize,
    /// Number of peers per region.
    pub peers_per_region: HashMap<String, usize>,
    /// Average peers per region.
    pub avg_peers_per_region: f64,
}

/// Calculate the midpoint between two locations.
#[must_use]
pub fn midpoint(loc1: &GeoLocation, loc2: &GeoLocation) -> GeoLocation {
    let lat1 = loc1.latitude.to_radians();
    let lon1 = loc1.longitude.to_radians();
    let lat2 = loc2.latitude.to_radians();
    let lon2 = loc2.longitude.to_radians();

    let bx = lat2.cos() * (lon2 - lon1).cos();
    let by = lat2.cos() * (lon2 - lon1).sin();

    let lat3 = (lat1.sin() + lat2.sin()).atan2(((lat1.cos() + bx).powi(2) + by.powi(2)).sqrt());
    let lon3 = lon1 + by.atan2(lat1.cos() + bx);

    GeoLocation {
        latitude: lat3.to_degrees(),
        longitude: lon3.to_degrees(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_location_creation() {
        let loc = GeoLocation::new(37.7749, -122.4194);
        assert_eq!(loc.latitude, 37.7749);
        assert_eq!(loc.longitude, -122.4194);
    }

    #[test]
    #[should_panic]
    fn test_invalid_latitude() {
        let _ = GeoLocation::new(91.0, 0.0);
    }

    #[test]
    fn test_haversine_distance() {
        // San Francisco to New York
        let sf = GeoLocation::new(37.7749, -122.4194);
        let ny = GeoLocation::new(40.7128, -74.0060);

        let distance = sf.distance_to(&ny);
        // Distance should be approximately 4130 km
        assert!((distance - 4130.0).abs() < 50.0);
    }

    #[test]
    fn test_same_location_distance() {
        let loc = GeoLocation::new(0.0, 0.0);
        assert_eq!(loc.distance_to(&loc), 0.0);
    }

    #[test]
    fn test_is_within_radius() {
        let loc1 = GeoLocation::new(37.7749, -122.4194);
        let loc2 = GeoLocation::new(37.3382, -121.8863);

        // These locations are about 70km apart
        assert!(loc1.is_within(&loc2, 100.0));
        assert!(!loc1.is_within(&loc2, 50.0));
    }

    #[test]
    fn test_geo_selector() {
        let config = GeoConfig::default();
        let mut selector = GeoSelector::new(config);

        let peer1 = GeoPeer {
            peer_id: "peer1".to_string(),
            location: GeoLocation::new(37.7749, -122.4194),
            region: "us-west".to_string(),
            latency_ms: 50.0,
            bandwidth_mbps: 100.0,
        };

        let peer2 = GeoPeer {
            peer_id: "peer2".to_string(),
            location: GeoLocation::new(40.7128, -74.0060),
            region: "us-east".to_string(),
            latency_ms: 120.0,
            bandwidth_mbps: 100.0,
        };

        selector.add_peer(peer1);
        selector.add_peer(peer2);

        assert_eq!(selector.peer_count(), 2);

        // Find nearest to San Jose (closer to SF)
        let target = GeoLocation::new(37.3382, -121.8863);
        let nearest = selector.find_nearest(&target, 1);

        assert_eq!(nearest.len(), 1);
        assert_eq!(nearest[0].peer_id, "peer1");
    }

    #[test]
    fn test_region_grouping() {
        let config = GeoConfig::default();
        let mut selector = GeoSelector::new(config);

        selector.add_peer(GeoPeer {
            peer_id: "peer1".to_string(),
            location: GeoLocation::new(37.7749, -122.4194),
            region: "us-west".to_string(),
            latency_ms: 50.0,
            bandwidth_mbps: 100.0,
        });

        let region_peers = selector.get_peers_by_region("us-west");
        assert_eq!(region_peers.len(), 1);

        let regions = selector.get_regions();
        assert!(regions.contains(&"us-west".to_string()));
    }

    #[test]
    fn test_midpoint() {
        let loc1 = GeoLocation::new(0.0, 0.0);
        let loc2 = GeoLocation::new(0.0, 10.0);

        let mid = midpoint(&loc1, &loc2);
        assert!((mid.latitude - 0.0).abs() < 0.01);
        assert!((mid.longitude - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_bearing() {
        let loc1 = GeoLocation::new(0.0, 0.0);
        let loc2 = GeoLocation::new(1.0, 0.0);

        let bearing = loc1.bearing_to(&loc2);
        // Should be approximately 0 degrees (north)
        assert!((bearing - 0.0).abs() < 1.0 || (bearing - 360.0).abs() < 1.0);
    }
}
