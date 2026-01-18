//! Geographic load balancing with zone awareness.
//!
//! This module provides intelligent geographic load balancing for P2P CDN nodes,
//! considering geographic zones, network latency, and node capacity. Essential
//! for global CDN deployments to minimize latency and maximize performance.
//!
//! # Features
//!
//! - Multi-zone load balancing with configurable zones
//! - Latency-based peer selection within zones
//! - Cross-zone failover for reliability
//! - Zone capacity management and load tracking
//! - Geographic distance calculation (Haversine)
//! - Weighted zone selection based on load
//! - Proximity-based routing
//! - Comprehensive geographic statistics
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::geo_load_balancer::{GeoLoadBalancer, GeoZone, GeoLocation};
//!
//! let mut balancer = GeoLoadBalancer::new();
//!
//! // Define zones
//! let us_east = GeoZone::new("us-east", GeoLocation::new(40.7128, -74.0060));
//! let eu_west = GeoZone::new("eu-west", GeoLocation::new(51.5074, -0.1278));
//!
//! balancer.add_zone(us_east);
//! balancer.add_zone(eu_west);
//!
//! // Add nodes to zones
//! balancer.add_node_to_zone("us-east", "node-1", 100.0); // 100ms latency
//! balancer.add_node_to_zone("us-east", "node-2", 120.0);
//!
//! // Select best node for a client location
//! let client_loc = GeoLocation::new(40.7589, -73.9851); // NYC
//! if let Some(node) = balancer.select_node(&client_loc) {
//!     println!("Selected node: {}", node);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Geographic coordinates
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Latitude in degrees
    pub latitude: f64,
    /// Longitude in degrees
    pub longitude: f64,
}

impl GeoLocation {
    /// Create a new geographic location
    pub fn new(latitude: f64, longitude: f64) -> Self {
        assert!((-90.0..=90.0).contains(&latitude), "Invalid latitude");
        assert!((-180.0..=180.0).contains(&longitude), "Invalid longitude");
        Self {
            latitude,
            longitude,
        }
    }

    /// Calculate distance to another location using Haversine formula (in kilometers)
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
}

/// Node information within a zone
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoNode {
    /// Node ID
    pub id: String,
    /// Latency to this node (milliseconds)
    pub latency: f64,
    /// Current load (0.0 to 1.0)
    pub load: f64,
    /// Node capacity (arbitrary units)
    pub capacity: u64,
    /// Whether this node is healthy
    pub healthy: bool,
    /// Number of active connections
    pub active_connections: u32,
}

impl GeoNode {
    /// Create a new geographic node
    pub fn new(id: impl Into<String>, latency: f64) -> Self {
        Self {
            id: id.into(),
            latency,
            load: 0.0,
            capacity: 1000,
            healthy: true,
            active_connections: 0,
        }
    }

    /// Set node capacity
    pub fn with_capacity(mut self, capacity: u64) -> Self {
        self.capacity = capacity;
        self
    }

    /// Calculate composite score for selection (lower is better)
    pub fn score(&self) -> f64 {
        if !self.healthy {
            return f64::MAX;
        }

        // Weighted score: latency (50%) + load (30%) + connection count (20%)
        let latency_score = self.latency * 0.5;
        let load_score = self.load * 1000.0 * 0.3; // Normalize to latency scale
        let connection_score = (self.active_connections as f64 / 100.0) * 1000.0 * 0.2;

        latency_score + load_score + connection_score
    }
}

/// Geographic zone
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoZone {
    /// Zone ID
    pub id: String,
    /// Zone center location
    pub location: GeoLocation,
    /// Nodes in this zone
    pub nodes: HashMap<String, GeoNode>,
    /// Zone capacity
    pub capacity: u64,
    /// Current zone load (0.0 to 1.0)
    pub load: f64,
}

impl GeoZone {
    /// Create a new geographic zone
    pub fn new(id: impl Into<String>, location: GeoLocation) -> Self {
        Self {
            id: id.into(),
            location,
            nodes: HashMap::new(),
            capacity: 10000,
            load: 0.0,
        }
    }

    /// Set zone capacity
    pub fn with_capacity(mut self, capacity: u64) -> Self {
        self.capacity = capacity;
        self
    }

    /// Add a node to this zone
    pub fn add_node(&mut self, node: GeoNode) {
        self.nodes.insert(node.id.clone(), node);
        self.update_load();
    }

    /// Remove a node from this zone
    pub fn remove_node(&mut self, node_id: &str) -> Option<GeoNode> {
        let result = self.nodes.remove(node_id);
        self.update_load();
        result
    }

    /// Update zone load based on node loads
    fn update_load(&mut self) {
        if self.nodes.is_empty() {
            self.load = 0.0;
            return;
        }

        let total_load: f64 = self.nodes.values().map(|n| n.load).sum();
        self.load = total_load / self.nodes.len() as f64;
    }

    /// Select best node in this zone
    pub fn select_node(&self) -> Option<&GeoNode> {
        self.nodes
            .values()
            .filter(|n| n.healthy)
            .min_by(|a, b| a.score().partial_cmp(&b.score()).unwrap())
    }

    /// Get available capacity
    pub fn available_capacity(&self) -> u64 {
        let used = (self.capacity as f64 * self.load) as u64;
        self.capacity.saturating_sub(used)
    }
}

/// Load balancing statistics
#[derive(Debug, Clone, Default)]
pub struct GeoLoadBalancerStats {
    /// Total node selections
    pub total_selections: u64,
    /// Selections by zone
    pub selections_by_zone: HashMap<String, u64>,
    /// Cross-zone failovers
    pub cross_zone_failovers: u64,
    /// Average selection latency
    pub avg_selection_latency: f64,
    /// Failed selections (no nodes available)
    pub failed_selections: u64,
}

/// Geographic load balancer
pub struct GeoLoadBalancer {
    /// Zones indexed by ID
    zones: HashMap<String, GeoZone>,
    /// Statistics
    stats: parking_lot::RwLock<GeoLoadBalancerStats>,
    /// Maximum distance for zone consideration (km)
    max_zone_distance: f64,
    /// Enable cross-zone failover
    enable_cross_zone: bool,
}

impl GeoLoadBalancer {
    /// Create a new geographic load balancer
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
            stats: parking_lot::RwLock::new(GeoLoadBalancerStats::default()),
            max_zone_distance: 5000.0, // 5000 km default
            enable_cross_zone: true,
        }
    }

    /// Create with custom configuration
    pub fn with_config(max_zone_distance: f64, enable_cross_zone: bool) -> Self {
        Self {
            zones: HashMap::new(),
            stats: parking_lot::RwLock::new(GeoLoadBalancerStats::default()),
            max_zone_distance,
            enable_cross_zone,
        }
    }

    /// Add a zone
    pub fn add_zone(&mut self, zone: GeoZone) {
        self.zones.insert(zone.id.clone(), zone);
    }

    /// Remove a zone
    pub fn remove_zone(&mut self, zone_id: &str) -> Option<GeoZone> {
        self.zones.remove(zone_id)
    }

    /// Add a node to a zone
    pub fn add_node_to_zone(&mut self, zone_id: &str, node_id: impl Into<String>, latency: f64) {
        if let Some(zone) = self.zones.get_mut(zone_id) {
            zone.add_node(GeoNode::new(node_id, latency));
        }
    }

    /// Add a node with full configuration
    pub fn add_node_to_zone_with_config(&mut self, zone_id: &str, node: GeoNode) -> bool {
        if let Some(zone) = self.zones.get_mut(zone_id) {
            zone.add_node(node);
            true
        } else {
            false
        }
    }

    /// Remove a node from a zone
    pub fn remove_node_from_zone(&mut self, zone_id: &str, node_id: &str) -> bool {
        if let Some(zone) = self.zones.get_mut(zone_id) {
            zone.remove_node(node_id).is_some()
        } else {
            false
        }
    }

    /// Update node load
    pub fn update_node_load(&mut self, zone_id: &str, node_id: &str, load: f64) {
        if let Some(zone) = self.zones.get_mut(zone_id) {
            if let Some(node) = zone.nodes.get_mut(node_id) {
                node.load = load.clamp(0.0, 1.0);
            }
            zone.update_load();
        }
    }

    /// Mark node as healthy or unhealthy
    pub fn set_node_health(&mut self, zone_id: &str, node_id: &str, healthy: bool) {
        if let Some(zone) = self.zones.get_mut(zone_id) {
            if let Some(node) = zone.nodes.get_mut(node_id) {
                node.healthy = healthy;
            }
        }
    }

    /// Select best node for a client location
    pub fn select_node(&self, client_location: &GeoLocation) -> Option<String> {
        // Find nearest zone
        let mut zone_distances: Vec<(&GeoZone, f64)> = self
            .zones
            .values()
            .map(|zone| (zone, client_location.distance_to(&zone.location)))
            .collect();

        zone_distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Try to find a node in the nearest zone
        for (zone, distance) in &zone_distances {
            if *distance > self.max_zone_distance && !self.enable_cross_zone {
                break;
            }

            if let Some(node) = zone.select_node() {
                // Update stats
                let mut stats = self.stats.write();
                stats.total_selections += 1;
                *stats.selections_by_zone.entry(zone.id.clone()).or_insert(0) += 1;
                stats.avg_selection_latency = (stats.avg_selection_latency
                    * (stats.total_selections - 1) as f64
                    + node.latency)
                    / stats.total_selections as f64;

                // Track cross-zone if not nearest
                if zone.id != zone_distances[0].0.id {
                    stats.cross_zone_failovers += 1;
                }

                return Some(node.id.clone());
            }
        }

        // No nodes available
        self.stats.write().failed_selections += 1;
        None
    }

    /// Select multiple nodes for redundancy
    pub fn select_nodes(&self, client_location: &GeoLocation, count: usize) -> Vec<String> {
        let mut selected = Vec::new();
        let mut zone_distances: Vec<(&GeoZone, f64)> = self
            .zones
            .values()
            .map(|zone| (zone, client_location.distance_to(&zone.location)))
            .collect();

        zone_distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        // Collect nodes from zones
        let mut candidates: Vec<(&GeoNode, &str)> = Vec::new();
        for (zone, _) in &zone_distances {
            for node in zone.nodes.values() {
                if node.healthy {
                    candidates.push((node, &zone.id));
                }
            }
        }

        // Sort by score and select top N
        candidates.sort_by(|a, b| a.0.score().partial_cmp(&b.0.score()).unwrap());

        for (node, _) in candidates.iter().take(count) {
            selected.push(node.id.clone());
        }

        selected
    }

    /// Get zone by ID
    pub fn get_zone(&self, zone_id: &str) -> Option<&GeoZone> {
        self.zones.get(zone_id)
    }

    /// Get all zones
    pub fn get_zones(&self) -> Vec<&GeoZone> {
        self.zones.values().collect()
    }

    /// Get nearest zone to a location
    pub fn get_nearest_zone(&self, location: &GeoLocation) -> Option<&GeoZone> {
        self.zones.values().min_by(|a, b| {
            let dist_a = location.distance_to(&a.location);
            let dist_b = location.distance_to(&b.location);
            dist_a.partial_cmp(&dist_b).unwrap()
        })
    }

    /// Get current statistics
    pub fn stats(&self) -> GeoLoadBalancerStats {
        self.stats.read().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        *self.stats.write() = GeoLoadBalancerStats::default();
    }
}

impl Default for GeoLoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geo_location() {
        let loc1 = GeoLocation::new(40.7128, -74.0060); // NYC
        let loc2 = GeoLocation::new(51.5074, -0.1278); // London

        let distance = loc1.distance_to(&loc2);
        assert!(distance > 5500.0 && distance < 5600.0); // ~5570 km
    }

    #[test]
    #[should_panic]
    fn test_invalid_latitude() {
        GeoLocation::new(100.0, 0.0);
    }

    #[test]
    #[should_panic]
    fn test_invalid_longitude() {
        GeoLocation::new(0.0, 200.0);
    }

    #[test]
    fn test_geo_node_score() {
        let node1 = GeoNode::new("node-1", 100.0);
        let mut node2 = GeoNode::new("node-2", 100.0);
        node2.load = 0.5;

        assert!(node1.score() < node2.score());
    }

    #[test]
    fn test_unhealthy_node_score() {
        let mut node = GeoNode::new("node-1", 100.0);
        node.healthy = false;

        assert_eq!(node.score(), f64::MAX);
    }

    #[test]
    fn test_geo_zone() {
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);

        zone.add_node(GeoNode::new("node-1", 100.0));
        zone.add_node(GeoNode::new("node-2", 120.0));

        assert_eq!(zone.nodes.len(), 2);
        assert!(zone.load >= 0.0);
    }

    #[test]
    fn test_zone_select_node() {
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);

        zone.add_node(GeoNode::new("node-1", 100.0));
        zone.add_node(GeoNode::new("node-2", 50.0));

        let selected = zone.select_node().unwrap();
        assert_eq!(selected.id, "node-2"); // Lower latency
    }

    #[test]
    fn test_load_balancer_add_zone() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let zone = GeoZone::new("us-east", location);

        balancer.add_zone(zone);
        assert_eq!(balancer.get_zones().len(), 1);
    }

    #[test]
    fn test_load_balancer_add_node() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let zone = GeoZone::new("us-east", location);

        balancer.add_zone(zone);
        balancer.add_node_to_zone("us-east", "node-1", 100.0);

        let zone = balancer.get_zone("us-east").unwrap();
        assert_eq!(zone.nodes.len(), 1);
    }

    #[test]
    fn test_select_node() {
        let mut balancer = GeoLoadBalancer::new();

        let us_east = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", us_east);
        zone.add_node(GeoNode::new("node-1", 100.0));

        balancer.add_zone(zone);

        let client = GeoLocation::new(40.7589, -73.9851); // NYC
        let selected = balancer.select_node(&client);

        assert_eq!(selected, Some("node-1".to_string()));
    }

    #[test]
    fn test_select_nearest_zone() {
        let mut balancer = GeoLoadBalancer::new();

        let us_east = GeoZone::new("us-east", GeoLocation::new(40.7128, -74.0060));
        let eu_west = GeoZone::new("eu-west", GeoLocation::new(51.5074, -0.1278));

        balancer.add_zone(us_east);
        balancer.add_zone(eu_west);

        let client = GeoLocation::new(40.7589, -73.9851); // NYC
        let nearest = balancer.get_nearest_zone(&client).unwrap();

        assert_eq!(nearest.id, "us-east");
    }

    #[test]
    fn test_select_multiple_nodes() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);

        zone.add_node(GeoNode::new("node-1", 100.0));
        zone.add_node(GeoNode::new("node-2", 120.0));
        zone.add_node(GeoNode::new("node-3", 80.0));

        balancer.add_zone(zone);

        let client = GeoLocation::new(40.7589, -73.9851);
        let selected = balancer.select_nodes(&client, 2);

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], "node-3"); // Lowest latency
    }

    #[test]
    fn test_update_node_load() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);
        zone.add_node(GeoNode::new("node-1", 100.0));

        balancer.add_zone(zone);
        balancer.update_node_load("us-east", "node-1", 0.75);

        let zone = balancer.get_zone("us-east").unwrap();
        let node = zone.nodes.get("node-1").unwrap();
        assert_eq!(node.load, 0.75);
    }

    #[test]
    fn test_set_node_health() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);
        zone.add_node(GeoNode::new("node-1", 100.0));

        balancer.add_zone(zone);
        balancer.set_node_health("us-east", "node-1", false);

        let client = GeoLocation::new(40.7589, -73.9851);
        let selected = balancer.select_node(&client);

        assert_eq!(selected, None); // Node is unhealthy
    }

    #[test]
    fn test_cross_zone_failover() {
        let mut balancer = GeoLoadBalancer::new();

        let mut us_east = GeoZone::new("us-east", GeoLocation::new(40.7128, -74.0060));
        us_east.add_node(GeoNode::new("node-1", 100.0));

        let mut eu_west = GeoZone::new("eu-west", GeoLocation::new(51.5074, -0.1278));
        eu_west.add_node(GeoNode::new("node-2", 200.0));

        balancer.add_zone(us_east);
        balancer.add_zone(eu_west);

        // Make US node unhealthy
        balancer.set_node_health("us-east", "node-1", false);

        let client = GeoLocation::new(40.7589, -73.9851); // NYC
        let selected = balancer.select_node(&client);

        // Should failover to EU node
        assert_eq!(selected, Some("node-2".to_string()));

        let stats = balancer.stats();
        assert_eq!(stats.cross_zone_failovers, 1);
    }

    #[test]
    fn test_stats() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);
        zone.add_node(GeoNode::new("node-1", 100.0));

        balancer.add_zone(zone);

        let client = GeoLocation::new(40.7589, -73.9851);
        balancer.select_node(&client);
        balancer.select_node(&client);

        let stats = balancer.stats();
        assert_eq!(stats.total_selections, 2);
        assert_eq!(stats.avg_selection_latency, 100.0);
    }

    #[test]
    fn test_reset_stats() {
        let mut balancer = GeoLoadBalancer::new();
        let location = GeoLocation::new(40.7128, -74.0060);
        let mut zone = GeoZone::new("us-east", location);
        zone.add_node(GeoNode::new("node-1", 100.0));

        balancer.add_zone(zone);

        let client = GeoLocation::new(40.7589, -73.9851);
        balancer.select_node(&client);

        balancer.reset_stats();
        let stats = balancer.stats();
        assert_eq!(stats.total_selections, 0);
    }
}
