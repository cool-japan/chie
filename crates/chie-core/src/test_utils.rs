//! Test utilities and helpers for testing.
//!
//! This module provides helpers and utilities to simplify writing tests
//! across the CHIE codebase.
//!
//! # Example
//!
//! ```rust
//! use chie_core::test_utils::{MockPeerBuilder, random_cid, TempDir};
//!
//! // Create mock peer
//! let peer = MockPeerBuilder::new("peer1")
//!     .with_reputation(0.8)
//!     .build();
//!
//! // Generate random test data
//! let cid = random_cid();
//! let temp_dir = TempDir::new("test").unwrap();
//! ```

use std::path::PathBuf;

/// Builder for creating mock peer data.
#[derive(Debug, Clone)]
pub struct MockPeerBuilder {
    peer_id: String,
    reputation_score: f64,
    latency_ms: f64,
    bandwidth_bps: u64,
    is_online: bool,
}

impl MockPeerBuilder {
    /// Create a new mock peer builder.
    #[inline]
    pub fn new(peer_id: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            reputation_score: 0.5,
            latency_ms: 50.0,
            bandwidth_bps: 10 * 1024 * 1024, // 10 Mbps
            is_online: true,
        }
    }

    /// Set the reputation score.
    #[inline]
    pub fn with_reputation(mut self, score: f64) -> Self {
        self.reputation_score = score.clamp(0.0, 1.0);
        self
    }

    /// Set the latency in milliseconds.
    #[inline]
    pub fn with_latency(mut self, latency_ms: f64) -> Self {
        self.latency_ms = latency_ms;
        self
    }

    /// Set the bandwidth in bytes per second.
    #[inline]
    pub fn with_bandwidth(mut self, bandwidth_bps: u64) -> Self {
        self.bandwidth_bps = bandwidth_bps;
        self
    }

    /// Set online status.
    #[inline]
    pub fn online(mut self, is_online: bool) -> Self {
        self.is_online = is_online;
        self
    }

    /// Build the peer data.
    #[inline]
    pub fn build(self) -> MockPeer {
        MockPeer {
            peer_id: self.peer_id,
            reputation_score: self.reputation_score,
            latency_ms: self.latency_ms,
            bandwidth_bps: self.bandwidth_bps,
            is_online: self.is_online,
        }
    }
}

/// Mock peer data.
#[derive(Debug, Clone)]
pub struct MockPeer {
    /// Peer identifier.
    pub peer_id: String,
    /// Reputation score (0.0 to 1.0).
    pub reputation_score: f64,
    /// Latency in milliseconds.
    pub latency_ms: f64,
    /// Bandwidth in bytes per second.
    pub bandwidth_bps: u64,
    /// Online status.
    pub is_online: bool,
}

/// Helper for creating temporary test directories.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a new temporary directory.
    pub fn new(prefix: &str) -> std::io::Result<Self> {
        let path =
            std::env::temp_dir().join(format!("chie-test-{}-{}", prefix, rand::random::<u64>()));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Get the path to the temporary directory.
    #[inline]
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Get the path as a string.
    #[inline]
    pub fn path_str(&self) -> &str {
        self.path.to_str().unwrap()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Generate a random CID for testing.
#[inline]
pub fn random_cid() -> String {
    format!("Qm{:x}", rand::random::<u128>())
}

/// Generate a random peer ID for testing.
#[inline]
pub fn random_peer_id() -> String {
    format!("peer-{:x}", rand::random::<u64>())
}

/// Generate random bytes for testing.
pub fn random_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|_| rand::random::<u8>()).collect()
}

/// Assert that two floats are approximately equal.
#[inline]
pub fn assert_approx_eq(a: f64, b: f64, epsilon: f64) {
    assert!(
        (a - b).abs() < epsilon,
        "Expected {} ≈ {}, diff: {}",
        a,
        b,
        (a - b).abs()
    );
}

/// Mock configuration for testing.
pub struct MockConfig;

impl MockConfig {
    /// Create a minimal storage configuration.
    #[inline]
    pub fn storage() -> crate::config::StorageSettings {
        crate::config::StorageSettings::new(
            PathBuf::from("/tmp/chie-test"),
            10 * 1024 * 1024 * 1024, // 10 GB
        )
    }

    /// Create a minimal network configuration.
    #[inline]
    pub fn network() -> crate::config::NetworkSettings {
        crate::config::NetworkSettings::new(100 * 1024 * 1024 / 8) // 100 Mbps
    }

    /// Create a minimal coordinator configuration.
    #[inline]
    pub fn coordinator() -> crate::config::CoordinatorSettings {
        crate::config::CoordinatorSettings::new("http://localhost:8080".to_string())
    }

    /// Create a complete node settings for testing.
    #[inline]
    pub fn node_settings() -> crate::config::NodeSettings {
        crate::config::NodeSettings {
            storage: Self::storage(),
            network: Self::network(),
            coordinator: Self::coordinator(),
            performance: crate::config::PerformanceSettings::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_peer_builder() {
        let peer = MockPeerBuilder::new("peer1")
            .with_reputation(0.8)
            .with_latency(100.0)
            .build();

        assert_eq!(peer.peer_id, "peer1");
        assert_eq!(peer.reputation_score, 0.8);
        assert_eq!(peer.latency_ms, 100.0);
    }

    #[test]
    fn test_mock_peer_reputation_clamping() {
        let peer = MockPeerBuilder::new("peer1").with_reputation(1.5).build();
        assert_eq!(peer.reputation_score, 1.0);

        let peer = MockPeerBuilder::new("peer2").with_reputation(-0.5).build();
        assert_eq!(peer.reputation_score, 0.0);
    }

    #[test]
    fn test_temp_dir_creation() {
        let temp = TempDir::new("test").unwrap();
        assert!(temp.path().exists());
        assert!(temp.path().is_dir());
    }

    #[test]
    fn test_temp_dir_cleanup() {
        let path = {
            let temp = TempDir::new("cleanup").unwrap();
            temp.path().clone()
        };
        // After drop, directory should be removed
        assert!(!path.exists());
    }

    #[test]
    fn test_random_cid() {
        let cid1 = random_cid();
        let cid2 = random_cid();

        assert!(cid1.starts_with("Qm"));
        assert_ne!(cid1, cid2); // Should be different
    }

    #[test]
    fn test_random_peer_id() {
        let peer1 = random_peer_id();
        let peer2 = random_peer_id();

        assert!(peer1.starts_with("peer-"));
        assert_ne!(peer1, peer2);
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(100);
        assert_eq!(bytes.len(), 100);
    }

    #[test]
    fn test_assert_approx_eq() {
        assert_approx_eq(1.0, 1.0001, 0.001);
        assert_approx_eq(0.5, 0.499, 0.01);
    }

    #[test]
    #[should_panic]
    fn test_assert_approx_eq_fails() {
        assert_approx_eq(1.0, 2.0, 0.001);
    }

    #[test]
    fn test_mock_config_storage() {
        let storage = MockConfig::storage();
        assert_eq!(storage.max_bytes, 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_mock_config_node_settings() {
        let settings = MockConfig::node_settings();
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn test_mock_peer_online_status() {
        let peer = MockPeerBuilder::new("peer1").online(false).build();
        assert!(!peer.is_online);

        let peer = MockPeerBuilder::new("peer2").online(true).build();
        assert!(peer.is_online);
    }
}
