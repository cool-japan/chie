//! Protocol upgrade negotiation for seamless protocol transitions.
//!
//! This module provides mechanisms for negotiating protocol upgrades between peers,
//! allowing the network to evolve while maintaining backward compatibility.

use chie_shared::{ChieError, ChieResult};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Protocol identifier
pub type ProtocolId = String;

/// Protocol version (major.minor.patch)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ProtocolVersion {
    /// Create new protocol version
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Check if this version is compatible with another (same major version)
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Check if this version is newer than another
    pub fn is_newer_than(&self, other: &Self) -> bool {
        if self.major != other.major {
            self.major > other.major
        } else if self.minor != other.minor {
            self.minor > other.minor
        } else {
            self.patch > other.patch
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl std::str::FromStr for ProtocolVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid version format".to_string());
        }

        Ok(Self {
            major: parts[0]
                .parse()
                .map_err(|_| "Invalid major version".to_string())?,
            minor: parts[1]
                .parse()
                .map_err(|_| "Invalid minor version".to_string())?,
            patch: parts[2]
                .parse()
                .map_err(|_| "Invalid patch version".to_string())?,
        })
    }
}

/// Protocol capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Protocol ID
    pub protocol_id: ProtocolId,
    /// Protocol version
    pub version: ProtocolVersion,
    /// Supported features
    pub features: HashSet<String>,
    /// Optional metadata
    pub metadata: HashMap<String, String>,
}

/// Upgrade request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRequest {
    /// Current protocol
    pub current_protocol: ProtocolId,
    /// Current version
    pub current_version: ProtocolVersion,
    /// Target protocol
    pub target_protocol: ProtocolId,
    /// Target version
    pub target_version: ProtocolVersion,
    /// Required features
    pub required_features: HashSet<String>,
}

/// Upgrade response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeResponse {
    /// Whether upgrade is accepted
    pub accepted: bool,
    /// Negotiated protocol
    pub protocol_id: Option<ProtocolId>,
    /// Negotiated version
    pub version: Option<ProtocolVersion>,
    /// Available features
    pub features: HashSet<String>,
    /// Reason if rejected
    pub reason: Option<String>,
}

/// Upgrade state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeState {
    /// No upgrade in progress
    Idle,
    /// Upgrade requested
    Requested,
    /// Upgrade negotiating
    Negotiating,
    /// Upgrade in progress
    InProgress,
    /// Upgrade completed
    Completed,
    /// Upgrade failed
    Failed,
}

/// Peer upgrade status
#[derive(Debug, Clone)]
struct PeerUpgradeStatus {
    /// Current protocol
    current_protocol: ProtocolId,
    /// Current version
    current_version: ProtocolVersion,
    /// Upgrade state
    state: UpgradeState,
    /// Target protocol (if upgrading)
    target_protocol: Option<ProtocolId>,
    /// Target version (if upgrading)
    target_version: Option<ProtocolVersion>,
    /// Last state change
    last_update: Instant,
    /// Upgrade attempts
    attempts: u32,
}

/// Protocol upgrade manager
pub struct ProtocolUpgradeManager {
    /// Supported protocols
    protocols: Arc<RwLock<HashMap<ProtocolId, ProtocolCapabilities>>>,
    /// Peer upgrade status
    peer_status: Arc<RwLock<HashMap<String, PeerUpgradeStatus>>>,
    /// Configuration
    config: UpgradeConfig,
    /// Statistics
    stats: Arc<RwLock<UpgradeStats>>,
}

/// Upgrade configuration
#[derive(Debug, Clone)]
pub struct UpgradeConfig {
    /// Maximum upgrade attempts per peer
    pub max_attempts: u32,
    /// Upgrade timeout
    pub upgrade_timeout: Duration,
    /// Allow downgrades
    pub allow_downgrades: bool,
    /// Require all features
    pub require_all_features: bool,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            upgrade_timeout: Duration::from_secs(30),
            allow_downgrades: false,
            require_all_features: false,
        }
    }
}

/// Upgrade statistics
#[derive(Debug, Clone, Default)]
pub struct UpgradeStats {
    /// Total upgrade requests
    pub total_requests: u64,
    /// Successful upgrades
    pub successful_upgrades: u64,
    /// Failed upgrades
    pub failed_upgrades: u64,
    /// Active upgrades
    pub active_upgrades: u64,
    /// Rejected upgrades
    pub rejected_upgrades: u64,
}

impl ProtocolUpgradeManager {
    /// Create new protocol upgrade manager
    pub fn new(config: UpgradeConfig) -> Self {
        Self {
            protocols: Arc::new(RwLock::new(HashMap::new())),
            peer_status: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: Arc::new(RwLock::new(UpgradeStats::default())),
        }
    }

    /// Register a protocol
    pub fn register_protocol(&self, capabilities: ProtocolCapabilities) -> ChieResult<()> {
        let mut protocols = self.protocols.write();
        protocols.insert(capabilities.protocol_id.clone(), capabilities);
        Ok(())
    }

    /// Get protocol capabilities
    pub fn get_protocol(&self, protocol_id: &str) -> Option<ProtocolCapabilities> {
        let protocols = self.protocols.read();
        protocols.get(protocol_id).cloned()
    }

    /// Create upgrade request
    pub fn create_upgrade_request(
        &self,
        peer_id: &str,
        current_protocol: ProtocolId,
        current_version: ProtocolVersion,
        target_protocol: ProtocolId,
        target_version: ProtocolVersion,
        required_features: HashSet<String>,
    ) -> ChieResult<UpgradeRequest> {
        let mut peer_status = self.peer_status.write();
        let mut stats = self.stats.write();

        // Check if peer has too many attempts
        if let Some(status) = peer_status.get(peer_id) {
            if status.attempts >= self.config.max_attempts {
                return Err(ChieError::resource_exhausted(
                    "Maximum upgrade attempts reached",
                ));
            }
        }

        // Verify target protocol exists
        let protocols = self.protocols.read();
        if !protocols.contains_key(&target_protocol) {
            return Err(ChieError::not_found("Target protocol not registered"));
        }

        // Create request
        let request = UpgradeRequest {
            current_protocol: current_protocol.clone(),
            current_version: current_version.clone(),
            target_protocol: target_protocol.clone(),
            target_version: target_version.clone(),
            required_features,
        };

        // Update peer status
        let status = peer_status
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerUpgradeStatus {
                current_protocol: current_protocol.clone(),
                current_version: current_version.clone(),
                state: UpgradeState::Idle,
                target_protocol: None,
                target_version: None,
                last_update: Instant::now(),
                attempts: 0,
            });

        status.state = UpgradeState::Requested;
        status.target_protocol = Some(target_protocol);
        status.target_version = Some(target_version);
        status.last_update = Instant::now();
        status.attempts += 1;

        stats.total_requests += 1;
        stats.active_upgrades += 1;

        Ok(request)
    }

    /// Handle upgrade request from peer
    pub fn handle_upgrade_request(
        &self,
        peer_id: &str,
        request: UpgradeRequest,
    ) -> ChieResult<UpgradeResponse> {
        let protocols = self.protocols.read();

        // Check if target protocol is supported
        let target_protocol = match protocols.get(&request.target_protocol) {
            Some(p) => p,
            None => {
                let mut stats = self.stats.write();
                stats.rejected_upgrades += 1;
                return Ok(UpgradeResponse {
                    accepted: false,
                    protocol_id: None,
                    version: None,
                    features: HashSet::new(),
                    reason: Some("Protocol not supported".to_string()),
                });
            }
        };

        // Check version compatibility
        if !target_protocol
            .version
            .is_compatible_with(&request.target_version)
        {
            let mut stats = self.stats.write();
            stats.rejected_upgrades += 1;
            return Ok(UpgradeResponse {
                accepted: false,
                protocol_id: None,
                version: None,
                features: HashSet::new(),
                reason: Some("Version not compatible".to_string()),
            });
        }

        // Check if it's a downgrade
        if !self.config.allow_downgrades
            && !request
                .target_version
                .is_newer_than(&request.current_version)
            && request.target_version != request.current_version
        {
            let mut stats = self.stats.write();
            stats.rejected_upgrades += 1;
            return Ok(UpgradeResponse {
                accepted: false,
                protocol_id: None,
                version: None,
                features: HashSet::new(),
                reason: Some("Downgrades not allowed".to_string()),
            });
        }

        // Check required features
        let missing_features: HashSet<_> = request
            .required_features
            .difference(&target_protocol.features)
            .collect();

        if !missing_features.is_empty() && self.config.require_all_features {
            let mut stats = self.stats.write();
            stats.rejected_upgrades += 1;
            return Ok(UpgradeResponse {
                accepted: false,
                protocol_id: None,
                version: None,
                features: target_protocol.features.clone(),
                reason: Some(format!("Missing required features: {:?}", missing_features)),
            });
        }

        // Accept upgrade
        let mut peer_status = self.peer_status.write();
        let status = peer_status
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerUpgradeStatus {
                current_protocol: request.current_protocol.clone(),
                current_version: request.current_version.clone(),
                state: UpgradeState::Idle,
                target_protocol: None,
                target_version: None,
                last_update: Instant::now(),
                attempts: 0,
            });

        status.state = UpgradeState::Negotiating;
        status.target_protocol = Some(request.target_protocol.clone());
        status.target_version = Some(request.target_version.clone());
        status.last_update = Instant::now();

        Ok(UpgradeResponse {
            accepted: true,
            protocol_id: Some(request.target_protocol),
            version: Some(request.target_version),
            features: target_protocol.features.clone(),
            reason: None,
        })
    }

    /// Confirm upgrade completed
    pub fn confirm_upgrade(&self, peer_id: &str, success: bool) -> ChieResult<()> {
        let mut peer_status = self.peer_status.write();
        let mut stats = self.stats.write();

        let status = peer_status
            .get_mut(peer_id)
            .ok_or_else(|| ChieError::not_found("Peer not found"))?;

        if success {
            if let (Some(target_protocol), Some(target_version)) =
                (&status.target_protocol, &status.target_version)
            {
                status.current_protocol = target_protocol.clone();
                status.current_version = target_version.clone();
                status.state = UpgradeState::Completed;
                status.target_protocol = None;
                status.target_version = None;
                status.attempts = 0;

                stats.successful_upgrades += 1;
                stats.active_upgrades = stats.active_upgrades.saturating_sub(1);
            }
        } else {
            status.state = UpgradeState::Failed;
            stats.failed_upgrades += 1;
            stats.active_upgrades = stats.active_upgrades.saturating_sub(1);
        }

        status.last_update = Instant::now();

        Ok(())
    }

    /// Get peer upgrade state
    pub fn get_peer_state(&self, peer_id: &str) -> Option<UpgradeState> {
        let peer_status = self.peer_status.read();
        peer_status.get(peer_id).map(|s| s.state)
    }

    /// Get peer current protocol
    pub fn get_peer_protocol(&self, peer_id: &str) -> Option<(ProtocolId, ProtocolVersion)> {
        let peer_status = self.peer_status.read();
        peer_status
            .get(peer_id)
            .map(|s| (s.current_protocol.clone(), s.current_version.clone()))
    }

    /// Clean up timed-out upgrades
    pub fn cleanup_timeouts(&self) -> usize {
        let mut peer_status = self.peer_status.write();
        let mut stats = self.stats.write();
        let now = Instant::now();
        let mut cleaned = 0;

        for (_, status) in peer_status.iter_mut() {
            if matches!(
                status.state,
                UpgradeState::Requested | UpgradeState::Negotiating | UpgradeState::InProgress
            ) && now.duration_since(status.last_update) > self.config.upgrade_timeout
            {
                status.state = UpgradeState::Failed;
                stats.failed_upgrades += 1;
                stats.active_upgrades = stats.active_upgrades.saturating_sub(1);
                cleaned += 1;
            }
        }

        cleaned
    }

    /// Get statistics
    pub fn stats(&self) -> UpgradeStats {
        self.stats.read().clone()
    }

    /// Get registered protocol count
    pub fn protocol_count(&self) -> usize {
        self.protocols.read().len()
    }

    /// Get all registered protocols
    pub fn get_all_protocols(&self) -> Vec<ProtocolCapabilities> {
        self.protocols.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_protocol(
        id: &str,
        version: ProtocolVersion,
        features: Vec<&str>,
    ) -> ProtocolCapabilities {
        ProtocolCapabilities {
            protocol_id: id.to_string(),
            version,
            features: features.iter().map(|s| s.to_string()).collect(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_protocol_version_parsing() {
        let v: ProtocolVersion = "1.2.3".parse().unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v2 = ProtocolVersion::new(1, 2, 0);
        let v3 = ProtocolVersion::new(2, 0, 0);

        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v2 = ProtocolVersion::new(1, 2, 0);
        let v3 = ProtocolVersion::new(2, 0, 0);

        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));
        assert!(!v1.is_newer_than(&v2));
    }

    #[test]
    fn test_register_protocol() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol =
            create_test_protocol("chie", ProtocolVersion::new(1, 0, 0), vec!["compression"]);

        assert!(manager.register_protocol(protocol.clone()).is_ok());
        assert_eq!(manager.protocol_count(), 1);

        let retrieved = manager.get_protocol("chie").unwrap();
        assert_eq!(retrieved.protocol_id, "chie");
    }

    #[test]
    fn test_create_upgrade_request() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol =
            create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec!["compression"]);
        manager.register_protocol(protocol).unwrap();

        let request = manager
            .create_upgrade_request(
                "peer1",
                "chie".to_string(),
                ProtocolVersion::new(1, 0, 0),
                "chie".to_string(),
                ProtocolVersion::new(2, 0, 0),
                HashSet::new(),
            )
            .unwrap();

        assert_eq!(request.target_protocol, "chie");
        assert_eq!(request.target_version, ProtocolVersion::new(2, 0, 0));
    }

    #[test]
    fn test_handle_upgrade_request_success() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol = create_test_protocol(
            "chie",
            ProtocolVersion::new(2, 0, 0),
            vec!["compression", "encryption"],
        );
        manager.register_protocol(protocol).unwrap();

        let request = UpgradeRequest {
            current_protocol: "chie".to_string(),
            current_version: ProtocolVersion::new(1, 0, 0),
            target_protocol: "chie".to_string(),
            target_version: ProtocolVersion::new(2, 0, 0),
            required_features: vec!["compression".to_string()].into_iter().collect(),
        };

        let response = manager.handle_upgrade_request("peer1", request).unwrap();
        assert!(response.accepted);
        assert_eq!(response.protocol_id.unwrap(), "chie");
    }

    #[test]
    fn test_handle_upgrade_request_unsupported_protocol() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());

        let request = UpgradeRequest {
            current_protocol: "chie".to_string(),
            current_version: ProtocolVersion::new(1, 0, 0),
            target_protocol: "unknown".to_string(),
            target_version: ProtocolVersion::new(2, 0, 0),
            required_features: HashSet::new(),
        };

        let response = manager.handle_upgrade_request("peer1", request).unwrap();
        assert!(!response.accepted);
        assert!(response.reason.is_some());
    }

    #[test]
    fn test_handle_upgrade_request_missing_features() {
        let config = UpgradeConfig {
            require_all_features: true,
            ..Default::default()
        };
        let manager = ProtocolUpgradeManager::new(config);
        let protocol =
            create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec!["compression"]);
        manager.register_protocol(protocol).unwrap();

        let request = UpgradeRequest {
            current_protocol: "chie".to_string(),
            current_version: ProtocolVersion::new(1, 0, 0),
            target_protocol: "chie".to_string(),
            target_version: ProtocolVersion::new(2, 0, 0),
            required_features: vec!["compression".to_string(), "encryption".to_string()]
                .into_iter()
                .collect(),
        };

        let response = manager.handle_upgrade_request("peer1", request).unwrap();
        assert!(!response.accepted);
    }

    #[test]
    fn test_downgrade_rejection() {
        let config = UpgradeConfig {
            allow_downgrades: false,
            ..Default::default()
        };
        let manager = ProtocolUpgradeManager::new(config);
        let protocol = create_test_protocol("chie", ProtocolVersion::new(1, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        let request = UpgradeRequest {
            current_protocol: "chie".to_string(),
            current_version: ProtocolVersion::new(2, 0, 0),
            target_protocol: "chie".to_string(),
            target_version: ProtocolVersion::new(1, 0, 0),
            required_features: HashSet::new(),
        };

        let response = manager.handle_upgrade_request("peer1", request).unwrap();
        assert!(!response.accepted);
    }

    #[test]
    fn test_downgrade_allowed() {
        let config = UpgradeConfig {
            allow_downgrades: true,
            ..Default::default()
        };
        let manager = ProtocolUpgradeManager::new(config);
        let protocol = create_test_protocol("chie", ProtocolVersion::new(1, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        let request = UpgradeRequest {
            current_protocol: "chie".to_string(),
            current_version: ProtocolVersion::new(2, 0, 0),
            target_protocol: "chie".to_string(),
            target_version: ProtocolVersion::new(1, 0, 0),
            required_features: HashSet::new(),
        };

        let response = manager.handle_upgrade_request("peer1", request).unwrap();
        assert!(response.accepted);
    }

    #[test]
    fn test_confirm_upgrade_success() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol = create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        manager
            .create_upgrade_request(
                "peer1",
                "chie".to_string(),
                ProtocolVersion::new(1, 0, 0),
                "chie".to_string(),
                ProtocolVersion::new(2, 0, 0),
                HashSet::new(),
            )
            .unwrap();

        assert!(manager.confirm_upgrade("peer1", true).is_ok());

        let (protocol, version) = manager.get_peer_protocol("peer1").unwrap();
        assert_eq!(protocol, "chie");
        assert_eq!(version, ProtocolVersion::new(2, 0, 0));
    }

    #[test]
    fn test_confirm_upgrade_failure() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol = create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        manager
            .create_upgrade_request(
                "peer1",
                "chie".to_string(),
                ProtocolVersion::new(1, 0, 0),
                "chie".to_string(),
                ProtocolVersion::new(2, 0, 0),
                HashSet::new(),
            )
            .unwrap();

        assert!(manager.confirm_upgrade("peer1", false).is_ok());
        assert_eq!(
            manager.get_peer_state("peer1").unwrap(),
            UpgradeState::Failed
        );
    }

    #[test]
    fn test_max_attempts() {
        let config = UpgradeConfig {
            max_attempts: 2,
            ..Default::default()
        };
        let manager = ProtocolUpgradeManager::new(config);
        let protocol = create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        // First attempt
        assert!(
            manager
                .create_upgrade_request(
                    "peer1",
                    "chie".to_string(),
                    ProtocolVersion::new(1, 0, 0),
                    "chie".to_string(),
                    ProtocolVersion::new(2, 0, 0),
                    HashSet::new(),
                )
                .is_ok()
        );

        manager.confirm_upgrade("peer1", false).unwrap();

        // Second attempt
        assert!(
            manager
                .create_upgrade_request(
                    "peer1",
                    "chie".to_string(),
                    ProtocolVersion::new(1, 0, 0),
                    "chie".to_string(),
                    ProtocolVersion::new(2, 0, 0),
                    HashSet::new(),
                )
                .is_ok()
        );

        manager.confirm_upgrade("peer1", false).unwrap();

        // Third attempt should fail (max 2)
        assert!(
            manager
                .create_upgrade_request(
                    "peer1",
                    "chie".to_string(),
                    ProtocolVersion::new(1, 0, 0),
                    "chie".to_string(),
                    ProtocolVersion::new(2, 0, 0),
                    HashSet::new(),
                )
                .is_err()
        );
    }

    #[test]
    fn test_cleanup_timeouts() {
        let config = UpgradeConfig {
            upgrade_timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let manager = ProtocolUpgradeManager::new(config);
        let protocol = create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        manager
            .create_upgrade_request(
                "peer1",
                "chie".to_string(),
                ProtocolVersion::new(1, 0, 0),
                "chie".to_string(),
                ProtocolVersion::new(2, 0, 0),
                HashSet::new(),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let cleaned = manager.cleanup_timeouts();
        assert_eq!(cleaned, 1);
        assert_eq!(
            manager.get_peer_state("peer1").unwrap(),
            UpgradeState::Failed
        );
    }

    #[test]
    fn test_stats_tracking() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol = create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec![]);
        manager.register_protocol(protocol).unwrap();

        manager
            .create_upgrade_request(
                "peer1",
                "chie".to_string(),
                ProtocolVersion::new(1, 0, 0),
                "chie".to_string(),
                ProtocolVersion::new(2, 0, 0),
                HashSet::new(),
            )
            .unwrap();

        manager.confirm_upgrade("peer1", true).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total_requests, 1);
        assert_eq!(stats.successful_upgrades, 1);
    }

    #[test]
    fn test_get_all_protocols() {
        let manager = ProtocolUpgradeManager::new(UpgradeConfig::default());
        let protocol1 = create_test_protocol("chie", ProtocolVersion::new(1, 0, 0), vec![]);
        let protocol2 = create_test_protocol("chie", ProtocolVersion::new(2, 0, 0), vec![]);

        manager.register_protocol(protocol1).unwrap();
        manager.register_protocol(protocol2).unwrap();

        let protocols = manager.get_all_protocols();
        assert_eq!(protocols.len(), 1); // Same ID, so only one
    }
}
