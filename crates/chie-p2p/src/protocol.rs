//! Protocol versioning and negotiation for CHIE P2P.
//!
//! This module provides:
//! - Protocol version definitions
//! - Version negotiation between peers
//! - Backward compatibility handling
//! - Upgrade path management
//! - Feature flags and deprecation tracking

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

/// Current protocol version.
pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0, 0);

/// Minimum supported protocol version.
pub const MIN_SUPPORTED_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0, 0);

/// Protocol version following semantic versioning.
///
/// # Examples
///
/// ```
/// use chie_p2p::{ProtocolVersion, CURRENT_VERSION};
///
/// let v1 = ProtocolVersion::new(1, 2, 3);
/// let v2 = ProtocolVersion::parse("1.2.3").unwrap();
/// assert_eq!(v1, v2);
///
/// // Check compatibility
/// let newer = ProtocolVersion::new(1, 3, 0);
/// assert!(newer.is_compatible_with(&v1));
///
/// // Get protocol string
/// assert_eq!(v1.protocol_string(), "/chie/bandwidth-proof/1.2.3");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version (breaking changes).
    pub major: u16,
    /// Minor version (new features, backward compatible).
    pub minor: u16,
    /// Patch version (bug fixes).
    pub patch: u16,
}

impl ProtocolVersion {
    /// Create a new protocol version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Parse from string (e.g., "1.2.3").
    pub fn parse(s: &str) -> Result<Self, VersionParseError> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(VersionParseError::InvalidFormat);
        }

        let major = parts[0]
            .parse()
            .map_err(|_| VersionParseError::InvalidNumber)?;
        let minor = parts[1]
            .parse()
            .map_err(|_| VersionParseError::InvalidNumber)?;
        let patch = parts[2]
            .parse()
            .map_err(|_| VersionParseError::InvalidNumber)?;

        Ok(Self::new(major, minor, patch))
    }

    /// Check if this version is compatible with another.
    /// Compatible means same major version and this version >= other.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && *self >= *other
    }

    /// Check if this version can communicate with another.
    /// This is true if both versions are within the supported range.
    pub fn can_communicate_with(&self, other: &Self) -> bool {
        other.major == self.major && *other >= MIN_SUPPORTED_VERSION
    }

    /// Get the protocol string for libp2p.
    pub fn protocol_string(&self) -> String {
        format!(
            "/chie/bandwidth-proof/{}.{}.{}",
            self.major, self.minor, self.patch
        )
    }

    /// Get the protocol string prefix for version negotiation.
    pub fn protocol_prefix() -> &'static str {
        "/chie/bandwidth-proof/"
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        CURRENT_VERSION
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Version parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionParseError {
    /// Invalid format (expected x.y.z).
    InvalidFormat,
    /// Invalid number in version.
    InvalidNumber,
}

impl std::fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionParseError::InvalidFormat => {
                write!(f, "Invalid version format (expected x.y.z)")
            }
            VersionParseError::InvalidNumber => write!(f, "Invalid number in version"),
        }
    }
}

impl std::error::Error for VersionParseError {}

/// Version negotiation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRequest {
    /// Versions we support (in order of preference).
    pub supported_versions: Vec<ProtocolVersion>,
    /// Our current version.
    pub current_version: ProtocolVersion,
    /// Node capabilities/features.
    pub capabilities: NodeCapabilities,
}

impl Default for VersionRequest {
    fn default() -> Self {
        Self {
            supported_versions: vec![CURRENT_VERSION],
            current_version: CURRENT_VERSION,
            capabilities: NodeCapabilities::default(),
        }
    }
}

/// Version negotiation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    /// Selected version for communication.
    pub selected_version: Option<ProtocolVersion>,
    /// Whether negotiation was successful.
    pub success: bool,
    /// Reason for failure (if any).
    pub error: Option<String>,
    /// Our capabilities.
    pub capabilities: NodeCapabilities,
}

/// Node capabilities and features.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Supports chunk streaming.
    pub streaming: bool,
    /// Supports compression.
    pub compression: bool,
    /// Supports encryption.
    pub encryption: bool,
    /// Supports relay connections.
    pub relay: bool,
    /// Maximum chunk size supported (bytes).
    pub max_chunk_size: u64,
    /// Supported encryption algorithms.
    pub encryption_algorithms: Vec<String>,
}

impl NodeCapabilities {
    /// Create capabilities with all features enabled.
    pub fn full() -> Self {
        Self {
            streaming: true,
            compression: true,
            encryption: true,
            relay: true,
            max_chunk_size: 16 * 1024 * 1024, // 16 MB
            encryption_algorithms: vec!["chacha20-poly1305".to_string()],
        }
    }

    /// Check if two capability sets are compatible.
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        // At minimum, both must support encryption
        if !self.encryption || !other.encryption {
            return false;
        }

        // Must have at least one common encryption algorithm
        self.encryption_algorithms
            .iter()
            .any(|alg| other.encryption_algorithms.contains(alg))
    }

    /// Get common capabilities between two nodes.
    pub fn common_with(&self, other: &Self) -> Self {
        Self {
            streaming: self.streaming && other.streaming,
            compression: self.compression && other.compression,
            encryption: self.encryption && other.encryption,
            relay: self.relay && other.relay,
            max_chunk_size: self.max_chunk_size.min(other.max_chunk_size),
            encryption_algorithms: self
                .encryption_algorithms
                .iter()
                .filter(|alg| other.encryption_algorithms.contains(alg))
                .cloned()
                .collect(),
        }
    }
}

/// Version negotiator.
pub struct VersionNegotiator {
    /// Our supported versions.
    supported_versions: Vec<ProtocolVersion>,
    /// Our capabilities.
    capabilities: NodeCapabilities,
}

impl Default for VersionNegotiator {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionNegotiator {
    /// Create a new version negotiator.
    pub fn new() -> Self {
        Self {
            supported_versions: vec![CURRENT_VERSION],
            capabilities: NodeCapabilities::full(),
        }
    }

    /// Create with custom supported versions.
    pub fn with_versions(versions: Vec<ProtocolVersion>) -> Self {
        Self {
            supported_versions: versions,
            capabilities: NodeCapabilities::full(),
        }
    }

    /// Set capabilities.
    pub fn with_capabilities(mut self, capabilities: NodeCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Create a version request.
    pub fn create_request(&self) -> VersionRequest {
        VersionRequest {
            supported_versions: self.supported_versions.clone(),
            current_version: CURRENT_VERSION,
            capabilities: self.capabilities.clone(),
        }
    }

    /// Handle an incoming version request.
    pub fn handle_request(&self, request: &VersionRequest) -> VersionResponse {
        // Find the highest common version
        let mut common_versions: Vec<&ProtocolVersion> = request
            .supported_versions
            .iter()
            .filter(|v| self.supported_versions.iter().any(|our_v| our_v == *v))
            .collect();

        common_versions.sort_by(|a, b| b.cmp(a)); // Descending order

        match common_versions.first() {
            Some(&version) => {
                // Check capability compatibility
                if !self.capabilities.is_compatible_with(&request.capabilities) {
                    return VersionResponse {
                        selected_version: None,
                        success: false,
                        error: Some("Incompatible capabilities".to_string()),
                        capabilities: self.capabilities.clone(),
                    };
                }

                VersionResponse {
                    selected_version: Some(*version),
                    success: true,
                    error: None,
                    capabilities: self.capabilities.clone(),
                }
            }
            None => VersionResponse {
                selected_version: None,
                success: false,
                error: Some(format!(
                    "No common protocol version found. Our versions: {:?}, their versions: {:?}",
                    self.supported_versions, request.supported_versions
                )),
                capabilities: self.capabilities.clone(),
            },
        }
    }

    /// Get our current version.
    pub fn current_version(&self) -> ProtocolVersion {
        CURRENT_VERSION
    }

    /// Get our supported versions.
    pub fn supported_versions(&self) -> &[ProtocolVersion] {
        &self.supported_versions
    }

    /// Get our capabilities.
    pub fn capabilities(&self) -> &NodeCapabilities {
        &self.capabilities
    }
}

/// Result of version negotiation.
#[derive(Debug, Clone)]
pub struct NegotiationResult {
    /// The negotiated version.
    pub version: ProtocolVersion,
    /// Common capabilities.
    pub capabilities: NodeCapabilities,
}

// ============================================================================
// Protocol Upgrade Path Management
// ============================================================================

/// Feature flag for protocol features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolFeature {
    /// Basic bandwidth proof (v1.0.0+).
    BandwidthProof,
    /// Chunk streaming (v1.1.0+).
    ChunkStreaming,
    /// Compression support (v1.1.0+).
    Compression,
    /// Batch proof submission (v1.2.0+).
    BatchProofs,
    /// Relay connections (v1.2.0+).
    RelayConnections,
    /// WebRTC transport (v1.3.0+).
    WebRtc,
    /// Enhanced fraud detection (v1.3.0+).
    EnhancedFraudDetection,
    /// Gossipsub announcements (v1.0.0+).
    GossipAnnouncements,
}

impl ProtocolFeature {
    /// Get the minimum version required for this feature.
    pub fn min_version(&self) -> ProtocolVersion {
        match self {
            ProtocolFeature::BandwidthProof => ProtocolVersion::new(1, 0, 0),
            ProtocolFeature::GossipAnnouncements => ProtocolVersion::new(1, 0, 0),
            ProtocolFeature::ChunkStreaming => ProtocolVersion::new(1, 1, 0),
            ProtocolFeature::Compression => ProtocolVersion::new(1, 1, 0),
            ProtocolFeature::BatchProofs => ProtocolVersion::new(1, 2, 0),
            ProtocolFeature::RelayConnections => ProtocolVersion::new(1, 2, 0),
            ProtocolFeature::WebRtc => ProtocolVersion::new(1, 3, 0),
            ProtocolFeature::EnhancedFraudDetection => ProtocolVersion::new(1, 3, 0),
        }
    }

    /// Check if this feature is available in the given version.
    pub fn is_available_in(&self, version: &ProtocolVersion) -> bool {
        *version >= self.min_version()
    }

    /// Get all features available in a version.
    pub fn available_features(version: &ProtocolVersion) -> Vec<ProtocolFeature> {
        let all_features = [
            ProtocolFeature::BandwidthProof,
            ProtocolFeature::GossipAnnouncements,
            ProtocolFeature::ChunkStreaming,
            ProtocolFeature::Compression,
            ProtocolFeature::BatchProofs,
            ProtocolFeature::RelayConnections,
            ProtocolFeature::WebRtc,
            ProtocolFeature::EnhancedFraudDetection,
        ];

        all_features
            .into_iter()
            .filter(|f| f.is_available_in(version))
            .collect()
    }
}

/// Deprecation status for protocol elements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationInfo {
    /// The version when this was deprecated.
    pub deprecated_in: ProtocolVersion,
    /// The version when this will be removed (if known).
    pub removal_version: Option<ProtocolVersion>,
    /// Migration guidance.
    pub migration_hint: String,
    /// Replacement feature (if any).
    pub replacement: Option<String>,
}

/// Protocol upgrade manager.
///
/// Handles version transitions, feature availability, and backward compatibility.
#[derive(Debug, Clone)]
pub struct UpgradeManager {
    /// Current version.
    current_version: ProtocolVersion,
    /// All supported versions (for backward compatibility).
    supported_versions: Vec<ProtocolVersion>,
    /// Deprecated features and their info.
    deprecations: HashMap<String, DeprecationInfo>,
    /// Feature availability overrides (for testing/gradual rollout).
    feature_overrides: HashMap<ProtocolFeature, bool>,
}

impl Default for UpgradeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UpgradeManager {
    /// Create a new upgrade manager.
    pub fn new() -> Self {
        Self {
            current_version: CURRENT_VERSION,
            supported_versions: vec![
                ProtocolVersion::new(1, 0, 0),
                // Future versions will be added here
            ],
            deprecations: HashMap::new(),
            feature_overrides: HashMap::new(),
        }
    }

    /// Get the current version.
    pub fn current_version(&self) -> ProtocolVersion {
        self.current_version
    }

    /// Get all supported versions.
    pub fn supported_versions(&self) -> &[ProtocolVersion] {
        &self.supported_versions
    }

    /// Check if a version is supported.
    pub fn is_version_supported(&self, version: &ProtocolVersion) -> bool {
        self.supported_versions.contains(version)
            || (version.major == self.current_version.major && *version <= self.current_version)
    }

    /// Check if a feature is available.
    pub fn is_feature_available(&self, feature: ProtocolFeature) -> bool {
        // Check for override first
        if let Some(&override_value) = self.feature_overrides.get(&feature) {
            return override_value;
        }
        feature.is_available_in(&self.current_version)
    }

    /// Enable a feature override (for testing/gradual rollout).
    pub fn set_feature_override(&mut self, feature: ProtocolFeature, enabled: bool) {
        self.feature_overrides.insert(feature, enabled);
    }

    /// Clear a feature override.
    pub fn clear_feature_override(&mut self, feature: ProtocolFeature) {
        self.feature_overrides.remove(&feature);
    }

    /// Get available features for the current version.
    pub fn available_features(&self) -> Vec<ProtocolFeature> {
        ProtocolFeature::available_features(&self.current_version)
            .into_iter()
            .filter(|f| self.is_feature_available(*f))
            .collect()
    }

    /// Mark a feature as deprecated.
    pub fn deprecate(&mut self, name: &str, info: DeprecationInfo) {
        self.deprecations.insert(name.to_string(), info);
    }

    /// Check if something is deprecated.
    pub fn is_deprecated(&self, name: &str) -> Option<&DeprecationInfo> {
        self.deprecations.get(name)
    }

    /// Get all deprecations.
    pub fn deprecations(&self) -> &HashMap<String, DeprecationInfo> {
        &self.deprecations
    }

    /// Get the upgrade path from one version to another.
    pub fn upgrade_path(
        &self,
        from: &ProtocolVersion,
        to: &ProtocolVersion,
    ) -> Result<Vec<UpgradeStep>, UpgradeError> {
        if from > to {
            return Err(UpgradeError::DowngradeNotSupported);
        }

        if from.major != to.major {
            return Err(UpgradeError::MajorVersionMismatch);
        }

        let mut steps = Vec::new();
        let mut current = *from;

        // Generate upgrade steps for each minor version bump
        while current < *to {
            let next = if current.minor < to.minor {
                ProtocolVersion::new(current.major, current.minor + 1, 0)
            } else {
                ProtocolVersion::new(current.major, current.minor, current.patch + 1)
            };

            let features_added = self.features_between(&current, &next);
            let features_removed = Vec::new(); // We don't remove features in minor versions

            steps.push(UpgradeStep {
                from: current,
                to: next,
                features_added,
                features_removed,
                migration_notes: self.migration_notes_for(&current, &next),
                breaking_changes: Vec::new(), // Minor versions don't have breaking changes
            });

            current = next;
        }

        Ok(steps)
    }

    /// Get features added between two versions.
    fn features_between(
        &self,
        from: &ProtocolVersion,
        to: &ProtocolVersion,
    ) -> Vec<ProtocolFeature> {
        let from_features: std::collections::HashSet<_> = ProtocolFeature::available_features(from)
            .into_iter()
            .collect();
        let to_features: std::collections::HashSet<_> = ProtocolFeature::available_features(to)
            .into_iter()
            .collect();

        to_features.difference(&from_features).cloned().collect()
    }

    /// Get migration notes for a version transition.
    fn migration_notes_for(&self, from: &ProtocolVersion, to: &ProtocolVersion) -> Vec<String> {
        let mut notes = Vec::new();

        // Add notes for each new feature
        for feature in self.features_between(from, to) {
            notes.push(format!(
                "New feature available: {:?} (from v{})",
                feature,
                feature.min_version()
            ));
        }

        // Add deprecation warnings
        for (name, info) in &self.deprecations {
            if info.deprecated_in > *from && info.deprecated_in <= *to {
                notes.push(format!("Deprecated: {} - {}", name, info.migration_hint));
            }
        }

        notes
    }

    /// Create a version negotiator with this manager's settings.
    pub fn create_negotiator(&self) -> VersionNegotiator {
        VersionNegotiator::with_versions(self.supported_versions.clone())
    }
}

/// A single upgrade step in the upgrade path.
#[derive(Debug, Clone)]
pub struct UpgradeStep {
    /// Starting version.
    pub from: ProtocolVersion,
    /// Target version.
    pub to: ProtocolVersion,
    /// Features added in this step.
    pub features_added: Vec<ProtocolFeature>,
    /// Features removed in this step.
    pub features_removed: Vec<ProtocolFeature>,
    /// Migration notes.
    pub migration_notes: Vec<String>,
    /// Breaking changes (for major version upgrades).
    pub breaking_changes: Vec<String>,
}

/// Upgrade error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeError {
    /// Downgrade is not supported.
    DowngradeNotSupported,
    /// Major version mismatch.
    MajorVersionMismatch,
    /// Version not supported.
    VersionNotSupported,
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpgradeError::DowngradeNotSupported => write!(f, "Downgrade is not supported"),
            UpgradeError::MajorVersionMismatch => {
                write!(f, "Cannot upgrade across major versions automatically")
            }
            UpgradeError::VersionNotSupported => write!(f, "Version is not supported"),
        }
    }
}

impl std::error::Error for UpgradeError {}

/// Protocol session context after negotiation.
///
/// This maintains the negotiated state for a peer connection.
#[derive(Debug, Clone)]
pub struct ProtocolSession {
    /// Negotiated version.
    pub version: ProtocolVersion,
    /// Common capabilities.
    pub capabilities: NodeCapabilities,
    /// Available features.
    pub features: Vec<ProtocolFeature>,
    /// Remote peer's version.
    pub remote_version: ProtocolVersion,
}

impl ProtocolSession {
    /// Create a new protocol session from negotiation result.
    pub fn from_negotiation(result: NegotiationResult, remote_version: ProtocolVersion) -> Self {
        let features = ProtocolFeature::available_features(&result.version);
        Self {
            version: result.version,
            capabilities: result.capabilities,
            features,
            remote_version,
        }
    }

    /// Check if a feature is available in this session.
    pub fn has_feature(&self, feature: ProtocolFeature) -> bool {
        self.features.contains(&feature)
    }

    /// Get the effective chunk size for this session.
    pub fn max_chunk_size(&self) -> u64 {
        self.capabilities.max_chunk_size
    }

    /// Check if compression is available.
    pub fn supports_compression(&self) -> bool {
        self.capabilities.compression && self.has_feature(ProtocolFeature::Compression)
    }

    /// Check if streaming is available.
    pub fn supports_streaming(&self) -> bool {
        self.capabilities.streaming && self.has_feature(ProtocolFeature::ChunkStreaming)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = ProtocolVersion::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_ordering() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v2 = ProtocolVersion::new(1, 1, 0);
        let v3 = ProtocolVersion::new(2, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = ProtocolVersion::new(1, 0, 0);
        let v2 = ProtocolVersion::new(1, 1, 0);
        let v3 = ProtocolVersion::new(2, 0, 0);

        assert!(v2.is_compatible_with(&v1));
        assert!(!v1.is_compatible_with(&v2));
        assert!(!v3.is_compatible_with(&v1));
    }

    #[test]
    fn test_version_negotiation() {
        let negotiator1 = VersionNegotiator::new();
        let negotiator2 = VersionNegotiator::new();

        let request = negotiator1.create_request();
        let response = negotiator2.handle_request(&request);

        assert!(response.success);
        assert_eq!(response.selected_version, Some(CURRENT_VERSION));
    }

    #[test]
    fn test_capability_compatibility() {
        let caps1 = NodeCapabilities::full();
        let caps2 = NodeCapabilities::full();

        assert!(caps1.is_compatible_with(&caps2));

        let caps3 = NodeCapabilities {
            encryption: false,
            ..Default::default()
        };
        assert!(!caps1.is_compatible_with(&caps3));
    }

    #[test]
    fn test_common_capabilities() {
        let caps1 = NodeCapabilities {
            streaming: true,
            compression: true,
            encryption: true,
            relay: false,
            max_chunk_size: 10 * 1024 * 1024,
            encryption_algorithms: vec!["chacha20-poly1305".to_string(), "aes-256-gcm".to_string()],
        };

        let caps2 = NodeCapabilities {
            streaming: true,
            compression: false,
            encryption: true,
            relay: true,
            max_chunk_size: 5 * 1024 * 1024,
            encryption_algorithms: vec!["chacha20-poly1305".to_string()],
        };

        let common = caps1.common_with(&caps2);
        assert!(common.streaming);
        assert!(!common.compression);
        assert!(common.encryption);
        assert!(!common.relay);
        assert_eq!(common.max_chunk_size, 5 * 1024 * 1024);
        assert_eq!(common.encryption_algorithms, vec!["chacha20-poly1305"]);
    }

    #[test]
    fn test_protocol_feature_availability() {
        let v100 = ProtocolVersion::new(1, 0, 0);
        let v110 = ProtocolVersion::new(1, 1, 0);
        let v120 = ProtocolVersion::new(1, 2, 0);

        assert!(ProtocolFeature::BandwidthProof.is_available_in(&v100));
        assert!(ProtocolFeature::GossipAnnouncements.is_available_in(&v100));
        assert!(!ProtocolFeature::ChunkStreaming.is_available_in(&v100));

        assert!(ProtocolFeature::ChunkStreaming.is_available_in(&v110));
        assert!(ProtocolFeature::Compression.is_available_in(&v110));
        assert!(!ProtocolFeature::BatchProofs.is_available_in(&v110));

        assert!(ProtocolFeature::BatchProofs.is_available_in(&v120));
        assert!(ProtocolFeature::RelayConnections.is_available_in(&v120));
    }

    #[test]
    fn test_available_features_by_version() {
        let v100 = ProtocolVersion::new(1, 0, 0);
        let features = ProtocolFeature::available_features(&v100);
        assert_eq!(features.len(), 2);
        assert!(features.contains(&ProtocolFeature::BandwidthProof));
        assert!(features.contains(&ProtocolFeature::GossipAnnouncements));

        let v130 = ProtocolVersion::new(1, 3, 0);
        let features = ProtocolFeature::available_features(&v130);
        assert_eq!(features.len(), 8);
    }

    #[test]
    fn test_upgrade_manager_basics() {
        let manager = UpgradeManager::new();
        assert_eq!(manager.current_version(), CURRENT_VERSION);
        assert!(manager.is_version_supported(&CURRENT_VERSION));
    }

    #[test]
    fn test_upgrade_manager_feature_overrides() {
        let mut manager = UpgradeManager::new();

        // Feature not available in v1.0.0
        assert!(!manager.is_feature_available(ProtocolFeature::ChunkStreaming));

        // Override to enable
        manager.set_feature_override(ProtocolFeature::ChunkStreaming, true);
        assert!(manager.is_feature_available(ProtocolFeature::ChunkStreaming));

        // Clear override
        manager.clear_feature_override(ProtocolFeature::ChunkStreaming);
        assert!(!manager.is_feature_available(ProtocolFeature::ChunkStreaming));
    }

    #[test]
    fn test_upgrade_path() {
        let manager = UpgradeManager::new();

        let from = ProtocolVersion::new(1, 0, 0);
        let to = ProtocolVersion::new(1, 2, 0);

        let path = manager.upgrade_path(&from, &to).unwrap();
        assert_eq!(path.len(), 2); // 1.0.0 -> 1.1.0 -> 1.2.0

        assert_eq!(path[0].from, from);
        assert_eq!(path[0].to, ProtocolVersion::new(1, 1, 0));

        assert_eq!(path[1].from, ProtocolVersion::new(1, 1, 0));
        assert_eq!(path[1].to, to);
    }

    #[test]
    fn test_upgrade_path_errors() {
        let manager = UpgradeManager::new();

        // Downgrade
        let result = manager.upgrade_path(
            &ProtocolVersion::new(1, 1, 0),
            &ProtocolVersion::new(1, 0, 0),
        );
        assert_eq!(result.unwrap_err(), UpgradeError::DowngradeNotSupported);

        // Major version mismatch
        let result = manager.upgrade_path(
            &ProtocolVersion::new(1, 0, 0),
            &ProtocolVersion::new(2, 0, 0),
        );
        assert_eq!(result.unwrap_err(), UpgradeError::MajorVersionMismatch);
    }

    #[test]
    fn test_deprecation_tracking() {
        let mut manager = UpgradeManager::new();

        manager.deprecate(
            "old_message_format",
            DeprecationInfo {
                deprecated_in: ProtocolVersion::new(1, 1, 0),
                removal_version: Some(ProtocolVersion::new(2, 0, 0)),
                migration_hint: "Use new_message_format instead".to_string(),
                replacement: Some("new_message_format".to_string()),
            },
        );

        assert!(manager.is_deprecated("old_message_format").is_some());
        assert!(manager.is_deprecated("nonexistent").is_none());
    }

    #[test]
    fn test_protocol_session() {
        let result = NegotiationResult {
            version: ProtocolVersion::new(1, 0, 0),
            capabilities: NodeCapabilities::full(),
        };

        let session = ProtocolSession::from_negotiation(result, ProtocolVersion::new(1, 0, 0));

        assert!(session.has_feature(ProtocolFeature::BandwidthProof));
        assert!(!session.has_feature(ProtocolFeature::ChunkStreaming));
        assert!(!session.supports_streaming()); // Feature not available in v1.0.0
    }
}
