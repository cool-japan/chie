//! Backward compatibility layer for protocol evolution.
//!
//! This module provides mechanisms for maintaining compatibility across
//! different protocol versions, allowing smooth network upgrades.

use chie_shared::{ChieError, ChieResult};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Protocol version (major.minor)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

impl Version {
    /// Create new version
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Check if this version is compatible with another
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    /// Check if this version is newer than another
    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.major > other.major || (self.major == other.major && self.minor > other.minor)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl std::str::FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err("Invalid version format, expected 'major.minor'".to_string());
        }

        Ok(Self {
            major: parts[0]
                .parse()
                .map_err(|_| "Invalid major version".to_string())?,
            minor: parts[1]
                .parse()
                .map_err(|_| "Invalid minor version".to_string())?,
        })
    }
}

/// Message envelope with version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedMessage {
    /// Protocol version
    pub version: Version,
    /// Message type identifier
    pub message_type: String,
    /// Serialized message payload
    pub payload: Vec<u8>,
    /// Optional metadata for compatibility
    pub metadata: HashMap<String, String>,
}

/// Message translator for version conversion
pub trait MessageTranslator: Send + Sync {
    /// Translate message from one version to another
    fn translate(
        &self,
        message: &VersionedMessage,
        target_version: Version,
    ) -> ChieResult<VersionedMessage>;

    /// Check if translation is supported
    fn supports_translation(&self, from: Version, to: Version) -> bool;
}

/// Feature flag for version-specific features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    /// Feature name
    pub name: String,
    /// Version where feature was introduced
    pub since: Version,
    /// Version where feature was deprecated (if any)
    pub deprecated_since: Option<Version>,
    /// Version where feature was removed (if any)
    pub removed_since: Option<Version>,
    /// Whether feature is required
    pub required: bool,
}

impl FeatureFlag {
    /// Check if feature is available in version
    pub fn is_available_in(&self, version: Version) -> bool {
        if version < self.since {
            return false;
        }

        if let Some(removed) = self.removed_since {
            if version >= removed {
                return false;
            }
        }

        true
    }

    /// Check if feature is deprecated in version
    pub fn is_deprecated_in(&self, version: Version) -> bool {
        if let Some(deprecated) = self.deprecated_since {
            if let Some(removed) = self.removed_since {
                return version >= deprecated && version < removed;
            }
            return version >= deprecated;
        }
        false
    }
}

/// Translation function type
type TranslationFn = Box<dyn Fn(&[u8]) -> ChieResult<Vec<u8>> + Send + Sync>;

/// Default message translator
pub struct DefaultTranslator {
    /// Translation rules
    rules: Arc<RwLock<HashMap<(Version, Version), TranslationFn>>>,
}

impl DefaultTranslator {
    /// Create new default translator
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register translation rule
    pub fn register_rule<F>(&self, from: Version, to: Version, translator: F)
    where
        F: Fn(&[u8]) -> ChieResult<Vec<u8>> + Send + Sync + 'static,
    {
        let mut rules = self.rules.write();
        rules.insert((from, to), Box::new(translator));
    }
}

impl Default for DefaultTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageTranslator for DefaultTranslator {
    fn translate(
        &self,
        message: &VersionedMessage,
        target_version: Version,
    ) -> ChieResult<VersionedMessage> {
        if message.version == target_version {
            return Ok(message.clone());
        }

        let rules = self.rules.read();
        let key = (message.version, target_version);

        if let Some(rule) = rules.get(&key) {
            let new_payload = rule(&message.payload)?;
            Ok(VersionedMessage {
                version: target_version,
                message_type: message.message_type.clone(),
                payload: new_payload,
                metadata: message.metadata.clone(),
            })
        } else {
            Err(ChieError::not_found(format!(
                "No translation rule from {} to {}",
                message.version, target_version
            )))
        }
    }

    fn supports_translation(&self, from: Version, to: Version) -> bool {
        let rules = self.rules.read();
        rules.contains_key(&(from, to))
    }
}

/// Backward compatibility manager
pub struct BackwardCompatManager {
    /// Current protocol version
    current_version: Version,
    /// Minimum supported version
    min_version: Version,
    /// Message translator
    translator: Arc<dyn MessageTranslator>,
    /// Feature flags
    features: Arc<RwLock<HashMap<String, FeatureFlag>>>,
    /// Statistics
    stats: Arc<RwLock<CompatStats>>,
}

/// Compatibility statistics
#[derive(Debug, Clone, Default)]
pub struct CompatStats {
    /// Total messages translated
    pub total_translations: u64,
    /// Successful translations
    pub successful_translations: u64,
    /// Failed translations
    pub failed_translations: u64,
    /// Deprecated features used
    pub deprecated_feature_usage: u64,
    /// Unsupported features encountered
    pub unsupported_features: u64,
}

impl BackwardCompatManager {
    /// Create new backward compatibility manager
    pub fn new(
        current_version: Version,
        min_version: Version,
        translator: Arc<dyn MessageTranslator>,
    ) -> Self {
        Self {
            current_version,
            min_version,
            translator,
            features: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CompatStats::default())),
        }
    }

    /// Get current version
    pub fn current_version(&self) -> Version {
        self.current_version
    }

    /// Get minimum supported version
    pub fn min_version(&self) -> Version {
        self.min_version
    }

    /// Check if version is supported
    pub fn is_version_supported(&self, version: Version) -> bool {
        version >= self.min_version && version.is_compatible_with(&self.current_version)
    }

    /// Register feature flag
    pub fn register_feature(&self, feature: FeatureFlag) {
        let mut features = self.features.write();
        features.insert(feature.name.clone(), feature);
    }

    /// Check if feature is available
    pub fn is_feature_available(&self, name: &str, version: Version) -> bool {
        let features = self.features.read();
        features
            .get(name)
            .map(|f| f.is_available_in(version))
            .unwrap_or(false)
    }

    /// Check if feature is deprecated
    pub fn is_feature_deprecated(&self, name: &str, version: Version) -> bool {
        let features = self.features.read();
        features
            .get(name)
            .map(|f| f.is_deprecated_in(version))
            .unwrap_or(false)
    }

    /// Translate message to target version
    pub fn translate_message(
        &self,
        message: &VersionedMessage,
        target_version: Version,
    ) -> ChieResult<VersionedMessage> {
        let mut stats = self.stats.write();
        stats.total_translations += 1;

        // Check if target version is supported
        if !self.is_version_supported(target_version) {
            stats.failed_translations += 1;
            return Err(ChieError::validation(format!(
                "Target version {} is not supported",
                target_version
            )));
        }

        // Translate message
        match self.translator.translate(message, target_version) {
            Ok(translated) => {
                stats.successful_translations += 1;
                Ok(translated)
            }
            Err(e) => {
                stats.failed_translations += 1;
                Err(e)
            }
        }
    }

    /// Translate message to current version
    pub fn translate_to_current(&self, message: &VersionedMessage) -> ChieResult<VersionedMessage> {
        self.translate_message(message, self.current_version)
    }

    /// Record deprecated feature usage
    pub fn record_deprecated_feature(&self, feature: &str) {
        let mut stats = self.stats.write();
        stats.deprecated_feature_usage += 1;

        // Log warning
        eprintln!("Warning: Using deprecated feature: {}", feature);
    }

    /// Record unsupported feature
    pub fn record_unsupported_feature(&self, feature: &str) {
        let mut stats = self.stats.write();
        stats.unsupported_features += 1;

        eprintln!("Error: Unsupported feature: {}", feature);
    }

    /// Get required features for version
    pub fn get_required_features(&self, version: Version) -> Vec<String> {
        let features = self.features.read();
        features
            .values()
            .filter(|f| f.required && f.is_available_in(version))
            .map(|f| f.name.clone())
            .collect()
    }

    /// Get optional features for version
    pub fn get_optional_features(&self, version: Version) -> Vec<String> {
        let features = self.features.read();
        features
            .values()
            .filter(|f| !f.required && f.is_available_in(version))
            .map(|f| f.name.clone())
            .collect()
    }

    /// Get deprecated features for version
    pub fn get_deprecated_features(&self, version: Version) -> Vec<String> {
        let features = self.features.read();
        features
            .values()
            .filter(|f| f.is_deprecated_in(version))
            .map(|f| f.name.clone())
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> CompatStats {
        self.stats.read().clone()
    }

    /// Check if translation is supported
    pub fn supports_translation(&self, from: Version, to: Version) -> bool {
        self.translator.supports_translation(from, to)
    }

    /// Get feature info
    pub fn get_feature(&self, name: &str) -> Option<FeatureFlag> {
        let features = self.features.read();
        features.get(name).cloned()
    }

    /// Get all features
    pub fn get_all_features(&self) -> Vec<FeatureFlag> {
        let features = self.features.read();
        features.values().cloned().collect()
    }

    /// Create versioned message
    pub fn create_message(&self, message_type: String, payload: Vec<u8>) -> VersionedMessage {
        VersionedMessage {
            version: self.current_version,
            message_type,
            payload,
            metadata: HashMap::new(),
        }
    }

    /// Validate message compatibility
    pub fn validate_message(&self, message: &VersionedMessage) -> ChieResult<()> {
        if !self.is_version_supported(message.version) {
            return Err(ChieError::validation(format!(
                "Message version {} is not supported (min: {}, current: {})",
                message.version, self.min_version, self.current_version
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v: Version = "1.2".parse().unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.to_string(), "1.2");
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = Version::new(1, 0);
        let v2 = Version::new(1, 2);
        let v3 = Version::new(2, 0);

        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_version_comparison() {
        let v1 = Version::new(1, 0);
        let v2 = Version::new(1, 2);
        let v3 = Version::new(2, 0);

        assert!(v2.is_newer_than(&v1));
        assert!(v3.is_newer_than(&v2));
        assert!(!v1.is_newer_than(&v2));
    }

    #[test]
    fn test_feature_availability() {
        let feature = FeatureFlag {
            name: "compression".to_string(),
            since: Version::new(1, 2),
            deprecated_since: Some(Version::new(2, 0)),
            removed_since: Some(Version::new(3, 0)),
            required: false,
        };

        assert!(!feature.is_available_in(Version::new(1, 0)));
        assert!(feature.is_available_in(Version::new(1, 2)));
        assert!(feature.is_available_in(Version::new(2, 0)));
        assert!(!feature.is_available_in(Version::new(3, 0)));
    }

    #[test]
    fn test_feature_deprecation() {
        let feature = FeatureFlag {
            name: "old_api".to_string(),
            since: Version::new(1, 0),
            deprecated_since: Some(Version::new(2, 0)),
            removed_since: Some(Version::new(3, 0)),
            required: false,
        };

        assert!(!feature.is_deprecated_in(Version::new(1, 5)));
        assert!(feature.is_deprecated_in(Version::new(2, 0)));
        assert!(feature.is_deprecated_in(Version::new(2, 5)));
        assert!(!feature.is_deprecated_in(Version::new(3, 0))); // Removed, not deprecated
    }

    #[test]
    fn test_default_translator() {
        let translator = DefaultTranslator::new();

        // Register a simple rule (identity translation for testing)
        translator.register_rule(Version::new(1, 0), Version::new(1, 1), |data| {
            Ok(data.to_vec())
        });

        assert!(translator.supports_translation(Version::new(1, 0), Version::new(1, 1)));
        assert!(!translator.supports_translation(Version::new(1, 0), Version::new(2, 0)));
    }

    #[test]
    fn test_message_translation() {
        let translator = Arc::new(DefaultTranslator::new());
        translator.register_rule(Version::new(1, 0), Version::new(1, 1), |data| {
            Ok(data.to_vec())
        });

        let manager =
            BackwardCompatManager::new(Version::new(1, 1), Version::new(1, 0), translator);

        let message = VersionedMessage {
            version: Version::new(1, 0),
            message_type: "test".to_string(),
            payload: vec![1, 2, 3],
            metadata: HashMap::new(),
        };

        let translated = manager
            .translate_message(&message, Version::new(1, 1))
            .unwrap();
        assert_eq!(translated.version, Version::new(1, 1));
        assert_eq!(translated.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_version_support() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 5), translator);

        assert!(manager.is_version_supported(Version::new(2, 0)));
        assert!(manager.is_version_supported(Version::new(2, 1)));
        assert!(!manager.is_version_supported(Version::new(1, 0)));
        assert!(!manager.is_version_supported(Version::new(3, 0)));
    }

    #[test]
    fn test_feature_registration() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        let feature = FeatureFlag {
            name: "encryption".to_string(),
            since: Version::new(1, 5),
            deprecated_since: None,
            removed_since: None,
            required: true,
        };

        manager.register_feature(feature);
        assert!(manager.is_feature_available("encryption", Version::new(2, 0)));
        assert!(!manager.is_feature_available("encryption", Version::new(1, 0)));
    }

    #[test]
    fn test_required_features() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        manager.register_feature(FeatureFlag {
            name: "required_feature".to_string(),
            since: Version::new(1, 0),
            deprecated_since: None,
            removed_since: None,
            required: true,
        });

        manager.register_feature(FeatureFlag {
            name: "optional_feature".to_string(),
            since: Version::new(1, 0),
            deprecated_since: None,
            removed_since: None,
            required: false,
        });

        let required = manager.get_required_features(Version::new(2, 0));
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "required_feature");
    }

    #[test]
    fn test_optional_features() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        manager.register_feature(FeatureFlag {
            name: "optional_feature".to_string(),
            since: Version::new(1, 0),
            deprecated_since: None,
            removed_since: None,
            required: false,
        });

        let optional = manager.get_optional_features(Version::new(2, 0));
        assert_eq!(optional.len(), 1);
        assert_eq!(optional[0], "optional_feature");
    }

    #[test]
    fn test_deprecated_features() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        manager.register_feature(FeatureFlag {
            name: "old_api".to_string(),
            since: Version::new(1, 0),
            deprecated_since: Some(Version::new(2, 0)),
            removed_since: None,
            required: false,
        });

        let deprecated = manager.get_deprecated_features(Version::new(2, 0));
        assert_eq!(deprecated.len(), 1);
        assert_eq!(deprecated[0], "old_api");
    }

    #[test]
    fn test_stats_tracking() {
        let translator = Arc::new(DefaultTranslator::new());
        translator.register_rule(Version::new(1, 0), Version::new(1, 1), |data| {
            Ok(data.to_vec())
        });

        let manager =
            BackwardCompatManager::new(Version::new(1, 1), Version::new(1, 0), translator);

        let message = manager.create_message("test".to_string(), vec![1, 2, 3]);
        let _ = manager.translate_message(&message, Version::new(1, 1));

        let stats = manager.stats();
        assert!(stats.total_translations > 0);
    }

    #[test]
    fn test_create_message() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        let message = manager.create_message("test".to_string(), vec![1, 2, 3]);
        assert_eq!(message.version, Version::new(2, 0));
        assert_eq!(message.message_type, "test");
        assert_eq!(message.payload, vec![1, 2, 3]);
    }

    #[test]
    fn test_validate_message() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 5), translator);

        let valid_message = VersionedMessage {
            version: Version::new(2, 0),
            message_type: "test".to_string(),
            payload: vec![],
            metadata: HashMap::new(),
        };

        let invalid_message = VersionedMessage {
            version: Version::new(1, 0),
            message_type: "test".to_string(),
            payload: vec![],
            metadata: HashMap::new(),
        };

        assert!(manager.validate_message(&valid_message).is_ok());
        assert!(manager.validate_message(&invalid_message).is_err());
    }

    #[test]
    fn test_get_feature() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        let feature = FeatureFlag {
            name: "test_feature".to_string(),
            since: Version::new(1, 0),
            deprecated_since: None,
            removed_since: None,
            required: false,
        };

        manager.register_feature(feature.clone());

        let retrieved = manager.get_feature("test_feature").unwrap();
        assert_eq!(retrieved.name, "test_feature");
    }

    #[test]
    fn test_get_all_features() {
        let translator = Arc::new(DefaultTranslator::new());
        let manager =
            BackwardCompatManager::new(Version::new(2, 0), Version::new(1, 0), translator);

        manager.register_feature(FeatureFlag {
            name: "feature1".to_string(),
            since: Version::new(1, 0),
            deprecated_since: None,
            removed_since: None,
            required: false,
        });

        manager.register_feature(FeatureFlag {
            name: "feature2".to_string(),
            since: Version::new(1, 5),
            deprecated_since: None,
            removed_since: None,
            required: true,
        });

        let all_features = manager.get_all_features();
        assert_eq!(all_features.len(), 2);
    }
}
