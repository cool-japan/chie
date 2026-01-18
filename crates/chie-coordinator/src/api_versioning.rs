//! API Versioning System
//!
//! Provides version management for API endpoints with support for:
//! - Multiple API versions (v1, v2, etc.)
//! - Version deprecation notices
//! - Sunset headers for deprecated APIs
//! - Version negotiation via path or Accept header
//! - Backward compatibility tracking

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};
use tracing::{debug, info, warn};

/// API version identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ApiVersion {
    /// Version 1 (initial release)
    #[default]
    V1,
    /// Version 2 (future version)
    V2,
}

impl ApiVersion {
    /// Parse version from string (e.g., "v1", "v2")
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "v1" | "1" => Some(ApiVersion::V1),
            "v2" | "2" => Some(ApiVersion::V2),
            _ => None,
        }
    }

    /// Get version as string (e.g., "v1")
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiVersion::V1 => "v1",
            ApiVersion::V2 => "v2",
        }
    }

    /// Get version number
    pub fn number(&self) -> u32 {
        match self {
            ApiVersion::V1 => 1,
            ApiVersion::V2 => 2,
        }
    }

    /// Check if this version is newer than another
    pub fn is_newer_than(&self, other: &ApiVersion) -> bool {
        self.number() > other.number()
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Version deprecation status
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeprecationInfo {
    /// Whether this version is deprecated
    #[serde(default)]
    pub deprecated: bool,
    /// Deprecation date (when it was marked deprecated)
    #[serde(default)]
    pub deprecated_at: Option<DateTime<Utc>>,
    /// Sunset date (when it will be removed)
    #[serde(default)]
    pub sunset_at: Option<DateTime<Utc>>,
    /// Migration guide URL
    #[serde(default)]
    pub migration_guide: Option<String>,
    /// Reason for deprecation
    #[serde(default)]
    pub reason: Option<String>,
    /// Replacement version
    #[serde(default)]
    pub replacement_version: Option<ApiVersion>,
}

/// API version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Version identifier
    pub version: ApiVersion,
    /// Whether this version is the current stable version
    pub is_stable: bool,
    /// Whether this version is the default
    pub is_default: bool,
    /// Deprecation information
    pub deprecation: DeprecationInfo,
    /// Release date
    pub released_at: DateTime<Utc>,
    /// Version description
    pub description: String,
}

impl VersionInfo {
    /// Create new version info
    pub fn new(version: ApiVersion, is_stable: bool, is_default: bool) -> Self {
        Self {
            version,
            is_stable,
            is_default,
            deprecation: DeprecationInfo::default(),
            released_at: Utc::now(),
            description: String::new(),
        }
    }

    /// Mark version as deprecated
    pub fn deprecate(
        mut self,
        sunset_at: Option<DateTime<Utc>>,
        reason: Option<String>,
        replacement: Option<ApiVersion>,
    ) -> Self {
        self.deprecation = DeprecationInfo {
            deprecated: true,
            deprecated_at: Some(Utc::now()),
            sunset_at,
            migration_guide: None,
            reason,
            replacement_version: replacement,
        };
        self
    }

    /// Check if version is currently deprecated
    pub fn is_deprecated(&self) -> bool {
        self.deprecation.deprecated
    }

    /// Check if version is past sunset date
    pub fn is_sunset(&self) -> bool {
        if let Some(sunset_at) = self.deprecation.sunset_at {
            Utc::now() > sunset_at
        } else {
            false
        }
    }
}

/// API versioning manager
pub struct VersioningManager {
    /// Registered API versions
    versions: RwLock<HashMap<ApiVersion, VersionInfo>>,
    /// Default API version
    default_version: ApiVersion,
    /// Configuration
    #[allow(dead_code)]
    config: VersioningConfig,
}

/// Versioning configuration
#[derive(Debug, Clone)]
pub struct VersioningConfig {
    /// Allow requests without version specification
    pub allow_unversioned: bool,
    /// Require Accept header for version negotiation
    pub require_accept_header: bool,
    /// Strict version validation
    pub strict_validation: bool,
}

impl Default for VersioningConfig {
    fn default() -> Self {
        Self {
            allow_unversioned: true,
            require_accept_header: false,
            strict_validation: false,
        }
    }
}

impl VersioningManager {
    /// Create new versioning manager
    pub fn new(config: VersioningConfig) -> Self {
        let mut versions = HashMap::new();

        // Register V1 as default and stable
        versions.insert(ApiVersion::V1, VersionInfo::new(ApiVersion::V1, true, true));

        Self {
            versions: RwLock::new(versions),
            default_version: ApiVersion::V1,
            config,
        }
    }

    /// Register a new API version
    pub fn register_version(&self, info: VersionInfo) {
        let mut versions = self.versions.write().unwrap();
        info!("Registering API version: {}", info.version);
        versions.insert(info.version, info);
    }

    /// Get version info
    pub fn get_version_info(&self, version: ApiVersion) -> Option<VersionInfo> {
        let versions = self.versions.read().unwrap();
        versions.get(&version).cloned()
    }

    /// List all registered versions
    pub fn list_versions(&self) -> Vec<VersionInfo> {
        let versions = self.versions.read().unwrap();
        let mut result: Vec<_> = versions.values().cloned().collect();
        result.sort_by_key(|v| v.version.number());
        result
    }

    /// Get default version
    pub fn default_version(&self) -> ApiVersion {
        self.default_version
    }

    /// Extract version from request path
    pub fn extract_version_from_path(&self, path: &str) -> Option<ApiVersion> {
        // Path format: /api/v1/... or /v1/...
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        for part in parts {
            if let Some(version) = ApiVersion::from_str(part) {
                return Some(version);
            }
        }

        None
    }

    /// Extract version from Accept header
    pub fn extract_version_from_accept(&self, headers: &HeaderMap) -> Option<ApiVersion> {
        // Accept: application/vnd.chie.v1+json
        if let Some(accept) = headers.get(header::ACCEPT) {
            if let Ok(accept_str) = accept.to_str() {
                if let Some(start) = accept_str.find(".v") {
                    let version_part = &accept_str[start + 2..];
                    if let Some(end) = version_part.find('+').or_else(|| version_part.find(';')) {
                        return ApiVersion::from_str(&version_part[..end]);
                    } else {
                        return ApiVersion::from_str(version_part);
                    }
                }
            }
        }
        None
    }

    /// Determine API version from request
    pub fn determine_version(&self, path: &str, headers: &HeaderMap) -> ApiVersion {
        // Priority: Path > Accept header > Default
        if let Some(version) = self.extract_version_from_path(path) {
            debug!("Version from path: {}", version);
            return version;
        }

        if let Some(version) = self.extract_version_from_accept(headers) {
            debug!("Version from Accept header: {}", version);
            return version;
        }

        debug!("Using default version: {}", self.default_version);
        self.default_version
    }

    /// Check if version is valid and not sunset
    pub fn validate_version(&self, version: ApiVersion) -> Result<(), String> {
        let versions = self.versions.read().unwrap();

        match versions.get(&version) {
            Some(info) => {
                if info.is_sunset() {
                    Err(format!(
                        "API version {} has been sunset and is no longer available",
                        version
                    ))
                } else {
                    Ok(())
                }
            }
            None => Err(format!("Unknown API version: {}", version)),
        }
    }

    /// Add deprecation headers to response
    pub fn add_deprecation_headers(&self, version: ApiVersion, headers: &mut HeaderMap) {
        if let Some(info) = self.get_version_info(version) {
            if info.is_deprecated() {
                // Deprecation header (RFC 8594)
                if let Ok(header_value) = HeaderValue::from_str("true") {
                    headers.insert("Deprecation", header_value);
                }

                // Sunset header (RFC 8594)
                if let Some(sunset_at) = info.deprecation.sunset_at {
                    if let Ok(header_value) = HeaderValue::from_str(&sunset_at.to_rfc2822()) {
                        headers.insert("Sunset", header_value);
                    }
                }

                // Link to migration guide
                if let Some(migration_guide) = &info.deprecation.migration_guide {
                    if let Ok(header_value) = HeaderValue::from_str(&format!(
                        "<{}>; rel=\"deprecation\"; type=\"text/html\"",
                        migration_guide
                    )) {
                        headers.insert(header::LINK, header_value);
                    }
                }

                warn!(
                    "API version {} is deprecated. Sunset: {:?}",
                    version, info.deprecation.sunset_at
                );
            }
        }
    }

    /// Get deprecation info for response
    pub fn get_deprecation_notice(&self, version: ApiVersion) -> Option<serde_json::Value> {
        if let Some(info) = self.get_version_info(version) {
            if info.is_deprecated() {
                return Some(serde_json::json!({
                    "deprecated": true,
                    "deprecated_at": info.deprecation.deprecated_at,
                    "sunset_at": info.deprecation.sunset_at,
                    "reason": info.deprecation.reason,
                    "replacement_version": info.deprecation.replacement_version,
                    "migration_guide": info.deprecation.migration_guide,
                }));
            }
        }
        None
    }
}

/// Middleware to handle API versioning
pub async fn versioning_middleware(
    State(manager): State<Arc<VersioningManager>>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();

    // Determine API version
    let version = manager.determine_version(&path, &headers);

    // Validate version
    if let Err(err) = manager.validate_version(version) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid API version",
                "message": err,
                "supported_versions": manager.list_versions().iter()
                    .filter(|v| !v.is_sunset())
                    .map(|v| v.version.as_str())
                    .collect::<Vec<_>>(),
            })),
        ));
    }

    // Add version to request extensions
    request.extensions_mut().insert(version);

    // Process request
    let mut response = next.run(request).await;

    // Add version header to response
    if let Ok(header_value) = HeaderValue::from_str(version.as_str()) {
        response.headers_mut().insert("X-API-Version", header_value);
    }

    // Add deprecation headers if needed
    manager.add_deprecation_headers(version, response.headers_mut());

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn test_version_parsing() {
        assert_eq!(ApiVersion::from_str("v1"), Some(ApiVersion::V1));
        assert_eq!(ApiVersion::from_str("V1"), Some(ApiVersion::V1));
        assert_eq!(ApiVersion::from_str("1"), Some(ApiVersion::V1));
        assert_eq!(ApiVersion::from_str("v2"), Some(ApiVersion::V2));
        assert_eq!(ApiVersion::from_str("v3"), None);
    }

    #[test]
    fn test_version_comparison() {
        assert!(ApiVersion::V2.is_newer_than(&ApiVersion::V1));
        assert!(!ApiVersion::V1.is_newer_than(&ApiVersion::V2));
        assert!(!ApiVersion::V1.is_newer_than(&ApiVersion::V1));
    }

    #[test]
    fn test_version_string_representation() {
        assert_eq!(ApiVersion::V1.as_str(), "v1");
        assert_eq!(ApiVersion::V2.as_str(), "v2");
        assert_eq!(ApiVersion::V1.to_string(), "v1");
    }

    #[test]
    fn test_deprecation_info() {
        let mut info = VersionInfo::new(ApiVersion::V1, true, true);
        assert!(!info.is_deprecated());
        assert!(!info.is_sunset());

        let sunset_date = Utc::now() + chrono::Duration::days(30);
        info = info.deprecate(
            Some(sunset_date),
            Some("Moving to V2".to_string()),
            Some(ApiVersion::V2),
        );

        assert!(info.is_deprecated());
        assert!(!info.is_sunset());
    }

    #[test]
    fn test_versioning_manager_registration() {
        let manager = VersioningManager::new(VersioningConfig::default());

        let v2_info = VersionInfo::new(ApiVersion::V2, true, false);
        manager.register_version(v2_info);

        let versions = manager.list_versions();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().any(|v| v.version == ApiVersion::V1));
        assert!(versions.iter().any(|v| v.version == ApiVersion::V2));
    }

    #[test]
    fn test_extract_version_from_path() {
        let manager = VersioningManager::new(VersioningConfig::default());

        assert_eq!(
            manager.extract_version_from_path("/api/v1/users"),
            Some(ApiVersion::V1)
        );
        assert_eq!(
            manager.extract_version_from_path("/v2/content"),
            Some(ApiVersion::V2)
        );
        assert_eq!(manager.extract_version_from_path("/api/users"), None);
    }

    #[test]
    fn test_extract_version_from_accept_header() {
        let manager = VersioningManager::new(VersioningConfig::default());

        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.chie.v1+json"),
        );

        assert_eq!(
            manager.extract_version_from_accept(&headers),
            Some(ApiVersion::V1)
        );

        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/vnd.chie.v2+json"),
        );
        assert_eq!(
            manager.extract_version_from_accept(&headers),
            Some(ApiVersion::V2)
        );
    }

    #[test]
    fn test_version_validation() {
        let manager = VersioningManager::new(VersioningConfig::default());

        // V1 should be valid
        assert!(manager.validate_version(ApiVersion::V1).is_ok());

        // V2 not registered, should fail in strict mode
        let result = manager.validate_version(ApiVersion::V2);
        assert!(result.is_err());
    }

    #[test]
    fn test_sunset_version() {
        let manager = VersioningManager::new(VersioningConfig::default());

        // Create a version that's already sunset
        let past_date = Utc::now() - chrono::Duration::days(1);
        let mut info = VersionInfo::new(ApiVersion::V2, false, false);
        info = info.deprecate(
            Some(past_date),
            Some("Old version".to_string()),
            Some(ApiVersion::V1),
        );
        manager.register_version(info);

        // Should fail validation because it's sunset
        assert!(manager.validate_version(ApiVersion::V2).is_err());
    }

    #[test]
    fn test_default_version() {
        let manager = VersioningManager::new(VersioningConfig::default());
        assert_eq!(manager.default_version(), ApiVersion::V1);
    }

    #[test]
    fn test_list_versions_sorted() {
        let manager = VersioningManager::new(VersioningConfig::default());
        manager.register_version(VersionInfo::new(ApiVersion::V2, true, false));

        let versions = manager.list_versions();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, ApiVersion::V1);
        assert_eq!(versions[1].version, ApiVersion::V2);
    }
}
