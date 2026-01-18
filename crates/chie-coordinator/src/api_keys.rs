//! API key management system for secure API access
//!
//! This module provides a complete API key management system including:
//! - API key generation and validation
//! - Key scopes and permissions
//! - Rate limiting per API key
//! - Key rotation and expiration
//! - Usage tracking and analytics

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// API key error
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("Missing API key header")]
    MissingKey,
    #[error("Invalid API key format")]
    InvalidFormat,
    #[error("API key not found")]
    NotFound,
    #[error("API key expired")]
    Expired,
    #[error("API key revoked")]
    Revoked,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// API key scope/permission
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Read access to user data
    UserRead,
    /// Write access to user data
    UserWrite,
    /// Read access to content
    ContentRead,
    /// Write access to content
    ContentWrite,
    /// Submit bandwidth proofs
    ProofsSubmit,
    /// Read node data
    NodesRead,
    /// Write node data
    NodesWrite,
    /// Access admin endpoints
    Admin,
    /// Full access to all resources
    All,
}

impl ApiKeyScope {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyScope::UserRead => "user:read",
            ApiKeyScope::UserWrite => "user:write",
            ApiKeyScope::ContentRead => "content:read",
            ApiKeyScope::ContentWrite => "content:write",
            ApiKeyScope::ProofsSubmit => "proofs:submit",
            ApiKeyScope::NodesRead => "nodes:read",
            ApiKeyScope::NodesWrite => "nodes:write",
            ApiKeyScope::Admin => "admin",
            ApiKeyScope::All => "all",
        }
    }

    /// Check if this scope includes another scope
    pub fn includes(&self, other: &ApiKeyScope) -> bool {
        if self == &ApiKeyScope::All {
            return true;
        }
        self == other
    }
}

/// API key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// API key ID
    pub id: String,
    /// The actual key value (hashed when stored)
    #[serde(skip_serializing)]
    pub key_hash: String,
    /// Human-readable name for the key
    pub name: String,
    /// Owner user ID
    pub owner_id: String,
    /// Scopes granted to this key
    pub scopes: HashSet<ApiKeyScope>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the key is active
    pub active: bool,
    /// Usage count
    pub usage_count: u64,
    /// Last used timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    /// Rate limit (requests per minute)
    pub rate_limit: u32,
}

/// API key usage statistics
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyUsage {
    /// API key ID
    pub key_id: String,
    /// Total requests
    pub total_requests: u64,
    /// Requests in the last hour
    pub requests_last_hour: u64,
    /// Requests in the last day
    pub requests_last_day: u64,
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
    /// Most accessed endpoints
    pub top_endpoints: Vec<(String, u64)>,
}

/// Configuration for API key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Default rate limit for new keys (requests per minute)
    pub default_rate_limit: u32,
    /// Default expiration days (None for no expiration)
    pub default_expiration_days: Option<i64>,
    /// Whether to require API keys for all endpoints
    pub require_for_all: bool,
    /// Endpoints that require API keys
    pub protected_endpoints: Vec<String>,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            default_rate_limit: 60,             // 60 requests per minute
            default_expiration_days: Some(365), // 1 year default
            require_for_all: false,
            protected_endpoints: vec!["/api/admin/".to_string()],
        }
    }
}

/// API key manager
#[derive(Debug, Clone)]
pub struct ApiKeyManager {
    config: Arc<ApiKeyConfig>,
    keys: Arc<RwLock<HashMap<String, ApiKey>>>,
    key_hash_to_id: Arc<RwLock<HashMap<String, String>>>,
    usage_tracking: Arc<RwLock<HashMap<String, Vec<DateTime<Utc>>>>>,
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new(config: ApiKeyConfig) -> Self {
        Self {
            config: Arc::new(config),
            keys: Arc::new(RwLock::new(HashMap::new())),
            key_hash_to_id: Arc::new(RwLock::new(HashMap::new())),
            usage_tracking: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ApiKeyConfig::default())
    }

    /// Generate a new API key
    pub fn generate_key(
        &self,
        name: String,
        owner_id: String,
        scopes: HashSet<ApiKeyScope>,
        rate_limit: Option<u32>,
        expires_in_days: Option<i64>,
    ) -> (String, ApiKey) {
        let id = uuid::Uuid::new_v4().to_string();
        let raw_key = format!("chie_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let key_hash = Self::hash_key(&raw_key);

        let expires_at = expires_in_days
            .or(self.config.default_expiration_days)
            .map(|days| Utc::now() + chrono::Duration::days(days));

        let api_key = ApiKey {
            id: id.clone(),
            key_hash: key_hash.clone(),
            name,
            owner_id,
            scopes,
            created_at: Utc::now(),
            expires_at,
            active: true,
            usage_count: 0,
            last_used_at: None,
            rate_limit: rate_limit.unwrap_or(self.config.default_rate_limit),
        };

        // Store the key
        {
            let mut keys = self.keys.write().unwrap();
            keys.insert(id.clone(), api_key.clone());
        }

        // Store hash-to-id mapping
        {
            let mut mapping = self.key_hash_to_id.write().unwrap();
            mapping.insert(key_hash, id);
        }

        (raw_key, api_key)
    }

    /// Validate an API key and check permissions
    pub fn validate_key(
        &self,
        raw_key: &str,
        required_scope: Option<ApiKeyScope>,
    ) -> Result<ApiKey, ApiKeyError> {
        let key_hash = Self::hash_key(raw_key);

        // Find the key ID from hash
        let key_id = {
            let mapping = self.key_hash_to_id.read().unwrap();
            mapping
                .get(&key_hash)
                .cloned()
                .ok_or(ApiKeyError::NotFound)?
        };

        // Get the key
        let mut key = {
            let keys = self.keys.read().unwrap();
            keys.get(&key_id).cloned().ok_or(ApiKeyError::NotFound)?
        };

        // Check if key is active
        if !key.active {
            return Err(ApiKeyError::Revoked);
        }

        // Check expiration
        if let Some(expires_at) = key.expires_at {
            if Utc::now() > expires_at {
                return Err(ApiKeyError::Expired);
            }
        }

        // Check permissions
        if let Some(scope) = required_scope {
            let has_permission = key.scopes.iter().any(|s| s.includes(&scope));
            if !has_permission {
                return Err(ApiKeyError::InsufficientPermissions);
            }
        }

        // Check rate limit
        {
            let mut tracking = self.usage_tracking.write().unwrap();
            let usage = tracking.entry(key_id.clone()).or_default();

            // Clean up old entries (older than 1 minute)
            let cutoff = Utc::now() - chrono::Duration::minutes(1);
            usage.retain(|&ts| ts > cutoff);

            // Check rate limit
            if usage.len() >= key.rate_limit as usize {
                return Err(ApiKeyError::RateLimitExceeded);
            }

            // Record usage
            usage.push(Utc::now());
        }

        // Update usage statistics
        {
            let mut keys = self.keys.write().unwrap();
            if let Some(k) = keys.get_mut(&key_id) {
                k.usage_count += 1;
                k.last_used_at = Some(Utc::now());
                key = k.clone();
            }
        }

        debug!(key_id = %key_id, owner = %key.owner_id, "API key validated");
        Ok(key)
    }

    /// Revoke an API key
    pub fn revoke_key(&self, key_id: &str) -> bool {
        let mut keys = self.keys.write().unwrap();
        if let Some(key) = keys.get_mut(key_id) {
            key.active = false;
            true
        } else {
            false
        }
    }

    /// Delete an API key
    pub fn delete_key(&self, key_id: &str) -> bool {
        let removed = {
            let mut keys = self.keys.write().unwrap();
            keys.remove(key_id)
        };

        if let Some(key) = removed {
            let mut mapping = self.key_hash_to_id.write().unwrap();
            mapping.remove(&key.key_hash);
            true
        } else {
            false
        }
    }

    /// Get all keys for a specific owner
    pub fn get_keys_for_owner(&self, owner_id: &str) -> Vec<ApiKey> {
        let keys = self.keys.read().unwrap();
        keys.values()
            .filter(|k| k.owner_id == owner_id)
            .cloned()
            .collect()
    }

    /// Get a specific key by ID
    pub fn get_key(&self, key_id: &str) -> Option<ApiKey> {
        let keys = self.keys.read().unwrap();
        keys.get(key_id).cloned()
    }

    /// Check if an endpoint requires API key
    pub fn is_protected(&self, path: &str) -> bool {
        if self.config.require_for_all {
            return true;
        }
        self.config
            .protected_endpoints
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Hash an API key for secure storage
    fn hash_key(key: &str) -> String {
        let hash = chie_crypto::hash(key.as_bytes());
        hex::encode(hash)
    }

    /// Get configuration
    pub fn config(&self) -> &ApiKeyConfig {
        &self.config
    }
}

/// Extract API key from request headers
fn extract_api_key(headers: &HeaderMap) -> Result<String, ApiKeyError> {
    // Check Authorization header (Bearer token)
    if let Some(auth_header) = headers.get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(key) = auth_str.strip_prefix("Bearer ") {
                return Ok(key.to_string());
            }
        }
    }

    // Check X-API-Key header
    if let Some(key_header) = headers.get("X-API-Key") {
        if let Ok(key_str) = key_header.to_str() {
            return Ok(key_str.to_string());
        }
    }

    Err(ApiKeyError::MissingKey)
}

/// Middleware for API key validation
#[allow(dead_code)]
pub async fn api_key_middleware(
    manager: Arc<ApiKeyManager>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let path = req.uri().path();

    // Skip validation for unprotected endpoints
    if !manager.is_protected(path) {
        return Ok(next.run(req).await);
    }

    let headers = req.headers();

    // Extract API key
    let api_key = match extract_api_key(headers) {
        Ok(key) => key,
        Err(e) => {
            warn!(error = %e, path = %path, "API key extraction failed");
            return Err((StatusCode::UNAUTHORIZED, format!("API key required: {}", e)));
        }
    };

    // Validate the key
    match manager.validate_key(&api_key, None) {
        Ok(key_info) => {
            debug!(
                path = %path,
                key_id = %key_info.id,
                owner = %key_info.owner_id,
                "API key validated"
            );
            crate::metrics::record_auth_event("api_key", true);
            Ok(next.run(req).await)
        }
        Err(e) => {
            warn!(error = %e, path = %path, "API key validation failed");
            crate::metrics::record_auth_event("api_key", false);
            Err((
                StatusCode::UNAUTHORIZED,
                format!("API key validation failed: {}", e),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_manager_creation() {
        let manager = ApiKeyManager::with_defaults();
        assert_eq!(manager.config().default_rate_limit, 60);
    }

    #[test]
    fn test_generate_key() {
        let manager = ApiKeyManager::with_defaults();
        let mut scopes = HashSet::new();
        scopes.insert(ApiKeyScope::UserRead);
        scopes.insert(ApiKeyScope::ContentRead);

        let (raw_key, api_key) = manager.generate_key(
            "Test Key".to_string(),
            "user123".to_string(),
            scopes.clone(),
            None,
            None,
        );

        assert!(raw_key.starts_with("chie_"));
        assert_eq!(api_key.name, "Test Key");
        assert_eq!(api_key.owner_id, "user123");
        assert_eq!(api_key.scopes, scopes);
        assert!(api_key.active);
    }

    #[test]
    fn test_validate_key() {
        let manager = ApiKeyManager::with_defaults();
        let mut scopes = HashSet::new();
        scopes.insert(ApiKeyScope::UserRead);

        let (raw_key, _) = manager.generate_key(
            "Test Key".to_string(),
            "user123".to_string(),
            scopes,
            Some(100),
            None,
        );

        // Validate with correct key
        let result = manager.validate_key(&raw_key, Some(ApiKeyScope::UserRead));
        assert!(result.is_ok());

        // Validate with insufficient permissions
        let result = manager.validate_key(&raw_key, Some(ApiKeyScope::Admin));
        assert!(matches!(result, Err(ApiKeyError::InsufficientPermissions)));

        // Validate with invalid key
        let result = manager.validate_key("invalid_key", None);
        assert!(matches!(result, Err(ApiKeyError::NotFound)));
    }

    #[test]
    fn test_revoke_key() {
        let manager = ApiKeyManager::with_defaults();
        let (raw_key, api_key) = manager.generate_key(
            "Test Key".to_string(),
            "user123".to_string(),
            HashSet::new(),
            None,
            None,
        );

        // Revoke the key
        assert!(manager.revoke_key(&api_key.id));

        // Try to validate the revoked key
        let result = manager.validate_key(&raw_key, None);
        assert!(matches!(result, Err(ApiKeyError::Revoked)));
    }

    #[test]
    fn test_rate_limiting() {
        let manager = ApiKeyManager::with_defaults();
        let (raw_key, _) = manager.generate_key(
            "Test Key".to_string(),
            "user123".to_string(),
            HashSet::new(),
            Some(3), // Only 3 requests per minute
            None,
        );

        // First 3 requests should succeed
        for _ in 0..3 {
            assert!(manager.validate_key(&raw_key, None).is_ok());
        }

        // 4th request should fail
        let result = manager.validate_key(&raw_key, None);
        assert!(matches!(result, Err(ApiKeyError::RateLimitExceeded)));
    }

    #[test]
    fn test_scope_includes() {
        assert!(ApiKeyScope::All.includes(&ApiKeyScope::UserRead));
        assert!(ApiKeyScope::All.includes(&ApiKeyScope::Admin));
        assert!(ApiKeyScope::UserRead.includes(&ApiKeyScope::UserRead));
        assert!(!ApiKeyScope::UserRead.includes(&ApiKeyScope::UserWrite));
    }

    #[test]
    fn test_get_keys_for_owner() {
        let manager = ApiKeyManager::with_defaults();

        manager.generate_key(
            "Key 1".to_string(),
            "user123".to_string(),
            HashSet::new(),
            None,
            None,
        );

        manager.generate_key(
            "Key 2".to_string(),
            "user123".to_string(),
            HashSet::new(),
            None,
            None,
        );

        manager.generate_key(
            "Key 3".to_string(),
            "user456".to_string(),
            HashSet::new(),
            None,
            None,
        );

        let user123_keys = manager.get_keys_for_owner("user123");
        assert_eq!(user123_keys.len(), 2);

        let user456_keys = manager.get_keys_for_owner("user456");
        assert_eq!(user456_keys.len(), 1);
    }

    #[test]
    fn test_delete_key() {
        let manager = ApiKeyManager::with_defaults();
        let (raw_key, api_key) = manager.generate_key(
            "Test Key".to_string(),
            "user123".to_string(),
            HashSet::new(),
            None,
            None,
        );

        // Verify key exists
        assert!(manager.validate_key(&raw_key, None).is_ok());

        // Delete the key
        assert!(manager.delete_key(&api_key.id));

        // Verify key no longer exists
        let result = manager.validate_key(&raw_key, None);
        assert!(matches!(result, Err(ApiKeyError::NotFound)));
    }
}
