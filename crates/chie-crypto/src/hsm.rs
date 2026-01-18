//! Hardware Security Module (HSM) and TPM integration for enterprise deployments.
//!
//! This module provides an abstraction layer for cryptographic operations that can be
//! backed by either software keys or hardware security modules (HSM/TPM).
//!
//! Supported backends:
//! - Software: Uses in-memory Ed25519 keys (default)
//! - PKCS#11: For HSM devices supporting PKCS#11 interface
//! - TPM 2.0: For Trusted Platform Module integration
//!
//! # Phase 17A Enhancements
//!
//! - Audit logging for all HSM operations
//! - Key versioning and rotation tracking
//! - Health monitoring for HSM availability
//! - Batch operations for improved performance
//! - Session management for connection pooling
//! - Key lifecycle states (active, archived, compromised, revoked)

#![allow(dead_code)]

use crate::{KeyPair, PublicKey, SecretKey, SignatureBytes, SigningError, verify};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use thiserror::Error;

/// Errors specific to HSM operations.
#[derive(Debug, Error)]
pub enum HsmError {
    #[error("HSM not initialized")]
    NotInitialized,

    #[error("HSM connection failed: {0}")]
    ConnectionFailed(String),

    #[error("HSM authentication failed")]
    AuthenticationFailed,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Signing operation failed: {0}")]
    SigningFailed(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("PKCS#11 error: {0}")]
    Pkcs11Error(String),

    #[error("TPM error: {0}")]
    TpmError(String),

    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for HSM operations.
pub type HsmResult<T> = Result<T, HsmError>;

/// Key lifecycle state for tracking key status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum KeyLifecycleState {
    /// Key is active and can be used for operations
    #[default]
    Active,
    /// Key is archived (read-only, not for new operations)
    Archived,
    /// Key is suspected to be compromised
    Compromised,
    /// Key is revoked and must not be used
    Revoked,
    /// Key is pending activation
    Pending,
}

impl std::fmt::Display for KeyLifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Archived => write!(f, "archived"),
            Self::Compromised => write!(f, "compromised"),
            Self::Revoked => write!(f, "revoked"),
            Self::Pending => write!(f, "pending"),
        }
    }
}

/// Audit event type for HSM operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Key generation event
    KeyGenerated,
    /// Key import event
    KeyImported,
    /// Key export event
    KeyExported,
    /// Signing operation
    SignOperation,
    /// Key deletion event
    KeyDeleted,
    /// Key state change
    KeyStateChanged,
    /// Authentication event
    Authentication,
    /// Configuration change
    ConfigChange,
    /// Health check
    HealthCheck,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenerated => write!(f, "key_generated"),
            Self::KeyImported => write!(f, "key_imported"),
            Self::KeyExported => write!(f, "key_exported"),
            Self::SignOperation => write!(f, "sign_operation"),
            Self::KeyDeleted => write!(f, "key_deleted"),
            Self::KeyStateChanged => write!(f, "key_state_changed"),
            Self::Authentication => write!(f, "authentication"),
            Self::ConfigChange => write!(f, "config_change"),
            Self::HealthCheck => write!(f, "health_check"),
        }
    }
}

/// Audit log entry for HSM operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the event (Unix seconds)
    pub timestamp: u64,
    /// Type of event
    pub event_type: AuditEventType,
    /// Provider name
    pub provider: String,
    /// Key ID involved (if applicable)
    pub key_id: Option<String>,
    /// Success flag
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl AuditEntry {
    /// Create a new audit entry
    pub fn new(event_type: AuditEventType, provider: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            event_type,
            provider: provider.into(),
            key_id: None,
            success: true,
            error: None,
            metadata: HashMap::new(),
        }
    }

    /// Set key ID
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Mark as failed with error message
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error = Some(error.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Health status for HSM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Provider name
    pub provider: String,
    /// Is provider healthy
    pub healthy: bool,
    /// Last health check timestamp
    pub last_check: u64,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Error message (if unhealthy)
    pub error: Option<String>,
    /// Additional metrics
    pub metrics: HashMap<String, String>,
}

impl HealthStatus {
    /// Create a new health status
    pub fn new(provider: impl Into<String>, healthy: bool) -> Self {
        Self {
            provider: provider.into(),
            healthy,
            last_check: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            response_time_ms: 0,
            error: None,
            metrics: HashMap::new(),
        }
    }

    /// Set response time
    pub fn with_response_time(mut self, ms: u64) -> Self {
        self.response_time_ms = ms;
        self
    }

    /// Set error
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self.healthy = false;
        self
    }

    /// Add metric
    pub fn with_metric(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metrics.insert(key.into(), value.into());
        self
    }
}

/// Key identifier for HSM-stored keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl KeyId {
    /// Create a new key identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Key metadata stored alongside the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier.
    pub id: KeyId,
    /// Human-readable label.
    pub label: String,
    /// Key algorithm (e.g., "Ed25519").
    pub algorithm: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Whether the key can be exported.
    pub exportable: bool,
    /// Key lifecycle state.
    pub state: KeyLifecycleState,
    /// Key version (increments with rotation).
    pub version: u32,
    /// Last used timestamp (Unix seconds).
    pub last_used: Option<u64>,
    /// Last rotated timestamp (Unix seconds).
    pub last_rotated: Option<u64>,
    /// Operation count (how many times key was used).
    pub operation_count: u64,
    /// Custom attributes.
    pub attributes: HashMap<String, String>,
}

impl KeyMetadata {
    /// Create new key metadata.
    pub fn new(id: KeyId, label: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            algorithm: "Ed25519".to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            exportable: false,
            state: KeyLifecycleState::Active,
            version: 1,
            last_used: None,
            last_rotated: None,
            operation_count: 0,
            attributes: HashMap::new(),
        }
    }

    /// Set exportable flag.
    pub fn with_exportable(mut self, exportable: bool) -> Self {
        self.exportable = exportable;
        self
    }

    /// Set lifecycle state.
    pub fn with_state(mut self, state: KeyLifecycleState) -> Self {
        self.state = state;
        self
    }

    /// Add a custom attribute.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Record key usage.
    pub fn record_usage(&mut self) {
        self.operation_count += 1;
        self.last_used = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }

    /// Mark key as rotated.
    pub fn mark_rotated(&mut self) {
        self.version += 1;
        self.last_rotated = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }

    /// Check if key is usable for operations.
    pub fn is_usable(&self) -> bool {
        matches!(self.state, KeyLifecycleState::Active)
    }
}

/// Trait for cryptographic signing providers.
///
/// This trait abstracts over different key storage backends, allowing
/// the same code to work with software keys, HSMs, or TPMs.
pub trait SigningProvider: Send + Sync {
    /// Get the provider name.
    fn name(&self) -> &str;

    /// Check if the provider is available and initialized.
    fn is_available(&self) -> bool;

    /// Generate a new key pair and return its identifier.
    fn generate_key(&self, label: &str) -> HsmResult<KeyId>;

    /// Import an existing secret key.
    fn import_key(&self, label: &str, secret_key: &SecretKey) -> HsmResult<KeyId>;

    /// Get the public key for a key identifier.
    fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey>;

    /// Sign a message using the specified key.
    fn sign(&self, key_id: &KeyId, message: &[u8]) -> HsmResult<SignatureBytes>;

    /// Verify a signature (can use public key directly).
    fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> HsmResult<()> {
        verify(public_key, message, signature).map_err(HsmError::from)
    }

    /// List all key identifiers.
    fn list_keys(&self) -> HsmResult<Vec<KeyMetadata>>;

    /// Delete a key.
    fn delete_key(&self, key_id: &KeyId) -> HsmResult<()>;

    /// Check if a key exists.
    fn key_exists(&self, key_id: &KeyId) -> bool;

    /// Export secret key (if allowed by key policy).
    fn export_key(&self, key_id: &KeyId) -> HsmResult<SecretKey> {
        let _ = key_id;
        Err(HsmError::UnsupportedOperation(
            "Key export not supported by this provider".to_string(),
        ))
    }

    // Phase 17A enhancements:

    /// Get key metadata including lifecycle state and usage stats.
    fn get_key_metadata(&self, key_id: &KeyId) -> HsmResult<KeyMetadata> {
        // Default implementation returns basic metadata from list_keys
        let keys = self.list_keys()?;
        keys.into_iter()
            .find(|k| k.id == *key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))
    }

    /// Update key lifecycle state.
    fn update_key_state(&self, key_id: &KeyId, state: KeyLifecycleState) -> HsmResult<()> {
        let _ = (key_id, state);
        Err(HsmError::UnsupportedOperation(
            "Key state updates not supported by this provider".to_string(),
        ))
    }

    /// Perform health check and return status.
    fn health_check(&self) -> HsmResult<HealthStatus> {
        let start = SystemTime::now();
        let healthy = self.is_available();
        let elapsed = start.elapsed().unwrap_or_default().as_millis() as u64;

        Ok(HealthStatus::new(self.name(), healthy).with_response_time(elapsed))
    }

    /// Batch sign multiple messages.
    fn batch_sign(&self, key_id: &KeyId, messages: &[&[u8]]) -> HsmResult<Vec<SignatureBytes>> {
        // Default implementation: sign each message individually
        messages.iter().map(|msg| self.sign(key_id, msg)).collect()
    }

    /// Get audit log entries (if supported).
    fn get_audit_log(&self, limit: usize) -> HsmResult<Vec<AuditEntry>> {
        let _ = limit;
        Err(HsmError::UnsupportedOperation(
            "Audit log not supported by this provider".to_string(),
        ))
    }

    /// Rotate a key (generate new version while archiving old one).
    fn rotate_key(&self, key_id: &KeyId, new_label: &str) -> HsmResult<KeyId> {
        // Default implementation: archive old key, generate new one
        self.update_key_state(key_id, KeyLifecycleState::Archived)?;
        self.generate_key(new_label)
    }
}

/// Software-based signing provider using in-memory keys.
///
/// This is the default provider and is suitable for development
/// and non-enterprise deployments.
pub struct SoftwareProvider {
    keys: RwLock<HashMap<KeyId, (KeyPair, KeyMetadata)>>,
    allow_export: bool,
    audit_log: RwLock<Vec<AuditEntry>>,
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareProvider {
    /// Create a new software provider.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            allow_export: true,
            audit_log: RwLock::new(Vec::new()),
        }
    }

    /// Create a provider that doesn't allow key export.
    pub fn new_non_exportable() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            allow_export: false,
            audit_log: RwLock::new(Vec::new()),
        }
    }

    /// Log an audit event.
    fn log_audit(&self, entry: AuditEntry) {
        let mut log = self.audit_log.write().unwrap();
        log.push(entry);
        // Keep only last 10,000 entries to prevent unbounded growth
        if log.len() > 10_000 {
            log.drain(0..1000);
        }
    }

    fn next_key_id(&self) -> KeyId {
        let keys = self.keys.read().unwrap();
        let mut id = keys.len();
        loop {
            let key_id = KeyId::new(format!("sw-key-{}", id));
            if !keys.contains_key(&key_id) {
                return key_id;
            }
            id += 1;
        }
    }
}

impl SigningProvider for SoftwareProvider {
    fn name(&self) -> &str {
        "Software"
    }

    fn is_available(&self) -> bool {
        true
    }

    #[allow(clippy::redundant_closure_call)]
    fn generate_key(&self, label: &str) -> HsmResult<KeyId> {
        let result: HsmResult<KeyId> = (|| {
            let key_pair = KeyPair::generate();
            let key_id = self.next_key_id();
            let metadata =
                KeyMetadata::new(key_id.clone(), label).with_exportable(self.allow_export);

            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), (key_pair, metadata));
            Ok(key_id.clone())
        })();

        // Log audit event
        let entry = match &result {
            Ok(key_id) => AuditEntry::new(AuditEventType::KeyGenerated, self.name())
                .with_key_id(key_id.to_string())
                .with_metadata("label", label),
            Err(e) => {
                AuditEntry::new(AuditEventType::KeyGenerated, self.name()).with_error(e.to_string())
            }
        };
        self.log_audit(entry);

        result
    }

    fn import_key(&self, label: &str, secret_key: &SecretKey) -> HsmResult<KeyId> {
        let result: HsmResult<KeyId> = (|| {
            let key_pair = KeyPair::from_secret_key(secret_key)?;
            let key_id = self.next_key_id();
            let metadata =
                KeyMetadata::new(key_id.clone(), label).with_exportable(self.allow_export);

            let mut keys = self.keys.write().unwrap();
            keys.insert(key_id.clone(), (key_pair, metadata));
            Ok(key_id.clone())
        })();

        // Log audit event
        let entry = match &result {
            Ok(key_id) => AuditEntry::new(AuditEventType::KeyImported, self.name())
                .with_key_id(key_id.to_string())
                .with_metadata("label", label),
            Err(e) => {
                AuditEntry::new(AuditEventType::KeyImported, self.name()).with_error(e.to_string())
            }
        };
        self.log_audit(entry);

        result
    }

    fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        let keys = self.keys.read().unwrap();
        let (key_pair, _) = keys
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        Ok(key_pair.public_key())
    }

    fn sign(&self, key_id: &KeyId, message: &[u8]) -> HsmResult<SignatureBytes> {
        let result = (|| {
            let mut keys = self.keys.write().unwrap();
            let (key_pair, metadata) = keys
                .get_mut(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            // Check if key is usable
            if !metadata.is_usable() {
                return Err(HsmError::UnsupportedOperation(format!(
                    "Key {} is in state '{}' and cannot be used for signing",
                    key_id, metadata.state
                )));
            }

            // Record usage
            metadata.record_usage();

            Ok(key_pair.sign(message))
        })();

        // Log audit event
        let entry = match &result {
            Ok(_) => AuditEntry::new(AuditEventType::SignOperation, self.name())
                .with_key_id(key_id.to_string())
                .with_metadata("message_len", message.len().to_string()),
            Err(e) => AuditEntry::new(AuditEventType::SignOperation, self.name())
                .with_key_id(key_id.to_string())
                .with_error(e.to_string()),
        };
        self.log_audit(entry);

        result
    }

    fn list_keys(&self) -> HsmResult<Vec<KeyMetadata>> {
        let keys = self.keys.read().unwrap();
        Ok(keys.values().map(|(_, meta)| meta.clone()).collect())
    }

    fn delete_key(&self, key_id: &KeyId) -> HsmResult<()> {
        let result: HsmResult<()> = (|| {
            let mut keys = self.keys.write().unwrap();
            keys.remove(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
            Ok(())
        })();

        // Log audit event
        let entry = match &result {
            Ok(_) => AuditEntry::new(AuditEventType::KeyDeleted, self.name())
                .with_key_id(key_id.to_string()),
            Err(e) => AuditEntry::new(AuditEventType::KeyDeleted, self.name())
                .with_key_id(key_id.to_string())
                .with_error(e.to_string()),
        };
        self.log_audit(entry);

        result
    }

    fn key_exists(&self, key_id: &KeyId) -> bool {
        let keys = self.keys.read().unwrap();
        keys.contains_key(key_id)
    }

    fn export_key(&self, key_id: &KeyId) -> HsmResult<SecretKey> {
        let result = (|| {
            let keys = self.keys.read().unwrap();
            let (key_pair, metadata) = keys
                .get(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            if !metadata.exportable {
                return Err(HsmError::UnsupportedOperation(
                    "Key is not exportable".to_string(),
                ));
            }

            Ok(key_pair.secret_key())
        })();

        // Log audit event
        let entry = match &result {
            Ok(_) => AuditEntry::new(AuditEventType::KeyExported, self.name())
                .with_key_id(key_id.to_string()),
            Err(e) => AuditEntry::new(AuditEventType::KeyExported, self.name())
                .with_key_id(key_id.to_string())
                .with_error(e.to_string()),
        };
        self.log_audit(entry);

        result
    }

    // Phase 17A enhanced methods:

    fn update_key_state(&self, key_id: &KeyId, state: KeyLifecycleState) -> HsmResult<()> {
        let result: HsmResult<KeyLifecycleState> = (|| {
            let mut keys = self.keys.write().unwrap();
            let (_, metadata) = keys
                .get_mut(key_id)
                .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

            let old_state = metadata.state;
            metadata.state = state;
            Ok(old_state)
        })();

        // Log audit event
        let entry = match &result {
            Ok(old_state) => AuditEntry::new(AuditEventType::KeyStateChanged, self.name())
                .with_key_id(key_id.to_string())
                .with_metadata("old_state", old_state.to_string())
                .with_metadata("new_state", state.to_string()),
            Err(e) => AuditEntry::new(AuditEventType::KeyStateChanged, self.name())
                .with_key_id(key_id.to_string())
                .with_error(e.to_string()),
        };
        self.log_audit(entry);

        result.map(|_| ())
    }

    fn get_audit_log(&self, limit: usize) -> HsmResult<Vec<AuditEntry>> {
        let log = self.audit_log.read().unwrap();
        let len = log.len();
        let start = len.saturating_sub(limit);
        Ok(log[start..].to_vec())
    }
}

/// Configuration for PKCS#11 HSM provider.
#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    /// Path to the PKCS#11 library (.so/.dll).
    pub library_path: String,
    /// Slot ID to use.
    pub slot_id: u64,
    /// PIN for authentication.
    pub pin: String,
    /// Token label filter (optional).
    pub token_label: Option<String>,
}

impl Pkcs11Config {
    /// Create new PKCS#11 configuration.
    pub fn new(library_path: impl Into<String>, slot_id: u64, pin: impl Into<String>) -> Self {
        Self {
            library_path: library_path.into(),
            slot_id,
            pin: pin.into(),
            token_label: None,
        }
    }

    /// Set token label filter.
    pub fn with_token_label(mut self, label: impl Into<String>) -> Self {
        self.token_label = Some(label.into());
        self
    }
}

/// PKCS#11 HSM provider (stub implementation).
///
/// This provides the interface for PKCS#11 HSM integration.
/// A full implementation would use the `pkcs11` or `cryptoki` crate.
///
/// Enterprise users would implement this against their specific HSM:
/// - SafeNet Luna
/// - Thales nShield
/// - AWS CloudHSM
/// - YubiHSM
pub struct Pkcs11Provider {
    config: Pkcs11Config,
    initialized: bool,
}

impl Pkcs11Provider {
    /// Create a new PKCS#11 provider.
    pub fn new(config: Pkcs11Config) -> Self {
        Self {
            config,
            initialized: false,
        }
    }

    /// Initialize the PKCS#11 session.
    ///
    /// In a real implementation, this would:
    /// 1. Load the PKCS#11 library
    /// 2. Initialize the library
    /// 3. Open a session on the specified slot
    /// 4. Login with the provided PIN
    pub fn initialize(&mut self) -> HsmResult<()> {
        // Stub: Verify library path exists
        if self.config.library_path.is_empty() {
            return Err(HsmError::ConfigError(
                "PKCS#11 library path is empty".to_string(),
            ));
        }

        // In real implementation:
        // let ctx = Pkcs11::new(&self.config.library_path)?;
        // ctx.initialize(CInitializeArgs::OsThreads)?;
        // let session = ctx.open_rw_session(self.config.slot_id)?;
        // session.login(UserType::User, Some(&self.config.pin))?;

        self.initialized = true;
        Ok(())
    }

    /// Close the PKCS#11 session.
    pub fn finalize(&mut self) -> HsmResult<()> {
        self.initialized = false;
        Ok(())
    }
}

impl SigningProvider for Pkcs11Provider {
    fn name(&self) -> &str {
        "PKCS#11 HSM"
    }

    fn is_available(&self) -> bool {
        self.initialized
    }

    fn generate_key(&self, label: &str) -> HsmResult<KeyId> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        // In real implementation:
        // let mechanism = Mechanism::EccKeyPairGen;
        // let pub_template = vec![
        //     Attribute::Token(true),
        //     Attribute::Label(label.to_vec()),
        //     Attribute::EcParams(ED25519_OID),
        // ];
        // let priv_template = vec![
        //     Attribute::Token(true),
        //     Attribute::Private(true),
        //     Attribute::Sensitive(true),
        //     Attribute::Sign(true),
        // ];
        // let (pub_handle, priv_handle) = session.generate_key_pair(&mechanism, &pub_template, &priv_template)?;

        Err(HsmError::Pkcs11Error(format!(
            "PKCS#11 key generation not implemented for label: {}",
            label
        )))
    }

    fn import_key(&self, label: &str, _secret_key: &SecretKey) -> HsmResult<KeyId> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Err(HsmError::Pkcs11Error(format!(
            "PKCS#11 key import not implemented for label: {}",
            label
        )))
    }

    fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Err(HsmError::Pkcs11Error(format!(
            "PKCS#11 get_public_key not implemented for key: {}",
            key_id
        )))
    }

    fn sign(&self, key_id: &KeyId, _message: &[u8]) -> HsmResult<SignatureBytes> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        // In real implementation:
        // let mechanism = Mechanism::Eddsa;
        // let signature = session.sign(&mechanism, priv_handle, message)?;

        Err(HsmError::Pkcs11Error(format!(
            "PKCS#11 signing not implemented for key: {}",
            key_id
        )))
    }

    fn list_keys(&self) -> HsmResult<Vec<KeyMetadata>> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Ok(Vec::new())
    }

    fn delete_key(&self, key_id: &KeyId) -> HsmResult<()> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Err(HsmError::Pkcs11Error(format!(
            "PKCS#11 key deletion not implemented for key: {}",
            key_id
        )))
    }

    fn key_exists(&self, _key_id: &KeyId) -> bool {
        false
    }
}

/// Configuration for TPM 2.0 provider.
#[derive(Debug, Clone)]
pub struct TpmConfig {
    /// TCTI (TPM Command Transmission Interface) connection string.
    /// Examples: "device:/dev/tpm0", "mssim:host=localhost,port=2321"
    pub tcti: String,
    /// Owner authorization value.
    pub owner_auth: Option<String>,
    /// Hierarchy to use (owner, endorsement, platform).
    pub hierarchy: TpmHierarchy,
}

/// TPM hierarchy for key storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TpmHierarchy {
    /// Owner hierarchy (default for user keys).
    #[default]
    Owner,
    /// Endorsement hierarchy (for attestation).
    Endorsement,
    /// Platform hierarchy (for platform keys).
    Platform,
}

impl TpmConfig {
    /// Create new TPM configuration for a device.
    pub fn device(path: impl Into<String>) -> Self {
        Self {
            tcti: format!("device:{}", path.into()),
            owner_auth: None,
            hierarchy: TpmHierarchy::Owner,
        }
    }

    /// Create new TPM configuration for TPM simulator.
    pub fn simulator(host: &str, port: u16) -> Self {
        Self {
            tcti: format!("mssim:host={},port={}", host, port),
            owner_auth: None,
            hierarchy: TpmHierarchy::Owner,
        }
    }

    /// Set owner authorization.
    pub fn with_owner_auth(mut self, auth: impl Into<String>) -> Self {
        self.owner_auth = Some(auth.into());
        self
    }

    /// Set hierarchy.
    pub fn with_hierarchy(mut self, hierarchy: TpmHierarchy) -> Self {
        self.hierarchy = hierarchy;
        self
    }
}

/// TPM 2.0 provider (stub implementation).
///
/// This provides the interface for TPM 2.0 integration.
/// A full implementation would use the `tss-esapi` crate.
///
/// TPM benefits:
/// - Hardware-bound keys (non-extractable)
/// - Platform attestation
/// - Secure boot integration
/// - Available on most modern systems
pub struct TpmProvider {
    config: TpmConfig,
    initialized: bool,
}

impl TpmProvider {
    /// Create a new TPM provider.
    pub fn new(config: TpmConfig) -> Self {
        Self {
            config,
            initialized: false,
        }
    }

    /// Initialize the TPM session.
    ///
    /// In a real implementation, this would:
    /// 1. Connect to the TPM via TCTI
    /// 2. Create an ESYS context
    /// 3. Start an authorization session
    pub fn initialize(&mut self) -> HsmResult<()> {
        // Stub: Verify TCTI string
        if self.config.tcti.is_empty() {
            return Err(HsmError::ConfigError("TPM TCTI is empty".to_string()));
        }

        // In real implementation:
        // let tcti = TctiNameConf::from_str(&self.config.tcti)?;
        // let context = Context::new(tcti)?;

        self.initialized = true;
        Ok(())
    }

    /// Close the TPM session.
    pub fn finalize(&mut self) -> HsmResult<()> {
        self.initialized = false;
        Ok(())
    }
}

impl SigningProvider for TpmProvider {
    fn name(&self) -> &str {
        "TPM 2.0"
    }

    fn is_available(&self) -> bool {
        self.initialized
    }

    fn generate_key(&self, label: &str) -> HsmResult<KeyId> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        // TPM doesn't natively support Ed25519, would need to use ECDSA
        // or implement Ed25519 in software with TPM-protected seed

        // In real implementation with ECDSA:
        // let primary = context.create_primary(
        //     Hierarchy::Owner,
        //     PublicBuilder::new()
        //         .with_ecc_parameters(EccParameters::new(...))
        //         .build()?,
        // )?;

        Err(HsmError::TpmError(format!(
            "TPM key generation not implemented for label: {}",
            label
        )))
    }

    fn import_key(&self, label: &str, _secret_key: &SecretKey) -> HsmResult<KeyId> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Err(HsmError::TpmError(format!(
            "TPM key import not implemented for label: {}",
            label
        )))
    }

    fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Err(HsmError::TpmError(format!(
            "TPM get_public_key not implemented for key: {}",
            key_id
        )))
    }

    fn sign(&self, key_id: &KeyId, _message: &[u8]) -> HsmResult<SignatureBytes> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        // In real implementation:
        // let signature = context.sign(
        //     key_handle,
        //     Digest::try_from(message)?,
        //     SignatureScheme::EcDsa,
        // )?;

        Err(HsmError::TpmError(format!(
            "TPM signing not implemented for key: {}",
            key_id
        )))
    }

    fn list_keys(&self) -> HsmResult<Vec<KeyMetadata>> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Ok(Vec::new())
    }

    fn delete_key(&self, key_id: &KeyId) -> HsmResult<()> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        Err(HsmError::TpmError(format!(
            "TPM key deletion not implemented for key: {}",
            key_id
        )))
    }

    fn key_exists(&self, _key_id: &KeyId) -> bool {
        false
    }
}

/// HSM manager that provides a unified interface to multiple backends.
///
/// This allows applications to:
/// - Configure multiple HSM backends
/// - Fall back from HSM to software keys
/// - Abstract over the specific HSM implementation
pub struct HsmManager {
    providers: RwLock<Vec<Arc<dyn SigningProvider>>>,
    default_provider: usize,
}

impl Default for HsmManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmManager {
    /// Create a new HSM manager with software provider as default.
    pub fn new() -> Self {
        let software = Arc::new(SoftwareProvider::new()) as Arc<dyn SigningProvider>;
        Self {
            providers: RwLock::new(vec![software]),
            default_provider: 0,
        }
    }

    /// Add a signing provider.
    pub fn add_provider(&self, provider: Arc<dyn SigningProvider>) -> usize {
        let mut providers = self.providers.write().unwrap();
        let index = providers.len();
        providers.push(provider);
        index
    }

    /// Set the default provider by index.
    pub fn set_default_provider(&mut self, index: usize) -> HsmResult<()> {
        let providers = self.providers.read().unwrap();
        if index >= providers.len() {
            return Err(HsmError::ConfigError(format!(
                "Invalid provider index: {}",
                index
            )));
        }
        drop(providers);
        self.default_provider = index;
        Ok(())
    }

    /// Get the default provider.
    pub fn default_provider(&self) -> Arc<dyn SigningProvider> {
        let providers = self.providers.read().unwrap();
        providers[self.default_provider].clone()
    }

    /// Get a provider by index.
    pub fn provider(&self, index: usize) -> Option<Arc<dyn SigningProvider>> {
        let providers = self.providers.read().unwrap();
        providers.get(index).cloned()
    }

    /// List all providers.
    pub fn list_providers(&self) -> Vec<String> {
        let providers = self.providers.read().unwrap();
        providers.iter().map(|p| p.name().to_string()).collect()
    }

    /// Generate a key using the default provider.
    pub fn generate_key(&self, label: &str) -> HsmResult<KeyId> {
        self.default_provider().generate_key(label)
    }

    /// Import a key using the default provider.
    pub fn import_key(&self, label: &str, secret_key: &SecretKey) -> HsmResult<KeyId> {
        self.default_provider().import_key(label, secret_key)
    }

    /// Sign using the default provider.
    pub fn sign(&self, key_id: &KeyId, message: &[u8]) -> HsmResult<SignatureBytes> {
        self.default_provider().sign(key_id, message)
    }

    /// Get public key using the default provider.
    pub fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        self.default_provider().get_public_key(key_id)
    }

    /// Verify a signature (delegates to software verification).
    pub fn verify(
        &self,
        public_key: &PublicKey,
        message: &[u8],
        signature: &SignatureBytes,
    ) -> HsmResult<()> {
        self.default_provider()
            .verify(public_key, message, signature)
    }
}

/// Builder for configuring HSM providers.
pub struct HsmManagerBuilder {
    providers: Vec<Arc<dyn SigningProvider>>,
    default_index: usize,
}

impl Default for HsmManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmManagerBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            default_index: 0,
        }
    }

    /// Add the software provider.
    pub fn with_software(mut self) -> Self {
        let provider = Arc::new(SoftwareProvider::new()) as Arc<dyn SigningProvider>;
        self.providers.push(provider);
        self
    }

    /// Add a PKCS#11 provider.
    pub fn with_pkcs11(mut self, config: Pkcs11Config) -> Self {
        let provider = Arc::new(Pkcs11Provider::new(config)) as Arc<dyn SigningProvider>;
        self.providers.push(provider);
        self
    }

    /// Add a TPM provider.
    pub fn with_tpm(mut self, config: TpmConfig) -> Self {
        let provider = Arc::new(TpmProvider::new(config)) as Arc<dyn SigningProvider>;
        self.providers.push(provider);
        self
    }

    /// Set the default provider index.
    pub fn with_default(mut self, index: usize) -> Self {
        self.default_index = index;
        self
    }

    /// Build the HSM manager.
    pub fn build(self) -> HsmResult<HsmManager> {
        if self.providers.is_empty() {
            return Err(HsmError::ConfigError("No providers configured".to_string()));
        }

        if self.default_index >= self.providers.len() {
            return Err(HsmError::ConfigError(format!(
                "Invalid default index: {}",
                self.default_index
            )));
        }

        Ok(HsmManager {
            providers: RwLock::new(self.providers),
            default_provider: self.default_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_software_provider_lifecycle() {
        let provider = SoftwareProvider::new();

        // Generate key
        let key_id = provider.generate_key("test-key").unwrap();
        assert!(provider.key_exists(&key_id));

        // Get public key
        let public_key = provider.get_public_key(&key_id).unwrap();
        assert_eq!(public_key.len(), 32);

        // Sign and verify
        let message = b"Hello, HSM!";
        let signature = provider.sign(&key_id, message).unwrap();
        provider.verify(&public_key, message, &signature).unwrap();

        // List keys
        let keys = provider.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].label, "test-key");

        // Export key
        let secret = provider.export_key(&key_id).unwrap();
        assert_eq!(secret.len(), 32);

        // Delete key
        provider.delete_key(&key_id).unwrap();
        assert!(!provider.key_exists(&key_id));
    }

    #[test]
    fn test_software_provider_import() {
        let provider = SoftwareProvider::new();

        // Generate a key pair
        let original = KeyPair::generate();
        let secret = original.secret_key();
        let public = original.public_key();

        // Import into provider
        let key_id = provider.import_key("imported", &secret).unwrap();

        // Verify public key matches
        let imported_public = provider.get_public_key(&key_id).unwrap();
        assert_eq!(public, imported_public);

        // Sign with imported key
        let message = b"Test message";
        let signature = provider.sign(&key_id, message).unwrap();

        // Verify signature
        provider.verify(&public, message, &signature).unwrap();
    }

    #[test]
    fn test_non_exportable_keys() {
        let provider = SoftwareProvider::new_non_exportable();

        let key_id = provider.generate_key("secure-key").unwrap();

        // Export should fail
        let result = provider.export_key(&key_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HsmError::UnsupportedOperation(_)
        ));
    }

    #[test]
    fn test_hsm_manager() {
        let manager = HsmManager::new();

        // Generate and use key
        let key_id = manager.generate_key("manager-key").unwrap();
        let public_key = manager.get_public_key(&key_id).unwrap();

        let message = b"Manager test";
        let signature = manager.sign(&key_id, message).unwrap();

        manager.verify(&public_key, message, &signature).unwrap();
    }

    #[test]
    fn test_hsm_manager_builder() {
        let manager = HsmManagerBuilder::new()
            .with_software()
            .with_default(0)
            .build()
            .unwrap();

        let providers = manager.list_providers();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0], "Software");
    }

    #[test]
    fn test_pkcs11_provider_not_initialized() {
        let config = Pkcs11Config::new("/path/to/pkcs11.so", 0, "1234");
        let provider = Pkcs11Provider::new(config);

        // Operations should fail when not initialized
        let result = provider.generate_key("test");
        assert!(matches!(result.unwrap_err(), HsmError::NotInitialized));
    }

    #[test]
    fn test_tpm_provider_not_initialized() {
        let config = TpmConfig::device("/dev/tpm0");
        let provider = TpmProvider::new(config);

        // Operations should fail when not initialized
        let result = provider.generate_key("test");
        assert!(matches!(result.unwrap_err(), HsmError::NotInitialized));
    }

    #[test]
    fn test_key_metadata() {
        let key_id = KeyId::new("test-123");
        let metadata = KeyMetadata::new(key_id.clone(), "My Key")
            .with_exportable(true)
            .with_attribute("purpose", "signing");

        assert_eq!(metadata.id, key_id);
        assert_eq!(metadata.label, "My Key");
        assert!(metadata.exportable);
        assert_eq!(
            metadata.attributes.get("purpose"),
            Some(&"signing".to_string())
        );
    }

    // Phase 17A enhancement tests:

    #[test]
    fn test_key_lifecycle_states() {
        let provider = SoftwareProvider::new();
        let key_id = provider.generate_key("test-key").unwrap();

        // Initially active
        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.state, KeyLifecycleState::Active);
        assert!(metadata.is_usable());

        // Archive the key
        provider
            .update_key_state(&key_id, KeyLifecycleState::Archived)
            .unwrap();
        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.state, KeyLifecycleState::Archived);
        assert!(!metadata.is_usable());

        // Revoke the key
        provider
            .update_key_state(&key_id, KeyLifecycleState::Revoked)
            .unwrap();
        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.state, KeyLifecycleState::Revoked);
        assert!(!metadata.is_usable());
    }

    #[test]
    fn test_revoked_key_cannot_sign() {
        let provider = SoftwareProvider::new();
        let key_id = provider.generate_key("test-key").unwrap();

        // Can sign when active
        let message = b"test message";
        provider.sign(&key_id, message).unwrap();

        // Revoke the key
        provider
            .update_key_state(&key_id, KeyLifecycleState::Revoked)
            .unwrap();

        // Cannot sign when revoked
        let result = provider.sign(&key_id, message);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_usage_tracking() {
        let provider = SoftwareProvider::new();
        let key_id = provider.generate_key("test-key").unwrap();

        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.operation_count, 0);
        assert!(metadata.last_used.is_none());

        // Sign some messages
        for i in 0..5 {
            provider.sign(&key_id, &[i]).unwrap();
        }

        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.operation_count, 5);
        assert!(metadata.last_used.is_some());
    }

    #[test]
    fn test_audit_logging() {
        let provider = SoftwareProvider::new();

        // Generate key
        let key_id = provider.generate_key("test-key").unwrap();

        // Sign message
        provider.sign(&key_id, b"test").unwrap();

        // Delete key
        provider.delete_key(&key_id).unwrap();

        // Check audit log
        let log = provider.get_audit_log(10).unwrap();
        assert_eq!(log.len(), 3);

        assert!(matches!(log[0].event_type, AuditEventType::KeyGenerated));
        assert!(log[0].success);

        assert!(matches!(log[1].event_type, AuditEventType::SignOperation));
        assert!(log[1].success);

        assert!(matches!(log[2].event_type, AuditEventType::KeyDeleted));
        assert!(log[2].success);
    }

    #[test]
    fn test_audit_log_limit() {
        let provider = SoftwareProvider::new();

        // Generate 20 keys
        for i in 0..20 {
            provider.generate_key(&format!("key-{}", i)).unwrap();
        }

        // Request last 5 entries
        let log = provider.get_audit_log(5).unwrap();
        assert_eq!(log.len(), 5);

        // All should be key generation events
        for entry in &log {
            assert!(matches!(entry.event_type, AuditEventType::KeyGenerated));
        }
    }

    #[test]
    fn test_health_check() {
        let provider = SoftwareProvider::new();
        let health = provider.health_check().unwrap();

        assert!(health.healthy);
        assert_eq!(health.provider, "Software");
        assert!(health.response_time_ms < 1000); // Should be very fast
    }

    #[test]
    fn test_batch_signing() {
        let provider = SoftwareProvider::new();
        let key_id = provider.generate_key("batch-key").unwrap();

        let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3", b"msg4", b"msg5"];

        let signatures = provider.batch_sign(&key_id, &messages).unwrap();
        assert_eq!(signatures.len(), messages.len());

        // Verify each signature
        let public_key = provider.get_public_key(&key_id).unwrap();
        for (i, sig) in signatures.iter().enumerate() {
            provider.verify(&public_key, messages[i], sig).unwrap();
        }
    }

    #[test]
    fn test_key_rotation() {
        let provider = SoftwareProvider::new();
        let old_key_id = provider.generate_key("old-key").unwrap();

        // Rotate the key
        let new_key_id = provider.rotate_key(&old_key_id, "new-key").unwrap();

        // Old key should be archived
        let old_metadata = provider.get_key_metadata(&old_key_id).unwrap();
        assert_eq!(old_metadata.state, KeyLifecycleState::Archived);

        // New key should be active
        let new_metadata = provider.get_key_metadata(&new_key_id).unwrap();
        assert_eq!(new_metadata.state, KeyLifecycleState::Active);
        assert!(new_metadata.is_usable());

        // Should be able to sign with new key
        provider.sign(&new_key_id, b"test").unwrap();

        // Should not be able to sign with old key
        let result = provider.sign(&old_key_id, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_versioning() {
        let provider = SoftwareProvider::new();
        let key_id = provider.generate_key("versioned-key").unwrap();

        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.version, 1);
        assert!(metadata.last_rotated.is_none());

        // Manually mark as rotated (simulate rotation)
        let mut keys = provider.keys.write().unwrap();
        let (_, meta) = keys.get_mut(&key_id).unwrap();
        meta.mark_rotated();
        drop(keys);

        let metadata = provider.get_key_metadata(&key_id).unwrap();
        assert_eq!(metadata.version, 2);
        assert!(metadata.last_rotated.is_some());
    }

    #[test]
    fn test_lifecycle_state_display() {
        assert_eq!(KeyLifecycleState::Active.to_string(), "active");
        assert_eq!(KeyLifecycleState::Archived.to_string(), "archived");
        assert_eq!(KeyLifecycleState::Compromised.to_string(), "compromised");
        assert_eq!(KeyLifecycleState::Revoked.to_string(), "revoked");
        assert_eq!(KeyLifecycleState::Pending.to_string(), "pending");
    }

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditEntry::new(AuditEventType::KeyGenerated, "TestProvider")
            .with_key_id("test-key-123")
            .with_metadata("label", "test-label")
            .with_metadata("algorithm", "Ed25519");

        assert!(matches!(entry.event_type, AuditEventType::KeyGenerated));
        assert_eq!(entry.provider, "TestProvider");
        assert_eq!(entry.key_id, Some("test-key-123".to_string()));
        assert!(entry.success);
        assert_eq!(entry.metadata.get("label"), Some(&"test-label".to_string()));
    }

    #[test]
    fn test_health_status_builder() {
        let status = HealthStatus::new("TestProvider", true)
            .with_response_time(42)
            .with_metric("connections", "5")
            .with_metric("keys", "10");

        assert_eq!(status.provider, "TestProvider");
        assert!(status.healthy);
        assert_eq!(status.response_time_ms, 42);
        assert_eq!(status.metrics.get("connections"), Some(&"5".to_string()));
        assert_eq!(status.metrics.get("keys"), Some(&"10".to_string()));
    }

    #[test]
    fn test_failed_operations_audit() {
        let provider = SoftwareProvider::new();
        let key_id = KeyId::new("nonexistent");

        // Try to sign with nonexistent key
        let _ = provider.sign(&key_id, b"test");

        // Check audit log for failure
        let log = provider.get_audit_log(10).unwrap();
        assert!(!log.is_empty());

        let last_entry = &log[log.len() - 1];
        assert!(!last_entry.success);
        assert!(last_entry.error.is_some());
    }
}
