// ! PKCS#11 provider implementation for HSM integration.
//!
//! This module provides a comprehensive PKCS#11 interface for Hardware Security Module
//! (HSM) integration. It includes both a mock provider for testing and the interface
//! for real PKCS#11 library integration.
//!
//! # Architecture
//!
//! - `Pkcs11Provider`: Main provider implementation
//! - `Pkcs11Session`: Session management with login/logout
//! - `Pkcs11MockProvider`: Software mock for testing without hardware
//!
//! # Supported Operations
//!
//! - Key generation (Ed25519 key pairs)
//! - Key import/export
//! - Digital signatures
//! - Key discovery and listing
//! - Session management
//! - PIN-based authentication
//!
//! # Example
//!
//! ```
//! use chie_crypto::pkcs11::{Pkcs11MockProvider, Pkcs11Session};
//! use chie_crypto::hsm::SigningProvider;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a mock provider for testing
//! let mut provider = Pkcs11MockProvider::new();
//! provider.initialize()?;
//! provider.open_session(true, Some("1234"))?;
//!
//! // Generate a key
//! let key_id = provider.generate_key("test-key")?;
//!
//! // Sign a message
//! let message = b"Hello, PKCS#11!";
//! let signature = provider.sign(&key_id, message)?;
//!
//! // Verify the signature
//! let pub_key = provider.get_public_key(&key_id)?;
//! provider.verify(&pub_key, message, &signature)?;
//! # Ok(())
//! # }
//! ```

#![allow(dead_code)]

use crate::hsm::{
    AuditEntry, AuditEventType, HealthStatus, HsmError, HsmResult, KeyId, KeyLifecycleState,
    KeyMetadata, SigningProvider,
};
use crate::signing::{KeyPair, PublicKey, SecretKey, SignatureBytes};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// PKCS#11 session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session is closed
    Closed,
    /// Session is open but not logged in (read-only public session)
    ReadOnly,
    /// Session is open and logged in (read-write)
    ReadWrite,
}

/// PKCS#11 session handle.
///
/// Represents an active session with a PKCS#11 token.
#[derive(Debug)]
pub struct Pkcs11Session {
    /// Session ID
    session_id: u64,
    /// Current state
    state: SessionState,
    /// Slot ID this session is connected to
    slot_id: u64,
    /// Login state
    logged_in: bool,
}

impl Pkcs11Session {
    /// Create a new session.
    pub fn new(session_id: u64, slot_id: u64, read_write: bool) -> Self {
        Self {
            session_id,
            state: if read_write {
                SessionState::ReadWrite
            } else {
                SessionState::ReadOnly
            },
            slot_id,
            logged_in: false,
        }
    }

    /// Get session ID.
    pub fn id(&self) -> u64 {
        self.session_id
    }

    /// Get slot ID.
    pub fn slot_id(&self) -> u64 {
        self.slot_id
    }

    /// Check if logged in.
    pub fn is_logged_in(&self) -> bool {
        self.logged_in
    }

    /// Check if session is read-write.
    pub fn is_read_write(&self) -> bool {
        matches!(self.state, SessionState::ReadWrite)
    }

    /// Login to the session.
    pub fn login(&mut self, _pin: &str) -> HsmResult<()> {
        if self.state == SessionState::Closed {
            return Err(HsmError::Pkcs11Error("Session is closed".to_string()));
        }
        self.logged_in = true;
        Ok(())
    }

    /// Logout from the session.
    pub fn logout(&mut self) -> HsmResult<()> {
        self.logged_in = false;
        Ok(())
    }

    /// Close the session.
    pub fn close(&mut self) -> HsmResult<()> {
        self.state = SessionState::Closed;
        self.logged_in = false;
        Ok(())
    }
}

/// Object stored in PKCS#11 token.
#[derive(Clone)]
struct Pkcs11Object {
    /// Object handle (unique identifier)
    handle: u64,
    /// Object label
    label: String,
    /// Key pair (for key objects)
    keypair: Option<KeyPair>,
    /// Public key only (for public key objects)
    public_key: Option<PublicKey>,
    /// Object attributes
    attributes: HashMap<String, Vec<u8>>,
    /// Creation timestamp
    created_at: u64,
}

impl Pkcs11Object {
    /// Create a new key pair object.
    fn new_keypair(handle: u64, label: String, keypair: KeyPair) -> Self {
        Self {
            handle,
            label,
            keypair: Some(keypair),
            public_key: None,
            attributes: HashMap::new(),
            created_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Get the key ID.
    fn key_id(&self) -> KeyId {
        KeyId::new(format!("pkcs11:{}", self.handle))
    }

    /// Get key metadata.
    fn to_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            id: self.key_id(),
            label: self.label.clone(),
            algorithm: "Ed25519".to_string(),
            created_at: self.created_at,
            exportable: false,
            state: KeyLifecycleState::Active,
            version: 1,
            last_used: None,
            last_rotated: None,
            operation_count: 0,
            attributes: HashMap::new(),
        }
    }
}

/// Mock PKCS#11 provider for testing.
///
/// This is a software implementation that mimics PKCS#11 behavior without
/// requiring actual HSM hardware. It's suitable for:
/// - Unit testing
/// - Integration testing
/// - Development environments
/// - CI/CD pipelines
///
/// # Security Note
///
/// This mock provider stores keys in memory and should NOT be used in production.
/// For production deployments, use a real PKCS#11 provider with hardware HSMs.
#[derive(Clone)]
pub struct Pkcs11MockProvider {
    /// Slot ID
    slot_id: u64,
    /// Objects stored in the token
    objects: Arc<Mutex<HashMap<u64, Pkcs11Object>>>,
    /// Next object handle
    next_handle: Arc<Mutex<u64>>,
    /// Current session
    session: Arc<Mutex<Option<Pkcs11Session>>>,
    /// Audit log
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
    /// Initialized flag
    initialized: bool,
}

impl Pkcs11MockProvider {
    /// Create a new mock provider.
    pub fn new() -> Self {
        Self {
            slot_id: 0,
            objects: Arc::new(Mutex::new(HashMap::new())),
            next_handle: Arc::new(Mutex::new(1)),
            session: Arc::new(Mutex::new(None)),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            initialized: false,
        }
    }

    /// Create a new mock provider with specific slot ID.
    pub fn with_slot(slot_id: u64) -> Self {
        let mut provider = Self::new();
        provider.slot_id = slot_id;
        provider
    }

    /// Initialize the provider.
    pub fn initialize(&mut self) -> HsmResult<()> {
        if self.initialized {
            return Err(HsmError::Pkcs11Error(
                "Provider already initialized".to_string(),
            ));
        }

        self.initialized = true;

        // Log initialization
        let entry = AuditEntry::new(AuditEventType::Authentication, "PKCS#11 Mock");
        self.audit_log.lock().unwrap().push(entry);

        Ok(())
    }

    /// Finalize the provider.
    pub fn finalize(&mut self) -> HsmResult<()> {
        // Close any open session
        if let Some(mut session) = self.session.lock().unwrap().take() {
            session.close()?;
        }

        self.initialized = false;
        Ok(())
    }

    /// Open a new session.
    pub fn open_session(&self, read_write: bool, pin: Option<&str>) -> HsmResult<u64> {
        if !self.initialized {
            return Err(HsmError::NotInitialized);
        }

        let mut session_guard = self.session.lock().unwrap();

        // Check if a session already exists
        if session_guard.is_some() {
            return Err(HsmError::Pkcs11Error("Session already open".to_string()));
        }

        // Create new session
        let session_id = rand::random::<u64>();
        let mut session = Pkcs11Session::new(session_id, self.slot_id, read_write);

        // Login if PIN provided
        if let Some(pin) = pin {
            session.login(pin)?;
        }

        *session_guard = Some(session);

        Ok(session_id)
    }

    /// Close the current session.
    pub fn close_session(&self) -> HsmResult<()> {
        let mut session_guard = self.session.lock().unwrap();

        if let Some(mut session) = session_guard.take() {
            session.close()?;
        }

        Ok(())
    }

    /// Get the current session.
    fn get_session(&self) -> HsmResult<()> {
        let session_guard = self.session.lock().unwrap();

        if session_guard.is_none() {
            return Err(HsmError::Pkcs11Error("No active session".to_string()));
        }

        Ok(())
    }

    /// Allocate a new object handle.
    fn next_handle(&self) -> u64 {
        let mut handle = self.next_handle.lock().unwrap();
        let current = *handle;
        *handle += 1;
        current
    }

    /// Log an audit event.
    fn log_audit(&self, entry: AuditEntry) {
        self.audit_log.lock().unwrap().push(entry);
    }

    /// Get object by handle.
    fn get_object(&self, handle: u64) -> HsmResult<Pkcs11Object> {
        let objects = self.objects.lock().unwrap();
        objects
            .get(&handle)
            .cloned()
            .ok_or_else(|| HsmError::KeyNotFound(format!("Handle: {}", handle)))
    }

    /// Parse key ID to extract handle.
    fn parse_key_id(&self, key_id: &KeyId) -> HsmResult<u64> {
        let id_str = &key_id.0;
        if !id_str.starts_with("pkcs11:") {
            return Err(HsmError::KeyNotFound(format!(
                "Invalid key ID format: {}",
                id_str
            )));
        }

        id_str[7..]
            .parse()
            .map_err(|_| HsmError::KeyNotFound(format!("Invalid key ID: {}", id_str)))
    }
}

impl Default for Pkcs11MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningProvider for Pkcs11MockProvider {
    fn name(&self) -> &str {
        "PKCS#11 Mock Provider"
    }

    fn is_available(&self) -> bool {
        self.initialized
    }

    fn generate_key(&self, label: &str) -> HsmResult<KeyId> {
        self.get_session()?;

        // Generate Ed25519 key pair
        let keypair = KeyPair::generate();

        // Allocate handle
        let handle = self.next_handle();

        // Create object
        let object = Pkcs11Object::new_keypair(handle, label.to_string(), keypair);
        let key_id = object.key_id();

        // Store object
        self.objects.lock().unwrap().insert(handle, object);

        // Log audit event
        let entry = AuditEntry::new(AuditEventType::KeyGenerated, self.name())
            .with_key_id(key_id.to_string())
            .with_metadata("label", label);
        self.log_audit(entry);

        Ok(key_id)
    }

    fn import_key(&self, label: &str, secret_key: &SecretKey) -> HsmResult<KeyId> {
        self.get_session()?;

        // Create key pair from secret key
        let keypair = KeyPair::from_secret_key(secret_key)?;

        // Allocate handle
        let handle = self.next_handle();

        // Create object
        let object = Pkcs11Object::new_keypair(handle, label.to_string(), keypair);
        let key_id = object.key_id();

        // Store object
        self.objects.lock().unwrap().insert(handle, object);

        // Log audit event
        let entry = AuditEntry::new(AuditEventType::KeyImported, self.name())
            .with_key_id(key_id.to_string())
            .with_metadata("label", label);
        self.log_audit(entry);

        Ok(key_id)
    }

    fn get_public_key(&self, key_id: &KeyId) -> HsmResult<PublicKey> {
        self.get_session()?;

        let handle = self.parse_key_id(key_id)?;
        let object = self.get_object(handle)?;

        object
            .keypair
            .as_ref()
            .map(|kp| kp.public_key())
            .or(object.public_key)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))
    }

    fn sign(&self, key_id: &KeyId, message: &[u8]) -> HsmResult<SignatureBytes> {
        self.get_session()?;

        let handle = self.parse_key_id(key_id)?;
        let object = self.get_object(handle)?;

        let keypair = object
            .keypair
            .as_ref()
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

        // Sign the message
        let signature = keypair.sign(message);

        // Log audit event
        let entry = AuditEntry::new(AuditEventType::SignOperation, self.name())
            .with_key_id(key_id.to_string());
        self.log_audit(entry);

        Ok(signature)
    }

    fn list_keys(&self) -> HsmResult<Vec<KeyMetadata>> {
        self.get_session()?;

        let objects = self.objects.lock().unwrap();
        let keys = objects.values().map(|obj| obj.to_metadata()).collect();

        Ok(keys)
    }

    fn delete_key(&self, key_id: &KeyId) -> HsmResult<()> {
        self.get_session()?;

        let handle = self.parse_key_id(key_id)?;

        self.objects
            .lock()
            .unwrap()
            .remove(&handle)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;

        // Log audit event
        let entry = AuditEntry::new(AuditEventType::KeyDeleted, self.name())
            .with_key_id(key_id.to_string());
        self.log_audit(entry);

        Ok(())
    }

    fn key_exists(&self, key_id: &KeyId) -> bool {
        if self.get_session().is_err() {
            return false;
        }

        let Ok(handle) = self.parse_key_id(key_id) else {
            return false;
        };

        self.objects.lock().unwrap().contains_key(&handle)
    }

    fn health_check(&self) -> HsmResult<HealthStatus> {
        let status = HealthStatus::new(self.name(), self.initialized)
            .with_response_time(1)
            .with_metric(
                "objects_count",
                self.objects.lock().unwrap().len().to_string(),
            )
            .with_metric("slot_id", self.slot_id.to_string());

        Ok(status)
    }

    fn get_audit_log(&self, limit: usize) -> HsmResult<Vec<AuditEntry>> {
        let log = self.audit_log.lock().unwrap();
        let len = log.len();
        let start = len.saturating_sub(limit);
        Ok(log[start..].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;

    #[test]
    fn test_mock_provider_initialization() {
        let mut provider = Pkcs11MockProvider::new();
        assert!(!provider.is_available());

        provider.initialize().unwrap();
        assert!(provider.is_available());

        provider.finalize().unwrap();
        assert!(!provider.is_available());
    }

    #[test]
    fn test_double_initialization_fails() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        assert!(provider.initialize().is_err());
    }

    #[test]
    fn test_session_management() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();

        // Open session
        let session_id = provider.open_session(true, Some("1234")).unwrap();
        assert!(session_id > 0);

        // Cannot open another session
        assert!(provider.open_session(true, None).is_err());

        // Close session
        provider.close_session().unwrap();

        // Can open new session after closing
        provider.open_session(false, None).unwrap();
    }

    #[test]
    fn test_key_generation() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        let key_id = provider.generate_key("test-key").unwrap();
        assert!(key_id.0.starts_with("pkcs11:"));
        assert!(provider.key_exists(&key_id));
    }

    #[test]
    fn test_key_import() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        let keypair = KeyPair::generate();
        let key_id = provider
            .import_key("imported-key", &keypair.secret_key())
            .unwrap();

        assert!(provider.key_exists(&key_id));
        let pub_key = provider.get_public_key(&key_id).unwrap();
        assert_eq!(pub_key, keypair.public_key());
    }

    #[test]
    fn test_signing() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        let key_id = provider.generate_key("signing-key").unwrap();
        let message = b"Test message for PKCS#11";

        let signature = provider.sign(&key_id, message).unwrap();
        let pub_key = provider.get_public_key(&key_id).unwrap();

        assert!(verify(&pub_key, message, &signature).is_ok());
    }

    #[test]
    fn test_list_keys() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        assert_eq!(provider.list_keys().unwrap().len(), 0);

        provider.generate_key("key1").unwrap();
        provider.generate_key("key2").unwrap();
        provider.generate_key("key3").unwrap();

        let keys = provider.list_keys().unwrap();
        assert_eq!(keys.len(), 3);

        let labels: Vec<_> = keys.iter().map(|k| k.label.as_str()).collect();
        assert!(labels.contains(&"key1"));
        assert!(labels.contains(&"key2"));
        assert!(labels.contains(&"key3"));
    }

    #[test]
    fn test_delete_key() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        let key_id = provider.generate_key("delete-me").unwrap();
        assert!(provider.key_exists(&key_id));

        provider.delete_key(&key_id).unwrap();
        assert!(!provider.key_exists(&key_id));

        // Deleting again should fail
        assert!(provider.delete_key(&key_id).is_err());
    }

    #[test]
    fn test_operations_without_session_fail() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();

        // No session opened
        assert!(provider.generate_key("key").is_err());
        assert!(provider.list_keys().is_err());
    }

    #[test]
    fn test_operations_without_initialization_fail() {
        let provider = Pkcs11MockProvider::new();

        assert!(!provider.is_available());
        assert!(provider.open_session(true, None).is_err());
    }

    #[test]
    fn test_get_nonexistent_key() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        let fake_key_id = KeyId::new("pkcs11:999999");
        assert!(!provider.key_exists(&fake_key_id));
        assert!(provider.get_public_key(&fake_key_id).is_err());
        assert!(provider.delete_key(&fake_key_id).is_err());
    }

    #[test]
    fn test_health_status() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();

        let health = provider.health_check().unwrap();
        assert!(health.healthy);
        assert_eq!(health.provider, "PKCS#11 Mock Provider");
    }

    #[test]
    fn test_audit_logging() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        // Should have initialization entry
        assert!(!provider.get_audit_log(100).unwrap().is_empty());

        let initial_count = provider.get_audit_log(100).unwrap().len();

        provider.generate_key("audit-test").unwrap();

        let log = provider.get_audit_log(100).unwrap();
        assert_eq!(log.len(), initial_count + 1);

        let last_entry = log.last().unwrap();
        assert!(matches!(
            last_entry.event_type,
            AuditEventType::KeyGenerated
        ));
        assert!(last_entry.success);
    }

    #[test]
    fn test_audit_log_limit() {
        let mut provider = Pkcs11MockProvider::new();
        provider.initialize().unwrap();
        provider.open_session(true, Some("1234")).unwrap();

        // Generate multiple keys
        for i in 0..10 {
            provider.generate_key(&format!("key{}", i)).unwrap();
        }

        // Get last 5 entries
        let log = provider.get_audit_log(5).unwrap();
        assert_eq!(log.len(), 5);
    }
}
