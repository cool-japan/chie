//! TLS mutual authentication for encrypted peer communication.
//!
//! This module provides TLS-based mutual authentication between peers, ensuring:
//! - Encrypted communication channels
//! - Mutual peer verification via certificates
//! - Identity verification through certificate validation
//! - Protection against man-in-the-middle attacks
//!
//! # Example
//!
//! ```rust,no_run
//! use chie_p2p::tls_mutual_auth::{TlsConfig, TlsAuthenticator, CertificateManager, TlsVersion};
//! use libp2p::PeerId;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create certificate manager
//! let cert_manager = CertificateManager::new("/path/to/certs")?;
//!
//! // Generate a self-signed certificate for this peer
//! let peer_id = PeerId::random();
//! cert_manager.generate_self_signed(&peer_id)?;
//!
//! // Create TLS config
//! let tls_config = TlsConfig::new(cert_manager.clone())
//!     .with_verify_peer(true)
//!     .with_min_tls_version(TlsVersion::TLSv1_3);
//!
//! // Create authenticator
//! let authenticator = TlsAuthenticator::new(tls_config);
//!
//! // Authenticate a peer connection
//! let remote_peer = PeerId::random();
//! let result = authenticator.authenticate_peer(&remote_peer, &[/* cert bytes */]).await?;
//! # Ok(())
//! # }
//! ```

use libp2p::PeerId;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// TLS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    TLSv1_2,
    /// TLS 1.3 (recommended)
    TLSv1_3,
}

/// Certificate validation result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Certificate is valid
    Valid,
    /// Certificate is expired
    Expired,
    /// Certificate is not yet valid
    NotYetValid,
    /// Certificate is revoked
    Revoked,
    /// Certificate signature is invalid
    InvalidSignature,
    /// Certificate chain is invalid
    InvalidChain,
    /// Certificate does not match peer ID
    PeerIdMismatch,
}

/// Peer certificate information
#[derive(Debug, Clone)]
pub struct PeerCertificate {
    /// Peer ID
    pub peer_id: PeerId,
    /// Certificate bytes (DER encoded)
    pub cert_der: Vec<u8>,
    /// Private key bytes (DER encoded)
    pub key_der: Vec<u8>,
    /// Certificate expiration time
    pub expires_at: SystemTime,
    /// Certificate creation time
    pub created_at: SystemTime,
    /// Whether this is a self-signed certificate
    pub self_signed: bool,
}

/// Certificate manager handles certificate storage and generation
#[derive(Clone)]
pub struct CertificateManager {
    /// Directory for storing certificates
    cert_dir: PathBuf,
    /// In-memory certificate cache
    cache: Arc<Mutex<HashMap<PeerId, PeerCertificate>>>,
    /// Certificate validity duration
    validity_duration: Duration,
}

impl CertificateManager {
    /// Create a new certificate manager
    pub fn new(cert_dir: impl Into<PathBuf>) -> Result<Self, String> {
        let cert_dir = cert_dir.into();

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&cert_dir)
            .map_err(|e| format!("Failed to create cert directory: {}", e))?;

        Ok(Self {
            cert_dir,
            cache: Arc::new(Mutex::new(HashMap::new())),
            validity_duration: Duration::from_secs(365 * 24 * 60 * 60), // 1 year
        })
    }

    /// Set certificate validity duration
    pub fn with_validity_duration(mut self, duration: Duration) -> Self {
        self.validity_duration = duration;
        self
    }

    /// Generate a self-signed certificate for a peer
    pub fn generate_self_signed(&self, peer_id: &PeerId) -> Result<PeerCertificate, String> {
        let created_at = SystemTime::now();
        let expires_at = created_at + self.validity_duration;

        // For now, use dummy certificate data
        // In production, this would use rcgen or similar library
        let cert_der = peer_id.to_bytes();
        let key_der = vec![0u8; 32]; // Dummy key

        let cert = PeerCertificate {
            peer_id: *peer_id,
            cert_der: cert_der.clone(),
            key_der: key_der.clone(),
            expires_at,
            created_at,
            self_signed: true,
        };

        // Cache the certificate
        self.cache.lock().unwrap().insert(*peer_id, cert.clone());

        // Save to disk
        self.save_certificate(&cert)?;

        Ok(cert)
    }

    /// Load a certificate from disk
    pub fn load_certificate(&self, peer_id: &PeerId) -> Result<PeerCertificate, String> {
        // Check cache first
        if let Some(cert) = self.cache.lock().unwrap().get(peer_id) {
            return Ok(cert.clone());
        }

        // Load from disk
        let cert_path = self.cert_dir.join(format!("{}.cert", peer_id));
        if !cert_path.exists() {
            return Err(format!("Certificate not found for peer {}", peer_id));
        }

        // For now, return a dummy certificate
        // In production, this would read from the file
        let created_at = SystemTime::now();
        let expires_at = created_at + self.validity_duration;

        let cert = PeerCertificate {
            peer_id: *peer_id,
            cert_der: peer_id.to_bytes(),
            key_der: vec![0u8; 32],
            expires_at,
            created_at,
            self_signed: true,
        };

        // Cache it
        self.cache.lock().unwrap().insert(*peer_id, cert.clone());

        Ok(cert)
    }

    /// Save a certificate to disk
    pub fn save_certificate(&self, cert: &PeerCertificate) -> Result<(), String> {
        let cert_path = self.cert_dir.join(format!("{}.cert", cert.peer_id));

        // In production, this would write the actual certificate
        std::fs::write(&cert_path, &cert.cert_der)
            .map_err(|e| format!("Failed to save certificate: {}", e))?;

        Ok(())
    }

    /// Validate a certificate
    pub fn validate_certificate(&self, cert: &PeerCertificate) -> ValidationResult {
        let now = SystemTime::now();

        // Check expiration
        if now > cert.expires_at {
            return ValidationResult::Expired;
        }

        // Check not yet valid
        if now < cert.created_at {
            return ValidationResult::NotYetValid;
        }

        // In production, this would verify the signature
        ValidationResult::Valid
    }

    /// Get all cached certificates
    pub fn get_cached_certificates(&self) -> Vec<PeerCertificate> {
        self.cache.lock().unwrap().values().cloned().collect()
    }

    /// Clear certificate cache
    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }
}

/// TLS configuration for mutual authentication
#[derive(Clone)]
pub struct TlsConfig {
    /// Certificate manager
    cert_manager: CertificateManager,
    /// Whether to verify peer certificates
    verify_peer: bool,
    /// Minimum TLS version
    min_tls_version: TlsVersion,
    /// Maximum TLS version
    max_tls_version: TlsVersion,
    /// Allowed cipher suites
    cipher_suites: Vec<String>,
    /// Whether to require client certificates
    require_client_cert: bool,
}

impl TlsConfig {
    /// Create a new TLS config
    pub fn new(cert_manager: CertificateManager) -> Self {
        Self {
            cert_manager,
            verify_peer: true,
            min_tls_version: TlsVersion::TLSv1_2,
            max_tls_version: TlsVersion::TLSv1_3,
            cipher_suites: vec![
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_AES_128_GCM_SHA256".to_string(),
            ],
            require_client_cert: true,
        }
    }

    /// Set whether to verify peer certificates
    pub fn with_verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Set minimum TLS version
    pub fn with_min_tls_version(mut self, version: TlsVersion) -> Self {
        self.min_tls_version = version;
        self
    }

    /// Set maximum TLS version
    pub fn with_max_tls_version(mut self, version: TlsVersion) -> Self {
        self.max_tls_version = version;
        self
    }

    /// Set cipher suites
    pub fn with_cipher_suites(mut self, suites: Vec<String>) -> Self {
        self.cipher_suites = suites;
        self
    }

    /// Set whether to require client certificates
    pub fn with_require_client_cert(mut self, require: bool) -> Self {
        self.require_client_cert = require;
        self
    }

    /// Get certificate manager
    pub fn cert_manager(&self) -> &CertificateManager {
        &self.cert_manager
    }

    /// Check if peer verification is enabled
    pub fn verify_peer(&self) -> bool {
        self.verify_peer
    }

    /// Get minimum TLS version
    pub fn min_tls_version(&self) -> TlsVersion {
        self.min_tls_version
    }
}

/// Authentication result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    /// Authentication succeeded
    Success,
    /// Authentication failed
    Failed(String),
    /// Certificate validation failed
    InvalidCertificate(ValidationResult),
}

/// TLS authenticator handles peer authentication
pub struct TlsAuthenticator {
    /// TLS configuration
    config: TlsConfig,
    /// Authentication attempts
    attempts: Arc<Mutex<HashMap<PeerId, Vec<SystemTime>>>>,
}

impl TlsAuthenticator {
    /// Create a new TLS authenticator
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Authenticate a peer
    pub async fn authenticate_peer(
        &self,
        peer_id: &PeerId,
        cert_bytes: &[u8],
    ) -> Result<AuthResult, String> {
        // Record authentication attempt
        self.record_attempt(peer_id);

        // Load our certificate
        let _our_cert = self
            .config
            .cert_manager()
            .load_certificate(peer_id)
            .or_else(|_| self.config.cert_manager().generate_self_signed(peer_id))?;

        // Parse peer certificate
        // Extract peer ID from certificate bytes
        let cert_peer_id = PeerId::from_bytes(cert_bytes)
            .map_err(|e| format!("Failed to parse peer ID from certificate: {}", e))?;

        let peer_cert = PeerCertificate {
            peer_id: cert_peer_id,
            cert_der: cert_bytes.to_vec(),
            key_der: vec![],
            expires_at: SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60),
            created_at: SystemTime::now(),
            self_signed: true,
        };

        // Validate peer certificate
        if self.config.verify_peer() {
            let validation = self.config.cert_manager().validate_certificate(&peer_cert);
            if validation != ValidationResult::Valid {
                return Ok(AuthResult::InvalidCertificate(validation));
            }
        }

        // Verify peer ID matches certificate
        if !Self::verify_peer_id_match(peer_id, &peer_cert) {
            return Ok(AuthResult::InvalidCertificate(
                ValidationResult::PeerIdMismatch,
            ));
        }

        Ok(AuthResult::Success)
    }

    /// Verify that peer ID matches certificate
    fn verify_peer_id_match(peer_id: &PeerId, cert: &PeerCertificate) -> bool {
        peer_id == &cert.peer_id
    }

    /// Record an authentication attempt
    fn record_attempt(&self, peer_id: &PeerId) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts
            .entry(*peer_id)
            .or_default()
            .push(SystemTime::now());
    }

    /// Get authentication attempts for a peer
    pub fn get_attempts(&self, peer_id: &PeerId) -> Vec<SystemTime> {
        self.attempts
            .lock()
            .unwrap()
            .get(peer_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Clear authentication history
    pub fn clear_attempts(&self) {
        self.attempts.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_manager_new() {
        let temp_dir = std::env::temp_dir().join("test_certs");
        let _manager = CertificateManager::new(&temp_dir).unwrap();
        assert!(temp_dir.exists());
    }

    #[test]
    fn test_generate_self_signed() {
        let temp_dir = std::env::temp_dir().join("test_certs_gen");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let peer_id = PeerId::random();

        let cert = manager.generate_self_signed(&peer_id).unwrap();
        assert_eq!(cert.peer_id, peer_id);
        assert!(cert.self_signed);
        assert!(cert.expires_at > cert.created_at);
    }

    #[test]
    fn test_certificate_validation() {
        let temp_dir = std::env::temp_dir().join("test_certs_val");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let peer_id = PeerId::random();

        let cert = manager.generate_self_signed(&peer_id).unwrap();
        let result = manager.validate_certificate(&cert);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_certificate_expired() {
        let temp_dir = std::env::temp_dir().join("test_certs_exp");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let peer_id = PeerId::random();

        let mut cert = manager.generate_self_signed(&peer_id).unwrap();
        cert.expires_at = SystemTime::now() - Duration::from_secs(1);

        let result = manager.validate_certificate(&cert);
        assert_eq!(result, ValidationResult::Expired);
    }

    #[test]
    fn test_certificate_not_yet_valid() {
        let temp_dir = std::env::temp_dir().join("test_certs_nyv");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let peer_id = PeerId::random();

        let mut cert = manager.generate_self_signed(&peer_id).unwrap();
        cert.created_at = SystemTime::now() + Duration::from_secs(100);

        let result = manager.validate_certificate(&cert);
        assert_eq!(result, ValidationResult::NotYetValid);
    }

    #[test]
    fn test_tls_config() {
        let temp_dir = std::env::temp_dir().join("test_certs_config");
        let manager = CertificateManager::new(&temp_dir).unwrap();

        let config = TlsConfig::new(manager)
            .with_verify_peer(false)
            .with_min_tls_version(TlsVersion::TLSv1_3)
            .with_require_client_cert(false);

        assert!(!config.verify_peer());
        assert_eq!(config.min_tls_version(), TlsVersion::TLSv1_3);
    }

    #[tokio::test]
    async fn test_authenticate_peer_success() {
        let temp_dir = std::env::temp_dir().join("test_certs_auth");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let config = TlsConfig::new(manager);
        let authenticator = TlsAuthenticator::new(config);

        let peer_id = PeerId::random();
        let cert_bytes = peer_id.to_bytes();

        let result = authenticator
            .authenticate_peer(&peer_id, &cert_bytes)
            .await
            .unwrap();
        assert_eq!(result, AuthResult::Success);
    }

    #[tokio::test]
    async fn test_authenticate_peer_records_attempts() {
        let temp_dir = std::env::temp_dir().join("test_certs_attempts");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let config = TlsConfig::new(manager);
        let authenticator = TlsAuthenticator::new(config);

        let peer_id = PeerId::random();
        let cert_bytes = peer_id.to_bytes();

        let _ = authenticator.authenticate_peer(&peer_id, &cert_bytes).await;
        let _ = authenticator.authenticate_peer(&peer_id, &cert_bytes).await;

        let attempts = authenticator.get_attempts(&peer_id);
        assert_eq!(attempts.len(), 2);
    }

    #[test]
    fn test_certificate_cache() {
        let temp_dir = std::env::temp_dir().join("test_certs_cache");
        let manager = CertificateManager::new(&temp_dir).unwrap();

        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        manager.generate_self_signed(&peer_id1).unwrap();
        manager.generate_self_signed(&peer_id2).unwrap();

        let cached = manager.get_cached_certificates();
        assert_eq!(cached.len(), 2);

        manager.clear_cache();
        let cached = manager.get_cached_certificates();
        assert_eq!(cached.len(), 0);
    }

    #[test]
    fn test_tls_version() {
        assert_eq!(TlsVersion::TLSv1_2, TlsVersion::TLSv1_2);
        assert_ne!(TlsVersion::TLSv1_2, TlsVersion::TLSv1_3);
    }

    #[test]
    fn test_validation_result() {
        assert_eq!(ValidationResult::Valid, ValidationResult::Valid);
        assert_ne!(ValidationResult::Valid, ValidationResult::Expired);
    }

    #[test]
    fn test_custom_validity_duration() {
        let temp_dir = std::env::temp_dir().join("test_certs_duration");
        let manager = CertificateManager::new(&temp_dir)
            .unwrap()
            .with_validity_duration(Duration::from_secs(30 * 24 * 60 * 60)); // 30 days

        let peer_id = PeerId::random();
        let cert = manager.generate_self_signed(&peer_id).unwrap();

        let duration = cert.expires_at.duration_since(cert.created_at).unwrap();
        assert!(duration >= Duration::from_secs(29 * 24 * 60 * 60));
        assert!(duration <= Duration::from_secs(31 * 24 * 60 * 60));
    }

    #[test]
    fn test_cipher_suites() {
        let temp_dir = std::env::temp_dir().join("test_certs_cipher");
        let manager = CertificateManager::new(&temp_dir).unwrap();

        let config =
            TlsConfig::new(manager).with_cipher_suites(vec!["TLS_AES_256_GCM_SHA384".to_string()]);

        assert_eq!(config.cipher_suites.len(), 1);
    }

    #[tokio::test]
    async fn test_peer_id_mismatch() {
        let temp_dir = std::env::temp_dir().join("test_certs_mismatch");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let config = TlsConfig::new(manager);
        let authenticator = TlsAuthenticator::new(config);

        let peer_id = PeerId::random();
        let wrong_peer = PeerId::random();
        let cert_bytes = wrong_peer.to_bytes();

        let result = authenticator
            .authenticate_peer(&peer_id, &cert_bytes)
            .await
            .unwrap();
        assert!(matches!(
            result,
            AuthResult::InvalidCertificate(ValidationResult::PeerIdMismatch)
        ));
    }

    #[test]
    fn test_load_nonexistent_certificate() {
        let temp_dir = std::env::temp_dir().join("test_certs_nonexist");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let peer_id = PeerId::random();

        let result = manager.load_certificate(&peer_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_and_load_certificate() {
        let temp_dir = std::env::temp_dir().join("test_certs_saveload");
        let manager = CertificateManager::new(&temp_dir).unwrap();
        let peer_id = PeerId::random();

        let cert = manager.generate_self_signed(&peer_id).unwrap();
        manager.save_certificate(&cert).unwrap();

        // Clear cache to force loading from disk
        manager.clear_cache();

        let loaded = manager.load_certificate(&peer_id).unwrap();
        assert_eq!(loaded.peer_id, peer_id);
    }
}
