//! Certificate management and key revocation system.
//!
//! This module provides a comprehensive certificate and key revocation infrastructure
//! for managing trust relationships in the CHIE protocol. It includes:
//!
//! - Certificate issuance and lifecycle management
//! - Certificate Revocation Lists (CRL)
//! - Certificate chain validation
//! - OCSP-like status checking
//! - Time-based certificate expiration
//! - Certificate renewal and rotation
//!
//! # Example
//!
//! ```
//! use chie_crypto::cert_manager::*;
//! use chie_crypto::KeyPair;
//!
//! // Create a certificate authority
//! let ca_keypair = KeyPair::generate();
//! let mut ca = CertificateAuthority::new(ca_keypair, "CHIE Root CA".to_string());
//!
//! // Issue a certificate
//! let peer_keypair = KeyPair::generate();
//! let cert = ca.issue_certificate(
//!     peer_keypair.public_key(),
//!     "peer-001".to_string(),
//!     CertificateMetadata::default()
//!         .with_validity_days(365)
//! ).unwrap();
//!
//! // Verify the certificate
//! assert!(ca.verify_certificate(&cert).is_ok());
//!
//! // Revoke the certificate
//! ca.revoke_certificate(&cert.serial_number, RevocationReason::KeyCompromise).unwrap();
//!
//! // Check revocation status
//! assert!(ca.is_revoked(&cert.serial_number));
//! ```

use crate::signing::{KeyPair, PublicKey, SignatureBytes, verify};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use thiserror::Error;

// Serde helper for [u8; 32] (PublicKey)
mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = <Vec<u8>>::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length for [u8; 32]"))
    }
}

// Serde helper for [u8; 64] (SignatureBytes)
mod serde_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = <Vec<u8>>::deserialize(deserializer)?;
        vec.try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length for [u8; 64]"))
    }
}

/// Errors that can occur in certificate management.
#[derive(Debug, Error)]
pub enum CertError {
    #[error("Certificate verification failed: {0}")]
    VerificationFailed(String),

    #[error("Certificate expired at {0}")]
    Expired(u64),

    #[error("Certificate not yet valid (valid from {0})")]
    NotYetValid(u64),

    #[error("Certificate revoked: {0}")]
    Revoked(String),

    #[error("Certificate not found: {0}")]
    NotFound(String),

    #[error("Invalid certificate chain: {0}")]
    InvalidChain(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Serial number collision: {0}")]
    SerialCollision(String),

    #[error("Invalid metadata: {0}")]
    InvalidMetadata(String),
}

/// Result type for certificate operations.
pub type CertResult<T> = Result<T, CertError>;

/// Reason for certificate revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Key has been compromised
    KeyCompromise,
    /// Certificate authority compromised
    CaCompromise,
    /// Affiliation changed (e.g., peer left network)
    AffiliationChanged,
    /// Certificate superseded by newer one
    Superseded,
    /// Operations ceased
    CessationOfOperation,
    /// Certificate on hold (temporary)
    CertificateHold,
    /// Reason not specified
    Unspecified,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyCompromise => write!(f, "keyCompromise"),
            Self::CaCompromise => write!(f, "caCompromise"),
            Self::AffiliationChanged => write!(f, "affiliationChanged"),
            Self::Superseded => write!(f, "superseded"),
            Self::CessationOfOperation => write!(f, "cessationOfOperation"),
            Self::CertificateHold => write!(f, "certificateHold"),
            Self::Unspecified => write!(f, "unspecified"),
        }
    }
}

/// Certificate metadata and attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// Validity period in days (default: 365)
    pub validity_days: u64,
    /// Custom extensions/attributes
    pub extensions: HashMap<String, String>,
    /// Certificate usage flags
    pub key_usage: Vec<KeyUsage>,
}

impl Default for CertificateMetadata {
    fn default() -> Self {
        Self {
            validity_days: 365,
            extensions: HashMap::new(),
            key_usage: vec![KeyUsage::DigitalSignature],
        }
    }
}

impl CertificateMetadata {
    /// Set validity period in days
    pub fn with_validity_days(mut self, days: u64) -> Self {
        self.validity_days = days;
        self
    }

    /// Add an extension
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extensions.insert(key.into(), value.into());
        self
    }

    /// Set key usage
    pub fn with_key_usage(mut self, usage: Vec<KeyUsage>) -> Self {
        self.key_usage = usage;
        self
    }
}

/// Key usage flags for certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Digital signature
    DigitalSignature,
    /// Key encipherment
    KeyEncipherment,
    /// Data encipherment
    DataEncipherment,
    /// Key agreement
    KeyAgreement,
    /// Certificate signing
    CertSign,
    /// CRL signing
    CrlSign,
}

/// Digital certificate for peer identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// Version number
    pub version: u32,
    /// Unique serial number
    pub serial_number: String,
    /// Issuer identifier (CA name)
    pub issuer: String,
    /// Subject identifier (peer/entity name)
    pub subject: String,
    /// Subject's public key
    #[serde(with = "serde_bytes_32")]
    pub subject_public_key: PublicKey,
    /// Validity period start (Unix timestamp)
    pub not_before: u64,
    /// Validity period end (Unix timestamp)
    pub not_after: u64,
    /// Certificate extensions
    pub extensions: HashMap<String, String>,
    /// Key usage flags
    pub key_usage: Vec<KeyUsage>,
    /// Issuer's signature over certificate data
    #[serde(with = "serde_bytes_64")]
    pub signature: SignatureBytes,
}

impl Certificate {
    /// Get the certificate data to be signed
    fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(self.serial_number.as_bytes());
        data.extend_from_slice(self.issuer.as_bytes());
        data.extend_from_slice(self.subject.as_bytes());
        data.extend_from_slice(&self.subject_public_key);
        data.extend_from_slice(&self.not_before.to_le_bytes());
        data.extend_from_slice(&self.not_after.to_le_bytes());

        // Include extensions in deterministic order
        let mut ext_keys: Vec<_> = self.extensions.keys().collect();
        ext_keys.sort();
        for key in ext_keys {
            data.extend_from_slice(key.as_bytes());
            data.extend_from_slice(self.extensions[key].as_bytes());
        }

        data
    }

    /// Check if certificate is currently valid (time-wise)
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }

    /// Check if certificate is currently valid
    pub fn is_currently_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.is_valid_at(now)
    }

    /// Get time until expiration in seconds (0 if expired)
    pub fn time_until_expiry(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.not_after.saturating_sub(now)
    }

    /// Check if certificate has expired
    pub fn is_expired(&self) -> bool {
        self.time_until_expiry() == 0
    }
}

/// Certificate Revocation List entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Serial number of revoked certificate
    pub serial_number: String,
    /// Revocation timestamp
    pub revoked_at: u64,
    /// Reason for revocation
    pub reason: RevocationReason,
}

/// Certificate Revocation List (CRL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    /// CRL version
    pub version: u32,
    /// Issuer (CA) name
    pub issuer: String,
    /// CRL issue timestamp
    pub this_update: u64,
    /// Next CRL update timestamp
    pub next_update: u64,
    /// Revoked certificates
    pub revoked_certificates: Vec<RevocationEntry>,
    /// CRL signature
    #[serde(with = "serde_bytes_64")]
    pub signature: SignatureBytes,
}

/// Certificate Authority for issuing and managing certificates.
pub struct CertificateAuthority {
    /// CA's signing keypair
    keypair: KeyPair,
    /// CA identifier
    ca_name: String,
    /// Issued certificates (keyed by serial number)
    certificates: HashMap<String, Certificate>,
    /// Certificate Revocation List
    crl: HashMap<String, RevocationEntry>,
    /// Next serial number to issue
    next_serial: u64,
}

impl CertificateAuthority {
    /// Create a new Certificate Authority
    pub fn new(keypair: KeyPair, ca_name: String) -> Self {
        Self {
            keypair,
            ca_name,
            certificates: HashMap::new(),
            crl: HashMap::new(),
            next_serial: 1,
        }
    }

    /// Get CA name
    pub fn name(&self) -> &str {
        &self.ca_name
    }

    /// Get CA public key
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Generate next serial number
    fn next_serial_number(&mut self) -> String {
        let serial = format!("{:016x}", self.next_serial);
        self.next_serial += 1;
        serial
    }

    /// Issue a new certificate
    pub fn issue_certificate(
        &mut self,
        subject_public_key: PublicKey,
        subject: String,
        metadata: CertificateMetadata,
    ) -> CertResult<Certificate> {
        let serial_number = self.next_serial_number();

        // Calculate validity period
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let not_before = now;
        let not_after = now + (metadata.validity_days * 24 * 3600);

        // Create certificate (without signature first)
        let mut cert = Certificate {
            version: 1,
            serial_number: serial_number.clone(),
            issuer: self.ca_name.clone(),
            subject,
            subject_public_key,
            not_before,
            not_after,
            extensions: metadata.extensions,
            key_usage: metadata.key_usage,
            signature: [0u8; 64], // Placeholder
        };

        // Sign the certificate
        let signable_data = cert.signable_data();
        cert.signature = self.keypair.sign(&signable_data);

        // Store certificate
        self.certificates.insert(serial_number, cert.clone());

        Ok(cert)
    }

    /// Verify a certificate
    pub fn verify_certificate(&self, cert: &Certificate) -> CertResult<()> {
        // Check if issued by this CA
        if cert.issuer != self.ca_name {
            return Err(CertError::VerificationFailed(format!(
                "Certificate not issued by this CA (expected {}, got {})",
                self.ca_name, cert.issuer
            )));
        }

        // Verify signature
        let signable_data = cert.signable_data();
        verify(&self.keypair.public_key(), &signable_data, &cert.signature)
            .map_err(|e| CertError::VerificationFailed(e.to_string()))?;

        // Check validity period
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now < cert.not_before {
            return Err(CertError::NotYetValid(cert.not_before));
        }

        if now > cert.not_after {
            return Err(CertError::Expired(cert.not_after));
        }

        // Check revocation status
        if self.is_revoked(&cert.serial_number) {
            let entry = self.crl.get(&cert.serial_number).unwrap();
            return Err(CertError::Revoked(format!(
                "Certificate revoked: {}",
                entry.reason
            )));
        }

        Ok(())
    }

    /// Revoke a certificate
    pub fn revoke_certificate(
        &mut self,
        serial_number: &str,
        reason: RevocationReason,
    ) -> CertResult<()> {
        // Check if certificate exists
        if !self.certificates.contains_key(serial_number) {
            return Err(CertError::NotFound(serial_number.to_string()));
        }

        // Add to CRL
        let revoked_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = RevocationEntry {
            serial_number: serial_number.to_string(),
            revoked_at,
            reason,
        };

        self.crl.insert(serial_number.to_string(), entry);

        Ok(())
    }

    /// Check if a certificate is revoked
    pub fn is_revoked(&self, serial_number: &str) -> bool {
        self.crl.contains_key(serial_number)
    }

    /// Get revocation information
    pub fn get_revocation_info(&self, serial_number: &str) -> Option<&RevocationEntry> {
        self.crl.get(serial_number)
    }

    /// Generate a Certificate Revocation List
    pub fn generate_crl(&self, validity_hours: u64) -> CertificateRevocationList {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut crl = CertificateRevocationList {
            version: 1,
            issuer: self.ca_name.clone(),
            this_update: now,
            next_update: now + (validity_hours * 3600),
            revoked_certificates: self.crl.values().cloned().collect(),
            signature: [0u8; 64], // Placeholder
        };

        // Sign the CRL
        let mut data = Vec::new();
        data.extend_from_slice(&crl.version.to_le_bytes());
        data.extend_from_slice(crl.issuer.as_bytes());
        data.extend_from_slice(&crl.this_update.to_le_bytes());
        data.extend_from_slice(&crl.next_update.to_le_bytes());
        for entry in &crl.revoked_certificates {
            data.extend_from_slice(entry.serial_number.as_bytes());
            data.extend_from_slice(&entry.revoked_at.to_le_bytes());
        }

        crl.signature = self.keypair.sign(&data);
        crl
    }

    /// List all issued certificates
    pub fn list_certificates(&self) -> Vec<&Certificate> {
        self.certificates.values().collect()
    }

    /// Get certificate by serial number
    pub fn get_certificate(&self, serial_number: &str) -> Option<&Certificate> {
        self.certificates.get(serial_number)
    }

    /// Count active (non-revoked) certificates
    pub fn count_active_certificates(&self) -> usize {
        self.certificates
            .keys()
            .filter(|sn| !self.is_revoked(sn))
            .count()
    }

    /// Count revoked certificates
    pub fn count_revoked_certificates(&self) -> usize {
        self.crl.len()
    }

    /// Renew a certificate (issue new one with same subject)
    pub fn renew_certificate(
        &mut self,
        old_cert: &Certificate,
        metadata: CertificateMetadata,
    ) -> CertResult<Certificate> {
        // Verify old certificate was issued by us
        if old_cert.issuer != self.ca_name {
            return Err(CertError::VerificationFailed(
                "Cannot renew certificate from different CA".to_string(),
            ));
        }

        // Issue new certificate
        let new_cert = self.issue_certificate(
            old_cert.subject_public_key,
            old_cert.subject.clone(),
            metadata,
        )?;

        // Revoke old certificate
        self.revoke_certificate(&old_cert.serial_number, RevocationReason::Superseded)?;

        Ok(new_cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_issuance() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default(),
            )
            .unwrap();

        assert_eq!(cert.subject, "peer-001");
        assert_eq!(cert.issuer, "Test CA");
        assert!(cert.is_currently_valid());
    }

    #[test]
    fn test_certificate_verification() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default(),
            )
            .unwrap();

        // Should verify successfully
        assert!(ca.verify_certificate(&cert).is_ok());
    }

    #[test]
    fn test_certificate_revocation() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default(),
            )
            .unwrap();

        // Initially not revoked
        assert!(!ca.is_revoked(&cert.serial_number));
        assert!(ca.verify_certificate(&cert).is_ok());

        // Revoke certificate
        ca.revoke_certificate(&cert.serial_number, RevocationReason::KeyCompromise)
            .unwrap();

        // Now revoked
        assert!(ca.is_revoked(&cert.serial_number));
        assert!(ca.verify_certificate(&cert).is_err());
    }

    #[test]
    fn test_crl_generation() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        // Issue and revoke some certificates
        for i in 0..3 {
            let peer_keypair = KeyPair::generate();
            let cert = ca
                .issue_certificate(
                    peer_keypair.public_key(),
                    format!("peer-{:03}", i),
                    CertificateMetadata::default(),
                )
                .unwrap();

            if i % 2 == 0 {
                ca.revoke_certificate(&cert.serial_number, RevocationReason::Unspecified)
                    .unwrap();
            }
        }

        // Generate CRL
        let crl = ca.generate_crl(24);

        assert_eq!(crl.issuer, "Test CA");
        assert_eq!(crl.revoked_certificates.len(), 2); // Revoked 2 out of 3
    }

    #[test]
    fn test_certificate_expiration() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();

        // Issue certificate with 0 day validity
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default().with_validity_days(0),
            )
            .unwrap();

        // Certificate should have 0 or very small time until expiry
        assert!(cert.time_until_expiry() <= 1);

        // Check validity at future timestamp (cert should be expired)
        let future = cert.not_after + 1;
        assert!(!cert.is_valid_at(future));

        // Check validity at past timestamp (cert should be valid)
        let past = cert.not_before;
        assert!(cert.is_valid_at(past));
    }

    #[test]
    fn test_certificate_renewal() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let old_cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default(),
            )
            .unwrap();

        // Renew certificate
        let new_cert = ca
            .renew_certificate(
                &old_cert,
                CertificateMetadata::default().with_validity_days(730),
            )
            .unwrap();

        // Old certificate should be revoked
        assert!(ca.is_revoked(&old_cert.serial_number));

        // New certificate should be valid
        assert!(!ca.is_revoked(&new_cert.serial_number));
        assert!(ca.verify_certificate(&new_cert).is_ok());

        // Subjects should match
        assert_eq!(old_cert.subject, new_cert.subject);

        // Serial numbers should differ
        assert_ne!(old_cert.serial_number, new_cert.serial_number);
    }

    #[test]
    fn test_metadata_extensions() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default()
                    .with_extension("node_type", "storage")
                    .with_extension("region", "us-west"),
            )
            .unwrap();

        assert_eq!(
            cert.extensions.get("node_type"),
            Some(&"storage".to_string())
        );
        assert_eq!(cert.extensions.get("region"), Some(&"us-west".to_string()));
    }

    #[test]
    fn test_key_usage() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default()
                    .with_key_usage(vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment]),
            )
            .unwrap();

        assert_eq!(cert.key_usage.len(), 2);
        assert!(cert.key_usage.contains(&KeyUsage::DigitalSignature));
        assert!(cert.key_usage.contains(&KeyUsage::KeyEncipherment));
    }

    #[test]
    fn test_revocation_reasons() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let reasons = [
            RevocationReason::KeyCompromise,
            RevocationReason::CaCompromise,
            RevocationReason::AffiliationChanged,
            RevocationReason::Superseded,
            RevocationReason::CessationOfOperation,
        ];

        for (i, reason) in reasons.iter().enumerate() {
            let peer_keypair = KeyPair::generate();
            let cert = ca
                .issue_certificate(
                    peer_keypair.public_key(),
                    format!("peer-{:03}", i),
                    CertificateMetadata::default(),
                )
                .unwrap();

            ca.revoke_certificate(&cert.serial_number, *reason).unwrap();

            let info = ca.get_revocation_info(&cert.serial_number).unwrap();
            assert_eq!(info.reason, *reason);
        }
    }

    #[test]
    fn test_certificate_counting() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        // Issue 5 certificates
        for i in 0..5 {
            let peer_keypair = KeyPair::generate();
            ca.issue_certificate(
                peer_keypair.public_key(),
                format!("peer-{:03}", i),
                CertificateMetadata::default(),
            )
            .unwrap();
        }

        assert_eq!(ca.list_certificates().len(), 5);
        assert_eq!(ca.count_active_certificates(), 5);
        assert_eq!(ca.count_revoked_certificates(), 0);

        // Revoke 2 certificates
        let certs: Vec<_> = ca
            .list_certificates()
            .iter()
            .take(2)
            .map(|c| c.serial_number.clone())
            .collect();
        for serial in &certs {
            ca.revoke_certificate(serial, RevocationReason::Unspecified)
                .unwrap();
        }

        assert_eq!(ca.count_active_certificates(), 3);
        assert_eq!(ca.count_revoked_certificates(), 2);
    }

    #[test]
    fn test_serial_number_uniqueness() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let mut serials = std::collections::HashSet::new();

        // Issue 100 certificates and check for unique serials
        for i in 0..100 {
            let peer_keypair = KeyPair::generate();
            let cert = ca
                .issue_certificate(
                    peer_keypair.public_key(),
                    format!("peer-{:03}", i),
                    CertificateMetadata::default(),
                )
                .unwrap();

            assert!(serials.insert(cert.serial_number.clone()));
        }
    }

    #[test]
    fn test_certificate_lookup() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default(),
            )
            .unwrap();

        // Lookup by serial number
        let found = ca.get_certificate(&cert.serial_number).unwrap();
        assert_eq!(found.subject, "peer-001");

        // Lookup non-existent
        assert!(ca.get_certificate("nonexistent").is_none());
    }

    #[test]
    fn test_revocation_info() {
        let ca_keypair = KeyPair::generate();
        let mut ca = CertificateAuthority::new(ca_keypair, "Test CA".to_string());

        let peer_keypair = KeyPair::generate();
        let cert = ca
            .issue_certificate(
                peer_keypair.public_key(),
                "peer-001".to_string(),
                CertificateMetadata::default(),
            )
            .unwrap();

        // No revocation info initially
        assert!(ca.get_revocation_info(&cert.serial_number).is_none());

        // Revoke
        ca.revoke_certificate(&cert.serial_number, RevocationReason::KeyCompromise)
            .unwrap();

        // Should have revocation info now
        let info = ca.get_revocation_info(&cert.serial_number).unwrap();
        assert_eq!(info.reason, RevocationReason::KeyCompromise);
        assert!(info.revoked_at > 0);
    }
}
