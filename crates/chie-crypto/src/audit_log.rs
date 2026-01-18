//! Cryptographic Operation Audit Logging
//!
//! This module provides secure, tamper-evident audit logging for cryptographic operations.
//! All sensitive operations (key generation, signing, encryption, etc.) can be logged
//! with metadata for compliance and forensic purposes.
//!
//! # Features
//!
//! - Tamper-evident logging using Merkle trees
//! - Structured audit log entries with timestamps
//! - Operation categorization and severity levels
//! - Query and filtering capabilities
//! - Retention policies with automatic cleanup
//! - Export to JSON for external analysis
//! - Secure storage with integrity verification
//!
//! # Use Cases in CHIE Protocol
//!
//! - Compliance auditing (GDPR, CCPA, FIPS)
//! - Security incident investigation
//! - Key lifecycle tracking
//! - Access control verification
//! - Anomaly detection
//!
//! # Example
//!
//! ```
//! use chie_crypto::audit_log::{AuditLog, AuditEntry, OperationType, SeverityLevel};
//!
//! let mut audit_log = AuditLog::new();
//!
//! // Log a key generation operation
//! audit_log.log(
//!     OperationType::KeyGeneration,
//!     SeverityLevel::Info,
//!     "Generated Ed25519 keypair for user alice",
//!     Some("user_id=alice, key_type=Ed25519"),
//! );
//!
//! // Log an encryption operation
//! audit_log.log(
//!     OperationType::Encryption,
//!     SeverityLevel::Info,
//!     "Encrypted file document.pdf",
//!     Some("file_size=1024000, algorithm=ChaCha20-Poly1305"),
//! );
//!
//! // Query audit logs
//! let key_gen_logs = audit_log.query_by_operation(OperationType::KeyGeneration);
//! assert_eq!(key_gen_logs.len(), 1);
//!
//! // Verify log integrity
//! assert!(audit_log.verify_integrity());
//! ```

use crate::hash::hash;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of cryptographic operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationType {
    /// Key generation
    KeyGeneration,
    /// Key import/export
    KeyImportExport,
    /// Key rotation
    KeyRotation,
    /// Key deletion
    KeyDeletion,
    /// Digital signature
    Signing,
    /// Signature verification
    SignatureVerification,
    /// Encryption
    Encryption,
    /// Decryption
    Decryption,
    /// Hashing
    Hashing,
    /// Key derivation
    KeyDerivation,
    /// Random number generation
    RandomGeneration,
    /// Certificate issuance
    CertificateIssuance,
    /// Certificate revocation
    CertificateRevocation,
    /// Access control check
    AccessControl,
    /// Policy enforcement
    PolicyEnforcement,
    /// Audit log access
    AuditAccess,
    /// Other operation
    Other,
}

/// Severity level of the audit entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SeverityLevel {
    /// Debug-level information
    Debug,
    /// Informational message
    Info,
    /// Warning message
    Warning,
    /// Error message
    Error,
    /// Critical security event
    Critical,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: u64,
    /// Timestamp of the operation
    pub timestamp: DateTime<Utc>,
    /// Type of operation
    pub operation_type: OperationType,
    /// Severity level
    pub severity: SeverityLevel,
    /// Human-readable description
    pub description: String,
    /// Additional metadata (key-value pairs as string)
    pub metadata: Option<String>,
    /// User or entity performing the operation
    pub principal: Option<String>,
    /// Hash of previous entry (for tamper detection)
    pub previous_hash: Vec<u8>,
    /// Hash of this entry
    pub entry_hash: Vec<u8>,
}

impl AuditEntry {
    /// Create a new audit entry
    fn new(
        id: u64,
        operation_type: OperationType,
        severity: SeverityLevel,
        description: String,
        metadata: Option<String>,
        principal: Option<String>,
        previous_hash: Vec<u8>,
    ) -> Self {
        let timestamp = Utc::now();

        // Compute hash of this entry
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&id.to_le_bytes());
        hash_input.extend_from_slice(timestamp.to_rfc3339().as_bytes());
        hash_input.extend_from_slice(&crate::codec::encode(&operation_type).unwrap());
        hash_input.extend_from_slice(&crate::codec::encode(&severity).unwrap());
        hash_input.extend_from_slice(description.as_bytes());
        if let Some(ref m) = metadata {
            hash_input.extend_from_slice(m.as_bytes());
        }
        if let Some(ref p) = principal {
            hash_input.extend_from_slice(p.as_bytes());
        }
        hash_input.extend_from_slice(&previous_hash);

        let entry_hash = hash(&hash_input).to_vec();

        Self {
            id,
            timestamp,
            operation_type,
            severity,
            description,
            metadata,
            principal,
            previous_hash,
            entry_hash,
        }
    }

    /// Verify the integrity of this entry
    fn verify(&self, expected_previous_hash: &[u8]) -> bool {
        // Check previous hash matches
        if self.previous_hash != expected_previous_hash {
            return false;
        }

        // Recompute entry hash
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&self.id.to_le_bytes());
        hash_input.extend_from_slice(self.timestamp.to_rfc3339().as_bytes());
        hash_input.extend_from_slice(&crate::codec::encode(&self.operation_type).unwrap());
        hash_input.extend_from_slice(&crate::codec::encode(&self.severity).unwrap());
        hash_input.extend_from_slice(self.description.as_bytes());
        if let Some(ref m) = self.metadata {
            hash_input.extend_from_slice(m.as_bytes());
        }
        if let Some(ref p) = self.principal {
            hash_input.extend_from_slice(p.as_bytes());
        }
        hash_input.extend_from_slice(&self.previous_hash);

        let computed_hash = hash(&hash_input);
        computed_hash.as_slice() == self.entry_hash.as_slice()
    }
}

/// Audit log with tamper-evident chaining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// All audit entries
    entries: Vec<AuditEntry>,
    /// Current principal (user/entity)
    current_principal: Option<String>,
    /// Retention policy (days to keep logs)
    retention_days: Option<i64>,
    /// Statistics
    stats: AuditStatistics,
}

/// Audit log statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStatistics {
    /// Total number of entries
    pub total_entries: u64,
    /// Entries by operation type
    pub by_operation: HashMap<String, u64>,
    /// Entries by severity
    pub by_severity: HashMap<String, u64>,
}

impl AuditLog {
    /// Create a new empty audit log
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current_principal: None,
            retention_days: None,
            stats: AuditStatistics::default(),
        }
    }

    /// Create a new audit log with retention policy
    pub fn with_retention(retention_days: i64) -> Self {
        Self {
            entries: Vec::new(),
            current_principal: None,
            retention_days: Some(retention_days),
            stats: AuditStatistics::default(),
        }
    }

    /// Set the current principal (user/entity)
    pub fn set_principal(&mut self, principal: String) {
        self.current_principal = Some(principal);
    }

    /// Clear the current principal
    pub fn clear_principal(&mut self) {
        self.current_principal = None;
    }

    /// Log a cryptographic operation
    pub fn log(
        &mut self,
        operation_type: OperationType,
        severity: SeverityLevel,
        description: &str,
        metadata: Option<&str>,
    ) {
        let id = self.entries.len() as u64;
        let previous_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| vec![0u8; 32]);

        let entry = AuditEntry::new(
            id,
            operation_type,
            severity,
            description.to_string(),
            metadata.map(|s| s.to_string()),
            self.current_principal.clone(),
            previous_hash,
        );

        self.entries.push(entry);

        // Update statistics
        self.stats.total_entries += 1;
        *self
            .stats
            .by_operation
            .entry(format!("{:?}", operation_type))
            .or_insert(0) += 1;
        *self
            .stats
            .by_severity
            .entry(format!("{:?}", severity))
            .or_insert(0) += 1;

        // Apply retention policy if set
        if let Some(days) = self.retention_days {
            self.apply_retention_policy(days);
        }
    }

    /// Apply retention policy (remove old entries)
    fn apply_retention_policy(&mut self, retention_days: i64) {
        let cutoff = Utc::now() - Duration::days(retention_days);
        self.entries.retain(|entry| entry.timestamp > cutoff);
    }

    /// Manually apply retention policy
    pub fn cleanup(&mut self) {
        if let Some(days) = self.retention_days {
            self.apply_retention_policy(days);
        }
    }

    /// Get all entries
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get total number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if log is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Query entries by operation type
    pub fn query_by_operation(&self, operation_type: OperationType) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.operation_type == operation_type)
            .collect()
    }

    /// Query entries by severity level (at least this level)
    pub fn query_by_severity(&self, min_severity: SeverityLevel) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity >= min_severity)
            .collect()
    }

    /// Query entries by time range
    pub fn query_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Query entries by principal
    pub fn query_by_principal(&self, principal: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.principal.as_ref().is_some_and(|p| p == principal))
            .collect()
    }

    /// Verify the integrity of the entire audit log
    pub fn verify_integrity(&self) -> bool {
        if self.entries.is_empty() {
            return true;
        }

        let mut previous_hash = vec![0u8; 32];
        for entry in &self.entries {
            if !entry.verify(&previous_hash) {
                return false;
            }
            previous_hash = entry.entry_hash.clone();
        }
        true
    }

    /// Get audit statistics
    pub fn statistics(&self) -> &AuditStatistics {
        &self.stats
    }

    /// Export audit log to JSON
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import audit log from JSON
    pub fn import_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Export to bytes (bincode)
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::codec::encode(self).expect("serialization failed")
    }

    /// Import from bytes (bincode)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(crate::codec::decode(bytes)?)
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_basic() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Generated keypair",
            None,
        );

        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_audit_log_with_metadata() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::Encryption,
            SeverityLevel::Info,
            "Encrypted file",
            Some("file=test.txt, size=1024"),
        );

        assert_eq!(
            log.entries()[0].metadata,
            Some("file=test.txt, size=1024".to_string())
        );
    }

    #[test]
    fn test_audit_log_with_principal() {
        let mut log = AuditLog::new();
        log.set_principal("alice".to_string());

        log.log(
            OperationType::Signing,
            SeverityLevel::Info,
            "Signed message",
            None,
        );

        assert_eq!(log.entries()[0].principal, Some("alice".to_string()));
    }

    #[test]
    fn test_integrity_verification() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );
        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);
        log.log(OperationType::Signing, SeverityLevel::Info, "Op 3", None);

        assert!(log.verify_integrity());
    }

    #[test]
    fn test_integrity_tamper_detection() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );
        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);

        // Tamper with an entry
        if let Some(entry) = log.entries.get_mut(0) {
            entry.description = "Tampered!".to_string();
        }

        assert!(!log.verify_integrity());
    }

    #[test]
    fn test_query_by_operation() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );
        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);
        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 3",
            None,
        );

        let results = log.query_by_operation(OperationType::KeyGeneration);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_query_by_severity() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );
        log.log(
            OperationType::Encryption,
            SeverityLevel::Warning,
            "Op 2",
            None,
        );
        log.log(OperationType::Signing, SeverityLevel::Error, "Op 3", None);
        log.log(
            OperationType::KeyDeletion,
            SeverityLevel::Critical,
            "Op 4",
            None,
        );

        let results = log.query_by_severity(SeverityLevel::Warning);
        assert_eq!(results.len(), 3); // Warning, Error, Critical
    }

    #[test]
    fn test_query_by_principal() {
        let mut log = AuditLog::new();

        log.set_principal("alice".to_string());
        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );

        log.set_principal("bob".to_string());
        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);

        log.set_principal("alice".to_string());
        log.log(OperationType::Signing, SeverityLevel::Info, "Op 3", None);

        let alice_ops = log.query_by_principal("alice");
        assert_eq!(alice_ops.len(), 2);
    }

    #[test]
    fn test_query_by_time_range() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );

        let start = Utc::now();
        std::thread::sleep(std::time::Duration::from_millis(10));

        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);

        let end = Utc::now();

        let results = log.query_by_time_range(start, end);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_statistics() {
        let mut log = AuditLog::new();

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );
        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);
        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Warning,
            "Op 3",
            None,
        );

        let stats = log.statistics();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(*stats.by_operation.get("KeyGeneration").unwrap(), 2);
        assert_eq!(*stats.by_severity.get("Info").unwrap(), 2);
    }

    #[test]
    fn test_retention_policy() {
        let mut log = AuditLog::with_retention(1); // 1 day retention

        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Op 1",
            None,
        );
        log.log(OperationType::Encryption, SeverityLevel::Info, "Op 2", None);

        assert_eq!(log.len(), 2);

        // Manually set an old timestamp
        if let Some(entry) = log.entries.get_mut(0) {
            entry.timestamp = Utc::now() - Duration::days(2);
        }

        log.cleanup();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_json_export_import() {
        let mut log = AuditLog::new();
        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Test",
            None,
        );

        let json = log.export_json().unwrap();
        let restored = AuditLog::import_json(&json).unwrap();

        assert_eq!(restored.len(), 1);
        assert!(restored.verify_integrity());
    }

    #[test]
    fn test_bincode_serialization() {
        let mut log = AuditLog::new();
        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Test",
            None,
        );

        let bytes = log.to_bytes();
        let restored = AuditLog::from_bytes(&bytes).unwrap();

        assert_eq!(restored.len(), 1);
        assert!(restored.verify_integrity());
    }

    #[test]
    fn test_multiple_principals() {
        let mut log = AuditLog::new();

        log.set_principal("alice".to_string());
        log.log(
            OperationType::KeyGeneration,
            SeverityLevel::Info,
            "Alice op 1",
            None,
        );
        log.log(
            OperationType::Encryption,
            SeverityLevel::Info,
            "Alice op 2",
            None,
        );

        log.set_principal("bob".to_string());
        log.log(
            OperationType::Signing,
            SeverityLevel::Info,
            "Bob op 1",
            None,
        );

        log.clear_principal();
        log.log(
            OperationType::Decryption,
            SeverityLevel::Info,
            "System op",
            None,
        );

        assert_eq!(log.query_by_principal("alice").len(), 2);
        assert_eq!(log.query_by_principal("bob").len(), 1);
    }

    #[test]
    fn test_all_operation_types() {
        let mut log = AuditLog::new();

        let operations = [
            OperationType::KeyGeneration,
            OperationType::KeyImportExport,
            OperationType::KeyRotation,
            OperationType::KeyDeletion,
            OperationType::Signing,
            OperationType::SignatureVerification,
            OperationType::Encryption,
            OperationType::Decryption,
            OperationType::Hashing,
            OperationType::KeyDerivation,
            OperationType::RandomGeneration,
            OperationType::CertificateIssuance,
            OperationType::CertificateRevocation,
            OperationType::AccessControl,
            OperationType::PolicyEnforcement,
            OperationType::AuditAccess,
            OperationType::Other,
        ];

        for op in &operations {
            log.log(*op, SeverityLevel::Info, "Test operation", None);
        }

        assert_eq!(log.len(), operations.len());
        assert!(log.verify_integrity());
    }

    #[test]
    fn test_all_severity_levels() {
        let mut log = AuditLog::new();

        let severities = [
            SeverityLevel::Debug,
            SeverityLevel::Info,
            SeverityLevel::Warning,
            SeverityLevel::Error,
            SeverityLevel::Critical,
        ];

        for severity in &severities {
            log.log(OperationType::Other, *severity, "Test severity", None);
        }

        assert_eq!(log.len(), severities.len());

        // Critical should be returned by all severity queries
        assert_eq!(log.query_by_severity(SeverityLevel::Debug).len(), 5);
        assert_eq!(log.query_by_severity(SeverityLevel::Info).len(), 4);
        assert_eq!(log.query_by_severity(SeverityLevel::Warning).len(), 3);
        assert_eq!(log.query_by_severity(SeverityLevel::Error).len(), 2);
        assert_eq!(log.query_by_severity(SeverityLevel::Critical).len(), 1);
    }
}
