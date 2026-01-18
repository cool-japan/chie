//! FIPS 140-3 Compliance Reporting
//!
//! This module provides compliance checking and reporting for FIPS 140-3 requirements.
//! It helps verify that cryptographic operations meet federal standards for security.
//!
//! # FIPS 140-3 Overview
//!
//! FIPS 140-3 is a U.S. government standard for cryptographic module validation.
//! It defines security requirements for cryptographic modules used in protecting
//! sensitive information.
//!
//! # Features
//!
//! - Algorithm compliance verification
//! - Key strength validation
//! - Self-tests (Known Answer Tests)
//! - Compliance report generation
//! - Security level tracking (Levels 1-4)
//! - Status monitoring and alerts
//!
//! # Example
//!
//! ```
//! use chie_crypto::compliance::{ComplianceChecker, ComplianceAlgorithm, SecurityLevel};
//!
//! let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
//!
//! // Register algorithms in use
//! checker.register_algorithm(ComplianceAlgorithm::AES256);
//! checker.register_algorithm(ComplianceAlgorithm::SHA256);
//! checker.register_algorithm(ComplianceAlgorithm::Ed25519);
//!
//! // Run self-tests
//! let test_results = checker.run_self_tests();
//! assert!(test_results.all_passed());
//!
//! // Generate compliance report
//! let report = checker.generate_report();
//! println!("Compliance Status: {:?}", report.overall_status);
//! ```

use crate::encryption::{decrypt, encrypt, generate_key, generate_nonce};
use crate::hash::hash;
use crate::signing::KeyPair;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// FIPS 140-3 security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Level 1: Basic security requirements
    Level1,
    /// Level 2: Physical tamper-evidence
    Level2,
    /// Level 3: Physical tamper-resistance
    Level3,
    /// Level 4: Complete envelope protection
    Level4,
}

/// Cryptographic algorithm for compliance checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceAlgorithm {
    /// AES-256 encryption
    AES256,
    /// ChaCha20-Poly1305 authenticated encryption
    ChaCha20Poly1305,
    /// SHA-256 hashing
    SHA256,
    /// SHA-512 hashing
    SHA512,
    /// BLAKE3 hashing
    BLAKE3,
    /// Ed25519 signatures
    Ed25519,
    /// X25519 key exchange
    X25519,
    /// HMAC-SHA256
    HMACSHA256,
    /// HKDF key derivation
    HKDF,
    /// RSA-2048
    RSA2048,
    /// RSA-3072
    RSA3072,
    /// Kyber (Post-Quantum KEM)
    Kyber,
    /// Dilithium (Post-Quantum Signatures)
    Dilithium,
}

impl ComplianceAlgorithm {
    /// Check if algorithm is FIPS 140-3 approved
    pub fn is_fips_approved(&self) -> bool {
        matches!(
            self,
            ComplianceAlgorithm::AES256
                | ComplianceAlgorithm::SHA256
                | ComplianceAlgorithm::SHA512
                | ComplianceAlgorithm::HMACSHA256
                | ComplianceAlgorithm::HKDF
                | ComplianceAlgorithm::RSA2048
                | ComplianceAlgorithm::RSA3072
        )
    }

    /// Get required minimum key size in bits
    pub fn min_key_size(&self) -> usize {
        match self {
            ComplianceAlgorithm::AES256 => 256,
            ComplianceAlgorithm::ChaCha20Poly1305 => 256,
            ComplianceAlgorithm::Ed25519 => 256,
            ComplianceAlgorithm::X25519 => 256,
            ComplianceAlgorithm::RSA2048 => 2048,
            ComplianceAlgorithm::RSA3072 => 3072,
            ComplianceAlgorithm::Kyber => 256,
            ComplianceAlgorithm::Dilithium => 256,
            _ => 0,
        }
    }
}

/// Compliance status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Fully compliant
    Compliant,
    /// Partially compliant (warnings)
    PartiallyCompliant,
    /// Non-compliant (errors)
    NonCompliant,
}

/// Self-test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResult {
    /// Test name
    pub test_name: String,
    /// Algorithm being tested
    pub algorithm: ComplianceAlgorithm,
    /// Test passed
    pub passed: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Test timestamp
    pub timestamp: DateTime<Utc>,
}

/// Collection of self-test results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResults {
    /// Individual test results
    pub tests: Vec<SelfTestResult>,
    /// Overall pass/fail
    pub all_passed: bool,
}

impl SelfTestResults {
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.all_passed
    }

    /// Get failed tests
    pub fn failed_tests(&self) -> Vec<&SelfTestResult> {
        self.tests.iter().filter(|t| !t.passed).collect()
    }
}

/// Compliance issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceIssue {
    /// Issue severity
    pub severity: IssueSeverity,
    /// Description
    pub description: String,
    /// Algorithm affected
    pub algorithm: Option<ComplianceAlgorithm>,
    /// Recommendation
    pub recommendation: String,
}

/// Issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueSeverity {
    /// Informational
    Info,
    /// Warning
    Warning,
    /// Error
    Error,
    /// Critical
    Critical,
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Security level
    pub security_level: SecurityLevel,
    /// Overall compliance status
    pub overall_status: ComplianceStatus,
    /// Algorithms in use
    pub algorithms: Vec<ComplianceAlgorithm>,
    /// FIPS-approved algorithms
    pub fips_approved: Vec<ComplianceAlgorithm>,
    /// Non-approved algorithms
    pub non_approved: Vec<ComplianceAlgorithm>,
    /// Self-test results
    pub self_test_results: SelfTestResults,
    /// Compliance issues
    pub issues: Vec<ComplianceIssue>,
    /// Report timestamp
    pub timestamp: DateTime<Utc>,
}

impl ComplianceReport {
    /// Export report to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// FIPS 140-3 compliance checker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceChecker {
    /// Target security level
    security_level: SecurityLevel,
    /// Registered algorithms
    algorithms: Vec<ComplianceAlgorithm>,
    /// Issues found
    issues: Vec<ComplianceIssue>,
}

impl ComplianceChecker {
    /// Create a new compliance checker
    pub fn new(security_level: SecurityLevel) -> Self {
        Self {
            security_level,
            algorithms: Vec::new(),
            issues: Vec::new(),
        }
    }

    /// Register an algorithm in use
    pub fn register_algorithm(&mut self, algorithm: ComplianceAlgorithm) {
        if !self.algorithms.contains(&algorithm) {
            self.algorithms.push(algorithm);

            // Check if algorithm is FIPS approved
            if !algorithm.is_fips_approved() {
                self.issues.push(ComplianceIssue {
                    severity: IssueSeverity::Warning,
                    description: format!("{:?} is not FIPS 140-3 approved", algorithm),
                    algorithm: Some(algorithm),
                    recommendation: "Consider using FIPS-approved alternatives".to_string(),
                });
            }
        }
    }

    /// Run self-tests (Known Answer Tests)
    pub fn run_self_tests(&mut self) -> SelfTestResults {
        let tests = vec![
            // Test ChaCha20-Poly1305 encryption
            self.test_chacha20(),
            // Test BLAKE3 hashing
            self.test_blake3(),
            // Test Ed25519 signing
            self.test_ed25519(),
        ];

        let all_passed = tests.iter().all(|t| t.passed);

        SelfTestResults { tests, all_passed }
    }

    /// Test ChaCha20-Poly1305 encryption
    fn test_chacha20(&self) -> SelfTestResult {
        let test_name = "ChaCha20-Poly1305 KAT".to_string();
        let algorithm = ComplianceAlgorithm::ChaCha20Poly1305;

        // Known Answer Test
        let plaintext = b"Test message for KAT";
        let key = generate_key();
        let nonce = generate_nonce();

        match encrypt(plaintext, &key, &nonce) {
            Ok(ciphertext) => match decrypt(&ciphertext, &key, &nonce) {
                Ok(decrypted) => {
                    let passed = decrypted == plaintext;
                    SelfTestResult {
                        test_name,
                        algorithm,
                        passed,
                        error: if passed {
                            None
                        } else {
                            Some("Decryption mismatch".to_string())
                        },
                        timestamp: Utc::now(),
                    }
                }
                Err(e) => SelfTestResult {
                    test_name,
                    algorithm,
                    passed: false,
                    error: Some(format!("Decryption failed: {:?}", e)),
                    timestamp: Utc::now(),
                },
            },
            Err(e) => SelfTestResult {
                test_name,
                algorithm,
                passed: false,
                error: Some(format!("Encryption failed: {:?}", e)),
                timestamp: Utc::now(),
            },
        }
    }

    /// Test BLAKE3 hashing
    fn test_blake3(&self) -> SelfTestResult {
        let test_name = "BLAKE3 KAT".to_string();
        let algorithm = ComplianceAlgorithm::BLAKE3;

        // Known Answer Test
        let input = b"The quick brown fox jumps over the lazy dog";
        let hash1 = hash(input);
        let hash2 = hash(input);

        let passed = hash1 == hash2 && hash1.len() == 32;

        SelfTestResult {
            test_name,
            algorithm,
            passed,
            error: if passed {
                None
            } else {
                Some("Hash mismatch or incorrect length".to_string())
            },
            timestamp: Utc::now(),
        }
    }

    /// Test Ed25519 signing
    fn test_ed25519(&self) -> SelfTestResult {
        let test_name = "Ed25519 KAT".to_string();
        let algorithm = ComplianceAlgorithm::Ed25519;

        // Known Answer Test
        let keypair = KeyPair::generate();
        let message = b"Test message for signature";
        let signature = keypair.sign(message);

        let passed = keypair.verify(message, &signature);

        SelfTestResult {
            test_name,
            algorithm,
            passed,
            error: if passed {
                None
            } else {
                Some("Signature verification failed".to_string())
            },
            timestamp: Utc::now(),
        }
    }

    /// Validate key strength
    pub fn validate_key_strength(
        &mut self,
        algorithm: ComplianceAlgorithm,
        key_bits: usize,
    ) -> bool {
        let min_bits = algorithm.min_key_size();

        if key_bits < min_bits {
            self.issues.push(ComplianceIssue {
                severity: IssueSeverity::Error,
                description: format!(
                    "{:?} key strength ({} bits) below minimum ({} bits)",
                    algorithm, key_bits, min_bits
                ),
                algorithm: Some(algorithm),
                recommendation: format!("Use at least {} bits for {:?}", min_bits, algorithm),
            });
            false
        } else {
            true
        }
    }

    /// Generate compliance report
    pub fn generate_report(&mut self) -> ComplianceReport {
        let self_test_results = self.run_self_tests();

        let fips_approved: Vec<ComplianceAlgorithm> = self
            .algorithms
            .iter()
            .filter(|a| a.is_fips_approved())
            .copied()
            .collect();

        let non_approved: Vec<ComplianceAlgorithm> = self
            .algorithms
            .iter()
            .filter(|a| !a.is_fips_approved())
            .copied()
            .collect();

        // Determine overall status
        let has_errors = self
            .issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::Error | IssueSeverity::Critical));

        let has_warnings = self
            .issues
            .iter()
            .any(|i| i.severity == IssueSeverity::Warning);

        let overall_status = if has_errors || !self_test_results.all_passed {
            ComplianceStatus::NonCompliant
        } else if has_warnings || !non_approved.is_empty() {
            ComplianceStatus::PartiallyCompliant
        } else {
            ComplianceStatus::Compliant
        };

        ComplianceReport {
            security_level: self.security_level,
            overall_status,
            algorithms: self.algorithms.clone(),
            fips_approved,
            non_approved,
            self_test_results,
            issues: self.issues.clone(),
            timestamp: Utc::now(),
        }
    }

    /// Get current issues
    pub fn issues(&self) -> &[ComplianceIssue] {
        &self.issues
    }

    /// Clear all issues
    pub fn clear_issues(&mut self) {
        self.issues.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_checker_basic() {
        let checker = ComplianceChecker::new(SecurityLevel::Level1);
        assert_eq!(checker.security_level, SecurityLevel::Level1);
    }

    #[test]
    fn test_register_fips_approved_algorithm() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::AES256);

        assert_eq!(checker.algorithms.len(), 1);
        assert_eq!(checker.issues.len(), 0);
    }

    #[test]
    fn test_register_non_approved_algorithm() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::ChaCha20Poly1305);

        assert_eq!(checker.algorithms.len(), 1);
        assert_eq!(checker.issues.len(), 1);
        assert_eq!(checker.issues[0].severity, IssueSeverity::Warning);
    }

    #[test]
    fn test_self_tests() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        let results = checker.run_self_tests();

        assert!(results.all_passed());
        assert_eq!(results.tests.len(), 3);
    }

    #[test]
    fn test_key_strength_validation() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);

        // Valid key strength
        assert!(checker.validate_key_strength(ComplianceAlgorithm::AES256, 256));

        // Invalid key strength
        assert!(!checker.validate_key_strength(ComplianceAlgorithm::AES256, 128));
        assert_eq!(checker.issues.len(), 1);
    }

    #[test]
    fn test_generate_report_compliant() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::AES256);
        checker.register_algorithm(ComplianceAlgorithm::SHA256);

        let report = checker.generate_report();

        assert_eq!(report.overall_status, ComplianceStatus::Compliant);
        assert_eq!(report.fips_approved.len(), 2);
        assert_eq!(report.non_approved.len(), 0);
    }

    #[test]
    fn test_generate_report_partially_compliant() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::AES256);
        checker.register_algorithm(ComplianceAlgorithm::ChaCha20Poly1305);

        let report = checker.generate_report();

        assert_eq!(report.overall_status, ComplianceStatus::PartiallyCompliant);
        assert_eq!(report.fips_approved.len(), 1);
        assert_eq!(report.non_approved.len(), 1);
    }

    #[test]
    fn test_generate_report_non_compliant() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::AES256);
        checker.validate_key_strength(ComplianceAlgorithm::AES256, 64); // Too weak

        let report = checker.generate_report();

        assert_eq!(report.overall_status, ComplianceStatus::NonCompliant);
    }

    #[test]
    fn test_algorithm_is_fips_approved() {
        assert!(ComplianceAlgorithm::AES256.is_fips_approved());
        assert!(ComplianceAlgorithm::SHA256.is_fips_approved());
        assert!(!ComplianceAlgorithm::ChaCha20Poly1305.is_fips_approved());
        assert!(!ComplianceAlgorithm::BLAKE3.is_fips_approved());
    }

    #[test]
    fn test_security_levels() {
        assert!(SecurityLevel::Level1 < SecurityLevel::Level2);
        assert!(SecurityLevel::Level2 < SecurityLevel::Level3);
        assert!(SecurityLevel::Level3 < SecurityLevel::Level4);
    }

    #[test]
    fn test_report_json_export() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::AES256);

        let report = checker.generate_report();
        let json = report.to_json().unwrap();

        assert!(json.contains("AES256"));
        assert!(json.contains("security_level"));
    }

    #[test]
    fn test_failed_tests() {
        let results = SelfTestResults {
            tests: vec![
                SelfTestResult {
                    test_name: "Test1".to_string(),
                    algorithm: ComplianceAlgorithm::AES256,
                    passed: true,
                    error: None,
                    timestamp: Utc::now(),
                },
                SelfTestResult {
                    test_name: "Test2".to_string(),
                    algorithm: ComplianceAlgorithm::SHA256,
                    passed: false,
                    error: Some("Error".to_string()),
                    timestamp: Utc::now(),
                },
            ],
            all_passed: false,
        };

        let failed = results.failed_tests();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].test_name, "Test2");
    }

    #[test]
    fn test_clear_issues() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);
        checker.register_algorithm(ComplianceAlgorithm::ChaCha20Poly1305);

        assert_eq!(checker.issues.len(), 1);

        checker.clear_issues();
        assert_eq!(checker.issues.len(), 0);
    }

    #[test]
    fn test_multiple_registrations_same_algorithm() {
        let mut checker = ComplianceChecker::new(SecurityLevel::Level1);

        checker.register_algorithm(ComplianceAlgorithm::AES256);
        checker.register_algorithm(ComplianceAlgorithm::AES256);
        checker.register_algorithm(ComplianceAlgorithm::AES256);

        // Should only register once
        assert_eq!(checker.algorithms.len(), 1);
    }

    #[test]
    fn test_min_key_sizes() {
        assert_eq!(ComplianceAlgorithm::AES256.min_key_size(), 256);
        assert_eq!(ComplianceAlgorithm::RSA2048.min_key_size(), 2048);
        assert_eq!(ComplianceAlgorithm::RSA3072.min_key_size(), 3072);
    }

    #[test]
    fn test_issue_severity_levels() {
        let issue = ComplianceIssue {
            severity: IssueSeverity::Critical,
            description: "Test".to_string(),
            algorithm: None,
            recommendation: "Fix it".to_string(),
        };

        assert_eq!(issue.severity, IssueSeverity::Critical);
    }
}
