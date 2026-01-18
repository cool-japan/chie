//! Certificate pinning for enhanced peer security.
//!
//! This module implements certificate pinning (also known as "public key pinning")
//! to prevent man-in-the-middle attacks by ensuring that only known and trusted
//! certificates are accepted for specific peers.
//!
//! # Security Benefits
//!
//! - Protection against compromised Certificate Authorities
//! - Prevention of MITM attacks with fraudulent certificates
//! - Enhanced trust model for critical peer connections
//! - Automatic detection of certificate changes
//!
//! # Example
//!
//! ```rust,no_run
//! use chie_p2p::cert_pinning::{CertificatePinner, Pin, PinPolicy};
//! use libp2p::PeerId;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let pinner = CertificatePinner::new();
//!
//! // Pin a certificate for a specific peer
//! let peer_id = PeerId::random();
//! let cert_hash = vec![1, 2, 3, 4];
//! pinner.add_pin(&peer_id, cert_hash.clone(), PinPolicy::Strict)?;
//!
//! // Verify a certificate matches the pin
//! let is_valid = pinner.verify_certificate(&peer_id, &cert_hash)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

use libp2p::PeerId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Pin policy determines how strict the pinning enforcement is
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinPolicy {
    /// Strict: Reject any certificate that doesn't match the pin
    Strict,
    /// TrustOnFirstUse: Accept first certificate, then pin it
    TrustOnFirstUse,
    /// Flexible: Warn on mismatch but allow connection
    Flexible,
    /// None: No pinning enforced
    None,
}

/// Hash algorithm for certificate fingerprinting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// BLAKE3
    Blake3,
}

/// Certificate pin information
#[derive(Debug, Clone)]
pub struct Pin {
    /// Peer ID this pin applies to
    pub peer_id: PeerId,
    /// Certificate hash (fingerprint)
    pub cert_hash: Vec<u8>,
    /// Hash algorithm used
    pub hash_algorithm: HashAlgorithm,
    /// Pin policy
    pub policy: PinPolicy,
    /// When this pin was created
    pub created_at: SystemTime,
    /// Optional expiration time
    pub expires_at: Option<SystemTime>,
    /// Number of times this pin has been verified successfully
    pub verify_count: u64,
    /// Last verification time
    pub last_verified: Option<SystemTime>,
}

impl Pin {
    /// Create a new pin
    pub fn new(peer_id: PeerId, cert_hash: Vec<u8>, policy: PinPolicy) -> Self {
        Self {
            peer_id,
            cert_hash,
            hash_algorithm: HashAlgorithm::Blake3,
            policy,
            created_at: SystemTime::now(),
            expires_at: None,
            verify_count: 0,
            last_verified: None,
        }
    }

    /// Set hash algorithm
    pub fn with_hash_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.hash_algorithm = algorithm;
        self
    }

    /// Set expiration time
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.expires_at = Some(SystemTime::now() + duration);
        self
    }

    /// Check if pin is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }

    /// Record a successful verification
    pub fn record_verification(&mut self) {
        self.verify_count += 1;
        self.last_verified = Some(SystemTime::now());
    }
}

/// Pin violation details
#[derive(Debug, Clone)]
pub struct PinViolation {
    /// Peer ID where violation occurred
    pub peer_id: PeerId,
    /// Expected certificate hash
    pub expected_hash: Vec<u8>,
    /// Actual certificate hash
    pub actual_hash: Vec<u8>,
    /// When the violation occurred
    pub occurred_at: SystemTime,
    /// Policy that was violated
    pub policy: PinPolicy,
}

/// Certificate pinner manages certificate pins for peers
pub struct CertificatePinner {
    /// Active pins
    pins: Arc<Mutex<HashMap<PeerId, Pin>>>,
    /// Pin violations
    violations: Arc<Mutex<Vec<PinViolation>>>,
    /// Default pin policy
    default_policy: PinPolicy,
    /// Maximum violations to keep in history
    max_violations: usize,
}

impl CertificatePinner {
    /// Create a new certificate pinner
    pub fn new() -> Self {
        Self {
            pins: Arc::new(Mutex::new(HashMap::new())),
            violations: Arc::new(Mutex::new(Vec::new())),
            default_policy: PinPolicy::TrustOnFirstUse,
            max_violations: 1000,
        }
    }

    /// Set default pin policy
    pub fn with_default_policy(mut self, policy: PinPolicy) -> Self {
        self.default_policy = policy;
        self
    }

    /// Set maximum violations to track
    pub fn with_max_violations(mut self, max: usize) -> Self {
        self.max_violations = max;
        self
    }

    /// Add a pin for a peer
    pub fn add_pin(
        &self,
        peer_id: &PeerId,
        cert_hash: Vec<u8>,
        policy: PinPolicy,
    ) -> Result<(), String> {
        let pin = Pin::new(*peer_id, cert_hash, policy);
        self.pins.lock().unwrap().insert(*peer_id, pin);
        Ok(())
    }

    /// Add a pin with custom configuration
    pub fn add_pin_custom(&self, pin: Pin) -> Result<(), String> {
        self.pins.lock().unwrap().insert(pin.peer_id, pin);
        Ok(())
    }

    /// Get pin for a peer
    pub fn get_pin(&self, peer_id: &PeerId) -> Option<Pin> {
        self.pins.lock().unwrap().get(peer_id).cloned()
    }

    /// Remove pin for a peer
    pub fn remove_pin(&self, peer_id: &PeerId) -> bool {
        self.pins.lock().unwrap().remove(peer_id).is_some()
    }

    /// Verify a certificate against the pin
    pub fn verify_certificate(&self, peer_id: &PeerId, cert_hash: &[u8]) -> Result<bool, String> {
        let mut pins = self.pins.lock().unwrap();

        // Get or create pin
        let pin = if let Some(pin) = pins.get_mut(peer_id) {
            pin
        } else {
            // Handle based on default policy
            match self.default_policy {
                PinPolicy::TrustOnFirstUse => {
                    // Create new pin with the provided certificate
                    let new_pin = Pin::new(*peer_id, cert_hash.to_vec(), self.default_policy);
                    pins.insert(*peer_id, new_pin);
                    return Ok(true);
                }
                PinPolicy::None => {
                    // No pinning, always accept
                    return Ok(true);
                }
                _ => {
                    // No pin found and strict/flexible policy
                    return Err(format!("No pin found for peer {}", peer_id));
                }
            }
        };

        // Check expiration
        if pin.is_expired() {
            return Err("Pin has expired".to_string());
        }

        // Verify hash matches
        let matches = pin.cert_hash == cert_hash;

        if matches {
            // Record successful verification
            pin.record_verification();
            Ok(true)
        } else {
            // Handle mismatch based on policy
            self.record_violation(PinViolation {
                peer_id: *peer_id,
                expected_hash: pin.cert_hash.clone(),
                actual_hash: cert_hash.to_vec(),
                occurred_at: SystemTime::now(),
                policy: pin.policy,
            });

            match pin.policy {
                PinPolicy::Strict => Ok(false),
                PinPolicy::Flexible => {
                    // Warn but allow
                    eprintln!("Warning: Certificate mismatch for peer {}", peer_id);
                    Ok(true)
                }
                PinPolicy::TrustOnFirstUse | PinPolicy::None => Ok(true),
            }
        }
    }

    /// Record a pin violation
    fn record_violation(&self, violation: PinViolation) {
        let mut violations = self.violations.lock().unwrap();
        violations.push(violation);

        // Trim if exceeds max
        if violations.len() > self.max_violations {
            let excess = violations.len() - self.max_violations;
            violations.drain(0..excess);
        }
    }

    /// Get all violations
    pub fn get_violations(&self) -> Vec<PinViolation> {
        self.violations.lock().unwrap().clone()
    }

    /// Get violations for a specific peer
    pub fn get_peer_violations(&self, peer_id: &PeerId) -> Vec<PinViolation> {
        self.violations
            .lock()
            .unwrap()
            .iter()
            .filter(|v| &v.peer_id == peer_id)
            .cloned()
            .collect()
    }

    /// Clear all violations
    pub fn clear_violations(&self) {
        self.violations.lock().unwrap().clear();
    }

    /// Get all pins
    pub fn get_all_pins(&self) -> Vec<Pin> {
        self.pins.lock().unwrap().values().cloned().collect()
    }

    /// Update pin for a peer (rotate certificate)
    pub fn update_pin(&self, peer_id: &PeerId, new_cert_hash: Vec<u8>) -> Result<(), String> {
        let mut pins = self.pins.lock().unwrap();

        if let Some(pin) = pins.get_mut(peer_id) {
            pin.cert_hash = new_cert_hash;
            pin.verify_count = 0;
            pin.last_verified = None;
            Ok(())
        } else {
            Err(format!("No pin found for peer {}", peer_id))
        }
    }

    /// Clean up expired pins
    pub fn cleanup_expired(&self) -> usize {
        let mut pins = self.pins.lock().unwrap();
        let before = pins.len();
        pins.retain(|_, pin| !pin.is_expired());
        before - pins.len()
    }

    /// Get pin statistics
    pub fn get_stats(&self) -> PinStats {
        let pins = self.pins.lock().unwrap();
        let violations = self.violations.lock().unwrap();

        let mut by_policy = HashMap::new();
        let mut expired = 0;

        for pin in pins.values() {
            *by_policy.entry(pin.policy).or_insert(0) += 1;
            if pin.is_expired() {
                expired += 1;
            }
        }

        PinStats {
            total_pins: pins.len(),
            active_pins: pins.len() - expired,
            expired_pins: expired,
            total_violations: violations.len(),
            pins_by_policy: by_policy,
        }
    }
}

impl Default for CertificatePinner {
    fn default() -> Self {
        Self::new()
    }
}

/// Pin statistics
#[derive(Debug, Clone)]
pub struct PinStats {
    /// Total number of pins
    pub total_pins: usize,
    /// Active (non-expired) pins
    pub active_pins: usize,
    /// Expired pins
    pub expired_pins: usize,
    /// Total violations recorded
    pub total_violations: usize,
    /// Pins grouped by policy
    pub pins_by_policy: HashMap<PinPolicy, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_pinner_new() {
        let pinner = CertificatePinner::new();
        assert_eq!(pinner.get_all_pins().len(), 0);
    }

    #[test]
    fn test_add_pin() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];

        pinner
            .add_pin(&peer_id, cert_hash.clone(), PinPolicy::Strict)
            .unwrap();

        let pin = pinner.get_pin(&peer_id).unwrap();
        assert_eq!(pin.cert_hash, cert_hash);
        assert_eq!(pin.policy, PinPolicy::Strict);
    }

    #[test]
    fn test_verify_certificate_strict_success() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];

        pinner
            .add_pin(&peer_id, cert_hash.clone(), PinPolicy::Strict)
            .unwrap();

        let result = pinner.verify_certificate(&peer_id, &cert_hash).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_certificate_strict_failure() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];
        let wrong_hash = vec![5, 6, 7, 8];

        pinner
            .add_pin(&peer_id, cert_hash, PinPolicy::Strict)
            .unwrap();

        let result = pinner.verify_certificate(&peer_id, &wrong_hash).unwrap();
        assert!(!result);

        // Check violation was recorded
        let violations = pinner.get_peer_violations(&peer_id);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_trust_on_first_use() {
        let pinner = CertificatePinner::new().with_default_policy(PinPolicy::TrustOnFirstUse);
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];

        // First verification should create pin
        let result = pinner.verify_certificate(&peer_id, &cert_hash).unwrap();
        assert!(result);

        // Verify pin was created
        let pin = pinner.get_pin(&peer_id).unwrap();
        assert_eq!(pin.cert_hash, cert_hash);
    }

    #[test]
    fn test_flexible_policy() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];
        let different_hash = vec![5, 6, 7, 8];

        pinner
            .add_pin(&peer_id, cert_hash, PinPolicy::Flexible)
            .unwrap();

        // Should allow even with mismatch
        let result = pinner
            .verify_certificate(&peer_id, &different_hash)
            .unwrap();
        assert!(result);

        // But violation should be recorded
        let violations = pinner.get_peer_violations(&peer_id);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_remove_pin() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];

        pinner
            .add_pin(&peer_id, cert_hash, PinPolicy::Strict)
            .unwrap();
        assert!(pinner.get_pin(&peer_id).is_some());

        let removed = pinner.remove_pin(&peer_id);
        assert!(removed);
        assert!(pinner.get_pin(&peer_id).is_none());
    }

    #[test]
    fn test_pin_expiration() {
        let peer_id = PeerId::random();
        let cert_hash = vec![1, 2, 3, 4];

        let pin = Pin::new(peer_id, cert_hash, PinPolicy::Strict)
            .with_expiration(Duration::from_millis(10));

        assert!(!pin.is_expired());

        std::thread::sleep(Duration::from_millis(20));
        assert!(pin.is_expired());
    }

    #[test]
    fn test_cleanup_expired() {
        let pinner = CertificatePinner::new();
        let peer_id1 = PeerId::random();
        let peer_id2 = PeerId::random();

        let pin1 = Pin::new(peer_id1, vec![1, 2], PinPolicy::Strict)
            .with_expiration(Duration::from_millis(10));
        let pin2 = Pin::new(peer_id2, vec![3, 4], PinPolicy::Strict);

        pinner.add_pin_custom(pin1).unwrap();
        pinner.add_pin_custom(pin2).unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let removed = pinner.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(pinner.get_all_pins().len(), 1);
    }

    #[test]
    fn test_update_pin() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();
        let old_hash = vec![1, 2, 3, 4];
        let new_hash = vec![5, 6, 7, 8];

        pinner
            .add_pin(&peer_id, old_hash, PinPolicy::Strict)
            .unwrap();
        pinner.update_pin(&peer_id, new_hash.clone()).unwrap();

        let pin = pinner.get_pin(&peer_id).unwrap();
        assert_eq!(pin.cert_hash, new_hash);
    }

    #[test]
    fn test_record_verification() {
        let mut pin = Pin::new(PeerId::random(), vec![1, 2], PinPolicy::Strict);
        assert_eq!(pin.verify_count, 0);
        assert!(pin.last_verified.is_none());

        pin.record_verification();
        assert_eq!(pin.verify_count, 1);
        assert!(pin.last_verified.is_some());
    }

    #[test]
    fn test_get_stats() {
        let pinner = CertificatePinner::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        pinner.add_pin(&peer1, vec![1], PinPolicy::Strict).unwrap();
        pinner
            .add_pin(&peer2, vec![2], PinPolicy::Flexible)
            .unwrap();

        // Create a violation
        pinner.verify_certificate(&peer1, &[99]).unwrap();

        let stats = pinner.get_stats();
        assert_eq!(stats.total_pins, 2);
        assert_eq!(stats.total_violations, 1);
        assert_eq!(stats.pins_by_policy.get(&PinPolicy::Strict), Some(&1));
    }

    #[test]
    fn test_hash_algorithm() {
        let pin = Pin::new(PeerId::random(), vec![1], PinPolicy::Strict)
            .with_hash_algorithm(HashAlgorithm::Sha256);

        assert_eq!(pin.hash_algorithm, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_violation_max_limit() {
        let pinner = CertificatePinner::new().with_max_violations(2);
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();

        pinner.add_pin(&peer1, vec![1], PinPolicy::Strict).unwrap();
        pinner.add_pin(&peer2, vec![2], PinPolicy::Strict).unwrap();
        pinner.add_pin(&peer3, vec![3], PinPolicy::Strict).unwrap();

        // Create 3 violations
        pinner.verify_certificate(&peer1, &[99]).unwrap();
        pinner.verify_certificate(&peer2, &[99]).unwrap();
        pinner.verify_certificate(&peer3, &[99]).unwrap();

        // Should only keep last 2
        let violations = pinner.get_violations();
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn test_clear_violations() {
        let pinner = CertificatePinner::new();
        let peer_id = PeerId::random();

        pinner
            .add_pin(&peer_id, vec![1], PinPolicy::Strict)
            .unwrap();
        pinner.verify_certificate(&peer_id, &[99]).unwrap();

        assert_eq!(pinner.get_violations().len(), 1);

        pinner.clear_violations();
        assert_eq!(pinner.get_violations().len(), 0);
    }

    #[test]
    fn test_pin_policy_none() {
        let pinner = CertificatePinner::new().with_default_policy(PinPolicy::None);

        let peer_id = PeerId::random();
        let result = pinner.verify_certificate(&peer_id, &[1, 2, 3]).unwrap();
        assert!(result);
    }

    #[test]
    fn test_default_implementation() {
        let pinner = CertificatePinner::default();
        assert_eq!(pinner.get_all_pins().len(), 0);
    }
}
