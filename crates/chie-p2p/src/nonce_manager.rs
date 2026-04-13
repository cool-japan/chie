//! Nonce management for secure challenge-response in bandwidth proof protocol.
//!
//! This module provides nonce generation and validation to prevent replay attacks
//! in the bandwidth proof protocol. Nonces are single-use tokens that ensure each
//! chunk request is unique and cannot be replayed.
//!
//! # Examples
//!
//! ```
//! use chie_p2p::nonce_manager::NonceManager;
//!
//! let manager = NonceManager::new();
//!
//! // Generate a new nonce for a request
//! let nonce = manager.generate_nonce();
//! assert!(manager.validate_nonce(&nonce).is_ok());
//!
//! // Nonce cannot be reused
//! assert!(manager.validate_nonce(&nonce).is_err());
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Errors that can occur during nonce operations.
#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    /// Nonce has already been used (replay attack).
    #[error("Nonce already used (potential replay attack): {0}")]
    NonceReused(String),

    /// Nonce has expired.
    #[error("Nonce expired: {0}")]
    NonceExpired(String),

    /// Nonce not found (may have been cleaned up).
    #[error("Nonce not found: {0}")]
    NonceNotFound(String),

    /// Invalid nonce format.
    #[error("Invalid nonce format: {0}")]
    InvalidNonce(String),
}

/// Nonce information.
#[derive(Debug, Clone)]
pub struct NonceInfo {
    /// The nonce value.
    pub nonce: String,
    /// When the nonce was created.
    pub created_at: Instant,
    /// Whether the nonce has been used.
    pub used: bool,
    /// When the nonce expires.
    pub expires_at: Instant,
}

impl NonceInfo {
    /// Create a new nonce info.
    pub fn new(nonce: String, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            nonce,
            created_at: now,
            used: false,
            expires_at: now + ttl,
        }
    }

    /// Check if the nonce has expired.
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Mark the nonce as used.
    pub fn mark_used(&mut self) {
        self.used = true;
    }
}

/// Configuration for nonce management.
#[derive(Debug, Clone)]
pub struct NonceConfig {
    /// Nonce time-to-live.
    pub nonce_ttl: Duration,
    /// Maximum number of nonces to track.
    pub max_nonces: usize,
    /// Cleanup interval for expired nonces.
    pub cleanup_interval: Duration,
    /// Nonce length in bytes (will be hex-encoded to 2x length).
    pub nonce_length: usize,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            nonce_ttl: Duration::from_secs(300), // 5 minutes
            max_nonces: 10000,
            cleanup_interval: Duration::from_secs(60), // 1 minute
            nonce_length: 32,                          // 32 bytes = 64 hex characters
        }
    }
}

/// Statistics for nonce operations.
#[derive(Debug, Default, Clone)]
pub struct NonceStats {
    /// Total nonces generated.
    pub generated: u64,
    /// Total nonces validated successfully.
    pub validated: u64,
    /// Total replay attack attempts detected.
    pub replay_attempts: u64,
    /// Total expired nonces rejected.
    pub expired_rejected: u64,
    /// Total nonces cleaned up.
    pub cleaned_up: u64,
    /// Current number of active nonces.
    pub active_nonces: usize,
}

impl NonceStats {
    /// Get the replay attack rate.
    pub fn replay_rate(&self) -> f64 {
        let total = self.validated + self.replay_attempts;
        if total == 0 {
            return 0.0;
        }
        self.replay_attempts as f64 / total as f64
    }

    /// Get the expiration rate.
    pub fn expiration_rate(&self) -> f64 {
        let total = self.validated + self.expired_rejected;
        if total == 0 {
            return 0.0;
        }
        self.expired_rejected as f64 / total as f64
    }
}

/// Nonce manager for bandwidth proof protocol.
pub struct NonceManager {
    config: NonceConfig,
    /// Map from nonce to nonce info.
    nonces: Arc<parking_lot::RwLock<HashMap<String, NonceInfo>>>,
    /// Queue of nonces in creation order (for cleanup).
    nonce_queue: Arc<parking_lot::RwLock<VecDeque<String>>>,
    /// Statistics.
    stats: Arc<parking_lot::RwLock<NonceStats>>,
    /// Last cleanup time.
    last_cleanup: Arc<parking_lot::RwLock<Instant>>,
}

impl NonceManager {
    /// Create a new nonce manager with default configuration.
    pub fn new() -> Self {
        Self::with_config(NonceConfig::default())
    }

    /// Create a new nonce manager with custom configuration.
    pub fn with_config(config: NonceConfig) -> Self {
        Self {
            config,
            nonces: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            nonce_queue: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            stats: Arc::new(parking_lot::RwLock::new(NonceStats::default())),
            last_cleanup: Arc::new(parking_lot::RwLock::new(Instant::now())),
        }
    }

    /// Generate a new nonce.
    pub fn generate_nonce(&self) -> String {
        // Generate random bytes
        use rand::RngExt as _;
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..self.config.nonce_length)
            .map(|_| rng.random::<u8>())
            .collect();

        // Convert to hex string
        let nonce = hex::encode(bytes);

        // Store nonce info
        let info = NonceInfo::new(nonce.clone(), self.config.nonce_ttl);
        {
            let mut nonces = self.nonces.write();
            let mut queue = self.nonce_queue.write();
            let mut stats = self.stats.write();

            // Enforce max nonces limit
            if nonces.len() >= self.config.max_nonces {
                // Remove oldest nonce
                if let Some(old_nonce) = queue.pop_front() {
                    nonces.remove(&old_nonce);
                }
            }

            nonces.insert(nonce.clone(), info);
            queue.push_back(nonce.clone());
            stats.generated += 1;
            stats.active_nonces = nonces.len();
        }

        // Maybe cleanup
        self.maybe_cleanup();

        nonce
    }

    /// Validate a nonce and mark it as used.
    ///
    /// Returns an error if the nonce has already been used, has expired, or is not found.
    pub fn validate_nonce(&self, nonce: &str) -> Result<(), NonceError> {
        let mut nonces = self.nonces.write();
        let mut stats = self.stats.write();

        if let Some(info) = nonces.get_mut(nonce) {
            // Check if expired
            if info.is_expired() {
                stats.expired_rejected += 1;
                return Err(NonceError::NonceExpired(nonce.to_string()));
            }

            // Check if already used (replay attack)
            if info.used {
                stats.replay_attempts += 1;
                return Err(NonceError::NonceReused(nonce.to_string()));
            }

            // Mark as used
            info.mark_used();
            stats.validated += 1;
            Ok(())
        } else {
            Err(NonceError::NonceNotFound(nonce.to_string()))
        }
    }

    /// Check if a nonce is valid (without marking it as used).
    pub fn is_valid(&self, nonce: &str) -> bool {
        let nonces = self.nonces.read();
        if let Some(info) = nonces.get(nonce) {
            !info.is_expired() && !info.used
        } else {
            false
        }
    }

    /// Get information about a nonce.
    pub fn get_nonce_info(&self, nonce: &str) -> Option<NonceInfo> {
        self.nonces.read().get(nonce).cloned()
    }

    /// Clean up expired and used nonces.
    pub fn cleanup(&self) -> usize {
        let mut nonces = self.nonces.write();
        let mut queue = self.nonce_queue.write();
        let mut stats = self.stats.write();

        // Find expired or used nonces
        let to_remove: Vec<String> = nonces
            .iter()
            .filter(|(_, info)| info.is_expired() || info.used)
            .map(|(nonce, _)| nonce.clone())
            .collect();

        let count = to_remove.len();

        // Remove from map
        for nonce in &to_remove {
            nonces.remove(nonce);
        }

        // Remove from queue (this is O(n) but happens infrequently)
        queue.retain(|n| !to_remove.contains(n));

        stats.cleaned_up += count as u64;
        stats.active_nonces = nonces.len();

        *self.last_cleanup.write() = Instant::now();

        count
    }

    /// Maybe cleanup if enough time has passed.
    fn maybe_cleanup(&self) {
        let last = *self.last_cleanup.read();
        if last.elapsed() >= self.config.cleanup_interval {
            self.cleanup();
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> NonceStats {
        self.stats.read().clone()
    }

    /// Get configuration.
    pub fn config(&self) -> &NonceConfig {
        &self.config
    }

    /// Get the number of active nonces.
    pub fn active_count(&self) -> usize {
        self.nonces.read().len()
    }

    /// Clear all nonces.
    pub fn clear(&self) {
        let mut nonces = self.nonces.write();
        let mut queue = self.nonce_queue.write();
        let mut stats = self.stats.write();

        nonces.clear();
        queue.clear();
        stats.active_nonces = 0;
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for NonceManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            nonces: Arc::clone(&self.nonces),
            nonce_queue: Arc::clone(&self.nonce_queue),
            stats: Arc::clone(&self.stats),
            last_cleanup: Arc::clone(&self.last_cleanup),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_nonce_config_default() {
        let config = NonceConfig::default();
        assert_eq!(config.nonce_ttl, Duration::from_secs(300));
        assert_eq!(config.max_nonces, 10000);
        assert_eq!(config.nonce_length, 32);
    }

    #[test]
    fn test_nonce_manager_new() {
        let manager = NonceManager::new();
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_generate_nonce() {
        let manager = NonceManager::new();
        let nonce = manager.generate_nonce();

        // Should be hex string of length 2 * nonce_length
        assert_eq!(nonce.len(), 64); // 32 bytes * 2 hex chars

        let stats = manager.stats();
        assert_eq!(stats.generated, 1);
        assert_eq!(stats.active_nonces, 1);
    }

    #[test]
    fn test_generate_unique_nonces() {
        let manager = NonceManager::new();
        let nonce1 = manager.generate_nonce();
        let nonce2 = manager.generate_nonce();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_validate_nonce_success() {
        let manager = NonceManager::new();
        let nonce = manager.generate_nonce();

        assert!(manager.validate_nonce(&nonce).is_ok());

        let stats = manager.stats();
        assert_eq!(stats.validated, 1);
        assert_eq!(stats.replay_attempts, 0);
    }

    #[test]
    fn test_validate_nonce_replay_attack() {
        let manager = NonceManager::new();
        let nonce = manager.generate_nonce();

        // First validation succeeds
        assert!(manager.validate_nonce(&nonce).is_ok());

        // Second validation fails (replay attack)
        let result = manager.validate_nonce(&nonce);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NonceError::NonceReused(_)));

        let stats = manager.stats();
        assert_eq!(stats.validated, 1);
        assert_eq!(stats.replay_attempts, 1);
    }

    #[test]
    fn test_validate_nonce_not_found() {
        let manager = NonceManager::new();
        let result = manager.validate_nonce("nonexistent");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NonceError::NonceNotFound(_)));
    }

    #[test]
    fn test_validate_nonce_expired() {
        let config = NonceConfig {
            nonce_ttl: Duration::from_millis(50), // Very short TTL
            ..Default::default()
        };
        let manager = NonceManager::with_config(config);
        let nonce = manager.generate_nonce();

        // Wait for expiration
        thread::sleep(Duration::from_millis(100));

        let result = manager.validate_nonce(&nonce);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NonceError::NonceExpired(_)));

        let stats = manager.stats();
        assert_eq!(stats.expired_rejected, 1);
    }

    #[test]
    fn test_is_valid() {
        let manager = NonceManager::new();
        let nonce = manager.generate_nonce();

        assert!(manager.is_valid(&nonce));

        manager.validate_nonce(&nonce).unwrap();
        assert!(!manager.is_valid(&nonce)); // No longer valid after use
    }

    #[test]
    fn test_get_nonce_info() {
        let manager = NonceManager::new();
        let nonce = manager.generate_nonce();

        let info = manager.get_nonce_info(&nonce);
        assert!(info.is_some());

        let info = info.unwrap();
        assert_eq!(info.nonce, nonce);
        assert!(!info.used);
        assert!(!info.is_expired());
    }

    #[test]
    fn test_cleanup_expired() {
        let config = NonceConfig {
            nonce_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let manager = NonceManager::with_config(config);

        // Generate some nonces
        let _nonce1 = manager.generate_nonce();
        let _nonce2 = manager.generate_nonce();

        assert_eq!(manager.active_count(), 2);

        // Wait for expiration
        thread::sleep(Duration::from_millis(100));

        let cleaned = manager.cleanup();
        assert_eq!(cleaned, 2);
        assert_eq!(manager.active_count(), 0);

        let stats = manager.stats();
        assert_eq!(stats.cleaned_up, 2);
    }

    #[test]
    fn test_cleanup_used() {
        let manager = NonceManager::new();

        let nonce = manager.generate_nonce();
        manager.validate_nonce(&nonce).unwrap(); // Mark as used

        assert_eq!(manager.active_count(), 1);

        let cleaned = manager.cleanup();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_max_nonces_limit() {
        let config = NonceConfig {
            max_nonces: 5,
            ..Default::default()
        };
        let manager = NonceManager::with_config(config);

        // Generate more nonces than the limit
        for _ in 0..10 {
            manager.generate_nonce();
        }

        // Should not exceed max
        assert_eq!(manager.active_count(), 5);
    }

    #[test]
    fn test_replay_rate() {
        let manager = NonceManager::new();
        let nonce1 = manager.generate_nonce();
        let nonce2 = manager.generate_nonce();

        manager.validate_nonce(&nonce1).unwrap(); // Success
        let _ = manager.validate_nonce(&nonce1); // Replay
        manager.validate_nonce(&nonce2).unwrap(); // Success

        let stats = manager.stats();
        // 2 validated + 1 replay = 3 total
        // replay_rate = 1/3 = 0.333...
        assert!((stats.replay_rate() - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_expiration_rate() {
        let config = NonceConfig {
            nonce_ttl: Duration::from_millis(50),
            ..Default::default()
        };
        let manager = NonceManager::with_config(config);

        let nonce1 = manager.generate_nonce();
        manager.validate_nonce(&nonce1).unwrap(); // Success

        let nonce2 = manager.generate_nonce();
        thread::sleep(Duration::from_millis(100));
        let _ = manager.validate_nonce(&nonce2); // Expired

        let stats = manager.stats();
        // 1 validated + 1 expired = 2 total
        // expiration_rate = 1/2 = 0.5
        assert_eq!(stats.expiration_rate(), 0.5);
    }

    #[test]
    fn test_clear() {
        let manager = NonceManager::new();

        manager.generate_nonce();
        manager.generate_nonce();
        assert_eq!(manager.active_count(), 2);

        manager.clear();
        assert_eq!(manager.active_count(), 0);

        let stats = manager.stats();
        assert_eq!(stats.active_nonces, 0);
    }

    #[test]
    fn test_clone() {
        let manager1 = NonceManager::new();
        manager1.generate_nonce();

        let manager2 = manager1.clone();
        // Stats should be shared
        assert_eq!(manager1.stats().generated, manager2.stats().generated);
        assert_eq!(manager1.active_count(), manager2.active_count());
    }
}
