//! Key rotation scheduler with configurable policies.
//!
//! This module provides automated key rotation scheduling with various policies
//! for different key types. It supports time-based, usage-based, and event-driven
//! rotation strategies.
//!
//! # Key Rotation Policies
//!
//! - **Time-based**: Rotate keys after a specific duration (e.g., every 30 days)
//! - **Usage-based**: Rotate keys after a certain number of operations
//! - **Hybrid**: Combine time and usage limits (whichever comes first)
//! - **Event-driven**: Rotate on specific events (e.g., suspected compromise)
//!
//! # Example
//!
//! ```
//! use chie_crypto::key_rotation_scheduler::*;
//! use std::time::Duration;
//!
//! // Create a time-based rotation policy (rotate every 30 days)
//! let policy = KeyRotationPolicy::TimeBased {
//!     max_age: Duration::from_secs(30 * 24 * 3600),
//! };
//!
//! // Create scheduler
//! let mut scheduler = KeyRotationScheduler::new(policy);
//!
//! // Register a key
//! let key_id = "signing-key-001".to_string();
//! scheduler.register_key(key_id.clone());
//!
//! // Check if rotation is needed
//! if scheduler.should_rotate(&key_id) {
//!     println!("Time to rotate key: {}", key_id);
//!     // Perform rotation...
//!     scheduler.mark_rotated(&key_id);
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Key rotation policy for scheduler
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeyRotationPolicy {
    /// Rotate after a specific time period
    TimeBased {
        /// Maximum age before rotation required
        max_age: Duration,
    },
    /// Rotate after a certain number of operations
    UsageBased {
        /// Maximum number of operations before rotation
        max_operations: u64,
    },
    /// Rotate based on both time and usage (whichever comes first)
    Hybrid {
        /// Maximum age before rotation required
        max_age: Duration,
        /// Maximum number of operations before rotation
        max_operations: u64,
    },
    /// Manual rotation only (no automatic triggers)
    Manual,
}

impl KeyRotationPolicy {
    /// Create a time-based policy with specified duration
    pub fn time_based(max_age: Duration) -> Self {
        Self::TimeBased { max_age }
    }

    /// Create a usage-based policy with specified operation limit
    pub fn usage_based(max_operations: u64) -> Self {
        Self::UsageBased { max_operations }
    }

    /// Create a hybrid policy with both time and usage limits
    pub fn hybrid(max_age: Duration, max_operations: u64) -> Self {
        Self::Hybrid {
            max_age,
            max_operations,
        }
    }

    /// Create a manual-only policy
    pub fn manual() -> Self {
        Self::Manual
    }
}

/// Key metadata for rotation tracking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for the key
    pub key_id: String,
    /// When the key was created or last rotated
    pub created_at: SystemTime,
    /// Number of operations performed with this key
    pub operation_count: u64,
    /// Whether the key is currently active
    pub active: bool,
    /// Optional expiration time
    pub expires_at: Option<SystemTime>,
}

impl KeyMetadata {
    /// Create new key metadata
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            created_at: SystemTime::now(),
            operation_count: 0,
            active: true,
            expires_at: None,
        }
    }

    /// Get the age of the key
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or(Duration::ZERO)
    }

    /// Check if the key has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() >= expires_at
        } else {
            false
        }
    }

    /// Increment operation counter
    pub fn increment_operations(&mut self) {
        self.operation_count += 1;
    }

    /// Mark key as rotated (reset counters, update timestamp)
    pub fn mark_rotated(&mut self) {
        self.created_at = SystemTime::now();
        self.operation_count = 0;
    }

    /// Mark key as inactive (after rotation)
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

/// Key rotation scheduler
pub struct KeyRotationScheduler {
    /// Rotation policy
    policy: KeyRotationPolicy,
    /// Tracked keys
    keys: HashMap<String, KeyMetadata>,
    /// Grace period after rotation trigger before forcing rotation
    grace_period: Option<Duration>,
}

impl KeyRotationScheduler {
    /// Create a new scheduler with the specified policy
    pub fn new(policy: KeyRotationPolicy) -> Self {
        Self {
            policy,
            keys: HashMap::new(),
            grace_period: None,
        }
    }

    /// Set grace period for rotation
    pub fn with_grace_period(mut self, grace_period: Duration) -> Self {
        self.grace_period = Some(grace_period);
        self
    }

    /// Register a new key for tracking
    pub fn register_key(&mut self, key_id: String) -> &KeyMetadata {
        self.keys
            .entry(key_id.clone())
            .or_insert_with(|| KeyMetadata::new(key_id.clone()));
        &self.keys[&key_id]
    }

    /// Register a key with custom metadata
    pub fn register_key_with_metadata(&mut self, metadata: KeyMetadata) {
        self.keys.insert(metadata.key_id.clone(), metadata);
    }

    /// Record an operation for a key
    pub fn record_operation(&mut self, key_id: &str) -> Result<(), String> {
        let metadata = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| format!("Key not registered: {}", key_id))?;

        if !metadata.active {
            return Err(format!("Key is inactive: {}", key_id));
        }

        metadata.increment_operations();
        Ok(())
    }

    /// Check if a key should be rotated according to the policy
    pub fn should_rotate(&self, key_id: &str) -> bool {
        let metadata = match self.keys.get(key_id) {
            Some(m) => m,
            None => return false,
        };

        // Inactive keys don't need rotation
        if !metadata.active {
            return false;
        }

        // Check expiration
        if metadata.is_expired() {
            return true;
        }

        // Check policy-specific triggers
        match &self.policy {
            KeyRotationPolicy::TimeBased { max_age } => metadata.age() >= *max_age,
            KeyRotationPolicy::UsageBased { max_operations } => {
                metadata.operation_count >= *max_operations
            }
            KeyRotationPolicy::Hybrid {
                max_age,
                max_operations,
            } => metadata.age() >= *max_age || metadata.operation_count >= *max_operations,
            KeyRotationPolicy::Manual => false,
        }
    }

    /// Force rotation check (ignore grace period)
    pub fn must_rotate(&self, key_id: &str) -> bool {
        if !self.should_rotate(key_id) {
            return false;
        }

        // If there's a grace period, check if we're past it
        if let Some(grace_period) = self.grace_period {
            let metadata = self.keys.get(key_id).unwrap();
            let time_since_trigger = match &self.policy {
                KeyRotationPolicy::TimeBased { max_age } => metadata.age().saturating_sub(*max_age),
                KeyRotationPolicy::Hybrid { max_age, .. } => {
                    metadata.age().saturating_sub(*max_age)
                }
                _ => Duration::ZERO,
            };
            time_since_trigger >= grace_period
        } else {
            true
        }
    }

    /// Mark a key as rotated
    pub fn mark_rotated(&mut self, key_id: &str) -> Result<(), String> {
        let metadata = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| format!("Key not registered: {}", key_id))?;

        metadata.mark_rotated();
        Ok(())
    }

    /// Deactivate a key (after successful rotation)
    pub fn deactivate_key(&mut self, key_id: &str) -> Result<(), String> {
        let metadata = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| format!("Key not registered: {}", key_id))?;

        metadata.deactivate();
        Ok(())
    }

    /// Get all keys that need rotation
    pub fn keys_needing_rotation(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(key_id, _)| self.should_rotate(key_id))
            .map(|(key_id, _)| key_id.clone())
            .collect()
    }

    /// Get all keys that must be rotated immediately
    pub fn keys_requiring_immediate_rotation(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(key_id, _)| self.must_rotate(key_id))
            .map(|(key_id, _)| key_id.clone())
            .collect()
    }

    /// Get metadata for a key
    pub fn get_metadata(&self, key_id: &str) -> Option<&KeyMetadata> {
        self.keys.get(key_id)
    }

    /// Get all active keys
    pub fn active_keys(&self) -> Vec<String> {
        self.keys
            .iter()
            .filter(|(_, metadata)| metadata.active)
            .map(|(key_id, _)| key_id.clone())
            .collect()
    }

    /// Get rotation policy
    pub fn policy(&self) -> &KeyRotationPolicy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_time_based_policy() {
        let policy = KeyRotationPolicy::time_based(Duration::from_millis(100));
        let mut scheduler = KeyRotationScheduler::new(policy);

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        // Should not need rotation immediately
        assert!(!scheduler.should_rotate(&key_id));

        // Wait for policy duration
        sleep(Duration::from_millis(150));

        // Should need rotation now
        assert!(scheduler.should_rotate(&key_id));
    }

    #[test]
    fn test_usage_based_policy() {
        let policy = KeyRotationPolicy::usage_based(5);
        let mut scheduler = KeyRotationScheduler::new(policy);

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        // Perform operations
        for _ in 0..4 {
            scheduler.record_operation(&key_id).unwrap();
        }

        // Should not need rotation yet
        assert!(!scheduler.should_rotate(&key_id));

        // One more operation
        scheduler.record_operation(&key_id).unwrap();

        // Should need rotation now
        assert!(scheduler.should_rotate(&key_id));
    }

    #[test]
    fn test_hybrid_policy() {
        let policy = KeyRotationPolicy::hybrid(Duration::from_millis(100), 10);
        let mut scheduler = KeyRotationScheduler::new(policy);

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        // Test time trigger
        sleep(Duration::from_millis(150));
        assert!(scheduler.should_rotate(&key_id));

        // Reset
        scheduler.mark_rotated(&key_id).unwrap();

        // Test usage trigger
        for _ in 0..10 {
            scheduler.record_operation(&key_id).unwrap();
        }
        assert!(scheduler.should_rotate(&key_id));
    }

    #[test]
    fn test_manual_policy() {
        let policy = KeyRotationPolicy::manual();
        let mut scheduler = KeyRotationScheduler::new(policy);

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        // Perform many operations
        for _ in 0..1000 {
            scheduler.record_operation(&key_id).unwrap();
        }

        // Should never trigger automatic rotation
        assert!(!scheduler.should_rotate(&key_id));
    }

    #[test]
    fn test_grace_period() {
        let policy = KeyRotationPolicy::time_based(Duration::from_millis(50));
        let mut scheduler =
            KeyRotationScheduler::new(policy).with_grace_period(Duration::from_millis(50));

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        sleep(Duration::from_millis(75));

        // Should rotate but not must rotate (within grace period)
        assert!(scheduler.should_rotate(&key_id));
        assert!(!scheduler.must_rotate(&key_id));

        sleep(Duration::from_millis(50));

        // Now must rotate (past grace period)
        assert!(scheduler.must_rotate(&key_id));
    }

    #[test]
    fn test_deactivate_key() {
        let policy = KeyRotationPolicy::manual();
        let mut scheduler = KeyRotationScheduler::new(policy);

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        // Key should be active
        let metadata = scheduler.get_metadata(&key_id).unwrap();
        assert!(metadata.active);

        // Deactivate
        scheduler.deactivate_key(&key_id).unwrap();

        // Should be inactive now
        let metadata = scheduler.get_metadata(&key_id).unwrap();
        assert!(!metadata.active);

        // Should not be able to record operations
        assert!(scheduler.record_operation(&key_id).is_err());
    }

    #[test]
    fn test_keys_needing_rotation() {
        let policy = KeyRotationPolicy::usage_based(5);
        let mut scheduler = KeyRotationScheduler::new(policy);

        scheduler.register_key("key1".to_string());
        scheduler.register_key("key2".to_string());
        scheduler.register_key("key3".to_string());

        // Trigger rotation for key1 and key3
        for _ in 0..5 {
            scheduler.record_operation("key1").unwrap();
            scheduler.record_operation("key3").unwrap();
        }

        let keys = scheduler.keys_needing_rotation();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key3".to_string()));
    }

    #[test]
    fn test_mark_rotated_resets_counters() {
        let policy = KeyRotationPolicy::usage_based(5);
        let mut scheduler = KeyRotationScheduler::new(policy);

        let key_id = "test-key".to_string();
        scheduler.register_key(key_id.clone());

        // Trigger rotation
        for _ in 0..5 {
            scheduler.record_operation(&key_id).unwrap();
        }
        assert!(scheduler.should_rotate(&key_id));

        // Mark as rotated
        scheduler.mark_rotated(&key_id).unwrap();

        // Should no longer need rotation
        assert!(!scheduler.should_rotate(&key_id));

        // Operation count should be reset
        let metadata = scheduler.get_metadata(&key_id).unwrap();
        assert_eq!(metadata.operation_count, 0);
    }

    #[test]
    fn test_active_keys() {
        let policy = KeyRotationPolicy::manual();
        let mut scheduler = KeyRotationScheduler::new(policy);

        scheduler.register_key("key1".to_string());
        scheduler.register_key("key2".to_string());
        scheduler.register_key("key3".to_string());

        assert_eq!(scheduler.active_keys().len(), 3);

        scheduler.deactivate_key("key2").unwrap();

        let active = scheduler.active_keys();
        assert_eq!(active.len(), 2);
        assert!(!active.contains(&"key2".to_string()));
    }

    #[test]
    fn test_key_expiration() {
        let mut metadata = KeyMetadata::new("test-key".to_string());

        // Set expiration in the past
        metadata.expires_at = Some(SystemTime::now() - Duration::from_secs(1));

        assert!(metadata.is_expired());

        // Set expiration in the future
        metadata.expires_at = Some(SystemTime::now() + Duration::from_secs(3600));

        assert!(!metadata.is_expired());
    }

    #[test]
    fn test_policy_serialization() {
        let policy = KeyRotationPolicy::hybrid(Duration::from_secs(3600), 1000);

        let serialized = crate::codec::encode(&policy).unwrap();
        let deserialized: KeyRotationPolicy = crate::codec::decode(&serialized).unwrap();

        match deserialized {
            KeyRotationPolicy::Hybrid {
                max_age,
                max_operations,
            } => {
                assert_eq!(max_age, Duration::from_secs(3600));
                assert_eq!(max_operations, 1000);
            }
            _ => panic!("Wrong policy type"),
        }
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = KeyMetadata::new("test-key".to_string());

        let serialized = crate::codec::encode(&metadata).unwrap();
        let deserialized: KeyMetadata = crate::codec::decode(&serialized).unwrap();

        assert_eq!(metadata.key_id, deserialized.key_id);
        assert_eq!(metadata.active, deserialized.active);
    }
}
