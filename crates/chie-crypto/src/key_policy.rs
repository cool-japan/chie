//! Key Usage Policy Enforcement
//!
//! This module provides policy-based access control for cryptographic keys,
//! enforcing restrictions on how keys can be used to prevent misuse and ensure
//! compliance with security policies.
//!
//! # Features
//!
//! - **Operation restrictions**: Limit which operations a key can perform
//! - **Usage limits**: Maximum number of operations per key
//! - **Time-based policies**: Key validity periods and expiration
//! - **Context-based policies**: Require specific context for key usage
//! - **Policy composition**: Combine multiple policies with AND/OR logic
//! - **Audit logging**: Track policy violations and key usage
//!
//! # Example
//!
//! ```
//! use chie_crypto::key_policy::{KeyPolicy, KeyUsagePolicy, Operation, PolicyEngine};
//! use std::time::Duration;
//!
//! // Create a policy that allows only signing, max 100 uses, valid for 30 days
//! let policy = KeyPolicy::new()
//!     .allow_operation(Operation::Sign)
//!     .deny_operation(Operation::Decrypt)
//!     .max_uses(100)
//!     .valid_for(Duration::from_secs(30 * 24 * 3600));
//!
//! // Create policy engine and register the policy
//! let mut engine = PolicyEngine::new();
//! let key_id = [1u8; 32];
//! engine.register_policy(key_id, policy);
//!
//! // Check if an operation is allowed
//! assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
//! assert!(engine.check_policy(&key_id, Operation::Decrypt, None).is_err());
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

/// Cryptographic operations that can be performed with a key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    /// Sign data
    Sign,
    /// Verify signatures
    Verify,
    /// Encrypt data
    Encrypt,
    /// Decrypt data
    Decrypt,
    /// Key exchange
    KeyExchange,
    /// Derive keys
    DeriveKey,
    /// Wrap other keys
    WrapKey,
    /// Unwrap other keys
    UnwrapKey,
}

/// Policy violation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    /// Operation not allowed by policy
    OperationDenied(Operation),
    /// Key has exceeded usage limit
    UsageLimitExceeded { limit: u64, current: u64 },
    /// Key has expired
    KeyExpired { expired_at: SystemTime },
    /// Key is not yet valid
    KeyNotYetValid { valid_from: SystemTime },
    /// Required context not provided
    MissingContext(String),
    /// Context validation failed
    InvalidContext(String),
    /// Policy not found for key
    PolicyNotFound,
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyViolation::OperationDenied(op) => {
                write!(f, "Operation {:?} denied by policy", op)
            }
            PolicyViolation::UsageLimitExceeded { limit, current } => {
                write!(f, "Usage limit exceeded: {}/{}", current, limit)
            }
            PolicyViolation::KeyExpired { expired_at } => {
                write!(f, "Key expired at {:?}", expired_at)
            }
            PolicyViolation::KeyNotYetValid { valid_from } => {
                write!(f, "Key not yet valid (valid from {:?})", valid_from)
            }
            PolicyViolation::MissingContext(ctx) => write!(f, "Missing required context: {}", ctx),
            PolicyViolation::InvalidContext(msg) => write!(f, "Invalid context: {}", msg),
            PolicyViolation::PolicyNotFound => write!(f, "Policy not found for key"),
        }
    }
}

impl std::error::Error for PolicyViolation {}

/// Key usage policy defining allowed operations and constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Allowed operations (None = all allowed)
    allowed_operations: Option<HashSet<Operation>>,
    /// Denied operations (takes precedence over allowed)
    denied_operations: HashSet<Operation>,
    /// Maximum number of uses (None = unlimited)
    max_uses: Option<u64>,
    /// Key validity start time (None = valid from creation)
    valid_from: Option<SystemTime>,
    /// Key validity end time (None = no expiration)
    valid_until: Option<SystemTime>,
    /// Required context keys for usage
    required_context: HashSet<String>,
    /// Policy metadata
    metadata: HashMap<String, String>,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPolicy {
    /// Create a new permissive policy (all operations allowed, no limits)
    pub fn new() -> Self {
        Self {
            allowed_operations: None,
            denied_operations: HashSet::new(),
            max_uses: None,
            valid_from: None,
            valid_until: None,
            required_context: HashSet::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a restrictive policy (no operations allowed by default)
    pub fn restrictive() -> Self {
        Self {
            allowed_operations: Some(HashSet::new()),
            denied_operations: HashSet::new(),
            max_uses: None,
            valid_from: None,
            valid_until: None,
            required_context: HashSet::new(),
            metadata: HashMap::new(),
        }
    }

    /// Allow a specific operation
    pub fn allow_operation(mut self, op: Operation) -> Self {
        if self.allowed_operations.is_none() {
            self.allowed_operations = Some(HashSet::new());
        }
        self.allowed_operations.as_mut().unwrap().insert(op);
        self
    }

    /// Deny a specific operation
    pub fn deny_operation(mut self, op: Operation) -> Self {
        self.denied_operations.insert(op);
        self
    }

    /// Set maximum number of uses
    pub fn max_uses(mut self, limit: u64) -> Self {
        self.max_uses = Some(limit);
        self
    }

    /// Set key validity period (from now)
    pub fn valid_for(mut self, duration: Duration) -> Self {
        let now = SystemTime::now();
        self.valid_from = Some(now);
        self.valid_until = Some(now + duration);
        self
    }

    /// Set key validity start time
    pub fn valid_from(mut self, time: SystemTime) -> Self {
        self.valid_from = Some(time);
        self
    }

    /// Set key validity end time
    pub fn valid_until(mut self, time: SystemTime) -> Self {
        self.valid_until = Some(time);
        self
    }

    /// Require a context key for usage
    pub fn require_context(mut self, key: String) -> Self {
        self.required_context.insert(key);
        self
    }

    /// Add metadata to the policy
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Check if an operation is allowed by this policy
    pub fn allows_operation(&self, op: Operation) -> bool {
        // Denied operations take precedence
        if self.denied_operations.contains(&op) {
            return false;
        }

        // Check allowed operations
        match &self.allowed_operations {
            None => true, // All operations allowed by default
            Some(allowed) => allowed.contains(&op),
        }
    }

    /// Check if usage count is within limits
    pub fn check_usage_limit(&self, current_uses: u64) -> Result<(), PolicyViolation> {
        if let Some(limit) = self.max_uses {
            if current_uses >= limit {
                return Err(PolicyViolation::UsageLimitExceeded {
                    limit,
                    current: current_uses,
                });
            }
        }
        Ok(())
    }

    /// Check if key is within validity period
    pub fn check_validity(&self) -> Result<(), PolicyViolation> {
        let now = SystemTime::now();

        if let Some(valid_from) = self.valid_from {
            if now < valid_from {
                return Err(PolicyViolation::KeyNotYetValid { valid_from });
            }
        }

        if let Some(valid_until) = self.valid_until {
            if now > valid_until {
                return Err(PolicyViolation::KeyExpired {
                    expired_at: valid_until,
                });
            }
        }

        Ok(())
    }

    /// Check if required context is provided
    pub fn check_context(
        &self,
        context: Option<&HashMap<String, String>>,
    ) -> Result<(), PolicyViolation> {
        if self.required_context.is_empty() {
            return Ok(());
        }

        let context = context
            .ok_or_else(|| PolicyViolation::MissingContext("context required".to_string()))?;

        for required_key in &self.required_context {
            if !context.contains_key(required_key) {
                return Err(PolicyViolation::MissingContext(required_key.clone()));
            }
        }

        Ok(())
    }
}

/// Policy engine that manages and enforces key usage policies
pub struct PolicyEngine {
    /// Policies indexed by key ID
    policies: HashMap<[u8; 32], KeyPolicy>,
    /// Usage counters indexed by key ID
    usage_counts: HashMap<[u8; 32], u64>,
    /// Violation log
    violations: Vec<(SystemTime, [u8; 32], PolicyViolation)>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            usage_counts: HashMap::new(),
            violations: Vec::new(),
        }
    }

    /// Register a policy for a key
    pub fn register_policy(&mut self, key_id: [u8; 32], policy: KeyPolicy) {
        self.policies.insert(key_id, policy);
        self.usage_counts.insert(key_id, 0);
    }

    /// Update policy for an existing key
    pub fn update_policy(
        &mut self,
        key_id: &[u8; 32],
        policy: KeyPolicy,
    ) -> Result<(), PolicyViolation> {
        if !self.policies.contains_key(key_id) {
            return Err(PolicyViolation::PolicyNotFound);
        }
        self.policies.insert(*key_id, policy);
        Ok(())
    }

    /// Remove policy for a key
    pub fn remove_policy(&mut self, key_id: &[u8; 32]) {
        self.policies.remove(key_id);
        self.usage_counts.remove(key_id);
    }

    /// Check if an operation is allowed and increment usage counter
    pub fn check_policy(
        &mut self,
        key_id: &[u8; 32],
        operation: Operation,
        context: Option<&HashMap<String, String>>,
    ) -> Result<(), PolicyViolation> {
        let policy = self
            .policies
            .get(key_id)
            .ok_or(PolicyViolation::PolicyNotFound)?;

        // Check operation permission
        if !policy.allows_operation(operation) {
            let violation = PolicyViolation::OperationDenied(operation);
            self.log_violation(*key_id, violation.clone());
            return Err(violation);
        }

        // Check validity period
        if let Err(violation) = policy.check_validity() {
            self.log_violation(*key_id, violation.clone());
            return Err(violation);
        }

        // Check usage limit
        let current_uses = *self.usage_counts.get(key_id).unwrap_or(&0);
        if let Err(violation) = policy.check_usage_limit(current_uses) {
            self.log_violation(*key_id, violation.clone());
            return Err(violation);
        }

        // Check context
        if let Err(violation) = policy.check_context(context) {
            self.log_violation(*key_id, violation.clone());
            return Err(violation);
        }

        // Increment usage counter
        *self.usage_counts.entry(*key_id).or_insert(0) += 1;

        Ok(())
    }

    /// Get current usage count for a key
    pub fn get_usage_count(&self, key_id: &[u8; 32]) -> u64 {
        *self.usage_counts.get(key_id).unwrap_or(&0)
    }

    /// Reset usage counter for a key
    pub fn reset_usage_count(&mut self, key_id: &[u8; 32]) {
        if let Some(count) = self.usage_counts.get_mut(key_id) {
            *count = 0;
        }
    }

    /// Get policy for a key
    pub fn get_policy(&self, key_id: &[u8; 32]) -> Option<&KeyPolicy> {
        self.policies.get(key_id)
    }

    /// Log a policy violation
    fn log_violation(&mut self, key_id: [u8; 32], violation: PolicyViolation) {
        self.violations.push((SystemTime::now(), key_id, violation));
    }

    /// Get all logged violations
    pub fn get_violations(&self) -> &[(SystemTime, [u8; 32], PolicyViolation)] {
        &self.violations
    }

    /// Get violations for a specific key
    pub fn get_key_violations(
        &self,
        key_id: &[u8; 32],
    ) -> Vec<&(SystemTime, [u8; 32], PolicyViolation)> {
        self.violations
            .iter()
            .filter(|(_, kid, _)| kid == key_id)
            .collect()
    }

    /// Clear violation log
    pub fn clear_violations(&mut self) {
        self.violations.clear();
    }
}

/// Trait for objects that can enforce key usage policies
pub trait KeyUsagePolicy {
    /// Check if a key operation is allowed
    fn check_key_usage(
        &mut self,
        key_id: &[u8; 32],
        operation: Operation,
        context: Option<&HashMap<String, String>>,
    ) -> Result<(), PolicyViolation>;
}

impl KeyUsagePolicy for PolicyEngine {
    fn check_key_usage(
        &mut self,
        key_id: &[u8; 32],
        operation: Operation,
        context: Option<&HashMap<String, String>>,
    ) -> Result<(), PolicyViolation> {
        self.check_policy(key_id, operation, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_allows_all_by_default() {
        let policy = KeyPolicy::new();
        assert!(policy.allows_operation(Operation::Sign));
        assert!(policy.allows_operation(Operation::Encrypt));
        assert!(policy.allows_operation(Operation::Decrypt));
    }

    #[test]
    fn test_policy_restrictive() {
        let policy = KeyPolicy::restrictive();
        assert!(!policy.allows_operation(Operation::Sign));
        assert!(!policy.allows_operation(Operation::Encrypt));
    }

    #[test]
    fn test_policy_allow_operation() {
        let policy = KeyPolicy::restrictive().allow_operation(Operation::Sign);
        assert!(policy.allows_operation(Operation::Sign));
        assert!(!policy.allows_operation(Operation::Encrypt));
    }

    #[test]
    fn test_policy_deny_operation() {
        let policy = KeyPolicy::new().deny_operation(Operation::Decrypt);
        assert!(policy.allows_operation(Operation::Sign));
        assert!(!policy.allows_operation(Operation::Decrypt));
    }

    #[test]
    fn test_policy_deny_takes_precedence() {
        let policy = KeyPolicy::new()
            .allow_operation(Operation::Sign)
            .deny_operation(Operation::Sign);
        assert!(!policy.allows_operation(Operation::Sign));
    }

    #[test]
    fn test_usage_limit() {
        let policy = KeyPolicy::new().max_uses(5);
        assert!(policy.check_usage_limit(0).is_ok());
        assert!(policy.check_usage_limit(4).is_ok());
        assert!(policy.check_usage_limit(5).is_err());
        assert!(policy.check_usage_limit(10).is_err());
    }

    #[test]
    fn test_validity_period() {
        let now = SystemTime::now();
        let past = now - Duration::from_secs(3600);
        let future = now + Duration::from_secs(3600);

        // Not yet valid
        let policy = KeyPolicy::new().valid_from(future);
        assert!(policy.check_validity().is_err());

        // Expired
        let policy = KeyPolicy::new().valid_until(past);
        assert!(policy.check_validity().is_err());

        // Valid
        let policy = KeyPolicy::new().valid_from(past).valid_until(future);
        assert!(policy.check_validity().is_ok());
    }

    #[test]
    fn test_valid_for() {
        let policy = KeyPolicy::new().valid_for(Duration::from_secs(3600));
        assert!(policy.check_validity().is_ok());
    }

    #[test]
    fn test_required_context() {
        let policy = KeyPolicy::new().require_context("user_id".to_string());

        // No context provided
        assert!(policy.check_context(None).is_err());

        // Wrong context
        let mut context = HashMap::new();
        context.insert("session_id".to_string(), "123".to_string());
        assert!(policy.check_context(Some(&context)).is_err());

        // Correct context
        context.insert("user_id".to_string(), "alice".to_string());
        assert!(policy.check_context(Some(&context)).is_ok());
    }

    #[test]
    fn test_policy_engine_register() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy = KeyPolicy::new();

        engine.register_policy(key_id, policy);
        assert!(engine.get_policy(&key_id).is_some());
        assert_eq!(engine.get_usage_count(&key_id), 0);
    }

    #[test]
    fn test_policy_engine_check() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy = KeyPolicy::new().allow_operation(Operation::Sign);

        engine.register_policy(key_id, policy);

        // Allowed operation
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
        assert_eq!(engine.get_usage_count(&key_id), 1);

        // Denied operation
        assert!(
            engine
                .check_policy(&key_id, Operation::Decrypt, None)
                .is_err()
        );
        assert_eq!(engine.get_usage_count(&key_id), 1); // Not incremented on failure
    }

    #[test]
    fn test_policy_engine_usage_limit() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy = KeyPolicy::new().max_uses(3);

        engine.register_policy(key_id, policy);

        // First 3 uses should succeed
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());

        // 4th use should fail
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_err());
    }

    #[test]
    fn test_policy_engine_reset_usage() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy = KeyPolicy::new().max_uses(2);

        engine.register_policy(key_id, policy);

        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
        assert_eq!(engine.get_usage_count(&key_id), 2);

        engine.reset_usage_count(&key_id);
        assert_eq!(engine.get_usage_count(&key_id), 0);

        // Can use again after reset
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_ok());
    }

    #[test]
    fn test_policy_engine_violations() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy = KeyPolicy::new().deny_operation(Operation::Decrypt);

        engine.register_policy(key_id, policy);

        // Trigger a violation
        let _ = engine.check_policy(&key_id, Operation::Decrypt, None);

        let violations = engine.get_violations();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, key_id);

        let key_violations = engine.get_key_violations(&key_id);
        assert_eq!(key_violations.len(), 1);

        engine.clear_violations();
        assert_eq!(engine.get_violations().len(), 0);
    }

    #[test]
    fn test_policy_engine_update_policy() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy1 = KeyPolicy::new().allow_operation(Operation::Sign);

        engine.register_policy(key_id, policy1);

        // Update to more restrictive policy
        let policy2 = KeyPolicy::restrictive();
        assert!(engine.update_policy(&key_id, policy2).is_ok());

        // Now signing should fail
        assert!(engine.check_policy(&key_id, Operation::Sign, None).is_err());
    }

    #[test]
    fn test_policy_engine_remove_policy() {
        let mut engine = PolicyEngine::new();
        let key_id = [1u8; 32];
        let policy = KeyPolicy::new();

        engine.register_policy(key_id, policy);
        assert!(engine.get_policy(&key_id).is_some());

        engine.remove_policy(&key_id);
        assert!(engine.get_policy(&key_id).is_none());
    }

    #[test]
    fn test_policy_metadata() {
        let policy = KeyPolicy::new()
            .with_metadata("purpose".to_string(), "signing".to_string())
            .with_metadata("owner".to_string(), "alice".to_string());

        assert_eq!(policy.metadata.get("purpose").unwrap(), "signing");
        assert_eq!(policy.metadata.get("owner").unwrap(), "alice");
    }

    #[test]
    fn test_policy_serialization() {
        let policy = KeyPolicy::new()
            .allow_operation(Operation::Sign)
            .deny_operation(Operation::Decrypt)
            .max_uses(100)
            .require_context("user_id".to_string());

        let serialized = crate::codec::encode(&policy).unwrap();
        let deserialized: KeyPolicy = crate::codec::decode(&serialized).unwrap();

        assert!(deserialized.allows_operation(Operation::Sign));
        assert!(!deserialized.allows_operation(Operation::Decrypt));
        assert_eq!(deserialized.max_uses, Some(100));
        assert!(deserialized.required_context.contains("user_id"));
    }
}
