//! Brute force protection for authentication endpoints
//!
//! This module provides protection against brute force attacks by:
//! - Tracking failed login attempts per user/IP
//! - Implementing exponential backoff
//! - Temporary account lockouts
//! - IP-based blocking for repeated failures
//! - CAPTCHA triggers after threshold

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, warn};

/// Brute force protection error
#[derive(Debug, thiserror::Error)]
pub enum BruteForceError {
    #[error("Account temporarily locked due to too many failed attempts")]
    AccountLocked,
    #[error("IP address temporarily blocked")]
    IpBlocked,
    #[error("Too many failed attempts, please wait {0} seconds")]
    RateLimited(i64),
    #[error("CAPTCHA verification required")]
    CaptchaRequired,
}

/// Configuration for brute force protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    /// Maximum failed attempts before account lockout
    pub max_failed_attempts: u32,
    /// Lockout duration in minutes
    pub lockout_duration_minutes: i64,
    /// Time window for counting failed attempts (minutes)
    pub attempt_window_minutes: i64,
    /// IP block duration in minutes
    pub ip_block_duration_minutes: i64,
    /// Failed attempts before requiring CAPTCHA
    pub captcha_threshold: u32,
    /// Whether to enable IP-based blocking
    pub enable_ip_blocking: bool,
    /// Whether to use exponential backoff
    pub use_exponential_backoff: bool,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            attempt_window_minutes: 10,
            ip_block_duration_minutes: 30,
            captcha_threshold: 3,
            enable_ip_blocking: true,
            use_exponential_backoff: true,
        }
    }
}

/// Information about a failed authentication attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAttempt {
    /// Timestamp of the attempt
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub ip_address: Option<IpAddr>,
    /// Endpoint that was accessed
    pub endpoint: String,
}

/// Account lockout information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLockout {
    /// Lockout start time
    pub locked_at: DateTime<Utc>,
    /// Lockout end time
    pub locked_until: DateTime<Utc>,
    /// Reason for lockout
    pub reason: String,
    /// Number of failed attempts that triggered the lockout
    pub failed_attempts: u32,
}

/// IP block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlock {
    /// Block start time
    pub blocked_at: DateTime<Utc>,
    /// Block end time
    pub blocked_until: DateTime<Utc>,
    /// Number of failed attempts from this IP
    pub failed_attempts: u32,
}

/// Statistics about brute force protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceStats {
    /// Total number of locked accounts
    pub locked_accounts: usize,
    /// Total number of blocked IPs
    pub blocked_ips: usize,
    /// Total failed attempts tracked
    pub total_failed_attempts: u64,
    /// Accounts currently requiring CAPTCHA
    pub captcha_required: usize,
}

/// Brute force protection manager
#[derive(Debug, Clone)]
pub struct BruteForceProtection {
    config: Arc<BruteForceConfig>,
    failed_attempts: Arc<RwLock<HashMap<String, VecDeque<FailedAttempt>>>>,
    account_lockouts: Arc<RwLock<HashMap<String, AccountLockout>>>,
    ip_blocks: Arc<RwLock<HashMap<IpAddr, IpBlock>>>,
    captcha_required: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    total_attempts: Arc<RwLock<u64>>,
}

impl BruteForceProtection {
    /// Create a new brute force protection manager
    pub fn new(config: BruteForceConfig) -> Self {
        Self {
            config: Arc::new(config),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
            account_lockouts: Arc::new(RwLock::new(HashMap::new())),
            ip_blocks: Arc::new(RwLock::new(HashMap::new())),
            captcha_required: Arc::new(RwLock::new(HashMap::new())),
            total_attempts: Arc::new(RwLock::new(0)),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(BruteForceConfig::default())
    }

    /// Check if authentication is allowed for a user/IP combination
    pub fn check_allowed(
        &self,
        identifier: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<(), BruteForceError> {
        // Check if account is locked
        {
            let lockouts = self.account_lockouts.read().unwrap();
            if let Some(lockout) = lockouts.get(identifier) {
                if Utc::now() < lockout.locked_until {
                    let remaining_secs = (lockout.locked_until - Utc::now()).num_seconds();
                    warn!(
                        identifier = identifier,
                        remaining_secs = remaining_secs,
                        "Account locked"
                    );
                    return Err(BruteForceError::AccountLocked);
                }
            }
        }

        // Check if IP is blocked
        if let Some(ip) = ip_address {
            if self.config.enable_ip_blocking {
                let blocks = self.ip_blocks.read().unwrap();
                if let Some(block) = blocks.get(&ip) {
                    if Utc::now() < block.blocked_until {
                        warn!(ip = %ip, "IP address blocked");
                        return Err(BruteForceError::IpBlocked);
                    }
                }
            }
        }

        // Check if CAPTCHA is required
        {
            let captcha = self.captcha_required.read().unwrap();
            if captcha.contains_key(identifier) {
                return Err(BruteForceError::CaptchaRequired);
            }
        }

        // Check exponential backoff
        if self.config.use_exponential_backoff {
            let attempts = self.failed_attempts.read().unwrap();
            if let Some(attempt_list) = attempts.get(identifier) {
                if let Some(last_attempt) = attempt_list.back() {
                    let attempts_count = attempt_list.len() as u32;
                    if attempts_count > 0 {
                        // Exponential backoff: 2^(attempts-1) seconds
                        let backoff_secs = 2_i64.pow((attempts_count - 1).min(10));
                        let required_wait = ChronoDuration::seconds(backoff_secs);
                        let elapsed = Utc::now() - last_attempt.timestamp;

                        if elapsed < required_wait {
                            let remaining = (required_wait - elapsed).num_seconds();
                            debug!(
                                identifier = identifier,
                                remaining_secs = remaining,
                                "Exponential backoff active"
                            );
                            return Err(BruteForceError::RateLimited(remaining));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Record a failed authentication attempt
    pub fn record_failure(&self, identifier: &str, ip_address: Option<IpAddr>, endpoint: String) {
        let now = Utc::now();
        let attempt = FailedAttempt {
            timestamp: now,
            ip_address,
            endpoint: endpoint.clone(),
        };

        // Update total attempts counter
        {
            let mut total = self.total_attempts.write().unwrap();
            *total += 1;
        }

        // Add to failed attempts list
        let mut attempts = self.failed_attempts.write().unwrap();
        let attempt_list = attempts.entry(identifier.to_string()).or_default();

        // Clean up old attempts outside the time window
        let cutoff = now - ChronoDuration::minutes(self.config.attempt_window_minutes);
        attempt_list.retain(|a| a.timestamp > cutoff);

        attempt_list.push_back(attempt.clone());

        let current_attempts = attempt_list.len() as u32;

        // Check if we should trigger CAPTCHA
        if current_attempts >= self.config.captcha_threshold
            && current_attempts < self.config.max_failed_attempts
        {
            let mut captcha = self.captcha_required.write().unwrap();
            captcha.insert(identifier.to_string(), now);
            warn!(
                identifier = identifier,
                attempts = current_attempts,
                "CAPTCHA required due to failed attempts"
            );
        }

        // Check if we should lock the account
        if current_attempts >= self.config.max_failed_attempts {
            let locked_until = now + ChronoDuration::minutes(self.config.lockout_duration_minutes);
            let lockout = AccountLockout {
                locked_at: now,
                locked_until,
                reason: format!("Too many failed attempts ({})", current_attempts),
                failed_attempts: current_attempts,
            };

            let mut lockouts = self.account_lockouts.write().unwrap();
            lockouts.insert(identifier.to_string(), lockout);

            warn!(
                identifier = identifier,
                attempts = current_attempts,
                locked_until = %locked_until,
                "Account locked due to failed attempts"
            );

            // Record metric
            crate::metrics::record_anomaly_detected("account_lockout", "high");
        }

        // Handle IP blocking
        if let Some(ip) = ip_address {
            if self.config.enable_ip_blocking {
                let mut ip_attempts: HashMap<IpAddr, u32> = HashMap::new();

                // Count attempts from this IP across all identifiers
                for (_, list) in attempts.iter() {
                    for attempt in list {
                        if let Some(attempt_ip) = attempt.ip_address {
                            if attempt_ip == ip && attempt.timestamp > cutoff {
                                *ip_attempts.entry(attempt_ip).or_insert(0) += 1;
                            }
                        }
                    }
                }

                if let Some(&ip_attempt_count) = ip_attempts.get(&ip) {
                    if ip_attempt_count >= self.config.max_failed_attempts {
                        let blocked_until =
                            now + ChronoDuration::minutes(self.config.ip_block_duration_minutes);
                        let block = IpBlock {
                            blocked_at: now,
                            blocked_until,
                            failed_attempts: ip_attempt_count,
                        };

                        let mut blocks = self.ip_blocks.write().unwrap();
                        blocks.insert(ip, block);

                        warn!(
                            ip = %ip,
                            attempts = ip_attempt_count,
                            blocked_until = %blocked_until,
                            "IP blocked due to failed attempts"
                        );

                        // Record metric
                        crate::metrics::record_anomaly_detected("ip_block", "high");
                    }
                }
            }
        }

        debug!(
            identifier = identifier,
            endpoint = endpoint,
            attempts = current_attempts,
            "Failed authentication attempt recorded"
        );
    }

    /// Record a successful authentication (clears failed attempts)
    pub fn record_success(&self, identifier: &str) {
        // Clear failed attempts
        {
            let mut attempts = self.failed_attempts.write().unwrap();
            attempts.remove(identifier);
        }

        // Clear CAPTCHA requirement
        {
            let mut captcha = self.captcha_required.write().unwrap();
            captcha.remove(identifier);
        }

        // Clear account lockout (allow early unlock on success, if implemented)
        // For now, we keep lockouts in place until they expire

        debug!(
            identifier = identifier,
            "Successful authentication recorded"
        );
    }

    /// Clear CAPTCHA requirement for an identifier (after successful CAPTCHA)
    pub fn clear_captcha(&self, identifier: &str) {
        let mut captcha = self.captcha_required.write().unwrap();
        captcha.remove(identifier);
        debug!(identifier = identifier, "CAPTCHA requirement cleared");
    }

    /// Manually unlock an account
    pub fn unlock_account(&self, identifier: &str) -> bool {
        // Remove the lockout
        let result = {
            let mut lockouts = self.account_lockouts.write().unwrap();
            lockouts.remove(identifier).is_some()
        };

        // Also clear failed attempts and CAPTCHA requirement to allow immediate access
        if result {
            let mut attempts = self.failed_attempts.write().unwrap();
            attempts.remove(identifier);

            let mut captcha = self.captcha_required.write().unwrap();
            captcha.remove(identifier);
        }

        result
    }

    /// Manually unblock an IP
    pub fn unblock_ip(&self, ip: &IpAddr) -> bool {
        let mut blocks = self.ip_blocks.write().unwrap();
        blocks.remove(ip).is_some()
    }

    /// Get statistics
    pub fn get_stats(&self) -> BruteForceStats {
        let lockouts = self.account_lockouts.read().unwrap();
        let blocks = self.ip_blocks.read().unwrap();
        let captcha = self.captcha_required.read().unwrap();
        let total = *self.total_attempts.read().unwrap();

        // Clean up expired entries
        let now = Utc::now();
        let active_lockouts = lockouts.values().filter(|l| l.locked_until > now).count();
        let active_blocks = blocks.values().filter(|b| b.blocked_until > now).count();

        BruteForceStats {
            locked_accounts: active_lockouts,
            blocked_ips: active_blocks,
            total_failed_attempts: total,
            captcha_required: captcha.len(),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &BruteForceConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_brute_force_protection_creation() {
        let protection = BruteForceProtection::with_defaults();
        assert_eq!(protection.config().max_failed_attempts, 5);
        assert_eq!(protection.config().lockout_duration_minutes, 15);
    }

    #[test]
    fn test_check_allowed_initially() {
        let protection = BruteForceProtection::with_defaults();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        assert!(protection.check_allowed("user123", Some(ip)).is_ok());
    }

    #[test]
    fn test_failed_attempts_and_lockout() {
        let config = BruteForceConfig {
            max_failed_attempts: 3,
            lockout_duration_minutes: 15,
            attempt_window_minutes: 10,
            ip_block_duration_minutes: 30,
            captcha_threshold: 2,
            enable_ip_blocking: false,
            use_exponential_backoff: false,
        };
        let protection = BruteForceProtection::new(config);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // First 2 attempts should be allowed
        for i in 0..2 {
            protection.record_failure("user123", Some(ip), "/api/login".to_string());
            let result = protection.check_allowed("user123", Some(ip));
            // After 2 attempts, CAPTCHA is required
            if i >= 1 {
                assert!(matches!(result, Err(BruteForceError::CaptchaRequired)));
            }
        }

        // Clear CAPTCHA for testing
        protection.clear_captcha("user123");

        // 3rd attempt should trigger lockout
        protection.record_failure("user123", Some(ip), "/api/login".to_string());
        let result = protection.check_allowed("user123", Some(ip));
        assert!(matches!(result, Err(BruteForceError::AccountLocked)));
    }

    #[test]
    fn test_successful_auth_clears_attempts() {
        let protection = BruteForceProtection::with_defaults();
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // Record some failed attempts
        protection.record_failure("user123", Some(ip), "/api/login".to_string());
        protection.record_failure("user123", Some(ip), "/api/login".to_string());

        // Record success
        protection.record_success("user123");

        // Should be allowed again
        assert!(protection.check_allowed("user123", Some(ip)).is_ok());
    }

    #[test]
    fn test_ip_blocking() {
        let config = BruteForceConfig {
            max_failed_attempts: 3,
            lockout_duration_minutes: 15,
            attempt_window_minutes: 10,
            ip_block_duration_minutes: 30,
            captcha_threshold: 10,
            enable_ip_blocking: true,
            use_exponential_backoff: false,
        };
        let protection = BruteForceProtection::new(config);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // Fail multiple times from the same IP with different users
        for i in 0..3 {
            protection.record_failure(&format!("user{}", i), Some(ip), "/api/login".to_string());
        }

        // IP should be blocked
        let result = protection.check_allowed("newuser", Some(ip));
        assert!(matches!(result, Err(BruteForceError::IpBlocked)));
    }

    #[test]
    fn test_exponential_backoff() {
        let config = BruteForceConfig {
            max_failed_attempts: 10,
            lockout_duration_minutes: 15,
            attempt_window_minutes: 10,
            ip_block_duration_minutes: 30,
            captcha_threshold: 10,
            enable_ip_blocking: false,
            use_exponential_backoff: true,
        };
        let protection = BruteForceProtection::new(config);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // Record a failed attempt
        protection.record_failure("user123", Some(ip), "/api/login".to_string());

        // Immediate retry should be rate limited
        let result = protection.check_allowed("user123", Some(ip));
        assert!(matches!(result, Err(BruteForceError::RateLimited(_))));
    }

    #[test]
    fn test_unlock_account() {
        let config = BruteForceConfig {
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            attempt_window_minutes: 10,
            ip_block_duration_minutes: 30,
            captcha_threshold: 3,
            enable_ip_blocking: false, // Disable IP blocking for this test
            use_exponential_backoff: false, // Disable backoff for this test
        };
        let protection = BruteForceProtection::new(config);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // Lock the account
        for _ in 0..5 {
            protection.record_failure("user123", Some(ip), "/api/login".to_string());
        }

        protection.clear_captcha("user123");

        // Verify locked
        let result = protection.check_allowed("user123", Some(ip));
        assert!(matches!(result, Err(BruteForceError::AccountLocked)));

        // Unlock
        assert!(protection.unlock_account("user123"));

        // Should be allowed now
        assert!(protection.check_allowed("user123", Some(ip)).is_ok());
    }

    #[test]
    fn test_statistics() {
        let protection = BruteForceProtection::with_defaults();
        let ip1 = IpAddr::from_str("192.168.1.1").unwrap();
        let ip2 = IpAddr::from_str("192.168.1.2").unwrap();

        // Trigger some lockouts
        for _ in 0..5 {
            protection.record_failure("user1", Some(ip1), "/api/login".to_string());
            protection.record_failure("user2", Some(ip2), "/api/login".to_string());
        }

        let stats = protection.get_stats();
        assert!(stats.total_failed_attempts >= 10);
    }

    #[test]
    fn test_captcha_requirement() {
        let config = BruteForceConfig {
            max_failed_attempts: 5,
            captcha_threshold: 2,
            use_exponential_backoff: false, // Disable backoff for this test
            ..Default::default()
        };
        let protection = BruteForceProtection::new(config);
        let ip = IpAddr::from_str("192.168.1.1").unwrap();

        // First attempt - OK
        protection.record_failure("user123", Some(ip), "/api/login".to_string());
        assert!(protection.check_allowed("user123", Some(ip)).is_ok());

        // Second attempt - CAPTCHA required
        protection.record_failure("user123", Some(ip), "/api/login".to_string());
        let result = protection.check_allowed("user123", Some(ip));
        assert!(matches!(result, Err(BruteForceError::CaptchaRequired)));

        // Clear CAPTCHA
        protection.clear_captcha("user123");
        assert!(protection.check_allowed("user123", Some(ip)).is_ok());
    }
}
