//! Comprehensive API input validation helpers.
//!
//! This module provides reusable validation functions for common input types
//! to ensure data quality and security across all API endpoints.

#![allow(dead_code)]

use regex::Regex;
use std::sync::OnceLock;

/// Validation result type.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validation error with detailed message.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl ValidationError {
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

// ==================== String Validation ====================

/// Validate string is not empty.
pub fn validate_not_empty(field: &str, value: &str) -> ValidationResult<()> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(field, "cannot be empty"));
    }
    Ok(())
}

/// Validate string length is within bounds.
pub fn validate_length(field: &str, value: &str, min: usize, max: usize) -> ValidationResult<()> {
    let len = value.len();
    if len < min {
        return Err(ValidationError::new(
            field,
            format!("must be at least {} characters (got {})", min, len),
        ));
    }
    if len > max {
        return Err(ValidationError::new(
            field,
            format!("must be at most {} characters (got {})", max, len),
        ));
    }
    Ok(())
}

/// Validate string contains only alphanumeric characters and allowed symbols.
pub fn validate_alphanumeric_with(
    field: &str,
    value: &str,
    allowed: &[char],
) -> ValidationResult<()> {
    if !value
        .chars()
        .all(|c| c.is_alphanumeric() || allowed.contains(&c))
    {
        let allowed_str = allowed.iter().collect::<String>();
        return Err(ValidationError::new(
            field,
            format!(
                "can only contain alphanumeric characters and: {}",
                allowed_str
            ),
        ));
    }
    Ok(())
}

// ==================== Email Validation ====================

/// Validate email format (simple validation).
pub fn validate_email(field: &str, email: &str) -> ValidationResult<()> {
    validate_not_empty(field, email)?;
    validate_length(field, email, 3, 255)?;

    // Simple email validation
    if !email.contains('@') {
        return Err(ValidationError::new(
            field,
            "invalid email format (missing @)",
        ));
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(ValidationError::new(
            field,
            "invalid email format (multiple @)",
        ));
    }

    let local = parts[0];
    let domain = parts[1];

    if local.is_empty() {
        return Err(ValidationError::new(
            field,
            "invalid email format (empty local part)",
        ));
    }

    if domain.is_empty() {
        return Err(ValidationError::new(
            field,
            "invalid email format (empty domain)",
        ));
    }

    if !domain.contains('.') {
        return Err(ValidationError::new(
            field,
            "invalid email format (domain missing .)",
        ));
    }

    Ok(())
}

// ==================== URL Validation ====================

static URL_REGEX: OnceLock<Regex> = OnceLock::new();

fn url_regex() -> &'static Regex {
    URL_REGEX.get_or_init(|| Regex::new(r"^https?://[^\s/$.?#].[^\s]*$").unwrap())
}

/// Validate URL format.
pub fn validate_url(field: &str, url: &str) -> ValidationResult<()> {
    validate_not_empty(field, url)?;

    if !url_regex().is_match(url) {
        return Err(ValidationError::new(
            field,
            "invalid URL format (must start with http:// or https://)",
        ));
    }

    Ok(())
}

/// Validate URL is HTTPS only.
pub fn validate_https_url(field: &str, url: &str) -> ValidationResult<()> {
    validate_url(field, url)?;

    if !url.starts_with("https://") {
        return Err(ValidationError::new(field, "URL must use HTTPS"));
    }

    Ok(())
}

// ==================== Username Validation ====================

/// Validate username format.
pub fn validate_username(field: &str, username: &str) -> ValidationResult<()> {
    validate_not_empty(field, username)?;
    validate_length(field, username, 3, 50)?;
    validate_alphanumeric_with(field, username, &['_', '-', '.'])?;

    // Additional check: cannot start with special characters
    if let Some(first_char) = username.chars().next() {
        if !first_char.is_alphanumeric() {
            return Err(ValidationError::new(
                field,
                "must start with a letter or number",
            ));
        }
    }

    Ok(())
}

// ==================== Password Validation ====================

/// Password strength requirements.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub special_chars: Vec<char>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            special_chars: vec![
                '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '[', ']',
                '{', '}', '|', '\\', ';', ':', '\'', '"', ',', '.', '<', '>', '/', '?',
            ],
        }
    }
}

/// Validate password strength.
pub fn validate_password(
    field: &str,
    password: &str,
    policy: &PasswordPolicy,
) -> ValidationResult<()> {
    validate_not_empty(field, password)?;

    if password.len() < policy.min_length {
        return Err(ValidationError::new(
            field,
            format!("must be at least {} characters", policy.min_length),
        ));
    }

    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(ValidationError::new(
            field,
            "must contain at least one uppercase letter",
        ));
    }

    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err(ValidationError::new(
            field,
            "must contain at least one lowercase letter",
        ));
    }

    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(ValidationError::new(
            field,
            "must contain at least one digit",
        ));
    }

    if policy.require_special && !password.chars().any(|c| policy.special_chars.contains(&c)) {
        return Err(ValidationError::new(
            field,
            "must contain at least one special character",
        ));
    }

    Ok(())
}

// ==================== Hexadecimal Validation ====================

/// Validate hexadecimal string.
pub fn validate_hex(field: &str, value: &str) -> ValidationResult<()> {
    validate_not_empty(field, value)?;

    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::new(field, "must be valid hexadecimal"));
    }

    Ok(())
}

/// Validate hexadecimal string with exact length.
pub fn validate_hex_exact_length(
    field: &str,
    value: &str,
    expected_length: usize,
) -> ValidationResult<()> {
    validate_hex(field, value)?;

    if value.len() != expected_length {
        return Err(ValidationError::new(
            field,
            format!("must be exactly {} characters", expected_length),
        ));
    }

    Ok(())
}

// ==================== Numeric Validation ====================

/// Validate number is within range (inclusive).
pub fn validate_range<T: std::cmp::PartialOrd + std::fmt::Display>(
    field: &str,
    value: T,
    min: T,
    max: T,
) -> ValidationResult<()> {
    if value < min || value > max {
        return Err(ValidationError::new(
            field,
            format!("must be between {} and {}", min, max),
        ));
    }
    Ok(())
}

/// Validate number is positive.
pub fn validate_positive<T: std::cmp::PartialOrd + Default + std::fmt::Display>(
    field: &str,
    value: T,
) -> ValidationResult<()> {
    if value <= T::default() {
        return Err(ValidationError::new(field, "must be positive"));
    }
    Ok(())
}

/// Validate number is non-negative.
pub fn validate_non_negative<T: std::cmp::PartialOrd + Default + std::fmt::Display>(
    field: &str,
    value: T,
) -> ValidationResult<()> {
    if value < T::default() {
        return Err(ValidationError::new(field, "must be non-negative"));
    }
    Ok(())
}

// ==================== Collection Validation ====================

/// Validate collection is not empty.
pub fn validate_not_empty_vec<T>(field: &str, vec: &[T]) -> ValidationResult<()> {
    if vec.is_empty() {
        return Err(ValidationError::new(field, "cannot be empty"));
    }
    Ok(())
}

/// Validate collection length is within bounds.
pub fn validate_vec_length<T>(
    field: &str,
    vec: &[T],
    min: usize,
    max: usize,
) -> ValidationResult<()> {
    let len = vec.len();
    if len < min {
        return Err(ValidationError::new(
            field,
            format!("must contain at least {} items (got {})", min, len),
        ));
    }
    if len > max {
        return Err(ValidationError::new(
            field,
            format!("must contain at most {} items (got {})", max, len),
        ));
    }
    Ok(())
}

// ==================== UUID Validation ====================

/// Validate UUID format.
pub fn validate_uuid(field: &str, value: &str) -> ValidationResult<()> {
    validate_not_empty(field, value)?;

    if uuid::Uuid::parse_str(value).is_err() {
        return Err(ValidationError::new(field, "invalid UUID format"));
    }

    Ok(())
}

// ==================== Content Hash Validation ====================

static CONTENT_HASH_REGEX: OnceLock<Regex> = OnceLock::new();

fn content_hash_regex() -> &'static Regex {
    CONTENT_HASH_REGEX.get_or_init(|| {
        // IPFS CID format (e.g., Qm... or bafy...)
        Regex::new(r"^(Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[0-9a-z]{55})$").unwrap()
    })
}

/// Validate content hash (IPFS CID).
pub fn validate_content_hash(field: &str, hash: &str) -> ValidationResult<()> {
    validate_not_empty(field, hash)?;

    if !content_hash_regex().is_match(hash) {
        return Err(ValidationError::new(
            field,
            "invalid content hash format (expected IPFS CID)",
        ));
    }

    Ok(())
}

// ==================== Peer ID Validation ====================

static PEER_ID_REGEX: OnceLock<Regex> = OnceLock::new();

fn peer_id_regex() -> &'static Regex {
    PEER_ID_REGEX.get_or_init(|| {
        // libp2p peer ID format (e.g., 12D3KooW...)
        Regex::new(r"^12D3KooW[1-9A-HJ-NP-Za-km-z]{44}$").unwrap()
    })
}

/// Validate libp2p peer ID.
pub fn validate_peer_id(field: &str, peer_id: &str) -> ValidationResult<()> {
    validate_not_empty(field, peer_id)?;

    if !peer_id_regex().is_match(peer_id) {
        return Err(ValidationError::new(
            field,
            "invalid peer ID format (expected libp2p format: 12D3KooW...)",
        ));
    }

    Ok(())
}

// ==================== JSON Validation ====================

/// Validate JSON string is valid.
pub fn validate_json(field: &str, json_str: &str) -> ValidationResult<()> {
    validate_not_empty(field, json_str)?;

    if serde_json::from_str::<serde_json::Value>(json_str).is_err() {
        return Err(ValidationError::new(field, "invalid JSON format"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate_email("email", "user@example.com").is_ok());
        assert!(validate_email("email", "test.user+tag@example.co.uk").is_ok());
        assert!(validate_email("email", "").is_err());
        assert!(validate_email("email", "invalid").is_err());
        assert!(validate_email("email", "@example.com").is_err());
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("username", "valid_user123").is_ok());
        assert!(validate_username("username", "test-user").is_ok());
        assert!(validate_username("username", "ab").is_err()); // too short
        assert!(validate_username("username", "_invalid").is_err()); // starts with symbol
        assert!(validate_username("username", "user@name").is_err()); // invalid char
    }

    #[test]
    fn test_validate_password() {
        let policy = PasswordPolicy::default();

        assert!(validate_password("password", "StrongPass123!", &policy).is_ok());
        assert!(validate_password("password", "weak", &policy).is_err()); // too short
        assert!(validate_password("password", "nouppercase123!", &policy).is_err());
        assert!(validate_password("password", "NOLOWERCASE123!", &policy).is_err());
        assert!(validate_password("password", "NoDigits!", &policy).is_err());
        assert!(validate_password("password", "NoSpecial123", &policy).is_err());
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("url", "http://example.com").is_ok());
        assert!(validate_url("url", "https://example.com/path").is_ok());
        assert!(validate_url("url", "invalid").is_err());
        assert!(validate_url("url", "ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_https_url() {
        assert!(validate_https_url("url", "https://example.com").is_ok());
        assert!(validate_https_url("url", "http://example.com").is_err());
    }

    #[test]
    fn test_validate_hex() {
        assert!(validate_hex("hex", "abcdef123456").is_ok());
        assert!(validate_hex("hex", "ABCDEF").is_ok());
        assert!(validate_hex("hex", "invalid_hex").is_err());
    }

    #[test]
    fn test_validate_range() {
        assert!(validate_range("number", 5, 1, 10).is_ok());
        assert!(validate_range("number", 0, 1, 10).is_err());
        assert!(validate_range("number", 11, 1, 10).is_err());
    }

    #[test]
    fn test_validate_peer_id() {
        assert!(
            validate_peer_id(
                "peer_id",
                "12D3KooWDpJ7As5PftzQRgSixwqeFXKwpYUfaJarwMfbZ9x1Bfg5"
            )
            .is_ok()
        );
        assert!(validate_peer_id("peer_id", "invalid_peer_id").is_err());
        assert!(validate_peer_id("peer_id", "12D3KooWABC0invalid").is_err()); // contains 0
    }

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("uuid", "550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("uuid", "invalid-uuid").is_err());
    }

    #[test]
    fn test_validate_json() {
        assert!(validate_json("json", r#"{"key": "value"}"#).is_ok());
        assert!(validate_json("json", "invalid json").is_err());
    }
}
