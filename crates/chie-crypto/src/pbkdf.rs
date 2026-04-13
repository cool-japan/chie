//! Password-based key derivation using Argon2id.
//!
//! This module provides secure password-to-key conversion for user-controlled
//! encryption scenarios. Argon2id is the recommended algorithm as it provides
//! resistance against both side-channel and GPU attacks.

use argon2::{
    Algorithm, Argon2, Params, ParamsBuilder, PasswordHash, PasswordVerifier, Version,
    password_hash::{PasswordHasher, SaltString},
};
use rand::Rng as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::EncryptionKey;

/// Default memory cost (64 MB).
#[allow(dead_code)]
const DEFAULT_M_COST: u32 = 65536; // 64 * 1024 KiB

/// Default time cost (iterations).
#[allow(dead_code)]
const DEFAULT_T_COST: u32 = 3;

/// Default parallelism.
#[allow(dead_code)]
const DEFAULT_P_COST: u32 = 4;

/// Output length for derived keys (32 bytes).
const OUTPUT_LENGTH: usize = 32;

/// Password-based key derivation error.
#[derive(Debug, Error)]
pub enum PbkdfError {
    #[error("Invalid password")]
    InvalidPassword,

    #[error("Invalid salt")]
    InvalidSalt,

    #[error("Argon2 error: {0}")]
    Argon2Error(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Hash verification failed")]
    VerificationFailed,
}

/// Strength presets for password-based key derivation.
#[derive(Debug, Clone, Copy)]
pub enum KeyDerivationStrength {
    /// Fast (for development/testing).
    /// Memory: 8 MB, Time: 1 iteration
    Fast,

    /// Interactive (for user-facing applications).
    /// Memory: 64 MB, Time: 3 iterations
    Interactive,

    /// Moderate (balanced security/performance).
    /// Memory: 256 MB, Time: 4 iterations
    Moderate,

    /// Strong (for sensitive data).
    /// Memory: 512 MB, Time: 5 iterations
    Strong,

    /// Paranoid (maximum security).
    /// Memory: 1 GB, Time: 10 iterations
    Paranoid,
}

impl KeyDerivationStrength {
    /// Get Argon2 parameters for this strength level.
    fn params(&self) -> Result<Params, PbkdfError> {
        let (m_cost, t_cost, p_cost) = match self {
            Self::Fast => (8 * 1024, 1, 1),         // 8 MB, 1 iter
            Self::Interactive => (64 * 1024, 3, 4), // 64 MB, 3 iter
            Self::Moderate => (256 * 1024, 4, 4),   // 256 MB, 4 iter
            Self::Strong => (512 * 1024, 5, 4),     // 512 MB, 5 iter
            Self::Paranoid => (1024 * 1024, 10, 8), // 1 GB, 10 iter
        };

        ParamsBuilder::new()
            .m_cost(m_cost)
            .t_cost(t_cost)
            .p_cost(p_cost)
            .output_len(OUTPUT_LENGTH)
            .build()
            .map_err(|e| PbkdfError::Argon2Error(e.to_string()))
    }
}

/// Password-based key derivation context.
pub struct PasswordKeyDerivation {
    params: Params,
}

impl Default for PasswordKeyDerivation {
    fn default() -> Self {
        Self::new(KeyDerivationStrength::Interactive)
    }
}

impl PasswordKeyDerivation {
    /// Create a new PBKDF context with the specified strength.
    pub fn new(strength: KeyDerivationStrength) -> Self {
        let params = strength.params().expect("Invalid parameters");
        Self { params }
    }

    /// Create with custom parameters.
    pub fn with_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Self, PbkdfError> {
        let params = ParamsBuilder::new()
            .m_cost(m_cost)
            .t_cost(t_cost)
            .p_cost(p_cost)
            .output_len(OUTPUT_LENGTH)
            .build()
            .map_err(|e| PbkdfError::InvalidParams(e.to_string()))?;

        Ok(Self { params })
    }

    /// Derive an encryption key from a password.
    ///
    /// Returns both the key and the salt (salt must be stored to derive the same key later).
    pub fn derive_key(&self, password: &str) -> Result<(EncryptionKey, Vec<u8>), PbkdfError> {
        if password.is_empty() {
            return Err(PbkdfError::InvalidPassword);
        }

        // Generate random salt
        let salt = SaltString::generate(&mut rand_core06::OsRng);

        // Derive key
        let key = self.derive_key_with_salt(password, salt.as_str())?;

        Ok((key, salt.as_str().as_bytes().to_vec()))
    }

    /// Derive a key with a specific salt.
    pub fn derive_key_with_salt(
        &self,
        password: &str,
        salt: &str,
    ) -> Result<EncryptionKey, PbkdfError> {
        if password.is_empty() {
            return Err(PbkdfError::InvalidPassword);
        }

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());

        // Use zeroizing string for password
        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());

        // Parse or create salt
        let salt_string = SaltString::from_b64(salt).map_err(|_| PbkdfError::InvalidSalt)?;

        // Derive the key
        let hash = argon2
            .hash_password(&password_bytes, &salt_string)
            .map_err(|e| PbkdfError::Argon2Error(e.to_string()))?;

        // Extract the hash bytes
        let hash_bytes = hash
            .hash
            .ok_or_else(|| PbkdfError::Argon2Error("No hash output".to_string()))?;

        if hash_bytes.len() != OUTPUT_LENGTH {
            return Err(PbkdfError::Argon2Error(format!(
                "Invalid output length: {} (expected {})",
                hash_bytes.len(),
                OUTPUT_LENGTH
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(hash_bytes.as_bytes());
        Ok(key)
    }

    /// Create a password hash for verification (PHC string format).
    pub fn hash_password(&self, password: &str) -> Result<String, PbkdfError> {
        if password.is_empty() {
            return Err(PbkdfError::InvalidPassword);
        }

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, self.params.clone());
        let salt = SaltString::generate(&mut rand_core06::OsRng);
        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());

        let hash = argon2
            .hash_password(&password_bytes, &salt)
            .map_err(|e| PbkdfError::Argon2Error(e.to_string()))?;

        Ok(hash.to_string())
    }

    /// Verify a password against a hash.
    pub fn verify_password(password: &str, hash: &str) -> Result<(), PbkdfError> {
        if password.is_empty() {
            return Err(PbkdfError::InvalidPassword);
        }

        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| PbkdfError::Argon2Error(e.to_string()))?;

        let password_bytes = Zeroizing::new(password.as_bytes().to_vec());

        // Use all Argon2 variants for verification
        Argon2::default()
            .verify_password(&password_bytes, &parsed_hash)
            .map_err(|_| PbkdfError::VerificationFailed)
    }
}

// ============================================================================
// Quick functions for common use cases
// ============================================================================

/// Derive a key from a password with default (Interactive) strength.
pub fn derive_key_from_password(password: &str) -> Result<(EncryptionKey, Vec<u8>), PbkdfError> {
    PasswordKeyDerivation::default().derive_key(password)
}

/// Derive a key from a password with a known salt.
pub fn derive_key_with_salt(password: &str, salt: &str) -> Result<EncryptionKey, PbkdfError> {
    PasswordKeyDerivation::default().derive_key_with_salt(password, salt)
}

/// Generate a random salt for use with password-based key derivation.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_from_password() {
        let password = "correct horse battery staple";
        let (key1, salt) = derive_key_from_password(password).unwrap();

        assert_eq!(key1.len(), 32);
        assert!(!salt.is_empty());

        // Same password + salt = same key
        let salt_str = std::str::from_utf8(&salt).unwrap();
        let key2 = derive_key_with_salt(password, salt_str).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let (key1, _) = derive_key_from_password("password1").unwrap();
        let (key2, _) = derive_key_from_password("password2").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_password_hashing() {
        let pbkdf = PasswordKeyDerivation::default();
        let password = "my secret password";

        let hash = pbkdf.hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));

        // Verify correct password
        assert!(PasswordKeyDerivation::verify_password(password, &hash).is_ok());

        // Verify wrong password
        assert!(PasswordKeyDerivation::verify_password("wrong password", &hash).is_err());
    }

    #[ignore = "slow: PBKDF2 strength-level benchmarking (~200s)"]
    #[test]
    fn test_strength_levels() {
        let password = "test password";

        // Test all strength levels
        for strength in &[
            KeyDerivationStrength::Fast,
            KeyDerivationStrength::Interactive,
            KeyDerivationStrength::Moderate,
            KeyDerivationStrength::Strong,
        ] {
            let pbkdf = PasswordKeyDerivation::new(*strength);
            let (key, salt) = pbkdf.derive_key(password).unwrap();

            assert_eq!(key.len(), 32);
            assert!(!salt.is_empty());
        }
    }

    #[test]
    fn test_empty_password() {
        let result = derive_key_from_password("");
        assert!(result.is_err());
    }

    #[test]
    fn test_custom_params() {
        let pbkdf = PasswordKeyDerivation::with_params(4096, 2, 1).unwrap();
        let (key, _) = pbkdf.derive_key("test").unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_deterministic_derivation() {
        let password = "test password";
        let pbkdf = PasswordKeyDerivation::default();

        let (_, salt1) = pbkdf.derive_key(password).unwrap();
        let salt_str = std::str::from_utf8(&salt1).unwrap();

        // Derive key multiple times with same salt
        let key1 = pbkdf.derive_key_with_salt(password, salt_str).unwrap();
        let key2 = pbkdf.derive_key_with_salt(password, salt_str).unwrap();

        assert_eq!(key1, key2);
    }
}
