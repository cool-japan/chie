//! Time-lock encryption for scheduled content release.
//!
//! This module provides time-lock encryption that allows encrypting content
//! that can only be decrypted after a certain time period. This is useful for:
//! - Scheduled content release in P2P networks
//! - Fair exchange protocols
//! - Delayed disclosure mechanisms
//!
//! # Example
//!
//! ```
//! use chie_crypto::timelock::{timelock_encrypt, timelock_decrypt, TimeParams};
//!
//! // Encrypt data that requires 100,000 sequential hash operations to decrypt
//! let data = b"Secret content to be released in the future";
//! let params = TimeParams::new(100_000);
//! let locked = timelock_encrypt(data, &params).unwrap();
//!
//! // Decrypt (requires performing the time-lock computation)
//! let decrypted = timelock_decrypt(&locked).unwrap();
//! assert_eq!(data, &decrypted[..]);
//! ```

use crate::encryption::{decrypt, encrypt};
use blake3;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// Error types for time-lock encryption operations.
#[derive(Debug, Error)]
pub enum TimeLockError {
    #[error("Invalid time parameter: must be > 0")]
    InvalidTimeParameter,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}

pub type TimeLockResult<T> = Result<T, TimeLockError>;

/// Parameters for time-lock encryption.
///
/// The `iterations` parameter determines how many sequential hash operations
/// must be performed to decrypt the content. Each iteration takes approximately
/// a constant time, so this provides a time delay that cannot be parallelized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeParams {
    /// Number of sequential hash iterations required
    pub iterations: u64,
}

impl TimeParams {
    /// Create new time parameters with specified number of iterations.
    ///
    /// # Example computation times (approximate)
    /// - 100,000 iterations: ~10ms on modern CPU
    /// - 1,000,000 iterations: ~100ms
    /// - 10,000,000 iterations: ~1 second
    /// - 100,000,000 iterations: ~10 seconds
    pub fn new(iterations: u64) -> Self {
        Self { iterations }
    }

    /// Create time parameters for approximately the given duration.
    ///
    /// This is an estimate based on ~10,000 iterations per millisecond
    /// on a typical modern CPU. Actual time will vary by hardware.
    pub fn from_duration_ms(duration_ms: u64) -> Self {
        Self {
            iterations: duration_ms * 10_000,
        }
    }

    /// Estimate the time delay in milliseconds.
    ///
    /// This is an approximation assuming ~10,000 iterations per millisecond.
    pub fn estimated_delay_ms(&self) -> u64 {
        self.iterations / 10_000
    }
}

/// A time-locked ciphertext that can only be decrypted after performing
/// the required number of hash iterations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeLockCiphertext {
    /// The encrypted data
    ciphertext: Vec<u8>,
    /// Initial puzzle value
    puzzle_start: [u8; 32],
    /// Time parameters
    params: TimeParams,
    /// Nonce for encryption
    nonce: [u8; 12],
}

impl TimeLockCiphertext {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> TimeLockResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| TimeLockError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> TimeLockResult<Self> {
        crate::codec::decode(bytes).map_err(|e| TimeLockError::SerializationError(e.to_string()))
    }

    /// Get the number of iterations required to decrypt.
    pub fn iterations(&self) -> u64 {
        self.params.iterations
    }

    /// Get estimated time to decrypt in milliseconds.
    pub fn estimated_time_ms(&self) -> u64 {
        self.params.estimated_delay_ms()
    }
}

/// Encrypt data with time-lock encryption.
///
/// The data will be encrypted using a key derived from a time-lock puzzle.
/// To decrypt, the recipient must perform `params.iterations` sequential
/// hash operations to recover the encryption key.
pub fn timelock_encrypt(data: &[u8], params: &TimeParams) -> TimeLockResult<TimeLockCiphertext> {
    if params.iterations == 0 {
        return Err(TimeLockError::InvalidTimeParameter);
    }

    // Generate random puzzle start value
    let mut puzzle_start = [0u8; 32];
    rand::rng().fill_bytes(&mut puzzle_start);

    // Solve the puzzle to get the encryption key
    let key = solve_time_lock_puzzle(&puzzle_start, params.iterations);

    // Generate random nonce
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    // Encrypt the data
    let ciphertext = encrypt(data, &key, &nonce).map_err(|_| TimeLockError::DecryptionFailed)?;

    Ok(TimeLockCiphertext {
        ciphertext,
        puzzle_start,
        params: params.clone(),
        nonce,
    })
}

/// Decrypt time-locked data.
///
/// This requires performing `ciphertext.iterations()` sequential hash operations
/// to recover the encryption key before decrypting the data.
pub fn timelock_decrypt(ciphertext: &TimeLockCiphertext) -> TimeLockResult<Vec<u8>> {
    // Solve the time-lock puzzle to get the key
    let key = solve_time_lock_puzzle(&ciphertext.puzzle_start, ciphertext.params.iterations);

    // Decrypt the data
    decrypt(&ciphertext.ciphertext, &key, &ciphertext.nonce)
        .map_err(|_| TimeLockError::DecryptionFailed)
}

/// Solve a time-lock puzzle by performing sequential hash iterations.
///
/// This is intentionally sequential and cannot be parallelized significantly.
/// Each iteration depends on the previous one.
fn solve_time_lock_puzzle(start: &[u8; 32], iterations: u64) -> [u8; 32] {
    let mut current = *start;

    for _ in 0..iterations {
        current = *blake3::hash(&current).as_bytes();
    }

    current
}

/// A time-lock puzzle that can be used for timed release of secrets.
///
/// This is a more general interface that allows creating puzzles separately
/// from encryption.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct TimeLockPuzzle {
    /// The puzzle starting point
    start: [u8; 32],
    /// Number of iterations
    iterations: u64,
    /// The solution (only known after solving)
    #[zeroize(skip)]
    solution: Option<[u8; 32]>,
}

impl TimeLockPuzzle {
    /// Create a new time-lock puzzle with random starting point.
    pub fn new(params: &TimeParams) -> TimeLockResult<Self> {
        if params.iterations == 0 {
            return Err(TimeLockError::InvalidTimeParameter);
        }

        let mut start = [0u8; 32];
        rand::rng().fill_bytes(&mut start);

        Ok(Self {
            start,
            iterations: params.iterations,
            solution: None,
        })
    }

    /// Create a puzzle from a specific starting point.
    pub fn from_start(start: [u8; 32], iterations: u64) -> TimeLockResult<Self> {
        if iterations == 0 {
            return Err(TimeLockError::InvalidTimeParameter);
        }

        Ok(Self {
            start,
            iterations,
            solution: None,
        })
    }

    /// Solve the puzzle (performs the time-lock computation).
    pub fn solve(&mut self) -> [u8; 32] {
        if let Some(solution) = self.solution {
            return solution;
        }

        let solution = solve_time_lock_puzzle(&self.start, self.iterations);
        self.solution = Some(solution);
        solution
    }

    /// Get the puzzle starting point.
    pub fn start(&self) -> &[u8; 32] {
        &self.start
    }

    /// Get the number of iterations.
    pub fn iterations(&self) -> u64 {
        self.iterations
    }

    /// Check if the puzzle has been solved.
    pub fn is_solved(&self) -> bool {
        self.solution.is_some()
    }

    /// Get the solution if it has been solved.
    pub fn solution(&self) -> Option<[u8; 32]> {
        self.solution
    }
}

/// Encrypt data using a pre-created time-lock puzzle.
pub fn timelock_encrypt_with_puzzle(
    data: &[u8],
    puzzle: &TimeLockPuzzle,
) -> TimeLockResult<TimeLockCiphertext> {
    // Solve the puzzle to get the key
    let key = solve_time_lock_puzzle(puzzle.start(), puzzle.iterations());

    // Generate random nonce
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);

    // Encrypt the data
    let ciphertext = encrypt(data, &key, &nonce).map_err(|_| TimeLockError::DecryptionFailed)?;

    Ok(TimeLockCiphertext {
        ciphertext,
        puzzle_start: *puzzle.start(),
        params: TimeParams::new(puzzle.iterations()),
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timelock_basic() {
        let data = b"Time-locked secret message";
        let params = TimeParams::new(1000);

        let locked = timelock_encrypt(data, &params).unwrap();
        let decrypted = timelock_decrypt(&locked).unwrap();

        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_timelock_different_iterations() {
        let data = b"Secret";

        for iterations in [100, 1_000, 10_000] {
            let params = TimeParams::new(iterations);
            let locked = timelock_encrypt(data, &params).unwrap();

            assert_eq!(locked.iterations(), iterations);

            let decrypted = timelock_decrypt(&locked).unwrap();
            assert_eq!(data, &decrypted[..]);
        }
    }

    #[test]
    fn test_timelock_serialization() {
        let data = b"Serialization test";
        let params = TimeParams::new(500);

        let locked = timelock_encrypt(data, &params).unwrap();

        // Serialize and deserialize
        let bytes = locked.to_bytes().unwrap();
        let deserialized = TimeLockCiphertext::from_bytes(&bytes).unwrap();

        // Decrypt deserialized ciphertext
        let decrypted = timelock_decrypt(&deserialized).unwrap();
        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_invalid_time_parameter() {
        let data = b"Test";
        let params = TimeParams::new(0);

        let result = timelock_encrypt(data, &params);
        assert!(matches!(result, Err(TimeLockError::InvalidTimeParameter)));
    }

    #[test]
    fn test_time_params_from_duration() {
        let params = TimeParams::from_duration_ms(100);
        assert_eq!(params.iterations, 1_000_000);
        assert_eq!(params.estimated_delay_ms(), 100);
    }

    #[test]
    fn test_puzzle_basic() {
        let params = TimeParams::new(1000);
        let mut puzzle = TimeLockPuzzle::new(&params).unwrap();

        assert!(!puzzle.is_solved());
        assert_eq!(puzzle.solution(), None);

        let solution1 = puzzle.solve();
        assert!(puzzle.is_solved());
        assert_eq!(puzzle.solution(), Some(solution1));

        // Solving again should return the same solution
        let solution2 = puzzle.solve();
        assert_eq!(solution1, solution2);
    }

    #[test]
    fn test_puzzle_deterministic() {
        let start = [42u8; 32];
        let iterations = 1000;

        let mut puzzle1 = TimeLockPuzzle::from_start(start, iterations).unwrap();
        let mut puzzle2 = TimeLockPuzzle::from_start(start, iterations).unwrap();

        let solution1 = puzzle1.solve();
        let solution2 = puzzle2.solve();

        assert_eq!(solution1, solution2);
    }

    #[test]
    fn test_timelock_with_puzzle() {
        let data = b"Test data";
        let params = TimeParams::new(500);
        let puzzle = TimeLockPuzzle::new(&params).unwrap();

        let locked = timelock_encrypt_with_puzzle(data, &puzzle).unwrap();
        let decrypted = timelock_decrypt(&locked).unwrap();

        assert_eq!(data, &decrypted[..]);
    }

    #[test]
    fn test_large_data() {
        let data = vec![0x42u8; 10_000]; // 10KB of data
        let params = TimeParams::new(1000);

        let locked = timelock_encrypt(&data, &params).unwrap();
        let decrypted = timelock_decrypt(&locked).unwrap();

        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_puzzle_different_iterations_different_solutions() {
        let start = [1u8; 32];

        let mut puzzle1 = TimeLockPuzzle::from_start(start, 100).unwrap();
        let mut puzzle2 = TimeLockPuzzle::from_start(start, 200).unwrap();

        let solution1 = puzzle1.solve();
        let solution2 = puzzle2.solve();

        assert_ne!(solution1, solution2);
    }
}
