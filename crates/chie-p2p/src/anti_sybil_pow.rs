//! Anti-Sybil protection using proof-of-work challenges.
//!
//! This module provides Sybil attack prevention using computational puzzles
//! that make it expensive to create many fake identities.

use blake3::Hasher;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Difficulty level for proof-of-work
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DifficultyLevel {
    VeryLow = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    VeryHigh = 5,
}

impl DifficultyLevel {
    /// Get leading zero bits required
    pub fn leading_zeros(&self) -> u32 {
        match self {
            Self::VeryLow => 8,
            Self::Low => 12,
            Self::Medium => 16,
            Self::High => 20,
            Self::VeryHigh => 24,
        }
    }

    /// Get from leading zeros
    pub fn from_leading_zeros(zeros: u32) -> Self {
        match zeros {
            0..=9 => Self::VeryLow,
            10..=13 => Self::Low,
            14..=18 => Self::Medium,
            19..=22 => Self::High,
            _ => Self::VeryHigh,
        }
    }
}

/// Proof-of-work challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoWChallenge {
    /// Challenge identifier
    pub challenge_id: String,
    /// Random nonce from challenger
    pub server_nonce: [u8; 32],
    /// Difficulty level
    pub difficulty: u32,
    /// Challenge timestamp
    pub timestamp: u64,
    /// Time to live (seconds)
    pub ttl: u64,
}

impl PoWChallenge {
    /// Create a new challenge
    pub fn new(difficulty: DifficultyLevel, ttl: Duration) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut server_nonce = [0u8; 32];
        rng.fill(&mut server_nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            server_nonce,
            difficulty: difficulty.leading_zeros(),
            timestamp,
            ttl: ttl.as_secs(),
        }
    }

    /// Check if challenge is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.timestamp + self.ttl
    }
}

/// Proof-of-work solution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoWSolution {
    /// Challenge ID this solves
    pub challenge_id: String,
    /// Peer ID claiming solution
    pub peer_id: String,
    /// Solution nonce
    pub client_nonce: u64,
    /// Hash result
    pub hash: Vec<u8>,
}

impl PoWSolution {
    /// Verify the solution
    pub fn verify(&self, challenge: &PoWChallenge, peer_id: &PeerId) -> bool {
        // Check challenge not expired
        if challenge.is_expired() {
            return false;
        }

        // Check peer ID matches
        if self.peer_id != peer_id.to_base58() {
            return false;
        }

        // Reconstruct hash
        let mut hasher = Hasher::new();
        hasher.update(&challenge.server_nonce);
        hasher.update(self.peer_id.as_bytes());
        hasher.update(&self.client_nonce.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Verify hash matches solution
        if hash_bytes != self.hash.as_slice() {
            return false;
        }

        // Check difficulty
        count_leading_zero_bits(hash_bytes) >= challenge.difficulty
    }
}

/// Count leading zero bits in a hash
fn count_leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Solve a proof-of-work challenge
pub fn solve_challenge(
    challenge: &PoWChallenge,
    peer_id: &PeerId,
    max_iterations: u64,
) -> Option<PoWSolution> {
    let peer_id_str = peer_id.to_base58();

    for nonce in 0..max_iterations {
        let mut hasher = Hasher::new();
        hasher.update(&challenge.server_nonce);
        hasher.update(peer_id_str.as_bytes());
        hasher.update(&nonce.to_le_bytes());

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        if count_leading_zero_bits(hash_bytes) >= challenge.difficulty {
            return Some(PoWSolution {
                challenge_id: challenge.challenge_id.clone(),
                peer_id: peer_id_str,
                client_nonce: nonce,
                hash: hash_bytes.to_vec(),
            });
        }
    }

    None
}

/// Anti-Sybil configuration
#[derive(Debug, Clone)]
pub struct AntiSybilConfig {
    /// Default difficulty level
    pub default_difficulty: DifficultyLevel,
    /// Challenge TTL
    pub challenge_ttl: Duration,
    /// Proof validity duration
    pub proof_validity: Duration,
    /// Maximum challenges per peer
    pub max_challenges_per_peer: usize,
    /// Challenge cleanup interval
    pub cleanup_interval: Duration,
}

impl Default for AntiSybilConfig {
    fn default() -> Self {
        Self {
            default_difficulty: DifficultyLevel::Medium,
            challenge_ttl: Duration::from_secs(300), // 5 minutes
            proof_validity: Duration::from_secs(3600), // 1 hour
            max_challenges_per_peer: 3,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Peer verification status
#[derive(Debug, Clone)]
struct PeerVerification {
    verified: bool,
    verified_at: Option<Instant>,
    challenge_count: usize,
}

/// Anti-Sybil manager
pub struct AntiSybilManager {
    config: AntiSybilConfig,
    active_challenges: Arc<RwLock<HashMap<String, PoWChallenge>>>,
    peer_verifications: Arc<RwLock<HashMap<PeerId, PeerVerification>>>,
    last_cleanup: Arc<RwLock<Instant>>,
}

impl AntiSybilManager {
    /// Create a new anti-Sybil manager
    pub fn new(config: AntiSybilConfig) -> Self {
        Self {
            config,
            active_challenges: Arc::new(RwLock::new(HashMap::new())),
            peer_verifications: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create a challenge for a peer
    pub fn create_challenge(&self, peer_id: &PeerId) -> Result<PoWChallenge, String> {
        let mut verifications = self.peer_verifications.write().unwrap();
        let verification = verifications.entry(*peer_id).or_insert(PeerVerification {
            verified: false,
            verified_at: None,
            challenge_count: 0,
        });

        // Check if peer is already verified and proof is still valid
        if verification.verified {
            if let Some(verified_at) = verification.verified_at {
                if verified_at.elapsed() < self.config.proof_validity {
                    return Err("Peer already verified".to_string());
                }
            }
        }

        // Check challenge limit
        if verification.challenge_count >= self.config.max_challenges_per_peer {
            return Err("Too many challenges for this peer".to_string());
        }

        verification.challenge_count += 1;
        drop(verifications);

        let challenge =
            PoWChallenge::new(self.config.default_difficulty, self.config.challenge_ttl);
        let challenge_id = challenge.challenge_id.clone();

        self.active_challenges
            .write()
            .unwrap()
            .insert(challenge_id, challenge.clone());

        Ok(challenge)
    }

    /// Verify a solution
    pub fn verify_solution(&self, solution: &PoWSolution, peer_id: &PeerId) -> bool {
        let challenges = self.active_challenges.read().unwrap();
        let Some(challenge) = challenges.get(&solution.challenge_id) else {
            return false;
        };

        if !solution.verify(challenge, peer_id) {
            return false;
        }

        drop(challenges);

        // Mark peer as verified
        let mut verifications = self.peer_verifications.write().unwrap();
        if let Some(verification) = verifications.get_mut(peer_id) {
            verification.verified = true;
            verification.verified_at = Some(Instant::now());
        }

        // Remove challenge
        self.active_challenges
            .write()
            .unwrap()
            .remove(&solution.challenge_id);

        true
    }

    /// Check if peer is verified
    pub fn is_verified(&self, peer_id: &PeerId) -> bool {
        let verifications = self.peer_verifications.read().unwrap();
        if let Some(verification) = verifications.get(peer_id) {
            if verification.verified {
                if let Some(verified_at) = verification.verified_at {
                    return verified_at.elapsed() < self.config.proof_validity;
                }
            }
        }
        false
    }

    /// Revoke verification for a peer
    pub fn revoke_verification(&self, peer_id: &PeerId) {
        if let Some(verification) = self.peer_verifications.write().unwrap().get_mut(peer_id) {
            verification.verified = false;
            verification.verified_at = None;
        }
    }

    /// Cleanup expired challenges and verifications
    pub fn cleanup(&self) {
        let mut last_cleanup = self.last_cleanup.write().unwrap();
        if last_cleanup.elapsed() < self.config.cleanup_interval {
            return;
        }
        *last_cleanup = Instant::now();
        drop(last_cleanup);

        // Remove expired challenges
        self.active_challenges
            .write()
            .unwrap()
            .retain(|_, challenge| !challenge.is_expired());

        // Remove expired verifications
        let validity = self.config.proof_validity;
        self.peer_verifications
            .write()
            .unwrap()
            .retain(|_, verification| {
                if verification.verified {
                    if let Some(verified_at) = verification.verified_at {
                        return verified_at.elapsed() < validity;
                    }
                }
                verification.challenge_count > 0
            });
    }

    /// Get statistics
    pub fn get_stats(&self) -> AntiSybilStats {
        let challenges = self.active_challenges.read().unwrap();
        let verifications = self.peer_verifications.read().unwrap();

        let verified_peers = verifications
            .values()
            .filter(|v| {
                v.verified
                    && v.verified_at
                        .map(|t| t.elapsed() < self.config.proof_validity)
                        .unwrap_or(false)
            })
            .count();

        AntiSybilStats {
            active_challenges: challenges.len(),
            verified_peers,
            total_tracked_peers: verifications.len(),
        }
    }
}

/// Anti-Sybil statistics
#[derive(Debug, Clone)]
pub struct AntiSybilStats {
    pub active_challenges: usize,
    pub verified_peers: usize,
    pub total_tracked_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn test_difficulty_level_leading_zeros() {
        assert_eq!(DifficultyLevel::VeryLow.leading_zeros(), 8);
        assert_eq!(DifficultyLevel::Low.leading_zeros(), 12);
        assert_eq!(DifficultyLevel::Medium.leading_zeros(), 16);
        assert_eq!(DifficultyLevel::High.leading_zeros(), 20);
        assert_eq!(DifficultyLevel::VeryHigh.leading_zeros(), 24);
    }

    #[test]
    fn test_difficulty_from_leading_zeros() {
        assert_eq!(
            DifficultyLevel::from_leading_zeros(8),
            DifficultyLevel::VeryLow
        );
        assert_eq!(
            DifficultyLevel::from_leading_zeros(12),
            DifficultyLevel::Low
        );
        assert_eq!(
            DifficultyLevel::from_leading_zeros(16),
            DifficultyLevel::Medium
        );
        assert_eq!(
            DifficultyLevel::from_leading_zeros(20),
            DifficultyLevel::High
        );
        assert_eq!(
            DifficultyLevel::from_leading_zeros(24),
            DifficultyLevel::VeryHigh
        );
    }

    #[test]
    fn test_challenge_creation() {
        let challenge = PoWChallenge::new(DifficultyLevel::Low, Duration::from_secs(300));
        assert_eq!(challenge.difficulty, 12);
        assert_eq!(challenge.ttl, 300);
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_challenge_expiry() {
        let mut challenge = PoWChallenge::new(DifficultyLevel::Low, Duration::from_secs(1));
        assert!(!challenge.is_expired());

        // Simulate expiry by setting old timestamp
        challenge.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_solve_challenge_very_low() {
        let challenge = PoWChallenge::new(DifficultyLevel::VeryLow, Duration::from_secs(300));
        let peer = create_test_peer();

        let solution = solve_challenge(&challenge, &peer, 1_000_000);
        assert!(solution.is_some());

        let sol = solution.unwrap();
        assert!(sol.verify(&challenge, &peer));
    }

    #[test]
    fn test_solution_verification() {
        let challenge = PoWChallenge::new(DifficultyLevel::VeryLow, Duration::from_secs(300));
        let peer = create_test_peer();

        let solution = solve_challenge(&challenge, &peer, 1_000_000).unwrap();
        assert!(solution.verify(&challenge, &peer));
    }

    #[test]
    fn test_solution_wrong_peer() {
        let challenge = PoWChallenge::new(DifficultyLevel::VeryLow, Duration::from_secs(300));
        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        let solution = solve_challenge(&challenge, &peer1, 1_000_000).unwrap();
        assert!(!solution.verify(&challenge, &peer2)); // Wrong peer
    }

    #[test]
    fn test_count_leading_zero_bits() {
        let zeros = vec![0u8, 0, 0, 0xFF];
        assert_eq!(count_leading_zero_bits(&zeros), 24);

        let partial = vec![0u8, 0, 0x0F, 0xFF];
        assert_eq!(count_leading_zero_bits(&partial), 20);

        let no_zeros = vec![0xFF, 0xFF];
        assert_eq!(count_leading_zero_bits(&no_zeros), 0);
    }

    #[test]
    fn test_anti_sybil_manager_new() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);
        let stats = manager.get_stats();
        assert_eq!(stats.active_challenges, 0);
    }

    #[test]
    fn test_create_challenge() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        let result = manager.create_challenge(&peer);
        assert!(result.is_ok());

        let stats = manager.get_stats();
        assert_eq!(stats.active_challenges, 1);
    }

    #[test]
    fn test_verify_solution() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        let challenge = manager.create_challenge(&peer).unwrap();
        let solution = solve_challenge(&challenge, &peer, 1_000_000).unwrap();

        assert!(manager.verify_solution(&solution, &peer));
        assert!(manager.is_verified(&peer));
    }

    #[test]
    fn test_already_verified() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        let challenge = manager.create_challenge(&peer).unwrap();
        let solution = solve_challenge(&challenge, &peer, 1_000_000).unwrap();
        manager.verify_solution(&solution, &peer);

        // Try to create another challenge
        let result = manager.create_challenge(&peer);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_challenges_per_peer() {
        let config = AntiSybilConfig {
            max_challenges_per_peer: 2,
            ..Default::default()
        };

        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        assert!(manager.create_challenge(&peer).is_ok());
        assert!(manager.create_challenge(&peer).is_ok());
        assert!(manager.create_challenge(&peer).is_err()); // Exceeds limit
    }

    #[test]
    fn test_revoke_verification() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        let challenge = manager.create_challenge(&peer).unwrap();
        let solution = solve_challenge(&challenge, &peer, 1_000_000).unwrap();
        manager.verify_solution(&solution, &peer);

        assert!(manager.is_verified(&peer));

        manager.revoke_verification(&peer);
        assert!(!manager.is_verified(&peer));
    }

    #[test]
    fn test_cleanup_expired_challenges() {
        let config = AntiSybilConfig {
            cleanup_interval: Duration::from_secs(0),
            ..Default::default()
        };

        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        let mut challenge = manager.create_challenge(&peer).unwrap();

        // Make it expired
        challenge.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1000;

        manager
            .active_challenges
            .write()
            .unwrap()
            .insert(challenge.challenge_id.clone(), challenge);

        manager.cleanup();

        // Expired challenge should be removed
        assert_eq!(manager.get_stats().active_challenges, 0);
    }

    #[test]
    fn test_stats() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);

        let peer1 = create_test_peer();
        let peer2 = create_test_peer();

        manager.create_challenge(&peer1).unwrap();
        let challenge2 = manager.create_challenge(&peer2).unwrap();
        let solution2 = solve_challenge(&challenge2, &peer2, 1_000_000).unwrap();
        manager.verify_solution(&solution2, &peer2);

        let stats = manager.get_stats();
        assert_eq!(stats.active_challenges, 1); // peer1's challenge still active
        assert_eq!(stats.verified_peers, 1); // peer2 verified
        assert_eq!(stats.total_tracked_peers, 2);
    }

    #[test]
    fn test_difficulty_ordering() {
        assert!(DifficultyLevel::VeryLow < DifficultyLevel::Low);
        assert!(DifficultyLevel::Low < DifficultyLevel::Medium);
        assert!(DifficultyLevel::Medium < DifficultyLevel::High);
        assert!(DifficultyLevel::High < DifficultyLevel::VeryHigh);
    }

    #[test]
    fn test_config_default() {
        let config = AntiSybilConfig::default();
        assert_eq!(config.default_difficulty, DifficultyLevel::Medium);
        assert_eq!(config.challenge_ttl, Duration::from_secs(300));
        assert_eq!(config.proof_validity, Duration::from_secs(3600));
    }

    #[test]
    fn test_invalid_challenge_id() {
        let config = AntiSybilConfig::default();
        let manager = AntiSybilManager::new(config);
        let peer = create_test_peer();

        let solution = PoWSolution {
            challenge_id: "nonexistent".to_string(),
            peer_id: peer.to_base58(),
            client_nonce: 0,
            hash: vec![0; 32],
        };

        assert!(!manager.verify_solution(&solution, &peer));
    }
}
