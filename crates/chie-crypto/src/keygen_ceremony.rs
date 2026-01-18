//! Multi-party key generation ceremony support.
//!
//! This module provides a high-level ceremony orchestration layer on top of
//! the existing DKG (Distributed Key Generation) implementation. It handles:
//!
//! - Ceremony coordination across multiple rounds
//! - Participant management and verification
//! - State management and persistence
//! - Communication message routing
//! - Error handling and recovery
//! - Ceremony attestation and audit trail
//!
//! # Example
//!
//! ```
//! use chie_crypto::keygen_ceremony::*;
//!
//! // Create a ceremony for 3 participants with 2-of-3 threshold
//! let mut ceremony = KeygenCeremony::new(
//!     CeremonyConfig::new(3, 2, "test-ceremony".to_string())
//! ).unwrap();
//!
//! // Each participant joins the ceremony
//! let participant_ids: Vec<_> = (0..3)
//!     .map(|i| ceremony.add_participant(format!("participant-{}", i)).unwrap())
//!     .collect();
//!
//! // Mark all participants as ready
//! for id in &participant_ids {
//!     ceremony.mark_ready(id).unwrap();
//! }
//!
//! // Start the ceremony
//! ceremony.start().unwrap();
//!
//! // Ceremony proceeds through rounds until complete
//! assert_eq!(ceremony.state(), CeremonyState::InProgress);
//! ```

use crate::dkg::DkgParams;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;
use thiserror::Error;

/// Errors that can occur during key generation ceremony.
#[derive(Debug, Error)]
pub enum CeremonyError {
    #[error("Invalid ceremony configuration: {0}")]
    InvalidConfig(String),

    #[error("Ceremony not in correct state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    #[error("Participant not found: {0}")]
    ParticipantNotFound(String),

    #[error("Participant already exists: {0}")]
    ParticipantAlreadyExists(String),

    #[error("Invalid participant count: expected {expected}, got {actual}")]
    InvalidParticipantCount { expected: usize, actual: usize },

    #[error("Round {0} not yet complete")]
    RoundIncomplete(usize),

    #[error("Ceremony timeout: {0}")]
    Timeout(String),

    #[error("DKG error: {0}")]
    DkgError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

/// Result type for ceremony operations.
pub type CeremonyResult<T> = Result<T, CeremonyError>;

/// Ceremony state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyState {
    /// Ceremony is being configured
    Setup,
    /// Waiting for all participants to join
    WaitingForParticipants,
    /// Ceremony is in progress
    InProgress,
    /// Ceremony completed successfully
    Completed,
    /// Ceremony was aborted
    Aborted,
    /// Ceremony failed
    Failed,
}

impl std::fmt::Display for CeremonyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup => write!(f, "Setup"),
            Self::WaitingForParticipants => write!(f, "WaitingForParticipants"),
            Self::InProgress => write!(f, "InProgress"),
            Self::Completed => write!(f, "Completed"),
            Self::Aborted => write!(f, "Aborted"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Participant information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfo {
    /// Unique participant ID
    pub id: String,
    /// Participant index (0-based)
    pub index: usize,
    /// When the participant joined (Unix timestamp)
    pub joined_at: u64,
    /// Whether the participant is ready
    pub ready: bool,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl ParticipantInfo {
    /// Create new participant info
    pub fn new(id: String, index: usize) -> Self {
        Self {
            id,
            index,
            joined_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            ready: false,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Ceremony configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    /// Total number of participants (N)
    pub total_participants: usize,
    /// Threshold (M in M-of-N)
    pub threshold: usize,
    /// Ceremony ID
    pub ceremony_id: String,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_seconds: u64,
    /// Require all participants to be ready before starting
    pub require_ready_check: bool,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl CeremonyConfig {
    /// Create new ceremony configuration
    pub fn new(total_participants: usize, threshold: usize, ceremony_id: String) -> Self {
        Self {
            total_participants,
            threshold,
            ceremony_id,
            timeout_seconds: 300, // 5 minutes default
            require_ready_check: true,
            metadata: HashMap::new(),
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Disable ready check
    pub fn without_ready_check(mut self) -> Self {
        self.require_ready_check = false;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Validate configuration
    pub fn validate(&self) -> CeremonyResult<()> {
        if self.total_participants < 2 {
            return Err(CeremonyError::InvalidConfig(
                "At least 2 participants required".to_string(),
            ));
        }

        if self.threshold < 1 || self.threshold > self.total_participants {
            return Err(CeremonyError::InvalidConfig(format!(
                "Threshold must be between 1 and {}, got {}",
                self.total_participants, self.threshold
            )));
        }

        if self.ceremony_id.is_empty() {
            return Err(CeremonyError::InvalidConfig(
                "Ceremony ID cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// Ceremony attestation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyAttestation {
    /// Ceremony ID
    pub ceremony_id: String,
    /// Configuration used
    pub config: CeremonyConfig,
    /// Participants who participated
    pub participants: Vec<ParticipantInfo>,
    /// Start timestamp (Unix seconds)
    pub started_at: u64,
    /// Completion timestamp (Unix seconds)
    pub completed_at: Option<u64>,
    /// Final state
    pub final_state: CeremonyState,
    /// Audit log
    pub audit_log: Vec<String>,
}

impl CeremonyAttestation {
    /// Create new attestation
    pub fn new(ceremony_id: String, config: CeremonyConfig) -> Self {
        Self {
            ceremony_id,
            config,
            participants: Vec::new(),
            started_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            completed_at: None,
            final_state: CeremonyState::Setup,
            audit_log: Vec::new(),
        }
    }

    /// Add audit log entry
    pub fn log(&mut self, entry: impl Into<String>) {
        self.audit_log.push(entry.into());
    }

    /// Mark as completed
    pub fn complete(&mut self, state: CeremonyState) {
        self.completed_at = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        self.final_state = state;
    }
}

/// Key generation ceremony orchestrator.
pub struct KeygenCeremony {
    config: CeremonyConfig,
    state: CeremonyState,
    participants: HashMap<String, ParticipantInfo>,
    dkg_params: Option<DkgParams>,
    current_round: usize,
    attestation: CeremonyAttestation,
}

impl KeygenCeremony {
    /// Create a new ceremony
    pub fn new(config: CeremonyConfig) -> CeremonyResult<Self> {
        config.validate()?;

        let attestation = CeremonyAttestation::new(config.ceremony_id.clone(), config.clone());

        Ok(Self {
            config,
            state: CeremonyState::Setup,
            participants: HashMap::new(),
            dkg_params: None,
            current_round: 0,
            attestation,
        })
    }

    /// Get current state
    pub fn state(&self) -> CeremonyState {
        self.state
    }

    /// Get ceremony ID
    pub fn ceremony_id(&self) -> &str {
        &self.config.ceremony_id
    }

    /// Add a participant to the ceremony
    pub fn add_participant(&mut self, id: String) -> CeremonyResult<String> {
        // Check if ceremony is in correct state
        if self.state != CeremonyState::Setup && self.state != CeremonyState::WaitingForParticipants
        {
            return Err(CeremonyError::InvalidState {
                expected: "Setup or WaitingForParticipants".to_string(),
                actual: self.state.to_string(),
            });
        }

        // Check if participant already exists
        if self.participants.contains_key(&id) {
            return Err(CeremonyError::ParticipantAlreadyExists(id));
        }

        // Check if we've reached the limit
        if self.participants.len() >= self.config.total_participants {
            return Err(CeremonyError::InvalidParticipantCount {
                expected: self.config.total_participants,
                actual: self.participants.len() + 1,
            });
        }

        let index = self.participants.len();
        let participant = ParticipantInfo::new(id.clone(), index);

        self.participants.insert(id.clone(), participant.clone());
        self.attestation.participants.push(participant);
        self.attestation
            .log(format!("Participant {} joined (index {})", id, index));

        // Transition to waiting state if this is the first participant
        if self.state == CeremonyState::Setup {
            self.state = CeremonyState::WaitingForParticipants;
        }

        Ok(id)
    }

    /// Mark a participant as ready
    pub fn mark_ready(&mut self, participant_id: &str) -> CeremonyResult<()> {
        let participant = self
            .participants
            .get_mut(participant_id)
            .ok_or_else(|| CeremonyError::ParticipantNotFound(participant_id.to_string()))?;

        participant.ready = true;
        self.attestation
            .log(format!("Participant {} marked ready", participant_id));

        Ok(())
    }

    /// Check if all participants have joined and are ready
    pub fn all_ready(&self) -> bool {
        if self.participants.len() != self.config.total_participants {
            return false;
        }

        if self.config.require_ready_check {
            self.participants.values().all(|p| p.ready)
        } else {
            true
        }
    }

    /// Start the ceremony
    pub fn start(&mut self) -> CeremonyResult<()> {
        // Check state
        if self.state != CeremonyState::WaitingForParticipants {
            return Err(CeremonyError::InvalidState {
                expected: "WaitingForParticipants".to_string(),
                actual: self.state.to_string(),
            });
        }

        // Check if all participants are ready
        if !self.all_ready() {
            return Err(CeremonyError::InvalidState {
                expected: "All participants ready".to_string(),
                actual: format!(
                    "{}/{} participants ready",
                    self.participants.values().filter(|p| p.ready).count(),
                    self.config.total_participants
                ),
            });
        }

        // Initialize DKG parameters
        let params = DkgParams::new(self.config.total_participants, self.config.threshold);

        self.dkg_params = Some(params);
        self.state = CeremonyState::InProgress;
        self.current_round = 1;
        self.attestation.log("Ceremony started".to_string());

        Ok(())
    }

    /// Abort the ceremony
    pub fn abort(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.state = CeremonyState::Aborted;
        self.attestation
            .log(format!("Ceremony aborted: {}", reason));
        self.attestation.complete(CeremonyState::Aborted);
    }

    /// Mark ceremony as completed
    pub fn complete(&mut self) -> CeremonyResult<()> {
        if self.state != CeremonyState::InProgress {
            return Err(CeremonyError::InvalidState {
                expected: "InProgress".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = CeremonyState::Completed;
        self.attestation
            .log("Ceremony completed successfully".to_string());
        self.attestation.complete(CeremonyState::Completed);

        Ok(())
    }

    /// Get attestation record
    pub fn attestation(&self) -> &CeremonyAttestation {
        &self.attestation
    }

    /// Get participant info
    pub fn get_participant(&self, id: &str) -> Option<&ParticipantInfo> {
        self.participants.get(id)
    }

    /// List all participants
    pub fn list_participants(&self) -> Vec<&ParticipantInfo> {
        self.participants.values().collect()
    }

    /// Get current round number
    pub fn current_round(&self) -> usize {
        self.current_round
    }

    /// Get DKG parameters
    pub fn dkg_params(&self) -> Option<&DkgParams> {
        self.dkg_params.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ceremony_config_validation() {
        // Valid config
        let config = CeremonyConfig::new(3, 2, "test".to_string());
        assert!(config.validate().is_ok());

        // Invalid: too few participants
        let config = CeremonyConfig::new(1, 1, "test".to_string());
        assert!(config.validate().is_err());

        // Invalid: threshold too high
        let config = CeremonyConfig::new(3, 4, "test".to_string());
        assert!(config.validate().is_err());

        // Invalid: threshold zero
        let config = CeremonyConfig::new(3, 0, "test".to_string());
        assert!(config.validate().is_err());

        // Invalid: empty ceremony ID
        let config = CeremonyConfig::new(3, 2, "".to_string());
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ceremony_lifecycle() {
        let config = CeremonyConfig::new(3, 2, "test-ceremony".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        assert_eq!(ceremony.state(), CeremonyState::Setup);

        // Add participants
        let p1 = ceremony.add_participant("alice".to_string()).unwrap();
        assert_eq!(ceremony.state(), CeremonyState::WaitingForParticipants);

        let p2 = ceremony.add_participant("bob".to_string()).unwrap();
        let p3 = ceremony.add_participant("charlie".to_string()).unwrap();

        // Cannot add more participants
        let result = ceremony.add_participant("dave".to_string());
        assert!(result.is_err());

        // Mark all as ready
        ceremony.mark_ready(&p1).unwrap();
        ceremony.mark_ready(&p2).unwrap();
        ceremony.mark_ready(&p3).unwrap();

        assert!(ceremony.all_ready());

        // Start ceremony
        ceremony.start().unwrap();
        assert_eq!(ceremony.state(), CeremonyState::InProgress);
        assert_eq!(ceremony.current_round(), 1);

        // Complete ceremony
        ceremony.complete().unwrap();
        assert_eq!(ceremony.state(), CeremonyState::Completed);
    }

    #[test]
    fn test_ceremony_abort() {
        let config = CeremonyConfig::new(2, 2, "abort-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        ceremony.add_participant("alice".to_string()).unwrap();
        ceremony.abort("Testing abort");

        assert_eq!(ceremony.state(), CeremonyState::Aborted);

        let attestation = ceremony.attestation();
        assert_eq!(attestation.final_state, CeremonyState::Aborted);
        assert!(attestation.completed_at.is_some());
    }

    #[test]
    fn test_participant_management() {
        let config = CeremonyConfig::new(3, 2, "participants-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        // Add participants
        ceremony.add_participant("alice".to_string()).unwrap();
        ceremony.add_participant("bob".to_string()).unwrap();

        // Get participant
        let alice = ceremony.get_participant("alice").unwrap();
        assert_eq!(alice.id, "alice");
        assert_eq!(alice.index, 0);
        assert!(!alice.ready);

        // List participants
        let participants = ceremony.list_participants();
        assert_eq!(participants.len(), 2);

        // Participant not found
        assert!(ceremony.get_participant("charlie").is_none());
    }

    #[test]
    fn test_ready_check() {
        let config = CeremonyConfig::new(2, 2, "ready-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        ceremony.add_participant("alice".to_string()).unwrap();
        ceremony.add_participant("bob".to_string()).unwrap();

        assert!(!ceremony.all_ready());

        ceremony.mark_ready("alice").unwrap();
        assert!(!ceremony.all_ready());

        ceremony.mark_ready("bob").unwrap();
        assert!(ceremony.all_ready());
    }

    #[test]
    fn test_ready_check_disabled() {
        let config = CeremonyConfig::new(2, 2, "no-ready-test".to_string()).without_ready_check();
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        ceremony.add_participant("alice".to_string()).unwrap();
        ceremony.add_participant("bob".to_string()).unwrap();

        // Should be ready even though no one marked ready
        assert!(ceremony.all_ready());
    }

    #[test]
    fn test_attestation() {
        let config = CeremonyConfig::new(2, 2, "attestation-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        ceremony.add_participant("alice".to_string()).unwrap();
        ceremony.add_participant("bob".to_string()).unwrap();
        ceremony.mark_ready("alice").unwrap();
        ceremony.mark_ready("bob").unwrap();
        ceremony.start().unwrap();
        ceremony.complete().unwrap();

        let attestation = ceremony.attestation();
        assert_eq!(attestation.ceremony_id, "attestation-test");
        assert_eq!(attestation.participants.len(), 2);
        assert_eq!(attestation.final_state, CeremonyState::Completed);
        assert!(attestation.completed_at.is_some());
        assert!(!attestation.audit_log.is_empty());
    }

    #[test]
    fn test_dkg_params_initialization() {
        let config = CeremonyConfig::new(3, 2, "dkg-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        // DKG params should not be set until ceremony starts
        assert!(ceremony.dkg_params().is_none());

        ceremony.add_participant("alice".to_string()).unwrap();
        ceremony.add_participant("bob".to_string()).unwrap();
        ceremony.add_participant("charlie".to_string()).unwrap();
        ceremony.mark_ready("alice").unwrap();
        ceremony.mark_ready("bob").unwrap();
        ceremony.mark_ready("charlie").unwrap();

        ceremony.start().unwrap();

        // DKG params should now be set
        let params = ceremony.dkg_params().unwrap();
        assert_eq!(params.threshold, 2);
        assert_eq!(params.total_parties, 3);
    }

    #[test]
    fn test_ceremony_state_transitions() {
        let config = CeremonyConfig::new(2, 2, "state-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        // Setup -> WaitingForParticipants (when first participant joins)
        assert_eq!(ceremony.state(), CeremonyState::Setup);
        ceremony.add_participant("alice".to_string()).unwrap();
        assert_eq!(ceremony.state(), CeremonyState::WaitingForParticipants);

        // Cannot start before all ready
        let result = ceremony.start();
        assert!(result.is_err());

        ceremony.add_participant("bob".to_string()).unwrap();
        ceremony.mark_ready("alice").unwrap();
        ceremony.mark_ready("bob").unwrap();

        // WaitingForParticipants -> InProgress
        ceremony.start().unwrap();
        assert_eq!(ceremony.state(), CeremonyState::InProgress);

        // InProgress -> Completed
        ceremony.complete().unwrap();
        assert_eq!(ceremony.state(), CeremonyState::Completed);
    }

    #[test]
    fn test_config_builder() {
        let config = CeremonyConfig::new(5, 3, "builder-test".to_string())
            .with_timeout(600)
            .without_ready_check()
            .with_metadata("purpose", "testing")
            .with_metadata("version", "1.0");

        assert_eq!(config.timeout_seconds, 600);
        assert!(!config.require_ready_check);
        assert_eq!(config.metadata.get("purpose"), Some(&"testing".to_string()));
        assert_eq!(config.metadata.get("version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_participant_info_metadata() {
        let participant = ParticipantInfo::new("alice".to_string(), 0)
            .with_metadata("role", "coordinator")
            .with_metadata("location", "US");

        assert_eq!(participant.id, "alice");
        assert_eq!(participant.index, 0);
        assert_eq!(
            participant.metadata.get("role"),
            Some(&"coordinator".to_string())
        );
        assert_eq!(
            participant.metadata.get("location"),
            Some(&"US".to_string())
        );
    }

    #[test]
    fn test_duplicate_participant() {
        let config = CeremonyConfig::new(3, 2, "dup-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        ceremony.add_participant("alice".to_string()).unwrap();

        // Try to add same participant again
        let result = ceremony.add_participant("alice".to_string());
        assert!(matches!(
            result,
            Err(CeremonyError::ParticipantAlreadyExists(_))
        ));
    }

    #[test]
    fn test_mark_ready_nonexistent_participant() {
        let config = CeremonyConfig::new(2, 2, "nonexistent-test".to_string());
        let mut ceremony = KeygenCeremony::new(config).unwrap();

        let result = ceremony.mark_ready("alice");
        assert!(matches!(result, Err(CeremonyError::ParticipantNotFound(_))));
    }
}
