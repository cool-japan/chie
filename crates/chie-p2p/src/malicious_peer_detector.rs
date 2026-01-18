//! Malicious peer detection and automatic banning.
//!
//! This module provides sophisticated detection of malicious peer behavior patterns
//! and automatic banning capabilities to protect the network.

use chie_shared::{ChieError, ChieResult};
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum evidence records to keep per peer
const MAX_EVIDENCE_RECORDS: usize = 100;

/// Malicious behavior type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaliciousBehavior {
    /// Excessive rate limit violations
    ExcessiveRateLimitViolations,
    /// Invalid or corrupted data
    CorruptedData,
    /// Replay attacks
    ReplayAttack,
    /// Eclipse attack attempts
    EclipseAttempt,
    /// Sybil attack patterns
    SybilPattern,
    /// Resource exhaustion attempts
    ResourceExhaustion,
    /// Malformed protocol messages
    MalformedMessages,
    /// Suspicious connection patterns
    SuspiciousConnections,
}

impl std::fmt::Display for MaliciousBehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExcessiveRateLimitViolations => write!(f, "Excessive rate limit violations"),
            Self::CorruptedData => write!(f, "Corrupted data"),
            Self::ReplayAttack => write!(f, "Replay attack"),
            Self::EclipseAttempt => write!(f, "Eclipse attack attempt"),
            Self::SybilPattern => write!(f, "Sybil pattern"),
            Self::ResourceExhaustion => write!(f, "Resource exhaustion"),
            Self::MalformedMessages => write!(f, "Malformed messages"),
            Self::SuspiciousConnections => write!(f, "Suspicious connections"),
        }
    }
}

/// Evidence of malicious behavior
#[derive(Debug, Clone)]
pub struct Evidence {
    /// Behavior type
    pub behavior: MaliciousBehavior,
    /// Timestamp
    pub timestamp: Instant,
    /// Severity (0.0 - 1.0, where 1.0 is most severe)
    pub severity: f64,
    /// Description
    pub description: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Detection score for a peer
#[derive(Debug, Clone)]
pub struct DetectionScore {
    /// Overall malicious score (0.0 - 1.0)
    pub score: f64,
    /// Contributing factors
    pub factors: HashMap<MaliciousBehavior, f64>,
    /// Total evidence count
    pub evidence_count: usize,
    /// First evidence timestamp
    pub first_evidence: Option<Instant>,
    /// Last evidence timestamp
    pub last_evidence: Option<Instant>,
}

/// Ban status
#[derive(Debug, Clone)]
pub struct BanStatus {
    /// Whether peer is banned
    pub is_banned: bool,
    /// Ban reason
    pub reason: Option<String>,
    /// Banned since
    pub banned_since: Option<Instant>,
    /// Ban expires at (None = permanent)
    pub expires_at: Option<Instant>,
    /// Ban appeal count
    pub appeal_count: u32,
}

/// Detector configuration
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// Ban threshold score (0.0 - 1.0)
    pub ban_threshold: f64,
    /// Evidence decay period
    pub evidence_decay: Duration,
    /// Ban duration for first offense
    pub initial_ban_duration: Duration,
    /// Ban duration multiplier for repeat offenses
    pub repeat_ban_multiplier: f64,
    /// Maximum ban duration
    pub max_ban_duration: Duration,
    /// Allow appeals
    pub allow_appeals: bool,
    /// Maximum appeals per peer
    pub max_appeals: u32,
    /// Evidence collection window
    pub evidence_window: Duration,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            ban_threshold: 0.7,
            evidence_decay: Duration::from_secs(3600), // 1 hour
            initial_ban_duration: Duration::from_secs(3600), // 1 hour
            repeat_ban_multiplier: 2.0,
            max_ban_duration: Duration::from_secs(86400 * 7), // 1 week
            allow_appeals: true,
            max_appeals: 3,
            evidence_window: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Per-peer detection state
#[derive(Debug, Clone)]
struct PeerDetectionState {
    /// Evidence records (most recent first)
    evidence: VecDeque<Evidence>,
    /// Current ban status
    ban_status: BanStatus,
    /// Total bans received
    total_bans: u32,
    /// Behavior counters
    behavior_counts: HashMap<MaliciousBehavior, u32>,
}

impl PeerDetectionState {
    fn new() -> Self {
        Self {
            evidence: VecDeque::new(),
            ban_status: BanStatus {
                is_banned: false,
                reason: None,
                banned_since: None,
                expires_at: None,
                appeal_count: 0,
            },
            total_bans: 0,
            behavior_counts: HashMap::new(),
        }
    }
}

/// Malicious peer detector
pub struct MaliciousPeerDetector {
    /// Configuration
    config: DetectorConfig,
    /// Per-peer detection state
    peer_states: Arc<RwLock<HashMap<String, PeerDetectionState>>>,
    /// Permanently banned peers
    permanent_bans: Arc<RwLock<Vec<String>>>,
    /// Statistics
    stats: Arc<RwLock<DetectorStats>>,
}

/// Detector statistics
#[derive(Debug, Clone, Default)]
pub struct DetectorStats {
    /// Total evidence collected
    pub total_evidence: u64,
    /// Total bans issued
    pub total_bans: u64,
    /// Currently banned peers
    pub banned_peers: u64,
    /// Total appeals received
    pub total_appeals: u64,
    /// Appeals granted
    pub appeals_granted: u64,
    /// Evidence by type
    pub evidence_by_type: HashMap<MaliciousBehavior, u64>,
}

impl MaliciousPeerDetector {
    /// Create new detector
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            permanent_bans: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(DetectorStats::default())),
        }
    }

    /// Report malicious behavior
    pub fn report_behavior(
        &self,
        peer_id: &str,
        behavior: MaliciousBehavior,
        severity: f64,
        description: String,
        metadata: HashMap<String, String>,
    ) -> ChieResult<()> {
        // Check permanent ban
        if self.permanent_bans.read().contains(&peer_id.to_string()) {
            return Ok(());
        }

        let mut peer_states = self.peer_states.write();
        let mut stats = self.stats.write();

        let state = peer_states
            .entry(peer_id.to_string())
            .or_insert_with(PeerDetectionState::new);

        // Add evidence
        let evidence = Evidence {
            behavior,
            timestamp: Instant::now(),
            severity: severity.clamp(0.0, 1.0),
            description,
            metadata,
        };

        state.evidence.push_front(evidence);
        *state.behavior_counts.entry(behavior).or_insert(0) += 1;

        // Limit evidence records
        while state.evidence.len() > MAX_EVIDENCE_RECORDS {
            state.evidence.pop_back();
        }

        stats.total_evidence += 1;
        *stats.evidence_by_type.entry(behavior).or_insert(0) += 1;

        // Calculate score and check for ban
        let score = self.calculate_score(state);
        if score.score >= self.config.ban_threshold && !state.ban_status.is_banned {
            self.issue_ban(state, &mut stats, peer_id, score)?;
        }

        Ok(())
    }

    /// Calculate detection score
    fn calculate_score(&self, state: &PeerDetectionState) -> DetectionScore {
        let now = Instant::now();
        let mut factors = HashMap::new();
        let mut total_score = 0.0;
        let mut weight_sum = 0.0;

        let mut first_evidence = None;
        let mut last_evidence = None;
        let mut evidence_count = 0;

        for evidence in &state.evidence {
            // Apply time decay
            let age = now.duration_since(evidence.timestamp);
            if age > self.config.evidence_decay {
                continue;
            }

            let decay_factor = 1.0 - (age.as_secs_f64() / self.config.evidence_decay.as_secs_f64());
            let weighted_severity = evidence.severity * decay_factor;

            total_score += weighted_severity;
            weight_sum += decay_factor;

            *factors.entry(evidence.behavior).or_insert(0.0) += weighted_severity;

            evidence_count += 1;
            if first_evidence.is_none() {
                first_evidence = Some(evidence.timestamp);
            }
            last_evidence = Some(evidence.timestamp);
        }

        let normalized_score = if weight_sum > 0.0 {
            (total_score / weight_sum).min(1.0)
        } else {
            0.0
        };

        DetectionScore {
            score: normalized_score,
            factors,
            evidence_count,
            first_evidence,
            last_evidence,
        }
    }

    /// Issue ban to peer
    fn issue_ban(
        &self,
        state: &mut PeerDetectionState,
        stats: &mut DetectorStats,
        _peer_id: &str,
        score: DetectionScore,
    ) -> ChieResult<()> {
        // Calculate ban duration based on offense count
        let multiplier = self
            .config
            .repeat_ban_multiplier
            .powi(state.total_bans as i32);
        let duration =
            Duration::from_secs_f64(self.config.initial_ban_duration.as_secs_f64() * multiplier)
                .min(self.config.max_ban_duration);

        let reason = format!(
            "Malicious score: {:.2}, Evidence: {}",
            score.score, score.evidence_count
        );

        state.ban_status = BanStatus {
            is_banned: true,
            reason: Some(reason),
            banned_since: Some(Instant::now()),
            expires_at: Some(Instant::now() + duration),
            appeal_count: 0,
        };

        state.total_bans += 1;
        stats.total_bans += 1;
        stats.banned_peers += 1;

        Ok(())
    }

    /// Check if peer is banned
    pub fn is_banned(&self, peer_id: &str) -> bool {
        // Check permanent ban
        if self.permanent_bans.read().contains(&peer_id.to_string()) {
            return true;
        }

        let mut peer_states = self.peer_states.write();
        if let Some(state) = peer_states.get_mut(peer_id) {
            // Check if ban expired
            if let Some(expires_at) = state.ban_status.expires_at {
                if Instant::now() >= expires_at {
                    state.ban_status.is_banned = false;
                    state.ban_status.expires_at = None;
                    state.ban_status.reason = None;
                    let mut stats = self.stats.write();
                    if stats.banned_peers > 0 {
                        stats.banned_peers -= 1;
                    }
                    return false;
                }
            }

            return state.ban_status.is_banned;
        }

        false
    }

    /// Get ban status for peer
    pub fn get_ban_status(&self, peer_id: &str) -> Option<BanStatus> {
        self.peer_states
            .read()
            .get(peer_id)
            .map(|s| s.ban_status.clone())
    }

    /// Get detection score for peer
    pub fn get_score(&self, peer_id: &str) -> Option<DetectionScore> {
        let peer_states = self.peer_states.read();
        peer_states
            .get(peer_id)
            .map(|state| self.calculate_score(state))
    }

    /// File an appeal for a ban
    pub fn appeal_ban(&self, peer_id: &str, reason: String) -> ChieResult<bool> {
        if !self.config.allow_appeals {
            return Err(ChieError::permission_denied("Appeals not allowed"));
        }

        let mut peer_states = self.peer_states.write();
        let mut stats = self.stats.write();

        let state = peer_states
            .get_mut(peer_id)
            .ok_or_else(|| ChieError::not_found("Peer not found"))?;

        if !state.ban_status.is_banned {
            return Err(ChieError::validation("Peer is not banned"));
        }

        if state.ban_status.appeal_count >= self.config.max_appeals {
            return Err(ChieError::resource_exhausted("Maximum appeals reached"));
        }

        state.ban_status.appeal_count += 1;
        stats.total_appeals += 1;

        // Simple appeal logic: grant if score dropped below threshold
        let score = self.calculate_score(state);
        if score.score < self.config.ban_threshold * 0.5 {
            state.ban_status.is_banned = false;
            state.ban_status.expires_at = None;
            state.ban_status.reason = Some(format!("Appeal granted: {}", reason));
            stats.appeals_granted += 1;
            if stats.banned_peers > 0 {
                stats.banned_peers -= 1;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Permanently ban a peer
    pub fn permanent_ban(&self, peer_id: &str, reason: String) -> ChieResult<()> {
        let mut permanent_bans = self.permanent_bans.write();
        if !permanent_bans.contains(&peer_id.to_string()) {
            permanent_bans.push(peer_id.to_string());
        }

        let mut peer_states = self.peer_states.write();
        if let Some(state) = peer_states.get_mut(peer_id) {
            state.ban_status = BanStatus {
                is_banned: true,
                reason: Some(reason),
                banned_since: Some(Instant::now()),
                expires_at: None,
                appeal_count: 0,
            };

            let mut stats = self.stats.write();
            stats.total_bans += 1;
            stats.banned_peers += 1;
        }

        Ok(())
    }

    /// Unban a peer (manual unban)
    pub fn unban(&self, peer_id: &str) -> ChieResult<()> {
        // Remove from permanent bans
        let mut permanent_bans = self.permanent_bans.write();
        permanent_bans.retain(|p| p != peer_id);

        let mut peer_states = self.peer_states.write();
        if let Some(state) = peer_states.get_mut(peer_id) {
            if state.ban_status.is_banned {
                state.ban_status.is_banned = false;
                state.ban_status.expires_at = None;
                state.ban_status.reason = Some("Manual unban".to_string());

                let mut stats = self.stats.write();
                if stats.banned_peers > 0 {
                    stats.banned_peers -= 1;
                }
            }
        }

        Ok(())
    }

    /// Get evidence for peer
    pub fn get_evidence(&self, peer_id: &str) -> Vec<Evidence> {
        self.peer_states
            .read()
            .get(peer_id)
            .map(|s| s.evidence.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get recent evidence (within window)
    pub fn get_recent_evidence(&self, peer_id: &str) -> Vec<Evidence> {
        let now = Instant::now();
        self.peer_states
            .read()
            .get(peer_id)
            .map(|s| {
                s.evidence
                    .iter()
                    .filter(|e| now.duration_since(e.timestamp) <= self.config.evidence_window)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all banned peers
    pub fn get_banned_peers(&self) -> Vec<String> {
        let peer_states = self.peer_states.read();
        let now = Instant::now();

        let mut banned: Vec<String> = peer_states
            .iter()
            .filter(|(_, state)| {
                if !state.ban_status.is_banned {
                    return false;
                }

                // Check if ban expired
                if let Some(expires_at) = state.ban_status.expires_at {
                    now < expires_at
                } else {
                    true // Permanent ban
                }
            })
            .map(|(id, _)| id.clone())
            .collect();

        // Add permanent bans
        banned.extend(self.permanent_bans.read().iter().cloned());
        banned.sort();
        banned.dedup();

        banned
    }

    /// Clear evidence for peer
    pub fn clear_evidence(&self, peer_id: &str) -> ChieResult<()> {
        let mut peer_states = self.peer_states.write();
        if let Some(state) = peer_states.get_mut(peer_id) {
            state.evidence.clear();
            state.behavior_counts.clear();
        }
        Ok(())
    }

    /// Get statistics
    pub fn stats(&self) -> DetectorStats {
        self.stats.read().clone()
    }

    /// Cleanup old evidence and expired bans
    pub fn cleanup(&self) -> usize {
        let now = Instant::now();
        let mut peer_states = self.peer_states.write();
        let mut stats = self.stats.write();
        let mut cleaned = 0;

        // Cleanup expired evidence and bans
        peer_states.retain(|_, state| {
            // Remove expired evidence
            let initial_count = state.evidence.len();
            state
                .evidence
                .retain(|e| now.duration_since(e.timestamp) <= self.config.evidence_decay);
            cleaned += initial_count - state.evidence.len();

            // Check ban expiry
            if let Some(expires_at) = state.ban_status.expires_at {
                if now >= expires_at {
                    state.ban_status.is_banned = false;
                    state.ban_status.expires_at = None;
                    if stats.banned_peers > 0 {
                        stats.banned_peers -= 1;
                    }
                }
            }

            // Keep state if has evidence or is banned
            !state.evidence.is_empty() || state.ban_status.is_banned
        });

        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_behavior() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        let result = detector.report_behavior(
            "peer1",
            MaliciousBehavior::CorruptedData,
            0.8,
            "Test".to_string(),
            HashMap::new(),
        );

        assert!(result.is_ok());
        assert_eq!(detector.get_evidence("peer1").len(), 1);
    }

    #[test]
    fn test_automatic_ban() {
        let config = DetectorConfig {
            ban_threshold: 0.5,
            ..Default::default()
        };
        let detector = MaliciousPeerDetector::new(config);

        // Report high severity behavior
        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::ReplayAttack,
                1.0,
                "Severe".to_string(),
                HashMap::new(),
            )
            .unwrap();

        // Should be banned due to high severity
        assert!(detector.is_banned("peer1"));
    }

    #[test]
    fn test_ban_status() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::SybilPattern,
                1.0,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        if detector.is_banned("peer1") {
            let status = detector.get_ban_status("peer1").unwrap();
            assert!(status.is_banned);
            assert!(status.reason.is_some());
        }
    }

    #[test]
    fn test_permanent_ban() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector
            .permanent_ban("peer1", "Test permanent ban".to_string())
            .unwrap();

        assert!(detector.is_banned("peer1"));
    }

    #[test]
    fn test_unban() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector.permanent_ban("peer1", "Test".to_string()).unwrap();
        assert!(detector.is_banned("peer1"));

        detector.unban("peer1").unwrap();
        assert!(!detector.is_banned("peer1"));
    }

    #[test]
    fn test_detection_score() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::CorruptedData,
                0.5,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        let score = detector.get_score("peer1").unwrap();
        assert!(score.score > 0.0);
        assert_eq!(score.evidence_count, 1);
    }

    #[test]
    fn test_appeal_ban() {
        let config = DetectorConfig {
            ban_threshold: 0.3,
            allow_appeals: true,
            ..Default::default()
        };
        let detector = MaliciousPeerDetector::new(config);

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::SuspiciousConnections,
                0.4,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        if detector.is_banned("peer1") {
            // Clear evidence to lower score
            detector.clear_evidence("peer1").unwrap();

            let result = detector.appeal_ban("peer1", "False positive".to_string());
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_get_banned_peers() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector.permanent_ban("peer1", "Test".to_string()).unwrap();
        detector.permanent_ban("peer2", "Test".to_string()).unwrap();

        let banned = detector.get_banned_peers();
        assert_eq!(banned.len(), 2);
    }

    #[test]
    fn test_stats_tracking() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::MalformedMessages,
                0.5,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        let stats = detector.stats();
        assert_eq!(stats.total_evidence, 1);
    }

    #[test]
    fn test_evidence_limit() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        // Add more than MAX_EVIDENCE_RECORDS
        for i in 0..150 {
            detector
                .report_behavior(
                    "peer1",
                    MaliciousBehavior::CorruptedData,
                    0.1,
                    format!("Evidence {}", i),
                    HashMap::new(),
                )
                .unwrap();
        }

        let evidence = detector.get_evidence("peer1");
        assert!(evidence.len() <= MAX_EVIDENCE_RECORDS);
    }

    #[test]
    fn test_cleanup() {
        let config = DetectorConfig {
            evidence_decay: Duration::from_millis(10),
            ..Default::default()
        };
        let detector = MaliciousPeerDetector::new(config);

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::ResourceExhaustion,
                0.5,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let cleaned = detector.cleanup();
        assert!(cleaned > 0);
    }

    #[test]
    fn test_get_recent_evidence() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::EclipseAttempt,
                0.5,
                "Recent".to_string(),
                HashMap::new(),
            )
            .unwrap();

        let recent = detector.get_recent_evidence("peer1");
        assert_eq!(recent.len(), 1);
    }

    #[test]
    fn test_max_appeals() {
        let config = DetectorConfig {
            ban_threshold: 0.3,
            allow_appeals: true,
            max_appeals: 2,
            ..Default::default()
        };
        let detector = MaliciousPeerDetector::new(config);

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::CorruptedData,
                1.0,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        // Try to appeal more than max
        for _ in 0..3 {
            let _ = detector.appeal_ban("peer1", "Test".to_string());
        }

        let status = detector.get_ban_status("peer1").unwrap();
        assert!(status.appeal_count <= 2);
    }

    #[test]
    fn test_behavior_display() {
        assert_eq!(
            MaliciousBehavior::CorruptedData.to_string(),
            "Corrupted data"
        );
    }

    #[test]
    fn test_clear_evidence() {
        let detector = MaliciousPeerDetector::new(DetectorConfig::default());

        detector
            .report_behavior(
                "peer1",
                MaliciousBehavior::SybilPattern,
                0.5,
                "Test".to_string(),
                HashMap::new(),
            )
            .unwrap();

        assert!(!detector.get_evidence("peer1").is_empty());

        detector.clear_evidence("peer1").unwrap();
        assert!(detector.get_evidence("peer1").is_empty());
    }
}
