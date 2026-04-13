//! Gamification engine for CHIE Protocol.
//!
//! This module implements the in-memory gamification system that manages:
//! - Badge eligibility checks based on user statistics
//! - Quest assignment, progress tracking, and completion
//! - Leaderboard ranking by monthly points
//! - User gamification state aggregation
//!
//! # Architecture
//!
//! The engine uses a [`DashMap`] for lock-free concurrent access to user
//! states, and a [`tokio::sync::RwLock`]-protected `Vec` for the leaderboard
//! (sorted on writes, cheap reads).
//!
//! All state is in-memory for v0.2.0. Persistence is delegated to the
//! coordinator's database layer in a future phase.

pub mod routes;
pub mod scheduler;

pub use routes::router;
pub use scheduler::spawn_scheduler;

use chrono::{Datelike, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use chie_shared::gamification::{
    Badge, LeaderboardEntry, Quest, QuestStatus, QuestType, UserGamificationState,
};

/// Errors that can occur within the gamification engine.
#[derive(Debug, thiserror::Error)]
pub enum GamificationError {
    /// The specified user was not found in the engine's state.
    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    /// The specified quest was not found for the user.
    #[error("Quest not found: quest_id={quest_id} for user={user_id}")]
    QuestNotFound {
        /// The user whose quest was not found.
        user_id: Uuid,
        /// The quest ID that was not found.
        quest_id: Uuid,
    },

    /// A points overflow was detected (would exceed u64::MAX).
    #[error("Points overflow for user {0}")]
    PointsOverflow(Uuid),

    /// An internal lock or consistency error occurred.
    #[error("Internal gamification error: {0}")]
    Internal(String),
}

/// Badge eligibility thresholds for determining when to award badges.
#[derive(Debug, Clone)]
struct BadgeThresholds {
    /// Total bytes that must be transferred for BandwidthHero.
    bandwidth_hero_bytes: u64,
    /// Minimum uptime percentage for SuperNode.
    super_node_uptime_pct: f64,
    /// Number of consecutive streak days for Reliable.
    reliable_streak_days: u32,
    /// Node network index limit for EarlyAdopter.
    early_adopter_limit: u32,
}

impl Default for BadgeThresholds {
    fn default() -> Self {
        Self {
            bandwidth_hero_bytes: Badge::BANDWIDTH_HERO_THRESHOLD_BYTES,
            super_node_uptime_pct: Badge::SUPER_NODE_UPTIME_THRESHOLD,
            reliable_streak_days: Badge::RELIABLE_STREAK_DAYS,
            early_adopter_limit: Badge::EARLY_ADOPTER_LIMIT,
        }
    }
}

/// In-memory statistics tracked per user for badge eligibility checks.
#[derive(Debug, Clone, Default)]
pub struct UserNetworkStats {
    /// Total bytes transferred (for BandwidthHero).
    pub total_bytes_transferred: u64,
    /// Current uptime percentage (for SuperNode).
    pub uptime_percentage: f64,
    /// Network join order index (for EarlyAdopter).
    pub join_index: Option<u32>,
    /// Monthly bandwidth provided in gigabytes (for leaderboard).
    pub monthly_bandwidth_gb: f64,
}

/// The central gamification engine.
///
/// Thread-safe and cheaply cloneable via interior `Arc` references.
/// All methods are async to allow future integration with async DB calls.
#[derive(Clone)]
pub struct GamificationEngine {
    /// Per-user gamification state, protected by DashMap for lock-free reads.
    states: Arc<DashMap<Uuid, UserGamificationState>>,
    /// Per-user network stats for badge eligibility, protected by DashMap.
    network_stats: Arc<DashMap<Uuid, UserNetworkStats>>,
    /// Sorted leaderboard (ascending by rank = descending by points).
    leaderboard: Arc<RwLock<Vec<LeaderboardEntry>>>,
    /// Badge eligibility thresholds.
    thresholds: BadgeThresholds,
    /// Total number of registered nodes (for EarlyAdopter badge).
    node_count: Arc<std::sync::atomic::AtomicU32>,
}

impl GamificationEngine {
    /// Creates a new gamification engine with default thresholds.
    pub fn new() -> Self {
        Self {
            states: Arc::new(DashMap::new()),
            network_stats: Arc::new(DashMap::new()),
            leaderboard: Arc::new(RwLock::new(Vec::new())),
            thresholds: BadgeThresholds::default(),
            node_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Creates a new engine with custom badge thresholds (for testing).
    pub fn with_thresholds(
        bandwidth_hero_bytes: u64,
        super_node_uptime_pct: f64,
        reliable_streak_days: u32,
        early_adopter_limit: u32,
    ) -> Self {
        Self {
            states: Arc::new(DashMap::new()),
            network_stats: Arc::new(DashMap::new()),
            leaderboard: Arc::new(RwLock::new(Vec::new())),
            thresholds: BadgeThresholds {
                bandwidth_hero_bytes,
                super_node_uptime_pct,
                reliable_streak_days,
                early_adopter_limit,
            },
            node_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Ensures a user has an initialized state, creating one if absent.
    ///
    /// Also increments the global node count on first registration,
    /// which is used to determine EarlyAdopter eligibility.
    pub async fn ensure_user(&self, user_id: Uuid) {
        if !self.states.contains_key(&user_id) {
            let index = self
                .node_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;
            self.states
                .insert(user_id, UserGamificationState::new(user_id));
            self.network_stats.insert(
                user_id,
                UserNetworkStats {
                    join_index: Some(index),
                    ..Default::default()
                },
            );
        }
    }

    /// Checks whether the user has earned any new badges based on current stats
    /// and awards them, returning the list of newly awarded badges.
    ///
    /// # Errors
    ///
    /// Returns [`GamificationError::UserNotFound`] if the user does not exist.
    pub async fn check_badge_eligibility(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Badge>, GamificationError> {
        let stats = self
            .network_stats
            .get(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?
            .clone();

        let mut state = self
            .states
            .get_mut(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?;

        let mut newly_awarded = Vec::new();

        // BandwidthHero: transferred > 1 TB total
        if stats.total_bytes_transferred >= self.thresholds.bandwidth_hero_bytes
            && state.award_badge(Badge::BandwidthHero)
        {
            state.total_points = state
                .total_points
                .saturating_add(Badge::BandwidthHero.point_value());
            newly_awarded.push(Badge::BandwidthHero);
        }

        // SuperNode: uptime >= threshold
        if stats.uptime_percentage >= self.thresholds.super_node_uptime_pct
            && state.award_badge(Badge::SuperNode)
        {
            state.total_points = state
                .total_points
                .saturating_add(Badge::SuperNode.point_value());
            newly_awarded.push(Badge::SuperNode);
        }

        // EarlyAdopter: join order within the first N nodes
        if let Some(join_index) = stats.join_index {
            if join_index <= self.thresholds.early_adopter_limit
                && state.award_badge(Badge::EarlyAdopter)
            {
                state.total_points = state
                    .total_points
                    .saturating_add(Badge::EarlyAdopter.point_value());
                newly_awarded.push(Badge::EarlyAdopter);
            }
        }

        // Reliable: consecutive streak days >= threshold
        if state.streak_days >= self.thresholds.reliable_streak_days
            && state.award_badge(Badge::Reliable)
        {
            state.total_points = state
                .total_points
                .saturating_add(Badge::Reliable.point_value());
            newly_awarded.push(Badge::Reliable);
        }

        Ok(newly_awarded)
    }

    /// Returns the set of active quests for the user, creating defaults
    /// if none exist or if existing quests have expired.
    ///
    /// On first call for a user, this creates the standard daily/weekly/monthly
    /// quest set. Expired quests are replaced with fresh ones.
    ///
    /// # Errors
    ///
    /// Returns [`GamificationError::UserNotFound`] if the user does not exist.
    pub async fn get_active_quests(&self, user_id: Uuid) -> Result<Vec<Quest>, GamificationError> {
        self.ensure_user(user_id).await;

        let mut state = self
            .states
            .get_mut(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?;

        let now = Utc::now();

        // Mark expired quests
        for quest in &mut state.active_quests {
            if matches!(quest.status, QuestStatus::Active) && now > quest.expires_at {
                quest.status = QuestStatus::Expired;
            }
        }

        // Remove expired and completed quests, keep only still-active ones
        let active_count = state
            .active_quests
            .iter()
            .filter(|q| matches!(q.status, QuestStatus::Active))
            .count();

        // If no active quests remain, assign the default quest set
        if active_count == 0 {
            let new_quests = vec![
                Quest::daily_uptime(),
                Quest::weekly_host_creators(),
                Quest::monthly_transfer(),
                Quest::weekly_bandwidth(),
                Quest::daily_proof_submission(),
            ];
            // Retain completed/expired for history, then append fresh actives
            state
                .active_quests
                .retain(|q| matches!(q.status, QuestStatus::Completed | QuestStatus::Expired));
            state.active_quests.extend(new_quests);
        }

        // Return only active ones to the caller
        let actives = state
            .active_quests
            .iter()
            .filter(|q| matches!(q.status, QuestStatus::Active))
            .cloned()
            .collect();

        Ok(actives)
    }

    /// Increments progress on the matching active quest for the user.
    ///
    /// If the quest reaches its target value, it is marked as completed
    /// and the reward points are immediately credited to the user.
    ///
    /// If the user has no active quest of the given type, this is a no-op
    /// (returns `Ok(())` so callers can safely fire-and-forget).
    ///
    /// # Errors
    ///
    /// Returns [`GamificationError::UserNotFound`] if the user does not exist.
    pub async fn update_quest_progress(
        &self,
        user_id: Uuid,
        quest_type: QuestType,
        increment: u64,
    ) -> Result<(), GamificationError> {
        self.ensure_user(user_id).await;

        let mut state = self
            .states
            .get_mut(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?;

        let now = Utc::now();
        let mut reward_to_add = 0u64;

        for quest in &mut state.active_quests {
            if quest.quest_type == quest_type && matches!(quest.status, QuestStatus::Active) {
                // Check expiry first
                if now > quest.expires_at {
                    quest.status = QuestStatus::Expired;
                    continue;
                }

                quest.current_value = quest.current_value.saturating_add(increment);

                if quest.current_value >= quest.target_value {
                    quest.status = QuestStatus::Completed;
                    quest.completed_at = Some(now);
                    reward_to_add = reward_to_add.saturating_add(quest.reward_points);
                    tracing::info!(
                        user_id = %user_id,
                        quest_type = ?quest_type,
                        reward = quest.reward_points,
                        "Quest completed"
                    );
                }
                // There may be multiple quests of the same type (edge case), update all
            }
        }

        if reward_to_add > 0 {
            state.total_points = state.total_points.saturating_add(reward_to_add);
            state.monthly_points = state.monthly_points.saturating_add(reward_to_add);
            state.completed_quests_count = state.completed_quests_count.saturating_add(1);
        }

        Ok(())
    }

    /// Awards points to a user for a specific action.
    ///
    /// Points are added to both `total_points` and `monthly_points`.
    /// After awarding, the leaderboard is refreshed asynchronously.
    ///
    /// # Errors
    ///
    /// Returns [`GamificationError::UserNotFound`] if the user does not exist.
    pub async fn award_points(
        &self,
        user_id: Uuid,
        points: u64,
        reason: &str,
    ) -> Result<(), GamificationError> {
        self.ensure_user(user_id).await;

        {
            let mut state = self
                .states
                .get_mut(&user_id)
                .ok_or(GamificationError::UserNotFound(user_id))?;

            state.total_points = state
                .total_points
                .checked_add(points)
                .ok_or(GamificationError::PointsOverflow(user_id))?;
            state.monthly_points = state
                .monthly_points
                .checked_add(points)
                .ok_or(GamificationError::PointsOverflow(user_id))?;
        }

        tracing::debug!(
            user_id = %user_id,
            points = points,
            reason = reason,
            "Points awarded"
        );

        // Rebuild leaderboard after each points award
        self.rebuild_leaderboard().await?;

        Ok(())
    }

    /// Returns the top `limit` users ordered by monthly points (descending).
    ///
    /// The leaderboard is cached in memory and rebuilt after each
    /// `award_points` call. This method simply reads the cached copy.
    ///
    /// # Errors
    ///
    /// Returns [`GamificationError::Internal`] if the RwLock is poisoned.
    pub async fn get_leaderboard(
        &self,
        limit: u32,
    ) -> Result<Vec<LeaderboardEntry>, GamificationError> {
        let board = self.leaderboard.read().await;
        let limit = limit as usize;
        Ok(board.iter().take(limit).cloned().collect())
    }

    /// Returns the full gamification state for the specified user.
    ///
    /// If the user has not been seen before, an empty state is created
    /// and returned with the default quest set assigned.
    ///
    /// # Errors
    ///
    /// Returns [`GamificationError::Internal`] on unexpected failures.
    pub async fn get_user_state(
        &self,
        user_id: Uuid,
    ) -> Result<UserGamificationState, GamificationError> {
        self.ensure_user(user_id).await;
        let state = self
            .states
            .get(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?;
        Ok(state.clone())
    }

    /// Updates a user's network statistics used for badge eligibility.
    ///
    /// Call this after receiving bandwidth proof submissions or uptime reports.
    /// Automatically triggers a badge eligibility check after the update.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user whose stats to update
    /// * `additional_bytes` - Additional bytes transferred (added to total)
    /// * `uptime_pct` - Current uptime percentage (replaces previous value)
    /// * `monthly_bandwidth_gb` - Current month's bandwidth in GB (replaces)
    pub async fn update_network_stats(
        &self,
        user_id: Uuid,
        additional_bytes: u64,
        uptime_pct: f64,
        monthly_bandwidth_gb: f64,
    ) -> Result<(), GamificationError> {
        self.ensure_user(user_id).await;

        {
            let mut stats = self
                .network_stats
                .get_mut(&user_id)
                .ok_or(GamificationError::UserNotFound(user_id))?;
            stats.total_bytes_transferred = stats
                .total_bytes_transferred
                .saturating_add(additional_bytes);
            stats.uptime_percentage = uptime_pct;
            stats.monthly_bandwidth_gb = monthly_bandwidth_gb;
        }

        // Check badge eligibility after stats update
        let _ = self.check_badge_eligibility(user_id).await;
        Ok(())
    }

    /// Increments the streak counter for a user by one day.
    ///
    /// Should be called once per day that the node shows any activity.
    /// Triggers badge eligibility check to potentially award the Reliable badge.
    pub async fn increment_streak(&self, user_id: Uuid) -> Result<(), GamificationError> {
        self.ensure_user(user_id).await;

        {
            let mut state = self
                .states
                .get_mut(&user_id)
                .ok_or(GamificationError::UserNotFound(user_id))?;
            state.streak_days = state.streak_days.saturating_add(1);
        }

        let _ = self.check_badge_eligibility(user_id).await;
        Ok(())
    }

    /// Resets the streak counter to zero (call when a day is missed).
    pub async fn reset_streak(&self, user_id: Uuid) -> Result<(), GamificationError> {
        self.ensure_user(user_id).await;
        let mut state = self
            .states
            .get_mut(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?;
        state.streak_days = 0;
        Ok(())
    }

    /// Manually awards the Founder badge to a user.
    ///
    /// The Founder badge must be awarded manually by the coordinator
    /// based on external criteria (launch participation, etc.).
    pub async fn award_founder_badge(&self, user_id: Uuid) -> Result<bool, GamificationError> {
        self.ensure_user(user_id).await;
        let mut state = self
            .states
            .get_mut(&user_id)
            .ok_or(GamificationError::UserNotFound(user_id))?;
        let awarded = state.award_badge(Badge::Founder);
        if awarded {
            state.total_points = state
                .total_points
                .saturating_add(Badge::Founder.point_value());
        }
        Ok(awarded)
    }

    /// Rebuilds the in-memory leaderboard from current user states.
    ///
    /// Users are ranked by `monthly_points` descending. The leaderboard
    /// uses the current calendar month's boundaries as the period.
    async fn rebuild_leaderboard(&self) -> Result<(), GamificationError> {
        let now = Utc::now();
        let period_start = now
            .with_day(1)
            .expect("day 1 always valid")
            .with_hour(0)
            .expect("hour 0 always valid")
            .with_minute(0)
            .expect("minute 0 always valid")
            .with_second(0)
            .expect("second 0 always valid")
            .with_nanosecond(0)
            .expect("nanosecond 0 always valid");
        let period_end = if now.month() == 12 {
            period_start
                .with_year(now.year() + 1)
                .expect("year increment always valid")
                .with_month(1)
                .expect("month 1 always valid")
        } else {
            period_start
                .with_month(now.month() + 1)
                .expect("month increment always valid")
        };

        // Collect all users with their current stats
        let mut entries: Vec<LeaderboardEntry> = self
            .states
            .iter()
            .map(|ref_multi| {
                let user_id = *ref_multi.key();
                let state = ref_multi.value();
                let stats = self
                    .network_stats
                    .get(&user_id)
                    .map(|s| s.clone())
                    .unwrap_or_default();

                LeaderboardEntry::new(
                    0, // rank set below
                    user_id,
                    format!("user_{}", &user_id.to_string()[..8]),
                    state.total_points,
                    stats.monthly_bandwidth_gb,
                    stats.uptime_percentage,
                    state.badges.clone(),
                    period_start,
                    period_end,
                )
            })
            .collect();

        // Sort descending by monthly points (read from states map for accuracy)
        entries.sort_by(|a, b| {
            let a_monthly = self
                .states
                .get(&a.user_id)
                .map(|s| s.monthly_points)
                .unwrap_or(0);
            let b_monthly = self
                .states
                .get(&b.user_id)
                .map(|s| s.monthly_points)
                .unwrap_or(0);
            b_monthly.cmp(&a_monthly)
        });

        // Assign ranks
        for (i, entry) in entries.iter_mut().enumerate() {
            entry.rank = (i + 1) as u32;
        }

        // Update rank in user states and check for TopSeeder badge
        for entry in &entries {
            if let Some(mut state) = self.states.get_mut(&entry.user_id) {
                state.current_rank = Some(entry.rank);
                // TopSeeder: top 10% of active users
                let total = entries.len() as u32;
                let top_threshold = (total / Badge::TOP_SEEDER_RANK_THRESHOLD).max(1);
                if entry.rank <= top_threshold && state.award_badge(Badge::TopSeeder) {
                    state.total_points = state
                        .total_points
                        .saturating_add(Badge::TopSeeder.point_value());
                }
            }
        }

        let mut board = self.leaderboard.write().await;
        *board = entries;
        Ok(())
    }

    /// Returns total number of tracked users.
    pub fn user_count(&self) -> usize {
        self.states.len()
    }

    /// Returns all registered user IDs (for scheduler maintenance).
    pub fn all_user_ids(&self) -> Vec<Uuid> {
        self.states.iter().map(|e| *e.key()).collect()
    }

    /// Resets monthly points for all users to zero and rebuilds the leaderboard.
    ///
    /// This should be called at the start of each calendar month.
    /// Returns the number of users whose monthly points were reset.
    pub async fn perform_monthly_reset(&self) -> usize {
        let mut count = 0usize;
        for mut entry in self.states.iter_mut() {
            entry.value_mut().monthly_points = 0;
            count += 1;
        }
        let _ = self.rebuild_leaderboard().await;
        count
    }
}

impl Default for GamificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

// Necessary for chrono operations in rebuild_leaderboard
use chrono::Timelike;

/// A monthly leaderboard snapshot (top entries + metadata).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MonthlySnapshot {
    /// Calendar year of the snapshot period.
    pub year: i32,
    /// Calendar month of the snapshot period (1–12).
    pub month: u32,
    /// RFC 3339 timestamp when the snapshot was captured.
    pub captured_at: String,
    /// Ordered leaderboard entries at the time of capture.
    pub entries: Vec<chie_shared::gamification::LeaderboardEntry>,
}

impl GamificationEngine {
    /// Capture and persist the current leaderboard as a monthly snapshot.
    ///
    /// The snapshot JSON is written to
    /// `<temp_dir>/chie-coordinator/snapshots/leaderboard_YYYY_MM.json`.
    ///
    /// # Errors
    ///
    /// Returns a descriptive `String` error if the directory cannot be created
    /// or the file cannot be written.
    pub async fn save_monthly_snapshot(&self, year: i32, month: u32) -> Result<(), String> {
        let leaderboard = self.leaderboard.read().await;
        let snapshot = MonthlySnapshot {
            year,
            month,
            captured_at: chrono::Utc::now().to_rfc3339(),
            entries: leaderboard.clone(),
        };
        drop(leaderboard);

        let dir = Self::snapshot_dir();
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| e.to_string())?;
        let filename = format!("leaderboard_{:04}_{:02}.json", year, month);
        let path = dir.join(filename);
        let json = serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
        tokio::fs::write(&path, json)
            .await
            .map_err(|e| e.to_string())?;
        tracing::info!(
            year = year,
            month = month,
            entries = snapshot.entries.len(),
            "Saved leaderboard snapshot"
        );
        Ok(())
    }

    /// Load all available monthly snapshots from disk, sorted newest-first.
    ///
    /// Files that cannot be read or parsed are silently skipped.
    pub async fn load_snapshots(&self) -> Vec<MonthlySnapshot> {
        let dir = Self::snapshot_dir();
        let mut snapshots = Vec::new();

        let read_dir = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(_) => return snapshots,
        };

        let mut read_dir = read_dir;
        while let Ok(Some(entry)) = read_dir.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let bytes = match tokio::fs::read(&path).await {
                Ok(b) => b,
                Err(_) => continue,
            };
            let snapshot = match serde_json::from_slice::<MonthlySnapshot>(&bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };
            snapshots.push(snapshot);
        }

        // Sort newest-first: descending year, then descending month
        snapshots.sort_by(|a, b| b.year.cmp(&a.year).then(b.month.cmp(&a.month)));
        snapshots
    }

    /// Returns the directory where snapshots are stored.
    fn snapshot_dir() -> std::path::PathBuf {
        std::env::temp_dir()
            .join("chie-coordinator")
            .join("snapshots")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_award_points_and_state() {
        let engine = GamificationEngine::new();
        let user_id = Uuid::new_v4();

        engine
            .award_points(user_id, 500, "test_reason")
            .await
            .expect("award should succeed");

        let state = engine
            .get_user_state(user_id)
            .await
            .expect("state should exist");
        // total_points >= 500 because the leaderboard rebuild may award TopSeeder badge
        // points on top of the base award when the user is the only ranked participant.
        assert!(
            state.total_points >= 500,
            "total_points should be at least 500, got {}",
            state.total_points
        );
        // monthly_points tracks only directly-awarded points (not badge bonuses)
        assert_eq!(state.monthly_points, 500);
    }

    #[tokio::test]
    async fn test_quest_progress_completes_quest() {
        let engine = GamificationEngine::new();
        let user_id = Uuid::new_v4();

        // Get quests to initialize the user
        let quests = engine
            .get_active_quests(user_id)
            .await
            .expect("quests should initialize");
        assert!(!quests.is_empty(), "should have active quests");

        // DailyProofSubmission needs 10 proofs; advance by 10 at once
        engine
            .update_quest_progress(user_id, QuestType::DailyProofSubmission, 10)
            .await
            .expect("progress update should succeed");

        let state = engine
            .get_user_state(user_id)
            .await
            .expect("state should exist");

        let completed = state
            .active_quests
            .iter()
            .find(|q| q.quest_type == QuestType::DailyProofSubmission);
        assert!(completed.is_some(), "quest should still be in state");
        if let Some(q) = completed {
            assert!(
                matches!(q.status, QuestStatus::Completed),
                "quest should be completed, got {:?}",
                q.status
            );
        }

        // Points from quest reward should be credited
        assert!(
            state.monthly_points >= Quest::daily_proof_submission().reward_points,
            "reward points should be credited"
        );
        assert_eq!(state.completed_quests_count, 1);
    }

    #[tokio::test]
    async fn test_quest_progress_partial_does_not_complete() {
        let engine = GamificationEngine::new();
        let user_id = Uuid::new_v4();

        engine
            .get_active_quests(user_id)
            .await
            .expect("init quests");

        // DailyUptime needs 12 hours; advance by only 5
        engine
            .update_quest_progress(user_id, QuestType::DailyUptime, 5)
            .await
            .expect("progress update should succeed");

        let state = engine.get_user_state(user_id).await.expect("state");
        let quest = state
            .active_quests
            .iter()
            .find(|q| q.quest_type == QuestType::DailyUptime)
            .expect("quest should exist");

        assert!(
            matches!(quest.status, QuestStatus::Active),
            "quest should still be active"
        );
        assert_eq!(quest.current_value, 5);
        assert_eq!(state.completed_quests_count, 0);
    }

    #[tokio::test]
    async fn test_badge_eligibility_bandwidth_hero() {
        let engine = GamificationEngine::with_thresholds(
            1_000, // low threshold for testing (1000 bytes instead of 1 TB)
            99.0, 30, 100,
        );
        let user_id = Uuid::new_v4();
        engine.ensure_user(user_id).await;

        // Update stats to exceed bandwidth threshold
        engine
            .update_network_stats(user_id, 2_000, 50.0, 0.1)
            .await
            .expect("stats update should succeed");

        let state = engine.get_user_state(user_id).await.expect("state");
        assert!(
            state.has_badge(&Badge::BandwidthHero),
            "BandwidthHero badge should be awarded"
        );
    }

    #[tokio::test]
    async fn test_badge_eligibility_super_node() {
        let engine = GamificationEngine::with_thresholds(
            u64::MAX, // disable BandwidthHero threshold
            95.0,     // SuperNode at 95% uptime
            30,
            100,
        );
        let user_id = Uuid::new_v4();
        engine.ensure_user(user_id).await;

        engine
            .update_network_stats(user_id, 0, 96.0, 0.0)
            .await
            .expect("stats update");

        let state = engine.get_user_state(user_id).await.expect("state");
        assert!(
            state.has_badge(&Badge::SuperNode),
            "SuperNode badge should be awarded at 96% uptime"
        );
    }

    #[tokio::test]
    async fn test_badge_eligibility_early_adopter() {
        let engine = GamificationEngine::with_thresholds(
            u64::MAX,
            100.0, // impossible uptime to disable SuperNode
            365,   // disable Reliable
            5,     // EarlyAdopter for first 5 nodes
        );

        // Register 5 users - all should get EarlyAdopter
        let mut user_ids = Vec::new();
        for _ in 0..5 {
            let uid = Uuid::new_v4();
            engine.ensure_user(uid).await;
            user_ids.push(uid);
        }

        // A 6th user should NOT get it
        let late_user = Uuid::new_v4();
        engine.ensure_user(late_user).await;

        for uid in &user_ids {
            let newly_awarded = engine
                .check_badge_eligibility(*uid)
                .await
                .expect("check should succeed");
            assert!(
                newly_awarded.contains(&Badge::EarlyAdopter),
                "User {:?} should earn EarlyAdopter",
                uid
            );
        }

        let late_state = engine.get_user_state(late_user).await.expect("state");
        assert!(
            !late_state.has_badge(&Badge::EarlyAdopter),
            "Late user should NOT have EarlyAdopter"
        );
    }

    #[tokio::test]
    async fn test_badge_not_awarded_twice() {
        let engine = GamificationEngine::with_thresholds(100, 0.0, 0, 9999);
        let user_id = Uuid::new_v4();
        engine.ensure_user(user_id).await;

        // First check awards both BandwidthHero and SuperNode (thresholds are 100 bytes and 0%)
        engine
            .update_network_stats(user_id, 200, 0.0, 0.0)
            .await
            .expect("stats update");

        let state_after_first = engine.get_user_state(user_id).await.expect("state");
        let badge_count_first = state_after_first.badges.len();

        // Second update - no new badges should be added
        engine
            .update_network_stats(user_id, 200, 0.0, 0.0)
            .await
            .expect("stats update");

        let state_after_second = engine.get_user_state(user_id).await.expect("state");
        assert_eq!(
            state_after_second.badges.len(),
            badge_count_first,
            "Badge count should not increase on re-check"
        );
    }

    #[tokio::test]
    async fn test_leaderboard_ordering() {
        let engine = GamificationEngine::new();

        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let user_c = Uuid::new_v4();

        // Award different points to each user
        engine
            .award_points(user_b, 3_000, "test")
            .await
            .expect("award");
        engine
            .award_points(user_a, 1_000, "test")
            .await
            .expect("award");
        engine
            .award_points(user_c, 5_000, "test")
            .await
            .expect("award");

        let leaderboard = engine.get_leaderboard(10).await.expect("leaderboard");
        assert_eq!(leaderboard.len(), 3);

        // Should be ordered: c (5000), b (3000), a (1000)
        assert_eq!(leaderboard[0].user_id, user_c, "user_c should be rank 1");
        assert_eq!(leaderboard[0].rank, 1);
        assert_eq!(leaderboard[1].user_id, user_b, "user_b should be rank 2");
        assert_eq!(leaderboard[1].rank, 2);
        assert_eq!(leaderboard[2].user_id, user_a, "user_a should be rank 3");
        assert_eq!(leaderboard[2].rank, 3);
    }

    #[tokio::test]
    async fn test_leaderboard_limit_respected() {
        let engine = GamificationEngine::new();
        for i in 0..20u64 {
            let uid = Uuid::new_v4();
            engine
                .award_points(uid, i * 100, "test")
                .await
                .expect("award");
        }

        let board = engine.get_leaderboard(5).await.expect("leaderboard");
        assert_eq!(board.len(), 5, "limit should be respected");
    }

    #[tokio::test]
    async fn test_streak_and_reliable_badge() {
        let engine = GamificationEngine::with_thresholds(
            u64::MAX,
            100.0, // disable SuperNode
            3,     // Reliable at 3 days for testing
            9999,  // disable EarlyAdopter
        );
        let user_id = Uuid::new_v4();
        engine.ensure_user(user_id).await;

        for _ in 0..3 {
            engine.increment_streak(user_id).await.expect("streak");
        }

        let state = engine.get_user_state(user_id).await.expect("state");
        assert_eq!(state.streak_days, 3);
        assert!(
            state.has_badge(&Badge::Reliable),
            "Reliable badge should be awarded at 3-day streak"
        );
    }

    #[tokio::test]
    async fn test_streak_reset() {
        let engine = GamificationEngine::new();
        let user_id = Uuid::new_v4();
        engine.ensure_user(user_id).await;

        for _ in 0..5 {
            engine.increment_streak(user_id).await.expect("streak");
        }

        engine.reset_streak(user_id).await.expect("reset");

        let state = engine.get_user_state(user_id).await.expect("state");
        assert_eq!(state.streak_days, 0, "streak should be reset to 0");
    }

    #[tokio::test]
    async fn test_founder_badge_manual_award() {
        let engine = GamificationEngine::new();
        let user_id = Uuid::new_v4();
        engine.ensure_user(user_id).await;

        let awarded = engine
            .award_founder_badge(user_id)
            .await
            .expect("award founder");
        assert!(awarded, "first award should return true");

        let awarded_again = engine
            .award_founder_badge(user_id)
            .await
            .expect("re-award founder");
        assert!(!awarded_again, "second award should return false");

        let state = engine.get_user_state(user_id).await.expect("state");
        assert!(state.has_badge(&Badge::Founder));
        assert_eq!(state.badges.len(), 1, "only one Founder badge");
    }

    #[tokio::test]
    async fn test_user_not_found_returns_error() {
        let engine = GamificationEngine::new();
        // Do NOT call ensure_user - just try to read a nonexistent user's badge eligibility
        // Since check_badge_eligibility requires both network_stats and states to exist,
        // and we're bypassing ensure_user, this should fail.
        let fake_id = Uuid::new_v4();

        // Note: the engine uses ensure_user internally in most methods,
        // so we test update_quest_progress without prior ensure_user.
        // Actually, update_quest_progress calls ensure_user internally,
        // so we test check_badge_eligibility directly.
        let result = engine.check_badge_eligibility(fake_id).await;
        assert!(
            matches!(result, Err(GamificationError::UserNotFound(_))),
            "should return UserNotFound for unknown user"
        );
    }
}
