//! Gamification types for CHIE Protocol.
//!
//! This module defines the core types for the CHIE gamification system,
//! including badges awarded to top contributors, quests with progress tracking,
//! and leaderboard entries for ranking participants by their network contributions.
//!
//! # Overview
//!
//! The gamification system rewards nodes for:
//! - Providing bandwidth to the network
//! - Maintaining high uptime
//! - Hosting content creators
//! - Submitting bandwidth proofs
//!
//! # Examples
//!
//! ## Creating a Daily Uptime Quest
//!
//! ```
//! use chie_shared::gamification::{Quest, QuestStatus};
//!
//! let quest = Quest::daily_uptime();
//! assert_eq!(quest.target_value, 12);
//! assert_eq!(quest.current_value, 0);
//! assert!(matches!(quest.status, QuestStatus::Active));
//! ```
//!
//! ## Working with Badges
//!
//! ```
//! use chie_shared::gamification::Badge;
//!
//! let badge = Badge::Founder;
//! println!("Earned: {}", badge.display_name());
//! println!("Description: {}", badge.description());
//! ```

use chrono::{DateTime, Utc};
#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Badges awarded to users for exceptional network contributions.
///
/// Badges are non-exhaustive to allow future additions without breaking changes.
/// Each badge represents a specific achievement milestone within the CHIE network.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Badge {
    /// Awarded to early network participants who joined during the initial launch.
    Founder,

    /// Awarded to the highest bandwidth providers in the network.
    TopSeeder,

    /// Awarded to nodes maintaining the highest uptime percentages.
    SuperNode,

    /// Awarded to the first 100 nodes to join the network.
    EarlyAdopter,

    /// Awarded when a user transfers more than 1 TB total bandwidth.
    BandwidthHero,

    /// Awarded for maintaining a 30-day consecutive activity streak.
    Reliable,
}

impl Badge {
    /// Returns the human-readable display name for this badge.
    pub fn display_name(&self) -> &'static str {
        match self {
            Badge::Founder => "Founder",
            Badge::TopSeeder => "Top Seeder",
            Badge::SuperNode => "Super Node",
            Badge::EarlyAdopter => "Early Adopter",
            Badge::BandwidthHero => "Bandwidth Hero",
            Badge::Reliable => "Reliable",
        }
    }

    /// Returns a short description of how this badge is earned.
    pub fn description(&self) -> &'static str {
        match self {
            Badge::Founder => "Joined the CHIE network during its initial launch phase",
            Badge::TopSeeder => "One of the highest bandwidth providers in the network",
            Badge::SuperNode => "Maintaining one of the highest uptime percentages",
            Badge::EarlyAdopter => "One of the first 100 nodes to join the network",
            Badge::BandwidthHero => "Has transferred more than 1 TB of total bandwidth",
            Badge::Reliable => "Maintained 30 consecutive days of network activity",
        }
    }

    /// Returns the point value awarded when this badge is earned.
    pub fn point_value(&self) -> u64 {
        match self {
            Badge::Founder => 5_000,
            Badge::TopSeeder => 2_000,
            Badge::SuperNode => 3_000,
            Badge::EarlyAdopter => 1_000,
            Badge::BandwidthHero => 10_000,
            Badge::Reliable => 1_500,
        }
    }

    /// Returns the total bandwidth threshold in bytes required for the BandwidthHero badge.
    pub const BANDWIDTH_HERO_THRESHOLD_BYTES: u64 = 1_099_511_627_776; // 1 TB

    /// Returns the consecutive days required for the Reliable badge.
    pub const RELIABLE_STREAK_DAYS: u32 = 30;

    /// Returns the maximum rank required for the TopSeeder badge (top 10%).
    pub const TOP_SEEDER_RANK_THRESHOLD: u32 = 10;

    /// Returns the node count limit for the EarlyAdopter badge.
    pub const EARLY_ADOPTER_LIMIT: u32 = 100;

    /// Returns the minimum uptime percentage required for the SuperNode badge.
    pub const SUPER_NODE_UPTIME_THRESHOLD: f64 = 99.0;
}

/// The type of quest, determining its requirements and reward structure.
///
/// Quests are non-exhaustive to allow future quest types without breaking changes.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuestType {
    /// Maintain uptime for 12 consecutive hours. Resets daily.
    DailyUptime,

    /// Host content for 5 different creators in a week.
    WeeklyHostCreators,

    /// Transfer a total of 100 GB of content in a month.
    MonthlyTransfer,

    /// Provide 50 GB of bandwidth to the network in a week.
    WeeklyBandwidth,

    /// Submit 10 bandwidth proofs in a single day.
    DailyProofSubmission,
}

impl QuestType {
    /// Returns the default title for this quest type.
    pub fn default_title(&self) -> &'static str {
        match self {
            QuestType::DailyUptime => "Daily Uptime Champion",
            QuestType::WeeklyHostCreators => "Weekly Creator Host",
            QuestType::MonthlyTransfer => "Monthly Transfer Goal",
            QuestType::WeeklyBandwidth => "Weekly Bandwidth Provider",
            QuestType::DailyProofSubmission => "Daily Proof Submitter",
        }
    }

    /// Returns the default description for this quest type.
    pub fn default_description(&self) -> &'static str {
        match self {
            QuestType::DailyUptime => "Maintain your node online for 12 consecutive hours today",
            QuestType::WeeklyHostCreators => "Host content for 5 different creators this week",
            QuestType::MonthlyTransfer => "Transfer a total of 100 GB of content this month",
            QuestType::WeeklyBandwidth => "Provide 50 GB of bandwidth to the network this week",
            QuestType::DailyProofSubmission => "Submit 10 bandwidth proofs today",
        }
    }

    /// Returns the default target value for this quest type.
    ///
    /// Units depend on the quest type:
    /// - `DailyUptime`: hours
    /// - `WeeklyHostCreators`: number of creators
    /// - `MonthlyTransfer`: gigabytes
    /// - `WeeklyBandwidth`: gigabytes
    /// - `DailyProofSubmission`: number of proofs
    pub fn default_target_value(&self) -> u64 {
        match self {
            QuestType::DailyUptime => 12,
            QuestType::WeeklyHostCreators => 5,
            QuestType::MonthlyTransfer => 100,
            QuestType::WeeklyBandwidth => 50,
            QuestType::DailyProofSubmission => 10,
        }
    }

    /// Returns the default reward in points for completing this quest.
    pub fn default_reward_points(&self) -> u64 {
        match self {
            QuestType::DailyUptime => 100,
            QuestType::WeeklyHostCreators => 500,
            QuestType::MonthlyTransfer => 2_000,
            QuestType::WeeklyBandwidth => 750,
            QuestType::DailyProofSubmission => 200,
        }
    }

    /// Returns the duration in seconds before this quest expires.
    pub fn expiry_duration_secs(&self) -> i64 {
        match self {
            QuestType::DailyUptime => 86_400,          // 1 day
            QuestType::WeeklyHostCreators => 604_800,  // 7 days
            QuestType::MonthlyTransfer => 2_592_000,   // 30 days
            QuestType::WeeklyBandwidth => 604_800,     // 7 days
            QuestType::DailyProofSubmission => 86_400, // 1 day
        }
    }
}

/// The current status of a quest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuestStatus {
    /// The quest is currently in progress.
    Active,

    /// The quest has been successfully completed.
    Completed,

    /// The quest expired before it was completed.
    Expired,

    /// The quest is waiting to start (future quests).
    Pending,
}

/// A quest assigned to a user with progress tracking.
///
/// Quests have a target value and current progress. When `current_value`
/// reaches `target_value`, the quest transitions to `Completed` status.
///
/// # Examples
///
/// ```
/// use chie_shared::gamification::{Quest, QuestStatus};
///
/// let mut quest = Quest::daily_uptime();
/// assert!(!quest.is_complete());
///
/// quest.current_value = quest.target_value;
/// assert!(quest.is_complete());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct Quest {
    /// Unique identifier for this quest instance.
    pub id: Uuid,

    /// The type of quest, defining its requirements.
    pub quest_type: QuestType,

    /// Human-readable title for display in UI.
    pub title: String,

    /// Detailed description of what the user must do.
    pub description: String,

    /// The goal value that must be reached to complete the quest.
    ///
    /// Units are quest-type specific (hours, count, GB, etc.).
    pub target_value: u64,

    /// The user's current progress toward the target.
    pub current_value: u64,

    /// Points awarded to the user upon completion.
    pub reward_points: u64,

    /// Current lifecycle status of this quest.
    pub status: QuestStatus,

    /// When the user began this quest.
    pub started_at: DateTime<Utc>,

    /// When this quest will expire if not completed.
    pub expires_at: DateTime<Utc>,

    /// When the quest was completed, if applicable.
    pub completed_at: Option<DateTime<Utc>>,
}

impl Quest {
    /// Creates a new quest with explicit parameters.
    ///
    /// # Arguments
    ///
    /// * `quest_type` - The type determining requirements and rewards
    /// * `title` - Display title for the quest
    /// * `description` - Detailed description
    /// * `target_value` - Goal value to reach
    /// * `reward_points` - Points awarded on completion
    /// * `expires_at` - When the quest will expire
    pub fn new(
        quest_type: QuestType,
        title: impl Into<String>,
        description: impl Into<String>,
        target_value: u64,
        reward_points: u64,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            quest_type,
            title: title.into(),
            description: description.into(),
            target_value,
            current_value: 0,
            reward_points,
            status: QuestStatus::Active,
            started_at: now,
            expires_at,
            completed_at: None,
        }
    }

    /// Creates a new DailyUptime quest starting now.
    ///
    /// Requires the node to stay online for 12 consecutive hours.
    /// Expires after 24 hours and awards 100 points on completion.
    pub fn daily_uptime() -> Self {
        let quest_type = QuestType::DailyUptime;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(quest_type.expiry_duration_secs());
        Self::new(
            quest_type,
            QuestType::DailyUptime.default_title(),
            QuestType::DailyUptime.default_description(),
            QuestType::DailyUptime.default_target_value(),
            QuestType::DailyUptime.default_reward_points(),
            expires_at,
        )
    }

    /// Creates a new WeeklyHostCreators quest starting now.
    ///
    /// Requires hosting content for 5 different creators within 7 days.
    /// Awards 500 points on completion.
    pub fn weekly_host_creators() -> Self {
        let quest_type = QuestType::WeeklyHostCreators;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(quest_type.expiry_duration_secs());
        Self::new(
            quest_type,
            QuestType::WeeklyHostCreators.default_title(),
            QuestType::WeeklyHostCreators.default_description(),
            QuestType::WeeklyHostCreators.default_target_value(),
            QuestType::WeeklyHostCreators.default_reward_points(),
            expires_at,
        )
    }

    /// Creates a new MonthlyTransfer quest starting now.
    ///
    /// Requires transferring a total of 100 GB within 30 days.
    /// Awards 2,000 points on completion.
    pub fn monthly_transfer() -> Self {
        let quest_type = QuestType::MonthlyTransfer;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(quest_type.expiry_duration_secs());
        Self::new(
            quest_type,
            QuestType::MonthlyTransfer.default_title(),
            QuestType::MonthlyTransfer.default_description(),
            QuestType::MonthlyTransfer.default_target_value(),
            QuestType::MonthlyTransfer.default_reward_points(),
            expires_at,
        )
    }

    /// Creates a new WeeklyBandwidth quest starting now.
    pub fn weekly_bandwidth() -> Self {
        let quest_type = QuestType::WeeklyBandwidth;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(quest_type.expiry_duration_secs());
        Self::new(
            quest_type,
            QuestType::WeeklyBandwidth.default_title(),
            QuestType::WeeklyBandwidth.default_description(),
            QuestType::WeeklyBandwidth.default_target_value(),
            QuestType::WeeklyBandwidth.default_reward_points(),
            expires_at,
        )
    }

    /// Creates a new DailyProofSubmission quest starting now.
    pub fn daily_proof_submission() -> Self {
        let quest_type = QuestType::DailyProofSubmission;
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(quest_type.expiry_duration_secs());
        Self::new(
            quest_type,
            QuestType::DailyProofSubmission.default_title(),
            QuestType::DailyProofSubmission.default_description(),
            QuestType::DailyProofSubmission.default_target_value(),
            QuestType::DailyProofSubmission.default_reward_points(),
            expires_at,
        )
    }

    /// Returns true if the quest has been successfully completed.
    pub fn is_complete(&self) -> bool {
        matches!(self.status, QuestStatus::Completed) || self.current_value >= self.target_value
    }

    /// Returns true if the quest has expired without completion.
    pub fn is_expired(&self) -> bool {
        matches!(self.status, QuestStatus::Expired) || Utc::now() > self.expires_at
    }

    /// Returns the progress as a percentage (0.0 to 100.0).
    pub fn progress_percentage(&self) -> f64 {
        if self.target_value == 0 {
            return 100.0;
        }
        ((self.current_value as f64 / self.target_value as f64) * 100.0).min(100.0)
    }

    /// Returns the remaining value needed to complete the quest.
    pub fn remaining_value(&self) -> u64 {
        self.target_value.saturating_sub(self.current_value)
    }
}

/// A single entry in the gamification leaderboard.
///
/// Represents a user's rank and stats within a specific time period
/// (typically the current calendar month).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LeaderboardEntry {
    /// The user's position in the leaderboard (1 = top).
    pub rank: u32,

    /// The unique identifier of the ranked user.
    pub user_id: Uuid,

    /// The user's display name.
    pub username: String,

    /// Total points accumulated by this user.
    pub total_points: u64,

    /// Bandwidth provided this month, in gigabytes.
    pub monthly_bandwidth_gb: f64,

    /// Node uptime as a percentage (0.0 to 100.0).
    pub uptime_percentage: f64,

    /// All badges earned by this user.
    pub badges: Vec<Badge>,

    /// Start of the leaderboard period.
    pub period_start: DateTime<Utc>,

    /// End of the leaderboard period.
    pub period_end: DateTime<Utc>,
}

impl LeaderboardEntry {
    /// Creates a new leaderboard entry.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rank: u32,
        user_id: Uuid,
        username: impl Into<String>,
        total_points: u64,
        monthly_bandwidth_gb: f64,
        uptime_percentage: f64,
        badges: Vec<Badge>,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Self {
        Self {
            rank,
            user_id,
            username: username.into(),
            total_points,
            monthly_bandwidth_gb,
            uptime_percentage,
            badges,
            period_start,
            period_end,
        }
    }

    /// Returns the badge count for this user.
    pub fn badge_count(&self) -> usize {
        self.badges.len()
    }

    /// Returns true if the user has a specific badge.
    pub fn has_badge(&self, badge: &Badge) -> bool {
        self.badges.contains(badge)
    }
}

/// The complete gamification state for a single user.
///
/// This aggregates all gamification-related data for a user,
/// including their points, rank, badges, and quest progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct UserGamificationState {
    /// The unique identifier of the user.
    pub user_id: Uuid,

    /// Total points earned across all time.
    pub total_points: u64,

    /// Points earned in the current calendar month.
    pub monthly_points: u64,

    /// The user's current rank in the leaderboard, if ranked.
    ///
    /// `None` if the user has no activity this period.
    pub current_rank: Option<u32>,

    /// All badges earned by this user.
    pub badges: Vec<Badge>,

    /// Currently active quests assigned to this user.
    pub active_quests: Vec<Quest>,

    /// Total number of quests completed across all time.
    pub completed_quests_count: u32,

    /// Number of consecutive days with any network activity.
    pub streak_days: u32,
}

impl UserGamificationState {
    /// Creates a new empty gamification state for a user.
    pub fn new(user_id: Uuid) -> Self {
        Self {
            user_id,
            total_points: 0,
            monthly_points: 0,
            current_rank: None,
            badges: Vec::new(),
            active_quests: Vec::new(),
            completed_quests_count: 0,
            streak_days: 0,
        }
    }

    /// Returns true if the user has earned a specific badge.
    pub fn has_badge(&self, badge: &Badge) -> bool {
        self.badges.contains(badge)
    }

    /// Awards a badge to the user if not already earned.
    ///
    /// Returns `true` if the badge was newly added, `false` if already present.
    pub fn award_badge(&mut self, badge: Badge) -> bool {
        if self.has_badge(&badge) {
            return false;
        }
        self.badges.push(badge);
        true
    }

    /// Returns the number of active quests.
    pub fn active_quest_count(&self) -> usize {
        self.active_quests.len()
    }

    /// Returns the quest with the given ID if it exists in active quests.
    pub fn find_quest(&self, quest_id: Uuid) -> Option<&Quest> {
        self.active_quests.iter().find(|q| q.id == quest_id)
    }

    /// Returns a mutable reference to the quest with the given ID.
    pub fn find_quest_mut(&mut self, quest_id: Uuid) -> Option<&mut Quest> {
        self.active_quests.iter_mut().find(|q| q.id == quest_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_badge_display_names() {
        assert_eq!(Badge::Founder.display_name(), "Founder");
        assert_eq!(Badge::TopSeeder.display_name(), "Top Seeder");
        assert_eq!(Badge::BandwidthHero.display_name(), "Bandwidth Hero");
        assert_eq!(Badge::Reliable.display_name(), "Reliable");
    }

    #[test]
    fn test_badge_point_values_are_positive() {
        let badges = [
            Badge::Founder,
            Badge::TopSeeder,
            Badge::SuperNode,
            Badge::EarlyAdopter,
            Badge::BandwidthHero,
            Badge::Reliable,
        ];
        for badge in &badges {
            assert!(
                badge.point_value() > 0,
                "Badge {:?} should have positive point value",
                badge
            );
        }
    }

    #[test]
    fn test_badge_serialization_round_trip() {
        let badge = Badge::BandwidthHero;
        let json = serde_json::to_string(&badge).expect("should serialize");
        let deserialized: Badge = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(badge, deserialized);
    }

    #[test]
    fn test_badge_serialization_format() {
        let badge = Badge::TopSeeder;
        let json = serde_json::to_string(&badge).expect("should serialize");
        assert_eq!(json, "\"TOP_SEEDER\"");
    }

    #[test]
    fn test_quest_type_defaults_are_nonzero() {
        let types = [
            QuestType::DailyUptime,
            QuestType::WeeklyHostCreators,
            QuestType::MonthlyTransfer,
            QuestType::WeeklyBandwidth,
            QuestType::DailyProofSubmission,
        ];
        for qt in &types {
            assert!(
                qt.default_target_value() > 0,
                "{:?} must have positive target",
                qt
            );
            assert!(
                qt.default_reward_points() > 0,
                "{:?} must have positive reward",
                qt
            );
            assert!(
                qt.expiry_duration_secs() > 0,
                "{:?} must have positive expiry",
                qt
            );
        }
    }

    #[test]
    fn test_quest_daily_uptime_factory() {
        let quest = Quest::daily_uptime();
        assert_eq!(quest.quest_type, QuestType::DailyUptime);
        assert_eq!(quest.target_value, 12);
        assert_eq!(quest.current_value, 0);
        assert_eq!(quest.reward_points, 100);
        assert!(matches!(quest.status, QuestStatus::Active));
        assert!(quest.completed_at.is_none());
        assert!(!quest.is_complete());
    }

    #[test]
    fn test_quest_weekly_host_creators_factory() {
        let quest = Quest::weekly_host_creators();
        assert_eq!(quest.quest_type, QuestType::WeeklyHostCreators);
        assert_eq!(quest.target_value, 5);
        assert_eq!(quest.reward_points, 500);
    }

    #[test]
    fn test_quest_monthly_transfer_factory() {
        let quest = Quest::monthly_transfer();
        assert_eq!(quest.quest_type, QuestType::MonthlyTransfer);
        assert_eq!(quest.target_value, 100);
        assert_eq!(quest.reward_points, 2_000);
    }

    #[test]
    fn test_quest_progress_percentage() {
        let mut quest = Quest::daily_uptime();
        assert_eq!(quest.progress_percentage(), 0.0);

        quest.current_value = 6;
        assert!((quest.progress_percentage() - 50.0).abs() < 0.001);

        quest.current_value = 12;
        assert!((quest.progress_percentage() - 100.0).abs() < 0.001);
    }

    #[test]
    fn test_quest_remaining_value() {
        let mut quest = Quest::daily_uptime();
        assert_eq!(quest.remaining_value(), 12);

        quest.current_value = 5;
        assert_eq!(quest.remaining_value(), 7);

        quest.current_value = 12;
        assert_eq!(quest.remaining_value(), 0);

        // Saturating sub should not overflow
        quest.current_value = 100;
        assert_eq!(quest.remaining_value(), 0);
    }

    #[test]
    fn test_quest_serialization_round_trip() {
        let quest = Quest::daily_uptime();
        let json = serde_json::to_string(&quest).expect("should serialize");
        let deserialized: Quest = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(quest.id, deserialized.id);
        assert_eq!(quest.target_value, deserialized.target_value);
        assert_eq!(quest.reward_points, deserialized.reward_points);
    }

    #[test]
    fn test_leaderboard_entry_construction() {
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let entry = LeaderboardEntry::new(
            1,
            user_id,
            "top_node",
            50_000,
            1024.5,
            99.9,
            vec![Badge::Founder, Badge::TopSeeder],
            now,
            now + chrono::Duration::days(30),
        );

        assert_eq!(entry.rank, 1);
        assert_eq!(entry.total_points, 50_000);
        assert_eq!(entry.badge_count(), 2);
        assert!(entry.has_badge(&Badge::Founder));
        assert!(!entry.has_badge(&Badge::Reliable));
    }

    #[test]
    fn test_user_gamification_state_badge_management() {
        let user_id = Uuid::new_v4();
        let mut state = UserGamificationState::new(user_id);

        assert!(!state.has_badge(&Badge::Founder));
        let added = state.award_badge(Badge::Founder);
        assert!(added);
        assert!(state.has_badge(&Badge::Founder));

        // Adding the same badge again should be a no-op
        let added_again = state.award_badge(Badge::Founder);
        assert!(!added_again);
        assert_eq!(state.badges.len(), 1);
    }

    #[test]
    fn test_user_gamification_state_find_quest() {
        let user_id = Uuid::new_v4();
        let mut state = UserGamificationState::new(user_id);
        let quest = Quest::daily_uptime();
        let quest_id = quest.id;

        state.active_quests.push(quest);

        assert!(state.find_quest(quest_id).is_some());
        assert!(state.find_quest(Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_quest_status_serialization() {
        let status = QuestStatus::Completed;
        let json = serde_json::to_string(&status).expect("should serialize");
        assert_eq!(json, "\"COMPLETED\"");
    }

    #[test]
    fn test_quest_type_serialization() {
        let qt = QuestType::DailyProofSubmission;
        let json = serde_json::to_string(&qt).expect("should serialize");
        assert_eq!(json, "\"DAILY_PROOF_SUBMISSION\"");
    }
}
