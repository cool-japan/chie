//! Feature flags system for gradual feature rollouts and A/B testing.
//!
//! Provides a flexible feature flag system with support for:
//! - Boolean flags (on/off)
//! - Percentage-based rollouts
//! - User/group targeting
//! - Emergency kill switches
//! - A/B testing experiments

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

/// Feature flag definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    /// Unique flag identifier.
    pub id: Uuid,
    /// Flag key (used for lookups).
    pub key: String,
    /// Flag name.
    pub name: String,
    /// Flag description.
    pub description: String,
    /// Whether the flag is enabled globally.
    pub enabled: bool,
    /// Rollout percentage (0-100).
    pub rollout_percentage: u8,
    /// User IDs that should always see this feature.
    pub target_users: HashSet<Uuid>,
    /// User IDs that should never see this feature.
    pub excluded_users: HashSet<Uuid>,
    /// Node peer IDs that should see this feature.
    pub target_nodes: HashSet<String>,
    /// Flag type.
    pub flag_type: FlagType,
    /// Timestamp when flag was created.
    pub created_at: u64,
    /// Timestamp when flag was last updated.
    pub updated_at: u64,
}

/// Feature flag type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlagType {
    /// Boolean flag (on/off).
    Boolean,
    /// Percentage rollout flag.
    Rollout,
    /// A/B test experiment.
    Experiment,
    /// Kill switch (emergency disable).
    KillSwitch,
}

impl FlagType {
    /// Convert flag type to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Rollout => "rollout",
            Self::Experiment => "experiment",
            Self::KillSwitch => "kill_switch",
        }
    }
}

/// Evaluation context for feature flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    /// User ID (if applicable).
    pub user_id: Option<Uuid>,
    /// Node peer ID (if applicable).
    pub peer_id: Option<String>,
    /// Additional attributes for targeting.
    pub attributes: HashMap<String, String>,
}

impl EvaluationContext {
    /// Create a new evaluation context.
    pub fn new() -> Self {
        Self {
            user_id: None,
            peer_id: None,
            attributes: HashMap::new(),
        }
    }

    /// Set user ID.
    pub fn with_user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set peer ID.
    pub fn with_peer_id(mut self, peer_id: String) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Add an attribute.
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.insert(key, value);
        self
    }
}

impl Default for EvaluationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Flag evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Whether the flag is enabled for this context.
    pub enabled: bool,
    /// Reason for the result.
    pub reason: String,
    /// Variant (for A/B tests).
    pub variant: Option<String>,
}

/// Flag statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlagStats {
    /// Total number of flags.
    pub total_flags: usize,
    /// Enabled flags count.
    pub enabled_flags: usize,
    /// Disabled flags count.
    pub disabled_flags: usize,
    /// Evaluations by flag key.
    pub evaluations: HashMap<String, usize>,
    /// Enabled count by flag key.
    pub enabled_count: HashMap<String, usize>,
}

/// Feature flags configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlagsConfig {
    /// Maximum number of flags.
    pub max_flags: usize,
    /// Whether to track evaluation statistics.
    pub track_stats: bool,
}

impl Default for FeatureFlagsConfig {
    fn default() -> Self {
        Self {
            max_flags: 1000,
            track_stats: true,
        }
    }
}

/// Feature flags manager.
pub struct FeatureFlagsManager {
    /// Configuration.
    config: FeatureFlagsConfig,
    /// Flags by ID.
    flags_by_id: Arc<RwLock<HashMap<Uuid, FeatureFlag>>>,
    /// Flags by key.
    flags_by_key: Arc<RwLock<HashMap<String, Uuid>>>,
    /// Evaluation statistics.
    stats: Arc<RwLock<FlagStats>>,
}

impl FeatureFlagsManager {
    /// Create a new feature flags manager.
    pub fn new(config: FeatureFlagsConfig) -> Self {
        Self {
            config,
            flags_by_id: Arc::new(RwLock::new(HashMap::new())),
            flags_by_key: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(FlagStats::default())),
        }
    }

    /// Create a new feature flag.
    pub async fn create_flag(&self, mut flag: FeatureFlag) -> Result<FeatureFlag, String> {
        let flags_by_id = self.flags_by_id.read().await;
        if flags_by_id.len() >= self.config.max_flags {
            return Err(format!(
                "Maximum number of flags ({}) reached",
                self.config.max_flags
            ));
        }
        drop(flags_by_id);

        // Check for duplicate key
        let flags_by_key = self.flags_by_key.read().await;
        if flags_by_key.contains_key(&flag.key) {
            return Err(format!("Flag with key '{}' already exists", flag.key));
        }
        drop(flags_by_key);

        // Set timestamps
        let now = current_timestamp();
        flag.created_at = now;
        flag.updated_at = now;

        // Generate ID if not set
        if flag.id == Uuid::nil() {
            flag.id = Uuid::new_v4();
        }

        let flag_id = flag.id;
        let flag_key = flag.key.clone();

        // Store flag
        let mut flags_by_id = self.flags_by_id.write().await;
        let mut flags_by_key = self.flags_by_key.write().await;

        flags_by_id.insert(flag_id, flag.clone());
        flags_by_key.insert(flag_key.clone(), flag_id);

        info!(flag_id = %flag_id, flag_key = %flag_key, "Feature flag created");

        // Drop locks before calling update_stats to avoid deadlock
        drop(flags_by_id);
        drop(flags_by_key);

        // Update stats
        self.update_stats().await;

        Ok(flag)
    }

    /// Get a flag by ID.
    pub async fn get_flag(&self, flag_id: Uuid) -> Option<FeatureFlag> {
        let flags = self.flags_by_id.read().await;
        flags.get(&flag_id).cloned()
    }

    /// Get a flag by key.
    pub async fn get_flag_by_key(&self, key: &str) -> Option<FeatureFlag> {
        let flags_by_key = self.flags_by_key.read().await;
        let flag_id = *flags_by_key.get(key)?;
        drop(flags_by_key);

        self.get_flag(flag_id).await
    }

    /// Update a flag.
    pub async fn update_flag(&self, mut flag: FeatureFlag) -> Result<FeatureFlag, String> {
        let mut flags_by_id = self.flags_by_id.write().await;

        if !flags_by_id.contains_key(&flag.id) {
            return Err("Flag not found".to_string());
        }

        flag.updated_at = current_timestamp();
        flags_by_id.insert(flag.id, flag.clone());

        info!(flag_id = %flag.id, flag_key = %flag.key, "Feature flag updated");

        // Update stats
        drop(flags_by_id);
        self.update_stats().await;

        Ok(flag)
    }

    /// Delete a flag.
    pub async fn delete_flag(&self, flag_id: Uuid) -> bool {
        let mut flags_by_id = self.flags_by_id.write().await;
        let mut flags_by_key = self.flags_by_key.write().await;

        if let Some(flag) = flags_by_id.remove(&flag_id) {
            flags_by_key.remove(&flag.key);
            info!(flag_id = %flag_id, flag_key = %flag.key, "Feature flag deleted");
            drop(flags_by_id);
            drop(flags_by_key);
            self.update_stats().await;
            true
        } else {
            false
        }
    }

    /// List all flags.
    pub async fn list_flags(&self) -> Vec<FeatureFlag> {
        let flags = self.flags_by_id.read().await;
        flags.values().cloned().collect()
    }

    /// Enable a flag.
    pub async fn enable_flag(&self, flag_id: Uuid) -> bool {
        let mut flags_by_id = self.flags_by_id.write().await;
        if let Some(flag) = flags_by_id.get_mut(&flag_id) {
            flag.enabled = true;
            flag.updated_at = current_timestamp();
            info!(flag_id = %flag_id, flag_key = %flag.key, "Feature flag enabled");
            drop(flags_by_id);
            self.update_stats().await;
            true
        } else {
            false
        }
    }

    /// Disable a flag.
    pub async fn disable_flag(&self, flag_id: Uuid) -> bool {
        let mut flags_by_id = self.flags_by_id.write().await;
        if let Some(flag) = flags_by_id.get_mut(&flag_id) {
            flag.enabled = false;
            flag.updated_at = current_timestamp();
            info!(flag_id = %flag_id, flag_key = %flag.key, "Feature flag disabled");
            drop(flags_by_id);
            self.update_stats().await;
            true
        } else {
            false
        }
    }

    /// Evaluate a flag for a given context.
    pub async fn evaluate(&self, key: &str, context: &EvaluationContext) -> EvaluationResult {
        // Track evaluation if enabled
        if self.config.track_stats {
            let mut stats = self.stats.write().await;
            *stats.evaluations.entry(key.to_string()).or_insert(0) += 1;
        }

        // Get flag
        let flag = match self.get_flag_by_key(key).await {
            Some(f) => f,
            None => {
                debug!(key = %key, "Flag not found, defaulting to disabled");
                return EvaluationResult {
                    enabled: false,
                    reason: "Flag not found".to_string(),
                    variant: None,
                };
            }
        };

        // Check if globally disabled
        if !flag.enabled {
            return EvaluationResult {
                enabled: false,
                reason: "Flag globally disabled".to_string(),
                variant: None,
            };
        }

        // Check excluded users
        if let Some(user_id) = context.user_id {
            if flag.excluded_users.contains(&user_id) {
                return EvaluationResult {
                    enabled: false,
                    reason: "User excluded".to_string(),
                    variant: None,
                };
            }
        }

        // Check target users (takes priority)
        if let Some(user_id) = context.user_id {
            if flag.target_users.contains(&user_id) {
                self.track_enabled(key).await;
                return EvaluationResult {
                    enabled: true,
                    reason: "User targeted".to_string(),
                    variant: None,
                };
            }
        }

        // Check target nodes
        if let Some(peer_id) = &context.peer_id {
            if flag.target_nodes.contains(peer_id) {
                self.track_enabled(key).await;
                return EvaluationResult {
                    enabled: true,
                    reason: "Node targeted".to_string(),
                    variant: None,
                };
            }
        }

        // Evaluate based on flag type
        match flag.flag_type {
            FlagType::Boolean => {
                // Simple boolean flag
                self.track_enabled(key).await;
                EvaluationResult {
                    enabled: true,
                    reason: "Boolean flag enabled".to_string(),
                    variant: None,
                }
            }
            FlagType::Rollout => {
                // Percentage-based rollout
                let enabled = self.evaluate_rollout(&flag, context);
                if enabled {
                    self.track_enabled(key).await;
                }
                EvaluationResult {
                    enabled,
                    reason: format!("Rollout {}%", flag.rollout_percentage),
                    variant: None,
                }
            }
            FlagType::Experiment => {
                // A/B test - assign variant based on hash
                let variant = self.assign_variant(&flag, context);
                self.track_enabled(key).await;
                EvaluationResult {
                    enabled: true,
                    reason: "Experiment active".to_string(),
                    variant: Some(variant),
                }
            }
            FlagType::KillSwitch => {
                // Kill switch - only enabled if explicitly targeting
                EvaluationResult {
                    enabled: false,
                    reason: "Kill switch active".to_string(),
                    variant: None,
                }
            }
        }
    }

    /// Evaluate rollout percentage.
    fn evaluate_rollout(&self, flag: &FeatureFlag, context: &EvaluationContext) -> bool {
        if flag.rollout_percentage == 0 {
            return false;
        }
        if flag.rollout_percentage >= 100 {
            return true;
        }

        // Use consistent hashing for stable rollout
        let hash = self.compute_hash(&flag.key, context);
        (hash % 100) < flag.rollout_percentage as u64
    }

    /// Assign variant for A/B test.
    fn assign_variant(&self, flag: &FeatureFlag, context: &EvaluationContext) -> String {
        let hash = self.compute_hash(&flag.key, context);
        // Simple A/B test: variant A or B
        if hash % 2 == 0 {
            "A".to_string()
        } else {
            "B".to_string()
        }
    }

    /// Compute hash for consistent assignment.
    fn compute_hash(&self, flag_key: &str, context: &EvaluationContext) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        flag_key.hash(&mut hasher);

        // Include user ID in hash for consistency
        if let Some(user_id) = context.user_id {
            user_id.hash(&mut hasher);
        }

        // Include peer ID if available
        if let Some(peer_id) = &context.peer_id {
            peer_id.hash(&mut hasher);
        }

        hasher.finish()
    }

    /// Track enabled evaluation.
    async fn track_enabled(&self, key: &str) {
        if self.config.track_stats {
            let mut stats = self.stats.write().await;
            *stats.enabled_count.entry(key.to_string()).or_insert(0) += 1;
        }
    }

    /// Update statistics.
    async fn update_stats(&self) {
        let flags = self.flags_by_id.read().await;
        let mut stats = self.stats.write().await;

        stats.total_flags = flags.len();
        stats.enabled_flags = flags.values().filter(|f| f.enabled).count();
        stats.disabled_flags = flags.len() - stats.enabled_flags;
    }

    /// Get statistics.
    pub async fn get_stats(&self) -> FlagStats {
        self.stats.read().await.clone()
    }

    /// Clear statistics.
    pub async fn clear_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.evaluations.clear();
        stats.enabled_count.clear();
    }
}

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_create_and_get_flag() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "test_feature".to_string(),
            name: "Test Feature".to_string(),
            description: "A test feature".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        let created = manager.create_flag(flag).await.unwrap();
        assert_ne!(created.id, Uuid::nil());

        let retrieved = manager.get_flag_by_key("test_feature").await.unwrap();
        assert_eq!(retrieved.key, "test_feature");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_duplicate_key_rejection() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag1 = FeatureFlag {
            id: Uuid::nil(),
            key: "duplicate".to_string(),
            name: "Flag 1".to_string(),
            description: "First flag".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        manager.create_flag(flag1).await.unwrap();

        let flag2 = FeatureFlag {
            id: Uuid::nil(),
            key: "duplicate".to_string(),
            name: "Flag 2".to_string(),
            description: "Duplicate flag".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        assert!(manager.create_flag(flag2).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_enable_disable_flag() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "toggle_test".to_string(),
            name: "Toggle Test".to_string(),
            description: "Test toggling".to_string(),
            enabled: false,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        let created = manager.create_flag(flag).await.unwrap();

        assert!(manager.enable_flag(created.id).await);
        let flag = manager.get_flag(created.id).await.unwrap();
        assert!(flag.enabled);

        assert!(manager.disable_flag(created.id).await);
        let flag = manager.get_flag(created.id).await.unwrap();
        assert!(!flag.enabled);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_boolean_flag_evaluation() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "boolean_test".to_string(),
            name: "Boolean Test".to_string(),
            description: "Test boolean flag".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        manager.create_flag(flag).await.unwrap();

        let context = EvaluationContext::new();
        let result = manager.evaluate("boolean_test", &context).await;
        assert!(result.enabled);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_target_user_evaluation() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let user_id = Uuid::new_v4();
        let mut target_users = HashSet::new();
        target_users.insert(user_id);

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "user_target_test".to_string(),
            name: "User Target Test".to_string(),
            description: "Test user targeting".to_string(),
            enabled: true,
            rollout_percentage: 0, // 0% rollout, but user is targeted
            target_users,
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Rollout,
            created_at: 0,
            updated_at: 0,
        };

        manager.create_flag(flag).await.unwrap();

        let context = EvaluationContext::new().with_user_id(user_id);
        let result = manager.evaluate("user_target_test", &context).await;
        assert!(result.enabled);
        assert_eq!(result.reason, "User targeted");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_excluded_user_evaluation() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let user_id = Uuid::new_v4();
        let mut excluded_users = HashSet::new();
        excluded_users.insert(user_id);

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "exclude_test".to_string(),
            name: "Exclude Test".to_string(),
            description: "Test user exclusion".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users,
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        manager.create_flag(flag).await.unwrap();

        let context = EvaluationContext::new().with_user_id(user_id);
        let result = manager.evaluate("exclude_test", &context).await;
        assert!(!result.enabled);
        assert_eq!(result.reason, "User excluded");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_delete_flag() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "delete_test".to_string(),
            name: "Delete Test".to_string(),
            description: "Test deletion".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        let created = manager.create_flag(flag).await.unwrap();

        assert!(manager.delete_flag(created.id).await);
        assert!(manager.get_flag(created.id).await.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_flag_stats() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "stats_test".to_string(),
            name: "Stats Test".to_string(),
            description: "Test statistics".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Boolean,
            created_at: 0,
            updated_at: 0,
        };

        manager.create_flag(flag).await.unwrap();

        let context = EvaluationContext::new();
        manager.evaluate("stats_test", &context).await;
        manager.evaluate("stats_test", &context).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_flags, 1);
        assert_eq!(stats.enabled_flags, 1);
        assert_eq!(*stats.evaluations.get("stats_test").unwrap(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_experiment_variant_assignment() {
        let manager = FeatureFlagsManager::new(FeatureFlagsConfig::default());

        let flag = FeatureFlag {
            id: Uuid::nil(),
            key: "experiment_test".to_string(),
            name: "Experiment Test".to_string(),
            description: "Test A/B experiment".to_string(),
            enabled: true,
            rollout_percentage: 100,
            target_users: HashSet::new(),
            excluded_users: HashSet::new(),
            target_nodes: HashSet::new(),
            flag_type: FlagType::Experiment,
            created_at: 0,
            updated_at: 0,
        };

        manager.create_flag(flag).await.unwrap();

        let user_id = Uuid::new_v4();
        let context = EvaluationContext::new().with_user_id(user_id);
        let result = manager.evaluate("experiment_test", &context).await;

        assert!(result.enabled);
        assert!(result.variant.is_some());
        let variant = result.variant.unwrap();
        assert!(variant == "A" || variant == "B");

        // Same user should get same variant
        let result2 = manager.evaluate("experiment_test", &context).await;
        assert_eq!(result2.variant.unwrap(), variant);
    }
}
