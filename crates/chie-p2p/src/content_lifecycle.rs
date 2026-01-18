// Content Lifecycle Manager
//
// Manages the entire lifecycle of content in the P2P network from creation
// through distribution, maintenance, archival, and eventual deletion.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Content identifier type
pub type ContentId = String;

/// Lifecycle stage of content
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleStage {
    /// Content is being created/uploaded
    Creating,
    /// Content is actively distributed and accessed
    Active,
    /// Content access is declining, entering warm storage
    Declining,
    /// Content is rarely accessed, in cold storage
    Archived,
    /// Content marked for deletion
    MarkedForDeletion,
    /// Content has been deleted
    Deleted,
}

impl LifecycleStage {
    /// Get the next natural stage in the lifecycle
    pub fn next_stage(&self) -> Option<LifecycleStage> {
        match self {
            LifecycleStage::Creating => Some(LifecycleStage::Active),
            LifecycleStage::Active => Some(LifecycleStage::Declining),
            LifecycleStage::Declining => Some(LifecycleStage::Archived),
            LifecycleStage::Archived => Some(LifecycleStage::MarkedForDeletion),
            LifecycleStage::MarkedForDeletion => Some(LifecycleStage::Deleted),
            LifecycleStage::Deleted => None,
        }
    }

    /// Check if content can be transitioned back to active
    pub fn can_reactivate(&self) -> bool {
        matches!(self, LifecycleStage::Declining | LifecycleStage::Archived)
    }
}

/// Content lifecycle metadata
#[derive(Debug, Clone)]
pub struct ContentLifecycle {
    pub content_id: ContentId,
    pub stage: LifecycleStage,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub last_modified: Instant,
    pub stage_changed_at: Instant,
    pub access_count: u64,
    pub size_bytes: u64,
    pub importance_score: f64, // 0.0 to 1.0
}

impl ContentLifecycle {
    /// Create new content lifecycle
    pub fn new(content_id: ContentId, size_bytes: u64) -> Self {
        let now = Instant::now();
        Self {
            content_id,
            stage: LifecycleStage::Creating,
            created_at: now,
            last_accessed: now,
            last_modified: now,
            stage_changed_at: now,
            access_count: 0,
            size_bytes,
            importance_score: 0.5,
        }
    }

    /// Record an access to this content
    pub fn record_access(&mut self) {
        self.last_accessed = Instant::now();
        self.access_count += 1;
    }

    /// Get age of content
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last access
    pub fn time_since_access(&self) -> Duration {
        self.last_accessed.elapsed()
    }

    /// Get time in current stage
    pub fn time_in_stage(&self) -> Duration {
        self.stage_changed_at.elapsed()
    }

    /// Calculate access rate (accesses per hour)
    pub fn access_rate(&self) -> f64 {
        let hours = self.age().as_secs() as f64 / 3600.0;
        if hours > 0.0 {
            self.access_count as f64 / hours
        } else {
            0.0
        }
    }
}

/// Lifecycle policy configuration
#[derive(Debug, Clone)]
pub struct LifecyclePolicy {
    /// Time without access before moving to declining (default: 7 days)
    pub declining_threshold: Duration,
    /// Time without access before archiving (default: 30 days)
    pub archive_threshold: Duration,
    /// Time in archive before marking for deletion (default: 90 days)
    pub deletion_threshold: Duration,
    /// Minimum importance score to avoid deletion (0.0 to 1.0)
    pub min_importance_for_keep: f64,
    /// Minimum access rate (per hour) to stay active
    pub min_active_access_rate: f64,
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self {
            declining_threshold: Duration::from_secs(7 * 24 * 3600), // 7 days
            archive_threshold: Duration::from_secs(30 * 24 * 3600),  // 30 days
            deletion_threshold: Duration::from_secs(90 * 24 * 3600), // 90 days
            min_importance_for_keep: 0.7,
            min_active_access_rate: 0.1, // 0.1 accesses per hour
        }
    }
}

/// Lifecycle transition recommendation
#[derive(Debug, Clone, PartialEq)]
pub struct LifecycleTransition {
    pub content_id: ContentId,
    pub from_stage: LifecycleStage,
    pub to_stage: LifecycleStage,
    pub reason: String,
}

/// Content lifecycle manager
pub struct ContentLifecycleManager {
    policy: LifecyclePolicy,
    content: HashMap<ContentId, ContentLifecycle>,
    stage_counts: HashMap<LifecycleStage, usize>,
}

impl ContentLifecycleManager {
    /// Create a new lifecycle manager
    pub fn new(policy: LifecyclePolicy) -> Self {
        Self {
            policy,
            content: HashMap::new(),
            stage_counts: HashMap::new(),
        }
    }

    /// Register new content
    pub fn register_content(&mut self, content_id: ContentId, size_bytes: u64) {
        let lifecycle = ContentLifecycle::new(content_id.clone(), size_bytes);
        self.content.insert(content_id, lifecycle);
        self.update_stage_count(LifecycleStage::Creating, 1);
    }

    /// Remove content from management
    pub fn unregister_content(&mut self, content_id: &ContentId) {
        if let Some(lifecycle) = self.content.remove(content_id) {
            self.update_stage_count(lifecycle.stage, -1);
        }
    }

    /// Record content access
    pub fn record_access(&mut self, content_id: &ContentId) {
        if let Some(lifecycle) = self.content.get_mut(content_id) {
            lifecycle.record_access();

            // Reactivate if in declining or archived stage
            if lifecycle.stage.can_reactivate() {
                self.transition_to(
                    content_id,
                    LifecycleStage::Active,
                    "Reactivated due to access",
                );
            }
        }
    }

    /// Update content importance score
    pub fn update_importance(&mut self, content_id: &ContentId, score: f64) {
        if let Some(lifecycle) = self.content.get_mut(content_id) {
            lifecycle.importance_score = score.clamp(0.0, 1.0);
        }
    }

    /// Manually transition content to a stage
    pub fn transition_to(
        &mut self,
        content_id: &ContentId,
        new_stage: LifecycleStage,
        _reason: &str,
    ) {
        // Extract current stage first to avoid borrowing issues
        let old_stage = self.content.get(content_id).map(|l| l.stage);

        if let Some(old_stage) = old_stage {
            if old_stage != new_stage {
                self.update_stage_count(old_stage, -1);
                if let Some(lifecycle) = self.content.get_mut(content_id) {
                    lifecycle.stage = new_stage;
                    lifecycle.stage_changed_at = Instant::now();
                }
                self.update_stage_count(new_stage, 1);
            }
        }
    }

    /// Evaluate lifecycle transitions for all content
    pub fn evaluate_transitions(&mut self) -> Vec<LifecycleTransition> {
        let mut transitions = Vec::new();

        let content_ids: Vec<_> = self.content.keys().cloned().collect();

        for content_id in content_ids {
            if let Some(lifecycle) = self.content.get(&content_id) {
                if let Some(transition) = self.evaluate_content_transition(lifecycle) {
                    transitions.push(transition);
                }
            }
        }

        // Apply transitions
        for transition in &transitions {
            self.transition_to(
                &transition.content_id,
                transition.to_stage,
                &transition.reason,
            );
        }

        transitions
    }

    /// Evaluate transition for a single content item
    fn evaluate_content_transition(
        &self,
        lifecycle: &ContentLifecycle,
    ) -> Option<LifecycleTransition> {
        let time_since_access = lifecycle.time_since_access();
        let access_rate = lifecycle.access_rate();
        let importance = lifecycle.importance_score;

        match lifecycle.stage {
            LifecycleStage::Creating => {
                // Move to active once creation is complete (assume it's complete after 1 minute)
                if lifecycle.time_in_stage() > Duration::from_secs(60) {
                    return Some(LifecycleTransition {
                        content_id: lifecycle.content_id.clone(),
                        from_stage: lifecycle.stage,
                        to_stage: LifecycleStage::Active,
                        reason: "Creation completed".to_string(),
                    });
                }
            }
            LifecycleStage::Active => {
                // Move to declining if not accessed recently or low access rate
                if time_since_access > self.policy.declining_threshold
                    || access_rate < self.policy.min_active_access_rate
                {
                    return Some(LifecycleTransition {
                        content_id: lifecycle.content_id.clone(),
                        from_stage: lifecycle.stage,
                        to_stage: LifecycleStage::Declining,
                        reason: format!(
                            "Low activity: {} since access, {:.2} access/hour",
                            humanize_duration(time_since_access),
                            access_rate
                        ),
                    });
                }
            }
            LifecycleStage::Declining => {
                // Archive if not accessed for a long time
                if time_since_access > self.policy.archive_threshold {
                    return Some(LifecycleTransition {
                        content_id: lifecycle.content_id.clone(),
                        from_stage: lifecycle.stage,
                        to_stage: LifecycleStage::Archived,
                        reason: format!("No access for {}", humanize_duration(time_since_access)),
                    });
                }
            }
            LifecycleStage::Archived => {
                // Mark for deletion if archived too long and low importance
                if lifecycle.time_in_stage() > self.policy.deletion_threshold
                    && importance < self.policy.min_importance_for_keep
                {
                    return Some(LifecycleTransition {
                        content_id: lifecycle.content_id.clone(),
                        from_stage: lifecycle.stage,
                        to_stage: LifecycleStage::MarkedForDeletion,
                        reason: format!(
                            "Archived for {}, importance: {:.2}",
                            humanize_duration(lifecycle.time_in_stage()),
                            importance
                        ),
                    });
                }
            }
            LifecycleStage::MarkedForDeletion => {
                // Delete after grace period (1 day)
                if lifecycle.time_in_stage() > Duration::from_secs(24 * 3600) {
                    return Some(LifecycleTransition {
                        content_id: lifecycle.content_id.clone(),
                        from_stage: lifecycle.stage,
                        to_stage: LifecycleStage::Deleted,
                        reason: "Grace period expired".to_string(),
                    });
                }
            }
            LifecycleStage::Deleted => {
                // Already deleted, no transition
            }
        }

        None
    }

    /// Get content in a specific stage
    pub fn get_content_by_stage(&self, stage: LifecycleStage) -> Vec<&ContentLifecycle> {
        self.content.values().filter(|c| c.stage == stage).collect()
    }

    /// Get lifecycle statistics
    pub fn stats(&self) -> LifecycleStats {
        let total_content = self.content.len();
        let total_size: u64 = self.content.values().map(|c| c.size_bytes).sum();
        let avg_age = if total_content > 0 {
            self.content
                .values()
                .map(|c| c.age().as_secs())
                .sum::<u64>()
                / total_content as u64
        } else {
            0
        };

        let total_accesses: u64 = self.content.values().map(|c| c.access_count).sum();

        LifecycleStats {
            total_content,
            total_size,
            avg_age_secs: avg_age,
            total_accesses,
            stage_counts: self.stage_counts.clone(),
        }
    }

    /// Get content that should be garbage collected
    pub fn get_garbage_collection_candidates(&self) -> Vec<&ContentLifecycle> {
        self.content
            .values()
            .filter(|c| c.stage == LifecycleStage::Deleted)
            .collect()
    }

    /// Helper to update stage counts
    fn update_stage_count(&mut self, stage: LifecycleStage, delta: i32) {
        let count = self.stage_counts.entry(stage).or_insert(0);
        if delta > 0 {
            *count += delta as usize;
        } else {
            *count = count.saturating_sub((-delta) as usize);
        }
    }
}

/// Lifecycle statistics
#[derive(Debug, Clone)]
pub struct LifecycleStats {
    pub total_content: usize,
    pub total_size: u64,
    pub avg_age_secs: u64,
    pub total_accesses: u64,
    pub stage_counts: HashMap<LifecycleStage, usize>,
}

/// Helper function to format duration in human-readable form
fn humanize_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_stage_next() {
        assert_eq!(
            LifecycleStage::Creating.next_stage(),
            Some(LifecycleStage::Active)
        );
        assert_eq!(
            LifecycleStage::Active.next_stage(),
            Some(LifecycleStage::Declining)
        );
        assert_eq!(
            LifecycleStage::Declining.next_stage(),
            Some(LifecycleStage::Archived)
        );
        assert_eq!(
            LifecycleStage::Archived.next_stage(),
            Some(LifecycleStage::MarkedForDeletion)
        );
        assert_eq!(
            LifecycleStage::MarkedForDeletion.next_stage(),
            Some(LifecycleStage::Deleted)
        );
        assert_eq!(LifecycleStage::Deleted.next_stage(), None);
    }

    #[test]
    fn test_lifecycle_stage_can_reactivate() {
        assert!(!LifecycleStage::Creating.can_reactivate());
        assert!(!LifecycleStage::Active.can_reactivate());
        assert!(LifecycleStage::Declining.can_reactivate());
        assert!(LifecycleStage::Archived.can_reactivate());
        assert!(!LifecycleStage::MarkedForDeletion.can_reactivate());
        assert!(!LifecycleStage::Deleted.can_reactivate());
    }

    #[test]
    fn test_content_lifecycle_new() {
        let lifecycle = ContentLifecycle::new("content1".to_string(), 1000);
        assert_eq!(lifecycle.content_id, "content1");
        assert_eq!(lifecycle.stage, LifecycleStage::Creating);
        assert_eq!(lifecycle.size_bytes, 1000);
        assert_eq!(lifecycle.access_count, 0);
        assert_eq!(lifecycle.importance_score, 0.5);
    }

    #[test]
    fn test_content_lifecycle_record_access() {
        let mut lifecycle = ContentLifecycle::new("content1".to_string(), 1000);
        assert_eq!(lifecycle.access_count, 0);

        lifecycle.record_access();
        assert_eq!(lifecycle.access_count, 1);

        lifecycle.record_access();
        assert_eq!(lifecycle.access_count, 2);
    }

    #[test]
    fn test_content_lifecycle_access_rate() {
        let mut lifecycle = ContentLifecycle::new("content1".to_string(), 1000);

        // Simulate 10 accesses
        for _ in 0..10 {
            lifecycle.record_access();
        }

        let rate = lifecycle.access_rate();
        assert!(rate >= 0.0); // Should be positive
    }

    #[test]
    fn test_lifecycle_policy_default() {
        let policy = LifecyclePolicy::default();
        assert_eq!(
            policy.declining_threshold,
            Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(
            policy.archive_threshold,
            Duration::from_secs(30 * 24 * 3600)
        );
        assert_eq!(
            policy.deletion_threshold,
            Duration::from_secs(90 * 24 * 3600)
        );
        assert_eq!(policy.min_importance_for_keep, 0.7);
        assert_eq!(policy.min_active_access_rate, 0.1);
    }

    #[test]
    fn test_manager_new() {
        let policy = LifecyclePolicy::default();
        let manager = ContentLifecycleManager::new(policy);
        assert_eq!(manager.content.len(), 0);
    }

    #[test]
    fn test_manager_register_content() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        assert_eq!(manager.content.len(), 1);

        let lifecycle = manager.content.get("content1").unwrap();
        assert_eq!(lifecycle.stage, LifecycleStage::Creating);
    }

    #[test]
    fn test_manager_unregister_content() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        assert_eq!(manager.content.len(), 1);

        manager.unregister_content(&"content1".to_string());
        assert_eq!(manager.content.len(), 0);
    }

    #[test]
    fn test_manager_record_access() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.record_access(&"content1".to_string());

        let lifecycle = manager.content.get("content1").unwrap();
        assert_eq!(lifecycle.access_count, 1);
    }

    #[test]
    fn test_manager_update_importance() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.update_importance(&"content1".to_string(), 0.9);

        let lifecycle = manager.content.get("content1").unwrap();
        assert_eq!(lifecycle.importance_score, 0.9);
    }

    #[test]
    fn test_manager_transition_to() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        assert_eq!(
            manager.content.get("content1").unwrap().stage,
            LifecycleStage::Creating
        );

        manager.transition_to(
            &"content1".to_string(),
            LifecycleStage::Active,
            "Manual transition",
        );
        assert_eq!(
            manager.content.get("content1").unwrap().stage,
            LifecycleStage::Active
        );
    }

    #[test]
    fn test_manager_reactivation_on_access() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.transition_to(&"content1".to_string(), LifecycleStage::Declining, "Test");

        // Access should reactivate
        manager.record_access(&"content1".to_string());
        assert_eq!(
            manager.content.get("content1").unwrap().stage,
            LifecycleStage::Active
        );
    }

    #[test]
    fn test_manager_get_content_by_stage() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.register_content("content2".to_string(), 2000);
        manager.transition_to(&"content2".to_string(), LifecycleStage::Active, "Test");

        let creating = manager.get_content_by_stage(LifecycleStage::Creating);
        assert_eq!(creating.len(), 1);

        let active = manager.get_content_by_stage(LifecycleStage::Active);
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn test_manager_stats() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.register_content("content2".to_string(), 2000);

        let stats = manager.stats();
        assert_eq!(stats.total_content, 2);
        assert_eq!(stats.total_size, 3000);
    }

    #[test]
    fn test_manager_garbage_collection_candidates() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.register_content("content2".to_string(), 2000);
        manager.transition_to(&"content2".to_string(), LifecycleStage::Deleted, "Test");

        let candidates = manager.get_garbage_collection_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].content_id, "content2");
    }

    #[test]
    fn test_humanize_duration() {
        assert_eq!(humanize_duration(Duration::from_secs(30)), "30s");
        assert_eq!(humanize_duration(Duration::from_secs(120)), "2m");
        assert_eq!(humanize_duration(Duration::from_secs(7200)), "2h");
        assert_eq!(humanize_duration(Duration::from_secs(172800)), "2d");
    }

    #[test]
    fn test_evaluate_transitions_creating_to_active() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);

        // Simulate time passing by manually transitioning
        if let Some(lifecycle) = manager.content.get_mut("content1") {
            lifecycle.created_at = Instant::now() - Duration::from_secs(120);
            lifecycle.stage_changed_at = Instant::now() - Duration::from_secs(120);
        }

        let transitions = manager.evaluate_transitions();
        assert!(!transitions.is_empty());
        assert_eq!(transitions[0].to_stage, LifecycleStage::Active);
    }

    #[test]
    fn test_stage_counts_update() {
        let policy = LifecyclePolicy::default();
        let mut manager = ContentLifecycleManager::new(policy);

        manager.register_content("content1".to_string(), 1000);
        manager.register_content("content2".to_string(), 2000);

        assert_eq!(
            *manager
                .stage_counts
                .get(&LifecycleStage::Creating)
                .unwrap_or(&0),
            2
        );

        manager.transition_to(&"content1".to_string(), LifecycleStage::Active, "Test");
        assert_eq!(
            *manager
                .stage_counts
                .get(&LifecycleStage::Creating)
                .unwrap_or(&0),
            1
        );
        assert_eq!(
            *manager
                .stage_counts
                .get(&LifecycleStage::Active)
                .unwrap_or(&0),
            1
        );
    }
}
