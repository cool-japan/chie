//! Content verification pipeline for automated integrity checking.
//!
//! This module provides a workflow orchestration system for verifying content integrity
//! across the P2P network, coordinating between integrity checkers, reputation systems,
//! and content routing.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Verification priority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerificationPriority {
    /// Background verification for cached content
    Background = 0,
    /// Low priority for non-critical content
    Low = 1,
    /// Normal priority for regular content
    Normal = 2,
    /// High priority for frequently accessed content
    High = 3,
    /// Critical priority for essential content
    Critical = 4,
}

/// Verification status for content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Pending verification
    Pending,
    /// Currently being verified
    InProgress,
    /// Verification passed
    Verified,
    /// Verification failed
    Failed,
    /// Verification skipped due to error
    Skipped,
}

/// Result of a verification operation.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Content ID that was verified
    pub content_id: String,
    /// Verification status
    pub status: VerificationStatus,
    /// Time taken to verify
    pub duration: Duration,
    /// Error message if verification failed
    pub error: Option<String>,
    /// Peer that provided the content
    pub provider: String,
}

/// A verification task in the pipeline.
#[derive(Debug, Clone)]
pub struct VerificationTask {
    /// Content ID to verify
    pub content_id: String,
    /// Expected hash of the content
    pub expected_hash: Vec<u8>,
    /// Priority of this task
    pub priority: VerificationPriority,
    /// Peer that provided this content
    pub provider: String,
    /// When this task was created
    pub created_at: Instant,
    /// Deadline for verification (if any)
    pub deadline: Option<Instant>,
}

/// Configuration for the verification pipeline.
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Maximum number of concurrent verifications
    pub max_concurrent: usize,
    /// Maximum queue size
    pub max_queue_size: usize,
    /// Default verification timeout
    pub verification_timeout: Duration,
    /// How long to keep results in history
    pub result_retention: Duration,
    /// Whether to retry failed verifications
    pub retry_failed: bool,
    /// Maximum retry attempts
    pub max_retries: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 4,
            max_queue_size: 1000,
            verification_timeout: Duration::from_secs(30),
            result_retention: Duration::from_secs(3600),
            retry_failed: true,
            max_retries: 3,
        }
    }
}

/// Statistics about the verification pipeline.
#[derive(Debug, Clone)]
pub struct PipelineStats {
    /// Total tasks enqueued
    pub tasks_enqueued: usize,
    /// Tasks currently in queue
    pub tasks_queued: usize,
    /// Tasks currently being processed
    pub tasks_in_progress: usize,
    /// Total tasks completed
    pub tasks_completed: usize,
    /// Tasks that passed verification
    pub tasks_verified: usize,
    /// Tasks that failed verification
    pub tasks_failed: usize,
    /// Tasks that were skipped
    pub tasks_skipped: usize,
    /// Average verification time
    pub avg_verification_time: f64,
    /// Success rate (verified / completed)
    pub success_rate: f64,
}

/// Content verification pipeline.
pub struct VerificationPipeline {
    config: PipelineConfig,
    queue: Arc<Mutex<VecDeque<VerificationTask>>>,
    in_progress: Arc<Mutex<HashMap<String, VerificationTask>>>,
    results: Arc<Mutex<Vec<(Instant, VerificationResult)>>>,
    stats: Arc<Mutex<PipelineStats>>,
    retry_count: Arc<Mutex<HashMap<String, usize>>>,
}

impl VerificationPipeline {
    /// Creates a new verification pipeline with default configuration.
    pub fn new() -> Self {
        Self::with_config(PipelineConfig::default())
    }

    /// Creates a new verification pipeline with custom configuration.
    pub fn with_config(config: PipelineConfig) -> Self {
        Self {
            config,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            in_progress: Arc::new(Mutex::new(HashMap::new())),
            results: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(PipelineStats {
                tasks_enqueued: 0,
                tasks_queued: 0,
                tasks_in_progress: 0,
                tasks_completed: 0,
                tasks_verified: 0,
                tasks_failed: 0,
                tasks_skipped: 0,
                avg_verification_time: 0.0,
                success_rate: 0.0,
            })),
            retry_count: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enqueues a verification task.
    pub fn enqueue(&self, task: VerificationTask) -> Result<(), String> {
        let mut queue = self.queue.lock().unwrap();

        if queue.len() >= self.config.max_queue_size {
            return Err("Queue is full".to_string());
        }

        // Insert based on priority
        let insert_pos = queue
            .iter()
            .position(|t| t.priority < task.priority)
            .unwrap_or(queue.len());

        queue.insert(insert_pos, task);

        let mut stats = self.stats.lock().unwrap();
        stats.tasks_enqueued += 1;
        stats.tasks_queued = queue.len();

        Ok(())
    }

    /// Gets the next task to process.
    pub fn next_task(&self) -> Option<VerificationTask> {
        let mut queue = self.queue.lock().unwrap();
        let task = queue.pop_front()?;

        let mut in_progress = self.in_progress.lock().unwrap();
        in_progress.insert(task.content_id.clone(), task.clone());

        let mut stats = self.stats.lock().unwrap();
        stats.tasks_queued = queue.len();
        stats.tasks_in_progress = in_progress.len();

        Some(task)
    }

    /// Checks if the pipeline can accept more work.
    pub fn can_accept_work(&self) -> bool {
        let in_progress = self.in_progress.lock().unwrap();
        in_progress.len() < self.config.max_concurrent
    }

    /// Records a verification result.
    pub fn record_result(&self, result: VerificationResult) {
        let content_id = result.content_id.clone();
        let status = result.status;

        // Remove from in-progress and save task for potential retry
        let task = {
            let mut in_progress = self.in_progress.lock().unwrap();
            in_progress.remove(&content_id)
        };

        // Add to results
        {
            let mut results = self.results.lock().unwrap();
            results.push((Instant::now(), result.clone()));

            // Cleanup old results
            let cutoff = Instant::now() - self.config.result_retention;
            results.retain(|(timestamp, _)| *timestamp >= cutoff);
        }

        // Update stats
        {
            let mut stats = self.stats.lock().unwrap();
            stats.tasks_in_progress = self.in_progress.lock().unwrap().len();
            stats.tasks_completed += 1;

            match status {
                VerificationStatus::Verified => stats.tasks_verified += 1,
                VerificationStatus::Failed => stats.tasks_failed += 1,
                VerificationStatus::Skipped => stats.tasks_skipped += 1,
                _ => {}
            }

            // Update average verification time
            let total_time = stats.avg_verification_time * (stats.tasks_completed - 1) as f64
                + result.duration.as_secs_f64();
            stats.avg_verification_time = total_time / stats.tasks_completed as f64;

            // Update success rate
            if stats.tasks_completed > 0 {
                stats.success_rate = stats.tasks_verified as f64 / stats.tasks_completed as f64;
            }
        }

        // Handle retries for failed verifications
        if status == VerificationStatus::Failed && self.config.retry_failed {
            if let Some(original_task) = task {
                let mut retry_count = self.retry_count.lock().unwrap();
                let count = retry_count.entry(content_id.clone()).or_insert(0);
                *count += 1;

                if *count < self.config.max_retries {
                    // Re-enqueue with lower priority
                    let retry_task = VerificationTask {
                        priority: VerificationPriority::Background,
                        ..original_task
                    };
                    let _ = self.enqueue(retry_task);
                } else {
                    // Max retries reached, remove from retry tracking
                    retry_count.remove(&content_id);
                }
            }
        }
    }

    /// Gets the result for a specific content ID.
    pub fn get_result(&self, content_id: &str) -> Option<VerificationResult> {
        let results = self.results.lock().unwrap();
        results
            .iter()
            .rev() // Most recent first
            .find(|(_, r)| r.content_id == content_id)
            .map(|(_, r)| r.clone())
    }

    /// Gets results for a specific peer.
    pub fn get_peer_results(&self, peer_id: &str) -> Vec<VerificationResult> {
        let results = self.results.lock().unwrap();
        results
            .iter()
            .filter(|(_, r)| r.provider == peer_id)
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Gets the peer's verification success rate.
    pub fn get_peer_success_rate(&self, peer_id: &str) -> f64 {
        let results = self.get_peer_results(peer_id);
        if results.is_empty() {
            return 0.0;
        }

        let verified = results
            .iter()
            .filter(|r| r.status == VerificationStatus::Verified)
            .count();

        verified as f64 / results.len() as f64
    }

    /// Checks if a task is overdue based on its deadline.
    pub fn is_overdue(&self, content_id: &str) -> bool {
        let in_progress = self.in_progress.lock().unwrap();
        if let Some(task) = in_progress.get(content_id) {
            if let Some(deadline) = task.deadline {
                return Instant::now() > deadline;
            }
        }
        false
    }

    /// Gets all overdue tasks.
    pub fn get_overdue_tasks(&self) -> Vec<VerificationTask> {
        let in_progress = self.in_progress.lock().unwrap();
        let now = Instant::now();

        in_progress
            .values()
            .filter(|task| {
                if let Some(deadline) = task.deadline {
                    now > deadline
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    /// Cancels a task.
    pub fn cancel_task(&self, content_id: &str) -> bool {
        // Try to remove from queue
        {
            let mut queue = self.queue.lock().unwrap();
            if let Some(pos) = queue.iter().position(|t| t.content_id == content_id) {
                queue.remove(pos);

                // Update stats
                let mut stats = self.stats.lock().unwrap();
                stats.tasks_queued = queue.len();
                return true;
            }
        }

        // Try to remove from in-progress
        {
            let mut in_progress = self.in_progress.lock().unwrap();
            if in_progress.remove(content_id).is_some() {
                // Update stats
                let mut stats = self.stats.lock().unwrap();
                stats.tasks_in_progress = in_progress.len();
                return true;
            }
        }

        false
    }

    /// Gets current statistics.
    pub fn stats(&self) -> PipelineStats {
        self.stats.lock().unwrap().clone()
    }

    /// Clears all queues and resets statistics.
    pub fn clear(&self) {
        self.queue.lock().unwrap().clear();
        self.in_progress.lock().unwrap().clear();
        self.results.lock().unwrap().clear();
        self.retry_count.lock().unwrap().clear();

        let mut stats = self.stats.lock().unwrap();
        *stats = PipelineStats {
            tasks_enqueued: 0,
            tasks_queued: 0,
            tasks_in_progress: 0,
            tasks_completed: 0,
            tasks_verified: 0,
            tasks_failed: 0,
            tasks_skipped: 0,
            avg_verification_time: 0.0,
            success_rate: 0.0,
        };
    }
}

impl Clone for VerificationPipeline {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            queue: Arc::new(Mutex::new(self.queue.lock().unwrap().clone())),
            in_progress: Arc::new(Mutex::new(self.in_progress.lock().unwrap().clone())),
            results: Arc::new(Mutex::new(self.results.lock().unwrap().clone())),
            stats: Arc::new(Mutex::new(self.stats.lock().unwrap().clone())),
            retry_count: Arc::new(Mutex::new(self.retry_count.lock().unwrap().clone())),
        }
    }
}

impl Default for VerificationPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_task(id: &str, priority: VerificationPriority) -> VerificationTask {
        VerificationTask {
            content_id: id.to_string(),
            expected_hash: vec![0u8; 32],
            priority,
            provider: "peer1".to_string(),
            created_at: Instant::now(),
            deadline: None,
        }
    }

    #[test]
    fn test_pipeline_new() {
        let pipeline = VerificationPipeline::new();
        let stats = pipeline.stats();

        assert_eq!(stats.tasks_enqueued, 0);
        assert_eq!(stats.tasks_completed, 0);
    }

    #[test]
    fn test_enqueue_task() {
        let pipeline = VerificationPipeline::new();
        let task = create_task("content1", VerificationPriority::Normal);

        let result = pipeline.enqueue(task);
        assert!(result.is_ok());

        let stats = pipeline.stats();
        assert_eq!(stats.tasks_enqueued, 1);
        assert_eq!(stats.tasks_queued, 1);
    }

    #[test]
    fn test_priority_ordering() {
        let pipeline = VerificationPipeline::new();

        pipeline
            .enqueue(create_task("low", VerificationPriority::Low))
            .unwrap();
        pipeline
            .enqueue(create_task("critical", VerificationPriority::Critical))
            .unwrap();
        pipeline
            .enqueue(create_task("normal", VerificationPriority::Normal))
            .unwrap();

        // Should dequeue in priority order
        let task1 = pipeline.next_task().unwrap();
        assert_eq!(task1.content_id, "critical");

        let task2 = pipeline.next_task().unwrap();
        assert_eq!(task2.content_id, "normal");

        let task3 = pipeline.next_task().unwrap();
        assert_eq!(task3.content_id, "low");
    }

    #[test]
    fn test_next_task() {
        let pipeline = VerificationPipeline::new();
        let task = create_task("content1", VerificationPriority::Normal);

        pipeline.enqueue(task).unwrap();

        let next = pipeline.next_task();
        assert!(next.is_some());
        assert_eq!(next.unwrap().content_id, "content1");

        let stats = pipeline.stats();
        assert_eq!(stats.tasks_queued, 0);
        assert_eq!(stats.tasks_in_progress, 1);
    }

    #[test]
    fn test_record_verified_result() {
        let pipeline = VerificationPipeline::new();
        let task = create_task("content1", VerificationPriority::Normal);

        pipeline.enqueue(task).unwrap();
        pipeline.next_task().unwrap();

        let result = VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(1),
            error: None,
            provider: "peer1".to_string(),
        };

        pipeline.record_result(result);

        let stats = pipeline.stats();
        assert_eq!(stats.tasks_completed, 1);
        assert_eq!(stats.tasks_verified, 1);
        assert_eq!(stats.success_rate, 1.0);
    }

    #[test]
    fn test_record_failed_result() {
        let pipeline = VerificationPipeline::new();
        let task = create_task("content1", VerificationPriority::Normal);

        pipeline.enqueue(task).unwrap();
        pipeline.next_task().unwrap();

        let result = VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Failed,
            duration: Duration::from_secs(1),
            error: Some("Hash mismatch".to_string()),
            provider: "peer1".to_string(),
        };

        pipeline.record_result(result);

        let stats = pipeline.stats();
        assert_eq!(stats.tasks_completed, 1);
        assert_eq!(stats.tasks_failed, 1);
        assert_eq!(stats.success_rate, 0.0);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_retry_failed() {
        let mut config = PipelineConfig::default();
        config.retry_failed = true;
        config.max_retries = 2;

        let pipeline = VerificationPipeline::with_config(config);
        let task = create_task("content1", VerificationPriority::Normal);

        pipeline.enqueue(task).unwrap();
        pipeline.next_task().unwrap();

        let result = VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Failed,
            duration: Duration::from_secs(1),
            error: Some("Hash mismatch".to_string()),
            provider: "peer1".to_string(),
        };

        pipeline.record_result(result);

        // Should have re-enqueued for retry
        let stats = pipeline.stats();
        assert!(stats.tasks_queued > 0);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_max_queue_size() {
        let mut config = PipelineConfig::default();
        config.max_queue_size = 2;

        let pipeline = VerificationPipeline::with_config(config);

        assert!(
            pipeline
                .enqueue(create_task("1", VerificationPriority::Normal))
                .is_ok()
        );
        assert!(
            pipeline
                .enqueue(create_task("2", VerificationPriority::Normal))
                .is_ok()
        );
        assert!(
            pipeline
                .enqueue(create_task("3", VerificationPriority::Normal))
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_can_accept_work() {
        let mut config = PipelineConfig::default();
        config.max_concurrent = 2;

        let pipeline = VerificationPipeline::with_config(config);

        assert!(pipeline.can_accept_work());

        pipeline
            .enqueue(create_task("1", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task();
        assert!(pipeline.can_accept_work());

        pipeline
            .enqueue(create_task("2", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task();
        assert!(!pipeline.can_accept_work());
    }

    #[test]
    fn test_get_result() {
        let pipeline = VerificationPipeline::new();
        let task = create_task("content1", VerificationPriority::Normal);

        pipeline.enqueue(task).unwrap();
        pipeline.next_task().unwrap();

        let result = VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(1),
            error: None,
            provider: "peer1".to_string(),
        };

        pipeline.record_result(result);

        let retrieved = pipeline.get_result("content1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().status, VerificationStatus::Verified);
    }

    #[test]
    fn test_get_peer_results() {
        let pipeline = VerificationPipeline::new();

        let mut task1 = create_task("content1", VerificationPriority::Normal);
        task1.provider = "peer1".to_string();

        let mut task2 = create_task("content2", VerificationPriority::Normal);
        task2.provider = "peer2".to_string();

        pipeline.enqueue(task1).unwrap();
        pipeline.next_task().unwrap();
        pipeline.record_result(VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(1),
            error: None,
            provider: "peer1".to_string(),
        });

        pipeline.enqueue(task2).unwrap();
        pipeline.next_task().unwrap();
        pipeline.record_result(VerificationResult {
            content_id: "content2".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(1),
            error: None,
            provider: "peer2".to_string(),
        });

        let peer1_results = pipeline.get_peer_results("peer1");
        assert_eq!(peer1_results.len(), 1);
        assert_eq!(peer1_results[0].content_id, "content1");
    }

    #[test]
    fn test_get_peer_success_rate() {
        let pipeline = VerificationPipeline::new();

        pipeline
            .enqueue(create_task("content1", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task().unwrap();
        pipeline.record_result(VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(1),
            error: None,
            provider: "peer1".to_string(),
        });

        pipeline
            .enqueue(create_task("content2", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task().unwrap();
        pipeline.record_result(VerificationResult {
            content_id: "content2".to_string(),
            status: VerificationStatus::Failed,
            duration: Duration::from_secs(1),
            error: Some("Error".to_string()),
            provider: "peer1".to_string(),
        });

        let success_rate = pipeline.get_peer_success_rate("peer1");
        assert_eq!(success_rate, 0.5);
    }

    #[test]
    fn test_cancel_task_in_queue() {
        let pipeline = VerificationPipeline::new();
        pipeline
            .enqueue(create_task("content1", VerificationPriority::Normal))
            .unwrap();

        assert!(pipeline.cancel_task("content1"));
        assert_eq!(pipeline.stats().tasks_queued, 0);
    }

    #[test]
    fn test_cancel_task_in_progress() {
        let pipeline = VerificationPipeline::new();
        pipeline
            .enqueue(create_task("content1", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task().unwrap();

        assert!(pipeline.cancel_task("content1"));
        assert_eq!(pipeline.stats().tasks_in_progress, 0);
    }

    #[test]
    fn test_clear() {
        let pipeline = VerificationPipeline::new();

        pipeline
            .enqueue(create_task("content1", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task().unwrap();

        pipeline.clear();

        let stats = pipeline.stats();
        assert_eq!(stats.tasks_queued, 0);
        assert_eq!(stats.tasks_in_progress, 0);
        assert_eq!(stats.tasks_enqueued, 0);
    }

    #[test]
    fn test_clone() {
        let pipeline1 = VerificationPipeline::new();
        pipeline1
            .enqueue(create_task("content1", VerificationPriority::Normal))
            .unwrap();

        let pipeline2 = pipeline1.clone();
        let stats = pipeline2.stats();

        assert_eq!(stats.tasks_queued, 1);
    }

    #[test]
    fn test_config_default() {
        let config = PipelineConfig::default();

        assert_eq!(config.max_concurrent, 4);
        assert_eq!(config.max_queue_size, 1000);
        assert!(config.retry_failed);
    }

    #[test]
    fn test_avg_verification_time() {
        let pipeline = VerificationPipeline::new();

        pipeline
            .enqueue(create_task("content1", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task().unwrap();
        pipeline.record_result(VerificationResult {
            content_id: "content1".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(2),
            error: None,
            provider: "peer1".to_string(),
        });

        pipeline
            .enqueue(create_task("content2", VerificationPriority::Normal))
            .unwrap();
        pipeline.next_task().unwrap();
        pipeline.record_result(VerificationResult {
            content_id: "content2".to_string(),
            status: VerificationStatus::Verified,
            duration: Duration::from_secs(4),
            error: None,
            provider: "peer1".to_string(),
        });

        let stats = pipeline.stats();
        assert_eq!(stats.avg_verification_time, 3.0);
    }
}
