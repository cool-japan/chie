//! Job progress tracking for workers.
//!
//! This module provides:
//! - Real-time progress updates for long-running jobs
//! - Progress persistence in Redis
//! - Progress callbacks and notifications

use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Job progress information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    /// Job ID.
    pub job_id: Uuid,
    /// Progress percentage (0-100).
    pub percent: f64,
    /// Current step description.
    pub current_step: String,
    /// Total steps.
    pub total_steps: u32,
    /// Completed steps.
    pub completed_steps: u32,
    /// Bytes processed (if applicable).
    pub bytes_processed: u64,
    /// Total bytes (if applicable).
    pub total_bytes: u64,
    /// Items processed (if applicable).
    pub items_processed: u64,
    /// Total items (if applicable).
    pub total_items: u64,
    /// Estimated time remaining (seconds).
    pub eta_seconds: Option<u64>,
    /// Started at.
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Last updated at.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Additional metadata.
    pub metadata: std::collections::HashMap<String, String>,
}

impl JobProgress {
    /// Create a new progress tracker for a job.
    pub fn new(job_id: Uuid) -> Self {
        let now = chrono::Utc::now();
        Self {
            job_id,
            percent: 0.0,
            current_step: String::new(),
            total_steps: 1,
            completed_steps: 0,
            bytes_processed: 0,
            total_bytes: 0,
            items_processed: 0,
            total_items: 0,
            eta_seconds: None,
            started_at: now,
            updated_at: now,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Set total steps.
    pub fn with_total_steps(mut self, steps: u32) -> Self {
        self.total_steps = steps;
        self
    }

    /// Set total bytes.
    pub fn with_total_bytes(mut self, bytes: u64) -> Self {
        self.total_bytes = bytes;
        self
    }

    /// Set total items.
    pub fn with_total_items(mut self, items: u64) -> Self {
        self.total_items = items;
        self
    }

    /// Update progress by incrementing completed steps.
    pub fn complete_step(&mut self, description: &str) {
        self.completed_steps += 1;
        self.current_step = description.to_string();
        self.update_percent();
        self.updated_at = chrono::Utc::now();
    }

    /// Update bytes processed.
    pub fn update_bytes(&mut self, bytes: u64) {
        self.bytes_processed = bytes;
        if self.total_bytes > 0 {
            self.percent = (bytes as f64 / self.total_bytes as f64) * 100.0;
        }
        self.calculate_eta();
        self.updated_at = chrono::Utc::now();
    }

    /// Update items processed.
    pub fn update_items(&mut self, items: u64) {
        self.items_processed = items;
        if self.total_items > 0 {
            self.percent = (items as f64 / self.total_items as f64) * 100.0;
        }
        self.calculate_eta();
        self.updated_at = chrono::Utc::now();
    }

    /// Set current step description.
    pub fn set_step(&mut self, description: &str) {
        self.current_step = description.to_string();
        self.updated_at = chrono::Utc::now();
    }

    /// Add metadata.
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    fn update_percent(&mut self) {
        if self.total_steps > 0 {
            self.percent = (self.completed_steps as f64 / self.total_steps as f64) * 100.0;
        }
        self.calculate_eta();
    }

    fn calculate_eta(&mut self) {
        let elapsed = (self.updated_at - self.started_at).num_seconds() as f64;
        if elapsed > 0.0 && self.percent > 0.0 && self.percent < 100.0 {
            let total_estimated = elapsed / (self.percent / 100.0);
            let remaining = total_estimated - elapsed;
            self.eta_seconds = Some(remaining.max(0.0) as u64);
        }
    }
}

/// Progress tracker that persists to Redis.
pub struct ProgressTracker {
    conn: MultiplexedConnection,
    key_prefix: String,
    ttl_seconds: u64,
}

impl ProgressTracker {
    /// Create a new progress tracker.
    pub async fn new(
        redis_url: &str,
        key_prefix: impl Into<String>,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self {
            conn,
            key_prefix: key_prefix.into(),
            ttl_seconds: 3600, // 1 hour default TTL
        })
    }

    /// Get the Redis key for a job's progress.
    fn progress_key(&self, job_id: &Uuid) -> String {
        format!("{}:progress:{}", self.key_prefix, job_id)
    }

    /// Save progress to Redis.
    pub async fn save_progress(&mut self, progress: &JobProgress) -> Result<(), redis::RedisError> {
        let key = self.progress_key(&progress.job_id);
        let data = serde_json::to_string(progress).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::Io,
                "JSON serialization error",
                e.to_string(),
            ))
        })?;

        self.conn
            .set_ex::<_, _, ()>(&key, data, self.ttl_seconds)
            .await?;

        Ok(())
    }

    /// Get progress from Redis.
    pub async fn get_progress(
        &mut self,
        job_id: &Uuid,
    ) -> Result<Option<JobProgress>, redis::RedisError> {
        let key = self.progress_key(job_id);
        let data: Option<String> = self.conn.get(&key).await?;

        match data {
            Some(json) => {
                let progress: JobProgress = serde_json::from_str(&json).map_err(|e| {
                    redis::RedisError::from((
                        redis::ErrorKind::Io,
                        "JSON deserialization error",
                        e.to_string(),
                    ))
                })?;
                Ok(Some(progress))
            }
            None => Ok(None),
        }
    }

    /// Delete progress (when job completes).
    pub async fn delete_progress(&mut self, job_id: &Uuid) -> Result<(), redis::RedisError> {
        let key = self.progress_key(job_id);
        self.conn.del::<_, ()>(&key).await?;
        Ok(())
    }

    /// List all tracked job IDs.
    pub async fn list_jobs(&mut self) -> Result<Vec<Uuid>, redis::RedisError> {
        let pattern = format!("{}:progress:*", self.key_prefix);
        let keys: Vec<String> = self.conn.keys(&pattern).await?;

        let jobs = keys
            .into_iter()
            .filter_map(|k| k.rsplit(':').next().and_then(|id| Uuid::parse_str(id).ok()))
            .collect();

        Ok(jobs)
    }
}

/// Progress reporter for use within job handlers.
pub struct ProgressReporter {
    progress: Arc<RwLock<JobProgress>>,
    tracker: Arc<RwLock<Option<ProgressTracker>>>,
    update_interval: Duration,
    last_update: Arc<RwLock<Instant>>,
}

impl ProgressReporter {
    /// Create a new progress reporter.
    pub fn new(job_id: Uuid) -> Self {
        Self {
            progress: Arc::new(RwLock::new(JobProgress::new(job_id))),
            tracker: Arc::new(RwLock::new(None)),
            update_interval: Duration::from_millis(500),
            last_update: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Create with a progress tracker for persistence.
    pub fn with_tracker(job_id: Uuid, tracker: ProgressTracker) -> Self {
        Self {
            progress: Arc::new(RwLock::new(JobProgress::new(job_id))),
            tracker: Arc::new(RwLock::new(Some(tracker))),
            update_interval: Duration::from_millis(500),
            last_update: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Set total steps.
    pub async fn set_total_steps(&self, steps: u32) {
        let mut progress = self.progress.write().await;
        progress.total_steps = steps;
    }

    /// Set total bytes.
    pub async fn set_total_bytes(&self, bytes: u64) {
        let mut progress = self.progress.write().await;
        progress.total_bytes = bytes;
    }

    /// Set total items.
    pub async fn set_total_items(&self, items: u64) {
        let mut progress = self.progress.write().await;
        progress.total_items = items;
    }

    /// Complete a step.
    pub async fn complete_step(&self, description: &str) {
        {
            let mut progress = self.progress.write().await;
            progress.complete_step(description);
        }
        self.maybe_persist().await;
    }

    /// Update bytes processed.
    pub async fn update_bytes(&self, bytes: u64) {
        {
            let mut progress = self.progress.write().await;
            progress.update_bytes(bytes);
        }
        self.maybe_persist().await;
    }

    /// Update items processed.
    pub async fn update_items(&self, items: u64) {
        {
            let mut progress = self.progress.write().await;
            progress.update_items(items);
        }
        self.maybe_persist().await;
    }

    /// Set current step description.
    pub async fn set_step(&self, description: &str) {
        let mut progress = self.progress.write().await;
        progress.set_step(description);
    }

    /// Get current progress snapshot.
    pub async fn get_progress(&self) -> JobProgress {
        self.progress.read().await.clone()
    }

    /// Force persist to Redis (if tracker is configured).
    pub async fn force_persist(&self) {
        let progress = self.progress.read().await.clone();
        let mut tracker = self.tracker.write().await;

        if let Some(ref mut t) = *tracker {
            if let Err(e) = t.save_progress(&progress).await {
                tracing::warn!("Failed to persist progress: {}", e);
            }
        }
    }

    /// Mark job as complete and cleanup.
    pub async fn complete(&self) {
        {
            let mut progress = self.progress.write().await;
            progress.percent = 100.0;
            progress.completed_steps = progress.total_steps;
            progress.bytes_processed = progress.total_bytes;
            progress.items_processed = progress.total_items;
            progress.updated_at = chrono::Utc::now();
        }

        let progress = self.progress.read().await;
        let mut tracker = self.tracker.write().await;

        if let Some(ref mut t) = *tracker {
            let _ = t.delete_progress(&progress.job_id).await;
        }
    }

    async fn maybe_persist(&self) {
        let should_update = {
            let last = self.last_update.read().await;
            last.elapsed() >= self.update_interval
        };

        if should_update {
            self.force_persist().await;
            let mut last = self.last_update.write().await;
            *last = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_progress_creation() {
        let job_id = Uuid::new_v4();
        let progress = JobProgress::new(job_id)
            .with_total_steps(5)
            .with_total_bytes(1000);

        assert_eq!(progress.total_steps, 5);
        assert_eq!(progress.total_bytes, 1000);
        assert_eq!(progress.percent, 0.0);
    }

    #[test]
    fn test_step_completion() {
        let job_id = Uuid::new_v4();
        let mut progress = JobProgress::new(job_id).with_total_steps(4);

        progress.complete_step("Step 1 done");
        assert_eq!(progress.completed_steps, 1);
        assert_eq!(progress.percent, 25.0);

        progress.complete_step("Step 2 done");
        assert_eq!(progress.completed_steps, 2);
        assert_eq!(progress.percent, 50.0);
    }

    #[test]
    fn test_bytes_progress() {
        let job_id = Uuid::new_v4();
        let mut progress = JobProgress::new(job_id).with_total_bytes(1000);

        progress.update_bytes(250);
        assert_eq!(progress.percent, 25.0);

        progress.update_bytes(750);
        assert_eq!(progress.percent, 75.0);
    }

    #[tokio::test]
    async fn test_progress_reporter() {
        let job_id = Uuid::new_v4();
        let reporter = ProgressReporter::new(job_id);

        reporter.set_total_steps(2).await;
        reporter.complete_step("First step").await;

        let progress = reporter.get_progress().await;
        assert_eq!(progress.completed_steps, 1);
        assert_eq!(progress.percent, 50.0);
    }
}
