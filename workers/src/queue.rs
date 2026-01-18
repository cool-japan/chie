//! Redis-based job queue for background processing.

use redis::AsyncCommands;
use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use uuid::Uuid;

/// Queue error types.
#[derive(Debug, Error)]
pub enum QueueError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Queue is empty")]
    Empty,

    #[error("Job not found: {0}")]
    JobNotFound(Uuid),

    #[error("Max retries exceeded: {attempts} attempts")]
    MaxRetriesExceeded { attempts: u32 },

    #[error("Job cancelled: {0}")]
    Cancelled(Uuid),
}

/// Job status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    Retrying,
    Cancelled,
}

/// A job in the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job<T> {
    /// Unique job ID.
    pub id: Uuid,
    /// Job payload.
    pub payload: T,
    /// Current status.
    pub status: JobStatus,
    /// Number of attempts made.
    pub attempts: u32,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Created timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last updated timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Error message if failed.
    pub error: Option<String>,
}

impl<T> Job<T> {
    /// Create a new job.
    pub fn new(payload: T) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            payload,
            status: JobStatus::Pending,
            attempts: 0,
            max_retries: 3,
            created_at: now,
            updated_at: now,
            error: None,
        }
    }

    /// Create a job with custom max retries.
    pub fn with_max_retries(payload: T, max_retries: u32) -> Self {
        let mut job = Self::new(payload);
        job.max_retries = max_retries;
        job
    }
}

/// Queue configuration.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Redis key prefix for the queue.
    pub key_prefix: String,
    /// Visibility timeout for processing jobs (seconds).
    pub visibility_timeout: u64,
    /// Polling interval when queue is empty (milliseconds).
    pub poll_interval_ms: u64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            key_prefix: "chie:jobs".to_string(),
            visibility_timeout: 300, // 5 minutes
            poll_interval_ms: 1000,  // 1 second
        }
    }
}

/// Redis-based job queue.
pub struct JobQueue {
    conn: MultiplexedConnection,
    config: QueueConfig,
}

impl JobQueue {
    /// Create a new job queue.
    pub async fn new(redis_url: &str, config: QueueConfig) -> Result<Self, QueueError> {
        let client = redis::Client::open(redis_url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self { conn, config })
    }

    /// Get the pending queue key.
    fn pending_key(&self, queue_name: &str) -> String {
        format!("{}:{}:pending", self.config.key_prefix, queue_name)
    }

    /// Get the processing queue key.
    fn processing_key(&self, queue_name: &str) -> String {
        format!("{}:{}:processing", self.config.key_prefix, queue_name)
    }

    /// Get the job data key.
    fn job_key(&self, job_id: &Uuid) -> String {
        format!("{}:job:{}", self.config.key_prefix, job_id)
    }

    /// Get the dead letter queue key.
    fn dlq_key(&self, queue_name: &str) -> String {
        format!("{}:{}:dlq", self.config.key_prefix, queue_name)
    }

    /// Get the cancelled set key.
    fn cancelled_key(&self, queue_name: &str) -> String {
        format!("{}:{}:cancelled", self.config.key_prefix, queue_name)
    }

    /// Enqueue a new job.
    pub async fn enqueue<T: Serialize>(
        &mut self,
        queue_name: &str,
        job: Job<T>,
    ) -> Result<Uuid, QueueError> {
        let job_id = job.id;
        let job_data = serde_json::to_string(&job)?;

        // Store job data
        let job_key = self.job_key(&job_id);
        self.conn.set::<_, _, ()>(&job_key, &job_data).await?;

        // Add to pending queue
        let pending_key = self.pending_key(queue_name);
        self.conn
            .lpush::<_, _, ()>(&pending_key, job_id.to_string())
            .await?;

        tracing::debug!("Enqueued job {} to queue {}", job_id, queue_name);
        Ok(job_id)
    }

    /// Dequeue a job for processing.
    pub async fn dequeue<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
    ) -> Result<Option<Job<T>>, QueueError> {
        let pending_key = self.pending_key(queue_name);
        let processing_key = self.processing_key(queue_name);

        // Move from pending to processing atomically
        let job_id: Option<String> = self.conn.rpoplpush(&pending_key, &processing_key).await?;

        match job_id {
            Some(id) => {
                let job_uuid =
                    Uuid::parse_str(&id).map_err(|_| QueueError::JobNotFound(Uuid::nil()))?;

                // Get job data
                let job_key = self.job_key(&job_uuid);
                let job_data: Option<String> = self.conn.get(&job_key).await?;

                match job_data {
                    Some(data) => {
                        let mut job: Job<T> = serde_json::from_str(&data)?;
                        job.status = JobStatus::Processing;
                        job.attempts += 1;
                        job.updated_at = chrono::Utc::now();

                        // Update job data
                        let updated_data = serde_json::to_string(&job)?;
                        self.conn.set::<_, _, ()>(&job_key, &updated_data).await?;

                        Ok(Some(job))
                    }
                    None => Err(QueueError::JobNotFound(job_uuid)),
                }
            }
            None => Ok(None),
        }
    }

    /// Mark a job as completed.
    pub async fn complete<T: Serialize>(
        &mut self,
        queue_name: &str,
        job: &mut Job<T>,
    ) -> Result<(), QueueError> {
        job.status = JobStatus::Completed;
        job.updated_at = chrono::Utc::now();

        // Update job data
        let job_key = self.job_key(&job.id);
        let job_data = serde_json::to_string(&job)?;
        self.conn.set::<_, _, ()>(&job_key, &job_data).await?;

        // Remove from processing queue
        let processing_key = self.processing_key(queue_name);
        self.conn
            .lrem::<_, _, ()>(&processing_key, 1, job.id.to_string())
            .await?;

        // Set TTL for completed job data (keep for 1 hour)
        self.conn.expire::<_, ()>(&job_key, 3600).await?;

        tracing::debug!("Completed job {}", job.id);
        Ok(())
    }

    /// Mark a job as failed and retry if possible.
    pub async fn fail<T: Serialize>(
        &mut self,
        queue_name: &str,
        job: &mut Job<T>,
        error: &str,
    ) -> Result<bool, QueueError> {
        job.error = Some(error.to_string());
        job.updated_at = chrono::Utc::now();

        let processing_key = self.processing_key(queue_name);

        if job.attempts < job.max_retries {
            // Retry: move back to pending
            job.status = JobStatus::Retrying;

            let job_key = self.job_key(&job.id);
            let job_data = serde_json::to_string(&job)?;
            self.conn.set::<_, _, ()>(&job_key, &job_data).await?;

            // Remove from processing, add to pending
            self.conn
                .lrem::<_, _, ()>(&processing_key, 1, job.id.to_string())
                .await?;
            let pending_key = self.pending_key(queue_name);
            self.conn
                .lpush::<_, _, ()>(&pending_key, job.id.to_string())
                .await?;

            tracing::warn!("Retrying job {} (attempt {})", job.id, job.attempts);
            Ok(true)
        } else {
            // Max retries exceeded: move to DLQ
            job.status = JobStatus::Failed;

            let job_key = self.job_key(&job.id);
            let job_data = serde_json::to_string(&job)?;
            self.conn.set::<_, _, ()>(&job_key, &job_data).await?;

            // Remove from processing, add to DLQ
            self.conn
                .lrem::<_, _, ()>(&processing_key, 1, job.id.to_string())
                .await?;
            let dlq_key = self.dlq_key(queue_name);
            self.conn
                .lpush::<_, _, ()>(&dlq_key, job.id.to_string())
                .await?;

            tracing::error!(
                "Job {} failed after {} attempts: {}",
                job.id,
                job.attempts,
                error
            );
            Ok(false)
        }
    }

    /// Get the length of the pending queue.
    pub async fn pending_count(&mut self, queue_name: &str) -> Result<u64, QueueError> {
        let pending_key = self.pending_key(queue_name);
        let count: u64 = self.conn.llen(&pending_key).await?;
        Ok(count)
    }

    /// Get the length of the processing queue.
    pub async fn processing_count(&mut self, queue_name: &str) -> Result<u64, QueueError> {
        let processing_key = self.processing_key(queue_name);
        let count: u64 = self.conn.llen(&processing_key).await?;
        Ok(count)
    }

    /// Get the length of the dead letter queue.
    pub async fn dlq_count(&mut self, queue_name: &str) -> Result<u64, QueueError> {
        let dlq_key = self.dlq_key(queue_name);
        let count: u64 = self.conn.llen(&dlq_key).await?;
        Ok(count)
    }

    /// Get a job by ID.
    pub async fn get_job<T: DeserializeOwned + Serialize>(
        &mut self,
        job_id: &Uuid,
    ) -> Result<Option<Job<T>>, QueueError> {
        let job_key = self.job_key(job_id);
        let job_data: Option<String> = self.conn.get(&job_key).await?;

        match job_data {
            Some(data) => {
                let job: Job<T> = serde_json::from_str(&data)?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }
}

/// Worker that processes jobs from a queue.
pub struct Worker<T, F, Fut>
where
    T: DeserializeOwned + Serialize + Send + 'static,
    F: Fn(Job<T>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send,
{
    queue: JobQueue,
    queue_name: String,
    handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, F, Fut> Worker<T, F, Fut>
where
    T: DeserializeOwned + Serialize + Send + 'static,
    F: Fn(Job<T>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), String>> + Send,
{
    /// Create a new worker.
    pub fn new(queue: JobQueue, queue_name: impl Into<String>, handler: F) -> Self {
        Self {
            queue,
            queue_name: queue_name.into(),
            handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Run the worker loop.
    pub async fn run(&mut self) -> Result<(), QueueError> {
        tracing::info!("Starting worker for queue: {}", self.queue_name);

        loop {
            match self.queue.dequeue::<T>(&self.queue_name).await? {
                Some(mut job) => {
                    tracing::info!("Processing job: {}", job.id);

                    // Clone job for handler (since we need to mutate it after)
                    let job_for_handler = Job {
                        id: job.id,
                        payload: serde_json::from_str(&serde_json::to_string(&job.payload)?)?,
                        status: job.status,
                        attempts: job.attempts,
                        max_retries: job.max_retries,
                        created_at: job.created_at,
                        updated_at: job.updated_at,
                        error: job.error.clone(),
                    };

                    match (self.handler)(job_for_handler).await {
                        Ok(()) => {
                            self.queue.complete(&self.queue_name, &mut job).await?;
                        }
                        Err(error) => {
                            self.queue.fail(&self.queue_name, &mut job, &error).await?;
                        }
                    }
                }
                None => {
                    // Queue is empty, wait before polling again
                    sleep(Duration::from_millis(self.queue.config.poll_interval_ms)).await;
                }
            }
        }
    }
}

/// Queue statistics.
#[derive(Debug, Clone, Serialize)]
pub struct QueueStats {
    pub queue_name: String,
    pub pending: u64,
    pub processing: u64,
    pub dead_letter: u64,
}

impl JobQueue {
    /// Get queue statistics.
    pub async fn stats(&mut self, queue_name: &str) -> Result<QueueStats, QueueError> {
        Ok(QueueStats {
            queue_name: queue_name.to_string(),
            pending: self.pending_count(queue_name).await?,
            processing: self.processing_count(queue_name).await?,
            dead_letter: self.dlq_count(queue_name).await?,
        })
    }

    /// List job IDs in the dead letter queue.
    pub async fn list_dlq(
        &mut self,
        queue_name: &str,
        limit: isize,
    ) -> Result<Vec<Uuid>, QueueError> {
        let dlq_key = self.dlq_key(queue_name);
        let job_ids: Vec<String> = self.conn.lrange(&dlq_key, 0, limit - 1).await?;

        let uuids = job_ids
            .into_iter()
            .filter_map(|id| Uuid::parse_str(&id).ok())
            .collect();

        Ok(uuids)
    }

    /// Get jobs from the dead letter queue with full details.
    pub async fn get_dlq_jobs<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
        limit: isize,
    ) -> Result<Vec<Job<T>>, QueueError> {
        let job_ids = self.list_dlq(queue_name, limit).await?;
        let mut jobs = Vec::with_capacity(job_ids.len());

        for job_id in job_ids {
            if let Some(job) = self.get_job::<T>(&job_id).await? {
                jobs.push(job);
            }
        }

        Ok(jobs)
    }

    /// Requeue a single job from the dead letter queue.
    ///
    /// Resets the job's attempt counter and moves it back to the pending queue.
    pub async fn requeue_from_dlq<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
        job_id: &Uuid,
    ) -> Result<(), QueueError> {
        let dlq_key = self.dlq_key(queue_name);

        // Check if job exists in DLQ
        let job_id_str = job_id.to_string();
        let exists: i64 = self
            .conn
            .lpos(&dlq_key, &job_id_str, Default::default())
            .await
            .unwrap_or(-1);

        if exists < 0 {
            return Err(QueueError::JobNotFound(*job_id));
        }

        // Get and update job
        let job_key = self.job_key(job_id);
        let job_data: Option<String> = self.conn.get(&job_key).await?;

        match job_data {
            Some(data) => {
                let mut job: Job<T> = serde_json::from_str(&data)?;
                job.status = JobStatus::Pending;
                job.attempts = 0;
                job.error = None;
                job.updated_at = chrono::Utc::now();

                // Update job data
                let updated_data = serde_json::to_string(&job)?;
                self.conn.set::<_, _, ()>(&job_key, &updated_data).await?;

                // Remove from DLQ
                self.conn.lrem::<_, _, ()>(&dlq_key, 1, &job_id_str).await?;

                // Add to pending queue
                let pending_key = self.pending_key(queue_name);
                self.conn
                    .lpush::<_, _, ()>(&pending_key, &job_id_str)
                    .await?;

                tracing::info!("Requeued job {} from DLQ", job_id);
                Ok(())
            }
            None => Err(QueueError::JobNotFound(*job_id)),
        }
    }

    /// Requeue all jobs from the dead letter queue.
    ///
    /// Returns the number of jobs requeued.
    pub async fn requeue_all_dlq<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
    ) -> Result<u64, QueueError> {
        let job_ids = self.list_dlq(queue_name, -1).await?;
        let mut requeued = 0;

        for job_id in job_ids {
            match self.requeue_from_dlq::<T>(queue_name, &job_id).await {
                Ok(()) => requeued += 1,
                Err(e) => {
                    tracing::warn!("Failed to requeue job {}: {}", job_id, e);
                }
            }
        }

        tracing::info!(
            "Requeued {} jobs from DLQ for queue {}",
            requeued,
            queue_name
        );
        Ok(requeued)
    }

    /// Delete a job from the dead letter queue permanently.
    pub async fn delete_from_dlq(
        &mut self,
        queue_name: &str,
        job_id: &Uuid,
    ) -> Result<(), QueueError> {
        let dlq_key = self.dlq_key(queue_name);
        let job_key = self.job_key(job_id);
        let job_id_str = job_id.to_string();

        // Remove from DLQ
        self.conn.lrem::<_, _, ()>(&dlq_key, 1, &job_id_str).await?;

        // Delete job data
        self.conn.del::<_, ()>(&job_key).await?;

        tracing::info!("Deleted job {} from DLQ", job_id);
        Ok(())
    }

    /// Clear all jobs from the dead letter queue.
    ///
    /// Returns the number of jobs deleted.
    pub async fn clear_dlq(&mut self, queue_name: &str) -> Result<u64, QueueError> {
        let job_ids = self.list_dlq(queue_name, -1).await?;
        let count = job_ids.len() as u64;

        for job_id in job_ids {
            let job_key = self.job_key(&job_id);
            self.conn.del::<_, ()>(&job_key).await?;
        }

        // Delete the DLQ list
        let dlq_key = self.dlq_key(queue_name);
        self.conn.del::<_, ()>(&dlq_key).await?;

        tracing::info!("Cleared {} jobs from DLQ for queue {}", count, queue_name);
        Ok(count)
    }

    /// Peek at a job in the dead letter queue without removing it.
    pub async fn peek_dlq<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
    ) -> Result<Option<Job<T>>, QueueError> {
        let dlq_key = self.dlq_key(queue_name);
        let job_id: Option<String> = self.conn.lindex(&dlq_key, 0).await?;

        match job_id {
            Some(id) => {
                let job_uuid =
                    Uuid::parse_str(&id).map_err(|_| QueueError::JobNotFound(Uuid::nil()))?;
                self.get_job(&job_uuid).await
            }
            None => Ok(None),
        }
    }

    /// Cancel a pending job.
    ///
    /// Removes the job from the pending queue and marks it as cancelled.
    /// Returns true if the job was found and cancelled.
    pub async fn cancel_pending<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
        job_id: &Uuid,
    ) -> Result<bool, QueueError> {
        let pending_key = self.pending_key(queue_name);
        let job_id_str = job_id.to_string();

        // Try to remove from pending queue
        let removed: i64 = self.conn.lrem(&pending_key, 1, &job_id_str).await?;

        if removed > 0 {
            // Update job status
            let job_key = self.job_key(job_id);
            if let Some(data) = self.conn.get::<_, Option<String>>(&job_key).await? {
                let mut job: Job<T> = serde_json::from_str(&data)?;
                job.status = JobStatus::Cancelled;
                job.updated_at = chrono::Utc::now();

                let updated_data = serde_json::to_string(&job)?;
                self.conn.set::<_, _, ()>(&job_key, &updated_data).await?;

                // Set TTL for cancelled job data
                self.conn.expire::<_, ()>(&job_key, 3600).await?;
            }

            tracing::info!("Cancelled pending job {}", job_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Request cancellation of a processing job.
    ///
    /// This marks the job for cancellation. The worker should check
    /// `is_cancelled()` periodically and abort if cancelled.
    pub async fn request_cancellation(
        &mut self,
        queue_name: &str,
        job_id: &Uuid,
    ) -> Result<(), QueueError> {
        let cancelled_key = self.cancelled_key(queue_name);
        let job_id_str = job_id.to_string();

        // Add to cancelled set with TTL
        self.conn
            .sadd::<_, _, ()>(&cancelled_key, &job_id_str)
            .await?;

        tracing::info!("Requested cancellation for job {}", job_id);
        Ok(())
    }

    /// Check if a job has been cancelled.
    ///
    /// Workers should call this periodically during long-running jobs.
    pub async fn is_cancelled(
        &mut self,
        queue_name: &str,
        job_id: &Uuid,
    ) -> Result<bool, QueueError> {
        let cancelled_key = self.cancelled_key(queue_name);
        let job_id_str = job_id.to_string();

        let is_member: bool = self.conn.sismember(&cancelled_key, &job_id_str).await?;
        Ok(is_member)
    }

    /// Acknowledge cancellation and clean up.
    ///
    /// Called by worker after it has stopped processing the cancelled job.
    pub async fn acknowledge_cancellation<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
        job: &mut Job<T>,
    ) -> Result<(), QueueError> {
        let cancelled_key = self.cancelled_key(queue_name);
        let processing_key = self.processing_key(queue_name);
        let job_id_str = job.id.to_string();

        // Remove from cancelled set
        self.conn
            .srem::<_, _, ()>(&cancelled_key, &job_id_str)
            .await?;

        // Remove from processing queue
        self.conn
            .lrem::<_, _, ()>(&processing_key, 1, &job_id_str)
            .await?;

        // Update job status
        job.status = JobStatus::Cancelled;
        job.updated_at = chrono::Utc::now();

        let job_key = self.job_key(&job.id);
        let job_data = serde_json::to_string(&job)?;
        self.conn.set::<_, _, ()>(&job_key, &job_data).await?;

        // Set TTL for cancelled job data
        self.conn.expire::<_, ()>(&job_key, 3600).await?;

        tracing::info!("Acknowledged cancellation for job {}", job.id);
        Ok(())
    }

    /// Cancel all pending jobs in a queue.
    ///
    /// Returns the number of jobs cancelled.
    pub async fn cancel_all_pending<T: DeserializeOwned + Serialize>(
        &mut self,
        queue_name: &str,
    ) -> Result<u64, QueueError> {
        let pending_key = self.pending_key(queue_name);
        let job_ids: Vec<String> = self.conn.lrange(&pending_key, 0, -1).await?;
        let count = job_ids.len() as u64;

        for job_id_str in &job_ids {
            if let Ok(job_id) = Uuid::parse_str(job_id_str) {
                let _ = self.cancel_pending::<T>(queue_name, &job_id).await;
            }
        }

        tracing::info!("Cancelled {} pending jobs in queue {}", count, queue_name);
        Ok(count)
    }

    /// Get count of jobs pending cancellation.
    pub async fn cancellation_count(&mut self, queue_name: &str) -> Result<u64, QueueError> {
        let cancelled_key = self.cancelled_key(queue_name);
        let count: u64 = self.conn.scard(&cancelled_key).await?;
        Ok(count)
    }

    /// List jobs pending cancellation.
    pub async fn list_cancellations(&mut self, queue_name: &str) -> Result<Vec<Uuid>, QueueError> {
        let cancelled_key = self.cancelled_key(queue_name);
        let job_ids: Vec<String> = self.conn.smembers(&cancelled_key).await?;

        let uuids = job_ids
            .into_iter()
            .filter_map(|id| Uuid::parse_str(&id).ok())
            .collect();

        Ok(uuids)
    }
}

/// Dead letter queue item with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqItem<T> {
    /// The failed job.
    pub job: Job<T>,
    /// Time spent in DLQ.
    pub time_in_dlq: chrono::Duration,
    /// Original failure reason.
    pub failure_reason: Option<String>,
}

impl<T: Clone> DlqItem<T> {
    /// Create a DLQ item from a job.
    pub fn from_job(job: Job<T>) -> Self {
        let time_in_dlq = chrono::Utc::now() - job.updated_at;
        Self {
            failure_reason: job.error.clone(),
            job,
            time_in_dlq,
        }
    }
}
