//! Proof submission with retry logic.
//!
//! Handles submitting bandwidth proofs to the coordinator with
//! automatic retry on transient failures.

use chie_shared::BandwidthProof;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Configuration for proof submission.
#[derive(Debug, Clone)]
pub struct ProofSubmitConfig {
    /// Coordinator URL.
    pub coordinator_url: String,
    /// Maximum retry attempts.
    pub max_retries: u32,
    /// Initial retry delay.
    pub initial_delay: Duration,
    /// Maximum retry delay.
    pub max_delay: Duration,
    /// Retry backoff multiplier.
    pub backoff_multiplier: f64,
    /// Request timeout.
    pub timeout: Duration,
    /// Maximum queue size for pending submissions.
    pub max_queue_size: usize,
    /// Whether to persist queue to disk.
    pub persist_queue: bool,
}

impl Default for ProofSubmitConfig {
    fn default() -> Self {
        Self {
            coordinator_url: "http://localhost:3000".to_string(),
            max_retries: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            timeout: Duration::from_secs(30),
            max_queue_size: 1000,
            persist_queue: true,
        }
    }
}

/// Submission result from coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitResult {
    /// Whether submission was accepted.
    pub accepted: bool,
    /// Proof ID assigned by coordinator.
    pub proof_id: Option<uuid::Uuid>,
    /// Reward amount if calculated.
    pub reward: Option<u64>,
    /// Error message if rejected.
    pub error: Option<String>,
}

/// Submission state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitState {
    /// Waiting in queue.
    Pending,
    /// Currently being submitted.
    Submitting,
    /// Successfully submitted.
    Submitted,
    /// Failed after all retries.
    Failed,
}

/// A queued proof submission.
#[derive(Debug, Clone)]
pub struct QueuedProof {
    /// The proof to submit.
    pub proof: BandwidthProof,
    /// Current state.
    pub state: SubmitState,
    /// Number of attempts made.
    pub attempts: u32,
    /// Last attempt time.
    pub last_attempt: Option<Instant>,
    /// Last error message.
    pub last_error: Option<String>,
    /// Next retry time.
    pub next_retry: Option<Instant>,
    /// When the proof was queued.
    pub queued_at: Instant,
}

impl QueuedProof {
    fn new(proof: BandwidthProof) -> Self {
        Self {
            proof,
            state: SubmitState::Pending,
            attempts: 0,
            last_attempt: None,
            last_error: None,
            next_retry: None,
            queued_at: Instant::now(),
        }
    }
}

/// Submission statistics.
#[derive(Debug, Clone, Default)]
pub struct SubmitStats {
    /// Total proofs submitted successfully.
    pub total_submitted: u64,
    /// Total proofs failed.
    pub total_failed: u64,
    /// Total retries performed.
    pub total_retries: u64,
    /// Average submission time (ms).
    pub avg_submit_time_ms: f64,
    /// Current queue size.
    pub queue_size: usize,
    /// Proofs pending retry.
    pub pending_retry: usize,
}

/// Proof submitter with retry logic.
pub struct ProofSubmitter {
    config: ProofSubmitConfig,
    client: reqwest::Client,
    queue: Arc<RwLock<VecDeque<QueuedProof>>>,
    stats: Arc<RwLock<SubmitStats>>,
    running: Arc<RwLock<bool>>,
}

impl ProofSubmitter {
    /// Create a new proof submitter.
    #[must_use]
    #[inline]
    pub fn new(config: ProofSubmitConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            queue: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(SubmitStats::default())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Queue a proof for submission.
    pub async fn queue_proof(&self, proof: BandwidthProof) -> Result<(), ProofSubmitError> {
        let mut queue = self.queue.write().await;

        if queue.len() >= self.config.max_queue_size {
            return Err(ProofSubmitError::QueueFull);
        }

        queue.push_back(QueuedProof::new(proof));

        let mut stats = self.stats.write().await;
        stats.queue_size = queue.len();

        debug!("Queued proof for submission, queue size: {}", queue.len());
        Ok(())
    }

    /// Submit a proof immediately (bypassing queue).
    pub async fn submit_now(
        &self,
        proof: &BandwidthProof,
    ) -> Result<SubmitResult, ProofSubmitError> {
        self.do_submit(proof).await
    }

    /// Submit a proof with retry logic.
    pub async fn submit_with_retry(
        &self,
        proof: BandwidthProof,
    ) -> Result<SubmitResult, ProofSubmitError> {
        let mut attempts = 0;
        let mut delay = self.config.initial_delay;
        let mut last_error = None;

        while attempts < self.config.max_retries {
            attempts += 1;

            match self.do_submit(&proof).await {
                Ok(result) => {
                    if result.accepted {
                        let mut stats = self.stats.write().await;
                        stats.total_submitted += 1;
                        if attempts > 1 {
                            stats.total_retries += attempts as u64 - 1;
                        }
                        return Ok(result);
                    } else {
                        // Rejected by coordinator - don't retry
                        return Ok(result);
                    }
                }
                Err(e) if e.is_retryable() => {
                    last_error = Some(e);
                    warn!(
                        "Proof submission attempt {} failed, retrying in {:?}",
                        attempts, delay
                    );
                    tokio::time::sleep(delay).await;

                    // Exponential backoff
                    delay = Duration::from_secs_f64(
                        (delay.as_secs_f64() * self.config.backoff_multiplier)
                            .min(self.config.max_delay.as_secs_f64()),
                    );
                }
                Err(e) => {
                    // Non-retryable error
                    return Err(e);
                }
            }
        }

        let mut stats = self.stats.write().await;
        stats.total_failed += 1;
        stats.total_retries += attempts as u64;

        Err(last_error.unwrap_or(ProofSubmitError::MaxRetriesExceeded))
    }

    /// Start the background submission worker.
    pub async fn start_worker(&self) {
        let mut running = self.running.write().await;
        if *running {
            return;
        }
        *running = true;
        drop(running);

        info!("Starting proof submission worker");

        loop {
            {
                let running = self.running.read().await;
                if !*running {
                    break;
                }
            }

            // Process the queue
            if let Err(e) = self.process_queue().await {
                error!("Queue processing error: {}", e);
            }

            // Small delay between processing cycles
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("Proof submission worker stopped");
    }

    /// Stop the background worker.
    pub async fn stop_worker(&self) {
        let mut running = self.running.write().await;
        *running = false;
    }

    /// Process queued proofs.
    async fn process_queue(&self) -> Result<(), ProofSubmitError> {
        let mut queue = self.queue.write().await;

        if queue.is_empty() {
            return Ok(());
        }

        let now = Instant::now();

        // Find next proof ready for processing
        let ready_idx = queue.iter().position(|p| {
            p.state == SubmitState::Pending
                || (p.state == SubmitState::Submitting && p.next_retry.is_none_or(|t| now >= t))
        });

        if let Some(idx) = ready_idx {
            let mut queued = queue.remove(idx).unwrap();
            queued.state = SubmitState::Submitting;
            queued.last_attempt = Some(now);
            queued.attempts += 1;

            // Release lock while submitting
            drop(queue);

            let start = Instant::now();
            let result = self.do_submit(&queued.proof).await;
            let submit_time = start.elapsed().as_millis() as f64;

            let mut queue = self.queue.write().await;
            let mut stats = self.stats.write().await;

            // Update average submit time
            let n = stats.total_submitted + stats.total_failed;
            stats.avg_submit_time_ms =
                (stats.avg_submit_time_ms * n as f64 + submit_time) / (n + 1) as f64;

            match result {
                Ok(res) if res.accepted => {
                    queued.state = SubmitState::Submitted;
                    stats.total_submitted += 1;
                    debug!("Proof submitted successfully: {:?}", res.proof_id);
                    // Don't re-add to queue - it's done
                }
                Ok(res) => {
                    // Rejected - don't retry
                    queued.state = SubmitState::Failed;
                    queued.last_error = res.error.clone();
                    stats.total_failed += 1;
                    warn!("Proof rejected by coordinator: {:?}", res.error);
                }
                Err(e) if e.is_retryable() && queued.attempts < self.config.max_retries => {
                    // Retryable error - schedule retry
                    let delay = self.calculate_delay(queued.attempts);
                    queued.next_retry = Some(Instant::now() + delay);
                    queued.state = SubmitState::Pending;
                    queued.last_error = Some(e.to_string());
                    stats.total_retries += 1;
                    stats.pending_retry += 1;
                    queue.push_back(queued);
                    warn!("Proof submission failed, scheduled retry in {:?}", delay);
                }
                Err(e) => {
                    // Non-retryable or max retries exceeded
                    queued.state = SubmitState::Failed;
                    queued.last_error = Some(e.to_string());
                    stats.total_failed += 1;
                    error!("Proof submission failed permanently: {}", e);
                }
            }

            stats.queue_size = queue.len();
        }

        Ok(())
    }

    /// Calculate delay for retry attempt.
    #[must_use]
    #[inline]
    fn calculate_delay(&self, attempts: u32) -> Duration {
        let delay_secs = self.config.initial_delay.as_secs_f64()
            * self.config.backoff_multiplier.powi(attempts as i32 - 1);
        Duration::from_secs_f64(delay_secs.min(self.config.max_delay.as_secs_f64()))
    }

    /// Perform the actual HTTP submission.
    async fn do_submit(&self, proof: &BandwidthProof) -> Result<SubmitResult, ProofSubmitError> {
        let url = format!("{}/api/proofs/submit", self.config.coordinator_url);

        let response = self
            .client
            .post(&url)
            .json(proof)
            .send()
            .await
            .map_err(ProofSubmitError::Http)?;

        let status = response.status();

        if status.is_success() {
            let result: SubmitResult = response.json().await.map_err(ProofSubmitError::Http)?;
            Ok(result)
        } else if status.is_server_error() {
            // Server error - retryable
            let error_text = response.text().await.unwrap_or_default();
            Err(ProofSubmitError::ServerError {
                status: status.as_u16(),
                message: error_text,
            })
        } else {
            // Client error - not retryable
            let error_text = response.text().await.unwrap_or_default();
            Err(ProofSubmitError::ClientError {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    /// Get current statistics.
    #[must_use]
    #[inline]
    pub async fn stats(&self) -> SubmitStats {
        self.stats.read().await.clone()
    }

    /// Get queue size.
    #[must_use]
    #[inline]
    pub async fn queue_size(&self) -> usize {
        self.queue.read().await.len()
    }

    /// Clear the queue (drops all pending proofs).
    pub async fn clear_queue(&self) {
        let mut queue = self.queue.write().await;
        let count = queue.len();
        queue.clear();

        let mut stats = self.stats.write().await;
        stats.queue_size = 0;
        stats.pending_retry = 0;

        info!("Cleared {} proofs from submission queue", count);
    }

    /// Drain and return all failed proofs.
    #[must_use]
    pub async fn drain_failed(&self) -> Vec<QueuedProof> {
        let mut queue = self.queue.write().await;
        let failed: Vec<_> = queue
            .iter()
            .filter(|p| p.state == SubmitState::Failed)
            .cloned()
            .collect();

        queue.retain(|p| p.state != SubmitState::Failed);

        let mut stats = self.stats.write().await;
        stats.queue_size = queue.len();

        failed
    }
}

/// Proof submission error.
#[derive(Debug)]
pub enum ProofSubmitError {
    /// HTTP request failed.
    Http(reqwest::Error),
    /// Server error (5xx).
    ServerError { status: u16, message: String },
    /// Client error (4xx).
    ClientError { status: u16, message: String },
    /// Queue is full.
    QueueFull,
    /// Maximum retries exceeded.
    MaxRetriesExceeded,
    /// Serialization error.
    Serialization(serde_json::Error),
}

impl ProofSubmitError {
    /// Check if this error is retryable.
    #[must_use]
    #[inline]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http(e) => e.is_timeout() || e.is_connect(),
            Self::ServerError { .. } => true,
            Self::ClientError { .. } => false,
            Self::QueueFull => false,
            Self::MaxRetriesExceeded => false,
            Self::Serialization(_) => false,
        }
    }
}

impl std::fmt::Display for ProofSubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "HTTP error: {}", e),
            Self::ServerError { status, message } => {
                write!(f, "Server error {}: {}", status, message)
            }
            Self::ClientError { status, message } => {
                write!(f, "Client error {}: {}", status, message)
            }
            Self::QueueFull => write!(f, "Submission queue is full"),
            Self::MaxRetriesExceeded => write!(f, "Maximum retries exceeded"),
            Self::Serialization(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for ProofSubmitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(e) => Some(e),
            Self::Serialization(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ProofSubmitConfig::default();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_delay_calculation() {
        let config = ProofSubmitConfig::default();
        let submitter = ProofSubmitter::new(config);

        let delay1 = submitter.calculate_delay(1);
        let delay2 = submitter.calculate_delay(2);
        let delay3 = submitter.calculate_delay(3);

        assert_eq!(delay1, Duration::from_secs(1));
        assert_eq!(delay2, Duration::from_secs(2));
        assert_eq!(delay3, Duration::from_secs(4));
    }

    #[test]
    fn test_error_retryable() {
        assert!(
            ProofSubmitError::ServerError {
                status: 500,
                message: "Internal error".to_string()
            }
            .is_retryable()
        );

        assert!(
            !ProofSubmitError::ClientError {
                status: 400,
                message: "Bad request".to_string()
            }
            .is_retryable()
        );

        assert!(!ProofSubmitError::QueueFull.is_retryable());
    }

    #[tokio::test]
    async fn test_queue_proof() {
        let config = ProofSubmitConfig::default();
        let submitter = ProofSubmitter::new(config);

        // Create a dummy proof
        let proof = BandwidthProof {
            session_id: uuid::Uuid::new_v4(),
            content_cid: "QmTest".to_string(),
            chunk_index: 0,
            bytes_transferred: 1024,
            provider_peer_id: "provider".to_string(),
            requester_peer_id: "requester".to_string(),
            provider_public_key: vec![0u8; 32],
            requester_public_key: vec![0u8; 32],
            provider_signature: vec![0u8; 64],
            requester_signature: vec![0u8; 64],
            challenge_nonce: vec![0u8; 32],
            chunk_hash: vec![0u8; 32],
            start_timestamp_ms: 0,
            end_timestamp_ms: 100,
            latency_ms: 100,
        };

        submitter.queue_proof(proof).await.unwrap();
        assert_eq!(submitter.queue_size().await, 1);
    }
}
