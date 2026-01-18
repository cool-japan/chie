//! Batch proof processing for the coordinator.
//!
//! This module provides:
//! - Batch proof submission and verification
//! - Parallel proof processing
//! - Batch result aggregation

use chie_shared::BandwidthProof;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, warn};
use uuid::Uuid;

/// Configuration for batch processing.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Maximum concurrent verifications.
    pub max_concurrent: usize,
    /// Timeout for batch processing.
    pub timeout: Duration,
    /// Whether to continue on individual failures.
    pub continue_on_error: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            max_concurrent: 10,
            timeout: Duration::from_secs(30),
            continue_on_error: true,
        }
    }
}

/// Batch submission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSubmission {
    /// Batch ID (auto-generated if not provided).
    #[serde(default = "Uuid::new_v4")]
    pub batch_id: Uuid,
    /// Proofs to process.
    pub proofs: Vec<BandwidthProof>,
}

/// Result of processing a single proof in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult {
    /// Session ID of the proof.
    pub session_id: Uuid,
    /// Whether processing succeeded.
    pub success: bool,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Quality score (if verified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality_score: Option<f64>,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
}

/// Result of batch processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// Batch ID.
    pub batch_id: Uuid,
    /// Total proofs submitted.
    pub total: usize,
    /// Successfully processed count.
    pub success_count: usize,
    /// Failed count.
    pub failure_count: usize,
    /// Individual results.
    pub results: Vec<ProofResult>,
    /// Total processing time in milliseconds.
    pub total_time_ms: u64,
}

impl BatchResult {
    /// Get success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.success_count as f64 / self.total as f64) * 100.0
    }

    /// Get average processing time per proof.
    pub fn avg_processing_time_ms(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.results.iter().map(|r| r.processing_time_ms).sum();
        sum as f64 / self.results.len() as f64
    }
}

/// Batch processor for proofs.
pub struct BatchProcessor {
    config: BatchConfig,
    semaphore: Arc<Semaphore>,
}

impl Default for BatchProcessor {
    fn default() -> Self {
        Self::new(BatchConfig::default())
    }
}

impl BatchProcessor {
    /// Create a new batch processor.
    pub fn new(config: BatchConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self { config, semaphore }
    }

    /// Process a batch of proofs.
    pub async fn process<F, Fut>(&self, submission: BatchSubmission, verify_fn: F) -> BatchResult
    where
        F: Fn(BandwidthProof) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<f64, String>> + Send,
    {
        let start = std::time::Instant::now();
        let batch_id = submission.batch_id;
        let total = submission.proofs.len();

        if total > self.config.max_batch_size {
            return BatchResult {
                batch_id,
                total,
                success_count: 0,
                failure_count: total,
                results: vec![ProofResult {
                    session_id: Uuid::nil(),
                    success: false,
                    error: Some(format!(
                        "Batch size {} exceeds maximum {}",
                        total, self.config.max_batch_size
                    )),
                    quality_score: None,
                    processing_time_ms: 0,
                }],
                total_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        let mut handles = Vec::with_capacity(total);

        for proof in submission.proofs {
            let sem = self.semaphore.clone();
            let verify = verify_fn.clone();
            let session_id = proof.session_id;

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let proof_start = std::time::Instant::now();

                let result = verify(proof).await;
                let processing_time_ms = proof_start.elapsed().as_millis() as u64;

                match result {
                    Ok(quality_score) => ProofResult {
                        session_id,
                        success: true,
                        error: None,
                        quality_score: Some(quality_score),
                        processing_time_ms,
                    },
                    Err(e) => ProofResult {
                        session_id,
                        success: false,
                        error: Some(e),
                        quality_score: None,
                        processing_time_ms,
                    },
                }
            });

            handles.push(handle);
        }

        // Collect results
        let mut results = Vec::with_capacity(total);
        let mut success_count = 0;
        let mut failure_count = 0;

        for handle in handles {
            match handle.await {
                Ok(result) => {
                    if result.success {
                        success_count += 1;
                    } else {
                        failure_count += 1;
                    }
                    results.push(result);
                }
                Err(e) => {
                    warn!("Task panicked: {}", e);
                    failure_count += 1;
                    results.push(ProofResult {
                        session_id: Uuid::nil(),
                        success: false,
                        error: Some(format!("Task panicked: {}", e)),
                        quality_score: None,
                        processing_time_ms: 0,
                    });
                }
            }
        }

        let total_time_ms = start.elapsed().as_millis() as u64;

        debug!(
            "Batch {} processed: {}/{} success in {}ms",
            batch_id, success_count, total, total_time_ms
        );

        BatchResult {
            batch_id,
            total,
            success_count,
            failure_count,
            results,
            total_time_ms,
        }
    }

    /// Process proofs in chunks.
    pub async fn process_chunked<F, Fut>(
        &self,
        proofs: Vec<BandwidthProof>,
        chunk_size: usize,
        verify_fn: F,
    ) -> Vec<BatchResult>
    where
        F: Fn(BandwidthProof) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<f64, String>> + Send,
    {
        let mut results = Vec::new();

        for (i, chunk) in proofs.chunks(chunk_size).enumerate() {
            let submission = BatchSubmission {
                batch_id: Uuid::new_v4(),
                proofs: chunk.to_vec(),
            };

            debug!("Processing chunk {} with {} proofs", i, chunk.len());
            let result = self.process(submission, verify_fn.clone()).await;
            results.push(result);
        }

        results
    }
}

/// Aggregated statistics for multiple batches.
#[derive(Debug, Clone, Default)]
pub struct BatchStats {
    /// Total batches processed.
    pub batches_processed: usize,
    /// Total proofs processed.
    pub total_proofs: usize,
    /// Total successful proofs.
    pub total_success: usize,
    /// Total failed proofs.
    pub total_failures: usize,
    /// Total processing time in milliseconds.
    pub total_time_ms: u64,
    /// Quality score histogram (buckets: 0-20, 20-40, 40-60, 60-80, 80-100).
    pub quality_histogram: [usize; 5],
}

impl BatchStats {
    /// Add batch result to statistics.
    pub fn add_result(&mut self, result: &BatchResult) {
        self.batches_processed += 1;
        self.total_proofs += result.total;
        self.total_success += result.success_count;
        self.total_failures += result.failure_count;
        self.total_time_ms += result.total_time_ms;

        for r in &result.results {
            if let Some(score) = r.quality_score {
                let bucket = ((score * 100.0 / 20.0) as usize).min(4);
                self.quality_histogram[bucket] += 1;
            }
        }
    }

    /// Get overall success rate.
    pub fn success_rate(&self) -> f64 {
        if self.total_proofs == 0 {
            return 0.0;
        }
        (self.total_success as f64 / self.total_proofs as f64) * 100.0
    }

    /// Get average throughput (proofs per second).
    pub fn throughput(&self) -> f64 {
        if self.total_time_ms == 0 {
            return 0.0;
        }
        (self.total_proofs as f64 / self.total_time_ms as f64) * 1000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_proof(session_id: Uuid) -> BandwidthProof {
        BandwidthProof {
            session_id,
            chunk_index: 0,
            content_cid: "QmTest".to_string(),
            provider_peer_id: "provider123".to_string(),
            requester_peer_id: "requester456".to_string(),
            provider_public_key: vec![0u8; 32],
            requester_public_key: vec![0u8; 32],
            provider_signature: vec![0u8; 64],
            requester_signature: vec![0u8; 64],
            challenge_nonce: vec![0u8; 32],
            chunk_hash: vec![0u8; 32],
            bytes_transferred: 1000,
            start_timestamp_ms: 0,
            end_timestamp_ms: 100,
            latency_ms: 100,
        }
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let processor = BatchProcessor::default();

        let proofs = vec![
            create_test_proof(Uuid::new_v4()),
            create_test_proof(Uuid::new_v4()),
            create_test_proof(Uuid::new_v4()),
        ];

        let submission = BatchSubmission {
            batch_id: Uuid::new_v4(),
            proofs,
        };

        // Simple verification function that always succeeds
        let verify_fn = |_proof: BandwidthProof| async move { Ok(0.95) };

        let result = processor.process(submission, verify_fn).await;

        assert_eq!(result.total, 3);
        assert_eq!(result.success_count, 3);
        assert_eq!(result.failure_count, 0);
    }

    #[tokio::test]
    async fn test_batch_with_failures() {
        let processor = BatchProcessor::default();

        let proofs = vec![
            create_test_proof(Uuid::new_v4()),
            create_test_proof(Uuid::new_v4()),
        ];

        let submission = BatchSubmission {
            batch_id: Uuid::new_v4(),
            proofs,
        };

        // Verification that fails on first proof
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let verify_fn = move |_proof: BandwidthProof| {
            let c = counter_clone.clone();
            async move {
                let n = c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    Err("First proof failed".to_string())
                } else {
                    Ok(0.9)
                }
            }
        };

        let result = processor.process(submission, verify_fn).await;

        assert_eq!(result.total, 2);
        assert_eq!(result.success_count, 1);
        assert_eq!(result.failure_count, 1);
    }

    #[test]
    fn test_batch_stats() {
        let mut stats = BatchStats::default();

        let result = BatchResult {
            batch_id: Uuid::new_v4(),
            total: 10,
            success_count: 8,
            failure_count: 2,
            results: vec![],
            total_time_ms: 1000,
        };

        stats.add_result(&result);

        assert_eq!(stats.total_proofs, 10);
        assert_eq!(stats.total_success, 8);
        assert_eq!(stats.success_rate(), 80.0);
        assert_eq!(stats.throughput(), 10.0); // 10 proofs per 1000ms = 10/s
    }
}
