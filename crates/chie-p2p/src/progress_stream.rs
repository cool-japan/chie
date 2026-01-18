//! Transfer progress streaming for UI updates.
//!
//! This module provides real-time progress streaming for transfers, allowing
//! UI components and monitoring systems to receive updates about ongoing transfers.
//!
//! # Features
//!
//! - Progress event streaming via channels
//! - Configurable update intervals
//! - Progress aggregation and statistics
//! - Multiple transfer tracking
//! - Bandwidth and ETA calculation

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// Transfer progress event
#[derive(Debug, Clone)]
pub enum ProgressEvent {
    /// Transfer started
    Started {
        transfer_id: String,
        content_hash: String,
        total_bytes: u64,
        total_chunks: u32,
    },
    /// Chunk downloaded
    ChunkProgress {
        transfer_id: String,
        chunk_index: u32,
        chunk_bytes: u64,
        downloaded_bytes: u64,
        total_bytes: u64,
        chunks_completed: u32,
        total_chunks: u32,
    },
    /// Transfer completed successfully
    Completed {
        transfer_id: String,
        content_hash: String,
        total_bytes: u64,
        duration: Duration,
        average_speed: f64,
    },
    /// Transfer failed
    Failed {
        transfer_id: String,
        content_hash: String,
        error: String,
        bytes_downloaded: u64,
    },
    /// Transfer paused
    Paused {
        transfer_id: String,
        bytes_downloaded: u64,
    },
    /// Transfer resumed
    Resumed {
        transfer_id: String,
        bytes_downloaded: u64,
    },
}

/// Transfer progress information
#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub transfer_id: String,
    pub content_hash: String,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub total_chunks: u32,
    pub completed_chunks: u32,
    pub start_time: Instant,
    pub last_update: Instant,
    pub average_speed: f64,
    pub current_speed: f64,
    pub eta_seconds: Option<u64>,
}

impl TransferProgress {
    /// Calculate progress percentage
    pub fn percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.downloaded_bytes as f64 / self.total_bytes as f64) * 100.0
    }

    /// Update progress with new chunk
    pub fn update_chunk(&mut self, chunk_bytes: u64) {
        self.downloaded_bytes += chunk_bytes;
        self.completed_chunks += 1;

        let now = Instant::now();
        let total_elapsed = now.duration_since(self.start_time).as_secs_f64();
        let recent_elapsed = now.duration_since(self.last_update).as_secs_f64();

        // Calculate average speed
        if total_elapsed > 0.0 {
            self.average_speed = self.downloaded_bytes as f64 / total_elapsed;
        }

        // Calculate current speed (based on last chunk)
        if recent_elapsed > 0.0 {
            self.current_speed = chunk_bytes as f64 / recent_elapsed;
        }

        // Calculate ETA
        if self.current_speed > 0.0 {
            let remaining_bytes = self.total_bytes.saturating_sub(self.downloaded_bytes);
            self.eta_seconds = Some((remaining_bytes as f64 / self.current_speed) as u64);
        }

        self.last_update = now;
    }
}

/// Progress stream configuration
#[derive(Debug, Clone)]
pub struct ProgressStreamConfig {
    /// Minimum interval between progress updates
    pub update_interval: Duration,
    /// Maximum number of events to buffer
    pub buffer_size: usize,
    /// Enable bandwidth calculation
    pub calculate_bandwidth: bool,
    /// Enable ETA calculation
    pub calculate_eta: bool,
}

impl Default for ProgressStreamConfig {
    fn default() -> Self {
        Self {
            update_interval: Duration::from_millis(100),
            buffer_size: 1000,
            calculate_bandwidth: true,
            calculate_eta: true,
        }
    }
}

/// Progress stream manager
pub struct ProgressStreamManager {
    config: ProgressStreamConfig,
    transfers: Arc<RwLock<HashMap<String, TransferProgress>>>,
    sender: broadcast::Sender<ProgressEvent>,
    last_updates: Arc<RwLock<HashMap<String, Instant>>>,
}

impl ProgressStreamManager {
    /// Create new progress stream manager
    pub fn new(config: ProgressStreamConfig) -> Self {
        let (sender, _) = broadcast::channel(config.buffer_size);

        Self {
            config,
            transfers: Arc::new(RwLock::new(HashMap::new())),
            sender,
            last_updates: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to progress events
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressEvent> {
        self.sender.subscribe()
    }

    /// Start a new transfer
    pub fn start_transfer(
        &self,
        transfer_id: String,
        content_hash: String,
        total_bytes: u64,
        total_chunks: u32,
    ) {
        let now = Instant::now();

        let progress = TransferProgress {
            transfer_id: transfer_id.clone(),
            content_hash: content_hash.clone(),
            total_bytes,
            downloaded_bytes: 0,
            total_chunks,
            completed_chunks: 0,
            start_time: now,
            last_update: now,
            average_speed: 0.0,
            current_speed: 0.0,
            eta_seconds: None,
        };

        self.transfers
            .write()
            .unwrap()
            .insert(transfer_id.clone(), progress);
        self.last_updates
            .write()
            .unwrap()
            .insert(transfer_id.clone(), now);

        let _ = self.sender.send(ProgressEvent::Started {
            transfer_id,
            content_hash,
            total_bytes,
            total_chunks,
        });
    }

    /// Update progress for a chunk
    pub fn update_chunk(&self, transfer_id: &str, chunk_index: u32, chunk_bytes: u64) {
        let mut transfers = self.transfers.write().unwrap();

        if let Some(progress) = transfers.get_mut(transfer_id) {
            progress.update_chunk(chunk_bytes);

            // Check if we should send update based on interval
            let should_update = {
                let last_updates = self.last_updates.read().unwrap();
                if let Some(last) = last_updates.get(transfer_id) {
                    last.elapsed() >= self.config.update_interval
                } else {
                    true
                }
            };

            if should_update {
                self.last_updates
                    .write()
                    .unwrap()
                    .insert(transfer_id.to_string(), Instant::now());

                let _ = self.sender.send(ProgressEvent::ChunkProgress {
                    transfer_id: transfer_id.to_string(),
                    chunk_index,
                    chunk_bytes,
                    downloaded_bytes: progress.downloaded_bytes,
                    total_bytes: progress.total_bytes,
                    chunks_completed: progress.completed_chunks,
                    total_chunks: progress.total_chunks,
                });
            }
        }
    }

    /// Mark transfer as completed
    pub fn complete_transfer(&self, transfer_id: &str) {
        let mut transfers = self.transfers.write().unwrap();

        if let Some(progress) = transfers.remove(transfer_id) {
            let duration = progress.start_time.elapsed();

            let _ = self.sender.send(ProgressEvent::Completed {
                transfer_id: transfer_id.to_string(),
                content_hash: progress.content_hash,
                total_bytes: progress.total_bytes,
                duration,
                average_speed: progress.average_speed,
            });

            self.last_updates.write().unwrap().remove(transfer_id);
        }
    }

    /// Mark transfer as failed
    pub fn fail_transfer(&self, transfer_id: &str, error: String) {
        let mut transfers = self.transfers.write().unwrap();

        if let Some(progress) = transfers.remove(transfer_id) {
            let _ = self.sender.send(ProgressEvent::Failed {
                transfer_id: transfer_id.to_string(),
                content_hash: progress.content_hash,
                error,
                bytes_downloaded: progress.downloaded_bytes,
            });

            self.last_updates.write().unwrap().remove(transfer_id);
        }
    }

    /// Pause transfer
    pub fn pause_transfer(&self, transfer_id: &str) {
        let transfers = self.transfers.read().unwrap();

        if let Some(progress) = transfers.get(transfer_id) {
            let _ = self.sender.send(ProgressEvent::Paused {
                transfer_id: transfer_id.to_string(),
                bytes_downloaded: progress.downloaded_bytes,
            });
        }
    }

    /// Resume transfer
    pub fn resume_transfer(&self, transfer_id: &str) {
        let transfers = self.transfers.read().unwrap();

        if let Some(progress) = transfers.get(transfer_id) {
            let _ = self.sender.send(ProgressEvent::Resumed {
                transfer_id: transfer_id.to_string(),
                bytes_downloaded: progress.downloaded_bytes,
            });
        }
    }

    /// Get current progress for a transfer
    pub fn get_progress(&self, transfer_id: &str) -> Option<TransferProgress> {
        self.transfers.read().unwrap().get(transfer_id).cloned()
    }

    /// Get all active transfers
    pub fn get_active_transfers(&self) -> Vec<TransferProgress> {
        self.transfers.read().unwrap().values().cloned().collect()
    }

    /// Get number of active transfers
    pub fn active_count(&self) -> usize {
        self.transfers.read().unwrap().len()
    }

    /// Get total bytes being transferred across all active transfers
    pub fn total_active_bytes(&self) -> u64 {
        self.transfers
            .read()
            .unwrap()
            .values()
            .map(|p| p.total_bytes)
            .sum()
    }

    /// Get total downloaded bytes across all active transfers
    pub fn total_downloaded_bytes(&self) -> u64 {
        self.transfers
            .read()
            .unwrap()
            .values()
            .map(|p| p.downloaded_bytes)
            .sum()
    }

    /// Get aggregate download speed across all transfers
    pub fn aggregate_speed(&self) -> f64 {
        self.transfers
            .read()
            .unwrap()
            .values()
            .map(|p| p.current_speed)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hash() -> String {
        "test_hash".to_string()
    }

    #[test]
    fn test_progress_percentage() {
        let now = Instant::now();
        let progress = TransferProgress {
            transfer_id: "test".to_string(),
            content_hash: create_test_hash(),
            total_bytes: 1000,
            downloaded_bytes: 250,
            total_chunks: 10,
            completed_chunks: 2,
            start_time: now,
            last_update: now,
            average_speed: 0.0,
            current_speed: 0.0,
            eta_seconds: None,
        };

        assert!((progress.percentage() - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_start_transfer() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());
        let mut rx = manager.subscribe();

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);

        let event = rx.try_recv().unwrap();
        match event {
            ProgressEvent::Started {
                transfer_id,
                total_bytes,
                total_chunks,
                ..
            } => {
                assert_eq!(transfer_id, "transfer1");
                assert_eq!(total_bytes, 1000);
                assert_eq!(total_chunks, 10);
            }
            _ => panic!("Expected Started event"),
        }

        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_update_chunk() {
        let config = ProgressStreamConfig {
            update_interval: Duration::from_millis(0), // No throttling for testing
            ..Default::default()
        };
        let manager = ProgressStreamManager::new(config);
        let mut rx = manager.subscribe();

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        let _ = rx.try_recv(); // Consume started event

        manager.update_chunk("transfer1", 0, 100);

        let event = rx.try_recv().unwrap();
        match event {
            ProgressEvent::ChunkProgress {
                transfer_id,
                chunk_index,
                chunk_bytes,
                downloaded_bytes,
                chunks_completed,
                ..
            } => {
                assert_eq!(transfer_id, "transfer1");
                assert_eq!(chunk_index, 0);
                assert_eq!(chunk_bytes, 100);
                assert_eq!(downloaded_bytes, 100);
                assert_eq!(chunks_completed, 1);
            }
            _ => panic!("Expected ChunkProgress event"),
        }
    }

    #[test]
    fn test_complete_transfer() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());
        let mut rx = manager.subscribe();

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        let _ = rx.try_recv(); // Consume started event

        manager.complete_transfer("transfer1");

        let event = rx.try_recv().unwrap();
        match event {
            ProgressEvent::Completed {
                transfer_id,
                total_bytes,
                ..
            } => {
                assert_eq!(transfer_id, "transfer1");
                assert_eq!(total_bytes, 1000);
            }
            _ => panic!("Expected Completed event"),
        }

        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_fail_transfer() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());
        let mut rx = manager.subscribe();

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        let _ = rx.try_recv(); // Consume started event

        manager.fail_transfer("transfer1", "Connection lost".to_string());

        let event = rx.try_recv().unwrap();
        match event {
            ProgressEvent::Failed {
                transfer_id,
                error,
                bytes_downloaded,
                ..
            } => {
                assert_eq!(transfer_id, "transfer1");
                assert_eq!(error, "Connection lost");
                assert_eq!(bytes_downloaded, 0);
            }
            _ => panic!("Expected Failed event"),
        }

        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_pause_resume() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());
        let mut rx = manager.subscribe();

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        let _ = rx.try_recv(); // Consume started event

        manager.pause_transfer("transfer1");
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, ProgressEvent::Paused { .. }));

        manager.resume_transfer("transfer1");
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, ProgressEvent::Resumed { .. }));
    }

    #[test]
    fn test_get_progress() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        manager.update_chunk("transfer1", 0, 100);

        let progress = manager.get_progress("transfer1").unwrap();
        assert_eq!(progress.downloaded_bytes, 100);
        assert_eq!(progress.completed_chunks, 1);
    }

    #[test]
    fn test_multiple_transfers() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        manager.start_transfer("transfer2".to_string(), create_test_hash(), 2000, 20);

        assert_eq!(manager.active_count(), 2);
        assert_eq!(manager.total_active_bytes(), 3000);

        manager.update_chunk("transfer1", 0, 100);
        manager.update_chunk("transfer2", 0, 200);

        assert_eq!(manager.total_downloaded_bytes(), 300);
    }

    #[test]
    fn test_aggregate_speed() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        manager.start_transfer("transfer2".to_string(), create_test_hash(), 2000, 20);

        // Simulate some downloads
        std::thread::sleep(Duration::from_millis(10));
        manager.update_chunk("transfer1", 0, 100);
        manager.update_chunk("transfer2", 0, 200);

        let speed = manager.aggregate_speed();
        assert!(speed > 0.0);
    }

    #[test]
    fn test_update_interval_throttling() {
        let config = ProgressStreamConfig {
            update_interval: Duration::from_millis(100),
            ..Default::default()
        };
        let manager = ProgressStreamManager::new(config);
        let mut rx = manager.subscribe();

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        let _ = rx.try_recv(); // Consume started event

        // Rapid updates should be throttled
        manager.update_chunk("transfer1", 0, 100);
        manager.update_chunk("transfer1", 1, 100);
        manager.update_chunk("transfer1", 2, 100);

        // Should only get one update due to throttling
        let count = std::iter::from_fn(|| rx.try_recv().ok()).count();
        assert!(count <= 2); // First update + maybe one more
    }

    #[test]
    fn test_bandwidth_calculation() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 10000, 100);

        // Simulate download over time
        std::thread::sleep(Duration::from_millis(50));
        manager.update_chunk("transfer1", 0, 1000);

        let progress = manager.get_progress("transfer1").unwrap();
        assert!(progress.average_speed > 0.0);
        assert!(progress.current_speed > 0.0);
    }

    #[test]
    fn test_eta_calculation() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 10000, 100);

        std::thread::sleep(Duration::from_millis(50));
        manager.update_chunk("transfer1", 0, 1000);

        let progress = manager.get_progress("transfer1").unwrap();
        assert!(progress.eta_seconds.is_some());
    }

    #[test]
    fn test_get_active_transfers() {
        let manager = ProgressStreamManager::new(ProgressStreamConfig::default());

        manager.start_transfer("transfer1".to_string(), create_test_hash(), 1000, 10);
        manager.start_transfer("transfer2".to_string(), create_test_hash(), 2000, 20);

        let active = manager.get_active_transfers();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_progress_update_chunk() {
        let now = Instant::now();
        let mut progress = TransferProgress {
            transfer_id: "test".to_string(),
            content_hash: create_test_hash(),
            total_bytes: 1000,
            downloaded_bytes: 0,
            total_chunks: 10,
            completed_chunks: 0,
            start_time: now,
            last_update: now,
            average_speed: 0.0,
            current_speed: 0.0,
            eta_seconds: None,
        };

        std::thread::sleep(Duration::from_millis(10));
        progress.update_chunk(100);

        assert_eq!(progress.downloaded_bytes, 100);
        assert_eq!(progress.completed_chunks, 1);
        assert!(progress.average_speed > 0.0);
        assert!(progress.current_speed > 0.0);
        assert!(progress.eta_seconds.is_some());
    }
}
