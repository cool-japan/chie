//! Multi-source download coordinator.
//!
//! This module coordinates downloading content from multiple sources simultaneously
//! to maximize throughput and reliability.
//!
//! # Example
//! ```
//! use chie_p2p::multi_source_download::{MultiSourceDownloader, DownloaderConfig, SourceInfo};
//! use std::time::Duration;
//!
//! let config = DownloaderConfig {
//!     max_concurrent_sources: 5,
//!     chunk_timeout: Duration::from_secs(30),
//!     min_sources: 2,
//!     enable_redundancy: true,
//!     redundancy_factor: 1.2,
//! };
//!
//! let mut downloader = MultiSourceDownloader::new(config);
//!
//! // Start download
//! let content_id = "content-123".to_string();
//! downloader.start_download(content_id.clone(), 100); // 100 chunks
//!
//! // Add sources
//! let source1 = SourceInfo {
//!     peer_id: "peer1".to_string(),
//!     bandwidth: 1_000_000, // 1 Mbps
//!     latency: Duration::from_millis(50),
//!     reliability: 0.95,
//! };
//! downloader.add_source(&content_id, source1);
//! ```

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Chunk identifier
pub type ChunkId = u64;

/// Content identifier
pub type ContentId = String;

/// Peer identifier
pub type PeerId = String;

/// Source information
#[derive(Debug, Clone)]
pub struct SourceInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Estimated bandwidth (bytes/sec)
    pub bandwidth: u64,
    /// Average latency
    pub latency: Duration,
    /// Reliability score (0.0-1.0)
    pub reliability: f64,
}

impl SourceInfo {
    /// Calculate source quality score
    pub fn quality_score(&self) -> f64 {
        // Higher bandwidth, lower latency, higher reliability = higher score
        let bandwidth_score = (self.bandwidth as f64 / 1_000_000.0).min(10.0) / 10.0; // Normalize to 0-1
        let latency_score = 1.0 - (self.latency.as_millis() as f64 / 1000.0).min(1.0); // Lower is better
        let reliability_score = self.reliability;

        (bandwidth_score * 0.4 + latency_score * 0.3 + reliability_score * 0.3).clamp(0.0, 1.0)
    }
}

/// Chunk download state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkState {
    /// Pending download
    Pending,
    /// Assigned to a source
    Assigned(PeerId),
    /// Download in progress
    InProgress(PeerId, Instant),
    /// Downloaded successfully
    Completed(PeerId),
    /// Failed to download
    Failed(PeerId, u32), // peer_id, retry_count
}

/// Download session
#[derive(Debug, Clone)]
pub struct DownloadSession {
    /// Content ID
    pub content_id: ContentId,
    /// Total chunks
    pub total_chunks: u64,
    /// Chunk states
    pub chunk_states: HashMap<ChunkId, ChunkState>,
    /// Available sources
    pub sources: HashMap<PeerId, SourceInfo>,
    /// Active downloads per source
    pub active_per_source: HashMap<PeerId, usize>,
    /// Started at
    pub started_at: Instant,
    /// Completed at
    pub completed_at: Option<Instant>,
    /// Total bytes downloaded
    pub bytes_downloaded: u64,
}

impl DownloadSession {
    /// Calculate overall progress
    pub fn progress(&self) -> f64 {
        let completed = self
            .chunk_states
            .values()
            .filter(|s| matches!(s, ChunkState::Completed(_)))
            .count();
        completed as f64 / self.total_chunks as f64
    }

    /// Check if download is complete
    pub fn is_complete(&self) -> bool {
        self.chunk_states
            .values()
            .all(|s| matches!(s, ChunkState::Completed(_)))
    }

    /// Get download duration
    pub fn duration(&self) -> Duration {
        self.completed_at
            .unwrap_or_else(Instant::now)
            .duration_since(self.started_at)
    }

    /// Get average download speed (bytes/sec)
    pub fn average_speed(&self) -> f64 {
        let duration_secs = self.duration().as_secs_f64();
        if duration_secs > 0.0 {
            self.bytes_downloaded as f64 / duration_secs
        } else {
            0.0
        }
    }
}

/// Downloader configuration
#[derive(Debug, Clone)]
pub struct DownloaderConfig {
    /// Maximum concurrent sources
    pub max_concurrent_sources: usize,
    /// Chunk download timeout
    pub chunk_timeout: Duration,
    /// Minimum sources required
    pub min_sources: usize,
    /// Enable redundant downloads
    pub enable_redundancy: bool,
    /// Redundancy factor (>1.0 means download some chunks from multiple sources)
    pub redundancy_factor: f64,
}

impl Default for DownloaderConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sources: 5,
            chunk_timeout: Duration::from_secs(30),
            min_sources: 2,
            enable_redundancy: false,
            redundancy_factor: 1.0,
        }
    }
}

/// Multi-source downloader
pub struct MultiSourceDownloader {
    /// Configuration
    config: DownloaderConfig,
    /// Active download sessions
    sessions: HashMap<ContentId, DownloadSession>,
    /// Chunk assignment queue
    assignment_queue: VecDeque<(ContentId, ChunkId)>,
    /// Total downloads started
    total_started: u64,
    /// Total downloads completed
    total_completed: u64,
    /// Total downloads failed
    total_failed: u64,
}

impl MultiSourceDownloader {
    /// Create a new multi-source downloader
    pub fn new(config: DownloaderConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            assignment_queue: VecDeque::new(),
            total_started: 0,
            total_completed: 0,
            total_failed: 0,
        }
    }

    /// Start a new download
    pub fn start_download(&mut self, content_id: ContentId, total_chunks: u64) -> bool {
        if self.sessions.contains_key(&content_id) {
            return false;
        }

        let mut chunk_states = HashMap::new();
        for chunk_id in 0..total_chunks {
            chunk_states.insert(chunk_id, ChunkState::Pending);
            self.assignment_queue
                .push_back((content_id.clone(), chunk_id));
        }

        let session = DownloadSession {
            content_id: content_id.clone(),
            total_chunks,
            chunk_states,
            sources: HashMap::new(),
            active_per_source: HashMap::new(),
            started_at: Instant::now(),
            completed_at: None,
            bytes_downloaded: 0,
        };

        self.sessions.insert(content_id, session);
        self.total_started += 1;
        true
    }

    /// Add a source for a download
    pub fn add_source(&mut self, content_id: &ContentId, source: SourceInfo) -> bool {
        if let Some(session) = self.sessions.get_mut(content_id) {
            let peer_id = source.peer_id.clone();
            session.sources.insert(peer_id.clone(), source);
            session.active_per_source.entry(peer_id).or_insert(0);
            true
        } else {
            false
        }
    }

    /// Remove a source
    pub fn remove_source(&mut self, content_id: &ContentId, peer_id: &PeerId) -> bool {
        if let Some(session) = self.sessions.get_mut(content_id) {
            session.sources.remove(peer_id);
            session.active_per_source.remove(peer_id);

            // Reassign chunks from this source
            for (chunk_id, state) in session.chunk_states.iter_mut() {
                match state {
                    ChunkState::Assigned(p) | ChunkState::InProgress(p, _) if p == peer_id => {
                        *state = ChunkState::Pending;
                        self.assignment_queue
                            .push_back((content_id.clone(), *chunk_id));
                    }
                    _ => {}
                }
            }

            true
        } else {
            false
        }
    }

    /// Assign chunks to sources
    pub fn assign_chunks(&mut self) -> Vec<(ContentId, ChunkId, PeerId)> {
        let mut assignments = Vec::new();

        while let Some((content_id, chunk_id)) = self.assignment_queue.pop_front() {
            let peer_id = if let Some(session) = self.sessions.get(&content_id) {
                // Find best available source
                self.select_best_source(session)
            } else {
                None
            };

            if let Some(peer_id) = peer_id {
                if let Some(session) = self.sessions.get_mut(&content_id) {
                    // Check if this is a retry from a failed state, preserve the retry count
                    let current_state = session.chunk_states.get(&chunk_id).cloned();

                    // Update chunk state (preserve retry count if retrying from failed state)
                    match current_state {
                        Some(ChunkState::Failed(_, _)) => {
                            // Keep the failed state but we'll retry, will be marked in_progress later
                        }
                        _ => {
                            session
                                .chunk_states
                                .insert(chunk_id, ChunkState::Assigned(peer_id.clone()));
                        }
                    }

                    // Update active count
                    *session
                        .active_per_source
                        .entry(peer_id.clone())
                        .or_insert(0) += 1;

                    assignments.push((content_id, chunk_id, peer_id));
                }
            } else {
                // No source available, put back in queue
                self.assignment_queue.push_back((content_id, chunk_id));
                break;
            }
        }

        assignments
    }

    /// Select best source for download
    fn select_best_source(&self, session: &DownloadSession) -> Option<PeerId> {
        if session.sources.is_empty() {
            return None;
        }

        // Find sources with capacity
        let mut available_sources: Vec<_> = session
            .sources
            .iter()
            .filter(|(peer_id, _)| {
                let active = session
                    .active_per_source
                    .get(*peer_id)
                    .copied()
                    .unwrap_or(0);
                active < self.config.max_concurrent_sources
            })
            .collect();

        if available_sources.is_empty() {
            return None;
        }

        // Sort by quality score (descending)
        available_sources.sort_by(|(_, a), (_, b)| {
            b.quality_score()
                .partial_cmp(&a.quality_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        available_sources
            .first()
            .map(|(peer_id, _)| (*peer_id).clone())
    }

    /// Mark chunk as in progress
    pub fn mark_in_progress(
        &mut self,
        content_id: &ContentId,
        chunk_id: ChunkId,
        peer_id: PeerId,
    ) -> bool {
        if let Some(session) = self.sessions.get_mut(content_id) {
            if let Some(state) = session.chunk_states.get_mut(&chunk_id) {
                // Allow transitioning from Assigned or Failed (for retries) to InProgress
                if matches!(state, ChunkState::Assigned(_) | ChunkState::Failed(_, _)) {
                    *state = ChunkState::InProgress(peer_id, Instant::now());
                    return true;
                }
            }
        }
        false
    }

    /// Mark chunk as completed
    pub fn mark_completed(
        &mut self,
        content_id: &ContentId,
        chunk_id: ChunkId,
        bytes: u64,
    ) -> bool {
        if let Some(session) = self.sessions.get_mut(content_id) {
            if let Some(state) = session.chunk_states.get_mut(&chunk_id) {
                if let ChunkState::InProgress(peer_id, _) = state {
                    let peer_id = peer_id.clone();

                    // Update state
                    *state = ChunkState::Completed(peer_id.clone());

                    // Update active count
                    if let Some(count) = session.active_per_source.get_mut(&peer_id) {
                        *count = count.saturating_sub(1);
                    }

                    // Update bytes
                    session.bytes_downloaded += bytes;

                    // Check if download is complete
                    if session.is_complete() {
                        session.completed_at = Some(Instant::now());
                        self.total_completed += 1;
                    }

                    return true;
                }
            }
        }
        false
    }

    /// Mark chunk as failed
    pub fn mark_failed(
        &mut self,
        content_id: &ContentId,
        chunk_id: ChunkId,
        max_retries: u32,
    ) -> bool {
        if let Some(session) = self.sessions.get_mut(content_id) {
            if let Some(state) = session.chunk_states.get(&chunk_id) {
                let (peer_id, retry_count) = match state {
                    ChunkState::InProgress(p, _) => (p.clone(), 1),
                    ChunkState::Failed(p, count) => (p.clone(), count + 1),
                    _ => return false,
                };

                // Update active count
                if let Some(count) = session.active_per_source.get_mut(&peer_id) {
                    *count = count.saturating_sub(1);
                }

                if retry_count < max_retries {
                    // Mark as failed but allow retry
                    session
                        .chunk_states
                        .insert(chunk_id, ChunkState::Failed(peer_id, retry_count));
                    self.assignment_queue
                        .push_back((content_id.clone(), chunk_id));
                } else {
                    // Give up
                    session
                        .chunk_states
                        .insert(chunk_id, ChunkState::Failed(peer_id, retry_count));
                    self.total_failed += 1;
                }

                return true;
            }
        }
        false
    }

    /// Check for timed-out chunks
    pub fn check_timeouts(&mut self) -> Vec<(ContentId, ChunkId)> {
        let mut timeouts = Vec::new();
        let now = Instant::now();

        for (content_id, session) in &mut self.sessions {
            for (chunk_id, state) in &mut session.chunk_states {
                if let ChunkState::InProgress(peer_id, started_at) = state {
                    if now.duration_since(*started_at) > self.config.chunk_timeout {
                        let peer_id = peer_id.clone();

                        // Update active count
                        if let Some(count) = session.active_per_source.get_mut(&peer_id) {
                            *count = count.saturating_sub(1);
                        }

                        // Reset to pending
                        *state = ChunkState::Pending;
                        timeouts.push((content_id.clone(), *chunk_id));
                        self.assignment_queue
                            .push_back((content_id.clone(), *chunk_id));
                    }
                }
            }
        }

        timeouts
    }

    /// Get download session
    pub fn get_session(&self, content_id: &ContentId) -> Option<&DownloadSession> {
        self.sessions.get(content_id)
    }

    /// Cancel a download
    pub fn cancel_download(&mut self, content_id: &ContentId) -> bool {
        self.sessions.remove(content_id).is_some()
    }

    /// Get statistics
    pub fn stats(&self) -> DownloaderStats {
        let active = self.sessions.values().filter(|s| !s.is_complete()).count();

        DownloaderStats {
            active_downloads: active,
            total_started: self.total_started,
            total_completed: self.total_completed,
            total_failed: self.total_failed,
            pending_assignments: self.assignment_queue.len(),
        }
    }
}

/// Downloader statistics
#[derive(Debug, Clone)]
pub struct DownloaderStats {
    /// Active downloads
    pub active_downloads: usize,
    /// Total downloads started
    pub total_started: u64,
    /// Total downloads completed
    pub total_completed: u64,
    /// Total downloads failed
    pub total_failed: u64,
    /// Pending chunk assignments
    pub pending_assignments: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_source(
        peer_id: &str,
        bandwidth: u64,
        latency_ms: u64,
        reliability: f64,
    ) -> SourceInfo {
        SourceInfo {
            peer_id: peer_id.to_string(),
            bandwidth,
            latency: Duration::from_millis(latency_ms),
            reliability,
        }
    }

    #[test]
    fn test_source_quality_score() {
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        let score = source.quality_score();
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_start_download() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        assert!(downloader.start_download("content1".to_string(), 10));
        assert!(!downloader.start_download("content1".to_string(), 10)); // Duplicate

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert_eq!(session.total_chunks, 10);
    }

    #[test]
    fn test_add_source() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 10);

        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        assert!(downloader.add_source(&"content1".to_string(), source));

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert_eq!(session.sources.len(), 1);
    }

    #[test]
    fn test_assign_chunks() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);

        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        let assignments = downloader.assign_chunks();
        assert_eq!(assignments.len(), 5);

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert_eq!(session.active_per_source.get("peer1"), Some(&5));
    }

    #[test]
    fn test_mark_in_progress() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();

        assert!(downloader.mark_in_progress(&"content1".to_string(), 0, "peer1".to_string()));

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert!(matches!(
            session.chunk_states.get(&0),
            Some(ChunkState::InProgress(_, _))
        ));
    }

    #[test]
    fn test_mark_completed() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();
        downloader.mark_in_progress(&"content1".to_string(), 0, "peer1".to_string());

        assert!(downloader.mark_completed(&"content1".to_string(), 0, 1024));

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert!(matches!(
            session.chunk_states.get(&0),
            Some(ChunkState::Completed(_))
        ));
        assert_eq!(session.bytes_downloaded, 1024);
    }

    #[test]
    fn test_mark_failed() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();
        downloader.mark_in_progress(&"content1".to_string(), 0, "peer1".to_string());

        assert!(downloader.mark_failed(&"content1".to_string(), 0, 3));

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        // After first failure, should be marked as Failed with retry count 1
        assert!(matches!(
            session.chunk_states.get(&0),
            Some(ChunkState::Failed(_, 1))
        ));
    }

    #[test]
    fn test_download_completion() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 3);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();

        for chunk_id in 0..3 {
            downloader.mark_in_progress(&"content1".to_string(), chunk_id, "peer1".to_string());
            downloader.mark_completed(&"content1".to_string(), chunk_id, 1024);
        }

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert!(session.is_complete());
        assert_eq!(session.progress(), 1.0);
    }

    #[test]
    fn test_multiple_sources() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 10);

        let source1 = create_test_source("peer1", 1_000_000, 50, 0.95);
        let source2 = create_test_source("peer2", 2_000_000, 30, 0.90);

        downloader.add_source(&"content1".to_string(), source1);
        downloader.add_source(&"content1".to_string(), source2);

        let assignments = downloader.assign_chunks();
        assert_eq!(assignments.len(), 10);

        // peer2 should get more chunks due to higher quality score
        let peer2_count = assignments.iter().filter(|(_, _, p)| p == "peer2").count();
        assert!(peer2_count > 0);
    }

    #[test]
    fn test_remove_source() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();

        assert!(downloader.remove_source(&"content1".to_string(), &"peer1".to_string()));

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert_eq!(session.sources.len(), 0);

        // All chunks should be reassigned
        for state in session.chunk_states.values() {
            assert_eq!(*state, ChunkState::Pending);
        }
    }

    #[test]
    fn test_timeout_check() {
        let config = DownloaderConfig {
            chunk_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();
        downloader.mark_in_progress(&"content1".to_string(), 0, "peer1".to_string());

        std::thread::sleep(Duration::from_millis(100));

        let timeouts = downloader.check_timeouts();
        assert_eq!(timeouts.len(), 1);
        assert_eq!(timeouts[0], ("content1".to_string(), 0));
    }

    #[test]
    fn test_cancel_download() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        assert!(downloader.cancel_download(&"content1".to_string()));
        assert!(downloader.get_session(&"content1".to_string()).is_none());
    }

    #[test]
    fn test_stats() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        downloader.start_download("content2".to_string(), 5);

        let stats = downloader.stats();
        assert_eq!(stats.total_started, 2);
        assert_eq!(stats.active_downloads, 2);
    }

    #[test]
    fn test_session_progress() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 10);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();

        for chunk_id in 0..5 {
            downloader.mark_in_progress(&"content1".to_string(), chunk_id, "peer1".to_string());
            downloader.mark_completed(&"content1".to_string(), chunk_id, 1024);
        }

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert_eq!(session.progress(), 0.5);
    }

    #[test]
    fn test_session_average_speed() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();

        std::thread::sleep(Duration::from_millis(100));

        for chunk_id in 0..5 {
            downloader.mark_in_progress(&"content1".to_string(), chunk_id, "peer1".to_string());
            downloader.mark_completed(&"content1".to_string(), chunk_id, 1024);
        }

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert!(session.average_speed() > 0.0);
    }

    #[test]
    fn test_max_retries() {
        let config = DownloaderConfig::default();
        let mut downloader = MultiSourceDownloader::new(config);

        downloader.start_download("content1".to_string(), 5);
        let source = create_test_source("peer1", 1_000_000, 50, 0.95);
        downloader.add_source(&"content1".to_string(), source);

        downloader.assign_chunks();
        downloader.mark_in_progress(&"content1".to_string(), 0, "peer1".to_string());

        // Fail multiple times
        for _ in 0..2 {
            downloader.mark_failed(&"content1".to_string(), 0, 3);
            downloader.assign_chunks();
            downloader.mark_in_progress(&"content1".to_string(), 0, "peer1".to_string());
        }

        // Final failure should exceed max retries
        downloader.mark_failed(&"content1".to_string(), 0, 3);

        let session = downloader.get_session(&"content1".to_string()).unwrap();
        assert!(matches!(
            session.chunk_states.get(&0),
            Some(ChunkState::Failed(_, _))
        ));
    }
}
