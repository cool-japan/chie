//! Chunk scheduler for optimized parallel downloads.
//!
//! This module provides intelligent scheduling of chunk downloads from multiple peers,
//! with load balancing, failure recovery, and priority-based scheduling.
//!
//! # Examples
//!
//! ```
//! use chie_p2p::chunk_scheduler::{ChunkScheduler, ChunkRequest, SchedulingStrategy};
//! use libp2p::PeerId;
//!
//! let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
//!
//! // Add peers
//! scheduler.add_peer(PeerId::random(), 100); // latency 100ms
//!
//! // Schedule chunks
//! let request = ChunkRequest::new("content_123".to_string(), 0, 4096);
//! scheduler.schedule_chunk(request);
//! ```

use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

/// Errors that can occur during chunk scheduling.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// No peers available for download.
    #[error("No peers available")]
    NoPeersAvailable,

    /// Chunk already scheduled.
    #[error("Chunk already scheduled: {0}")]
    AlreadyScheduled(String),

    /// Invalid chunk parameters.
    #[error("Invalid chunk parameters: {0}")]
    InvalidChunk(String),

    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
}

/// Chunk download request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkRequest {
    /// Content ID.
    pub content_id: String,
    /// Chunk index.
    pub chunk_index: usize,
    /// Chunk size in bytes.
    pub chunk_size: usize,
    /// Priority (higher = more important).
    pub priority: u8,
}

impl ChunkRequest {
    /// Create a new chunk request with default priority.
    pub fn new(content_id: String, chunk_index: usize, chunk_size: usize) -> Self {
        Self {
            content_id,
            chunk_index,
            chunk_size,
            priority: 128, // Medium priority
        }
    }

    /// Create a new chunk request with custom priority.
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Get a unique key for this chunk.
    pub fn key(&self) -> String {
        format!("{}:{}", self.content_id, self.chunk_index)
    }
}

/// Peer information for scheduling.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID.
    pub peer_id: PeerId,
    /// Average latency in milliseconds.
    pub latency_ms: u64,
    /// Current load (number of active downloads).
    pub current_load: usize,
    /// Maximum concurrent downloads.
    pub max_concurrent: usize,
    /// Success rate (0.0 to 1.0).
    pub success_rate: f64,
    /// Total bytes downloaded.
    pub total_bytes: u64,
    /// Last activity time.
    pub last_active: Instant,
}

impl PeerInfo {
    /// Create new peer info.
    pub fn new(peer_id: PeerId, latency_ms: u64) -> Self {
        Self {
            peer_id,
            latency_ms,
            current_load: 0,
            max_concurrent: 4, // Default max concurrent downloads
            success_rate: 1.0,
            total_bytes: 0,
            last_active: Instant::now(),
        }
    }

    /// Check if peer can accept more downloads.
    pub fn can_accept(&self) -> bool {
        self.current_load < self.max_concurrent
    }

    /// Calculate peer score (higher is better).
    pub fn score(&self) -> f64 {
        // Score based on success rate, latency, and current load
        let latency_score = 1.0 / (1.0 + self.latency_ms as f64 / 100.0);
        let load_score = 1.0 - (self.current_load as f64 / self.max_concurrent as f64);
        self.success_rate * latency_score * load_score
    }
}

/// Scheduling strategy for chunk downloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulingStrategy {
    /// Round-robin across peers.
    RoundRobin,
    /// Load-balanced based on peer score.
    LoadBalanced,
    /// Fastest peer first (lowest latency).
    FastestFirst,
    /// Priority-based scheduling.
    Priority,
}

/// Statistics for chunk scheduling.
#[derive(Debug, Default, Clone)]
pub struct SchedulerStats {
    /// Total chunks scheduled.
    pub total_scheduled: u64,
    /// Currently pending chunks.
    pub pending_chunks: usize,
    /// Successfully completed chunks.
    pub completed_chunks: u64,
    /// Failed chunks.
    pub failed_chunks: u64,
    /// Total bytes scheduled.
    pub total_bytes_scheduled: u64,
}

impl SchedulerStats {
    /// Get completion rate.
    pub fn completion_rate(&self) -> f64 {
        let total = self.completed_chunks + self.failed_chunks;
        if total == 0 {
            return 0.0;
        }
        self.completed_chunks as f64 / total as f64
    }
}

/// Scheduled chunk with assignment.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ScheduledChunk {
    request: ChunkRequest,
    assigned_peer: Option<PeerId>,
    scheduled_at: Instant,
    retry_count: usize,
}

/// Chunk scheduler for parallel downloads.
pub struct ChunkScheduler {
    strategy: SchedulingStrategy,
    /// Available peers.
    peers: Arc<parking_lot::RwLock<HashMap<PeerId, PeerInfo>>>,
    /// Pending chunk queue.
    pending_queue: Arc<parking_lot::RwLock<VecDeque<ScheduledChunk>>>,
    /// Scheduled chunks (by key).
    scheduled: Arc<parking_lot::RwLock<HashMap<String, ScheduledChunk>>>,
    /// Round-robin counter.
    rr_counter: Arc<parking_lot::RwLock<usize>>,
    /// Statistics.
    stats: Arc<parking_lot::RwLock<SchedulerStats>>,
}

impl ChunkScheduler {
    /// Create a new chunk scheduler with the given strategy.
    pub fn new(strategy: SchedulingStrategy) -> Self {
        Self {
            strategy,
            peers: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            pending_queue: Arc::new(parking_lot::RwLock::new(VecDeque::new())),
            scheduled: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            rr_counter: Arc::new(parking_lot::RwLock::new(0)),
            stats: Arc::new(parking_lot::RwLock::new(SchedulerStats::default())),
        }
    }

    /// Add a peer to the scheduler.
    pub fn add_peer(&self, peer_id: PeerId, latency_ms: u64) {
        let info = PeerInfo::new(peer_id, latency_ms);
        self.peers.write().insert(peer_id, info);
    }

    /// Remove a peer from the scheduler.
    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);
    }

    /// Schedule a chunk for download.
    pub fn schedule_chunk(&self, request: ChunkRequest) -> Result<(), SchedulerError> {
        let key = request.key();

        // Check if already scheduled
        if self.scheduled.read().contains_key(&key) {
            return Err(SchedulerError::AlreadyScheduled(key));
        }

        let chunk = ScheduledChunk {
            request: request.clone(),
            assigned_peer: None,
            scheduled_at: Instant::now(),
            retry_count: 0,
        };

        // Add to pending queue
        self.pending_queue.write().push_back(chunk.clone());

        // Add to scheduled map
        self.scheduled.write().insert(key, chunk);

        // Update stats
        let mut stats = self.stats.write();
        stats.total_scheduled += 1;
        stats.pending_chunks += 1;
        stats.total_bytes_scheduled += request.chunk_size as u64;

        Ok(())
    }

    /// Get next chunk assignment for a peer.
    pub fn get_next_chunk(&self) -> Option<(ChunkRequest, PeerId)> {
        let mut queue = self.pending_queue.write();
        let mut peers = self.peers.write();

        if queue.is_empty() || peers.is_empty() {
            return None;
        }

        // Sort queue by priority if using priority strategy
        if self.strategy == SchedulingStrategy::Priority {
            queue
                .make_contiguous()
                .sort_by(|a, b| b.request.priority.cmp(&a.request.priority));
        }

        // Find best peer based on strategy
        let peer_id = match self.strategy {
            SchedulingStrategy::RoundRobin => self.select_round_robin(&peers),
            SchedulingStrategy::LoadBalanced => self.select_load_balanced(&peers),
            SchedulingStrategy::FastestFirst => self.select_fastest(&peers),
            SchedulingStrategy::Priority => self.select_load_balanced(&peers),
        }?;

        // Get chunk from queue
        let mut chunk = queue.pop_front()?;
        chunk.assigned_peer = Some(peer_id);

        // Update peer load
        if let Some(peer) = peers.get_mut(&peer_id) {
            peer.current_load += 1;
            peer.last_active = Instant::now();
        }

        // Update scheduled map
        let key = chunk.request.key();
        self.scheduled.write().insert(key, chunk.clone());

        Some((chunk.request, peer_id))
    }

    /// Select peer using round-robin strategy.
    fn select_round_robin(&self, peers: &HashMap<PeerId, PeerInfo>) -> Option<PeerId> {
        let available: Vec<_> = peers.values().filter(|p| p.can_accept()).collect();

        if available.is_empty() {
            return None;
        }

        let mut counter = self.rr_counter.write();
        let index = *counter % available.len();
        *counter = (*counter + 1) % available.len();

        Some(available[index].peer_id)
    }

    /// Select peer using load-balanced strategy.
    fn select_load_balanced(&self, peers: &HashMap<PeerId, PeerInfo>) -> Option<PeerId> {
        peers
            .values()
            .filter(|p| p.can_accept())
            .max_by(|a, b| a.score().partial_cmp(&b.score()).unwrap())
            .map(|p| p.peer_id)
    }

    /// Select fastest peer.
    fn select_fastest(&self, peers: &HashMap<PeerId, PeerInfo>) -> Option<PeerId> {
        peers
            .values()
            .filter(|p| p.can_accept())
            .min_by_key(|p| p.latency_ms)
            .map(|p| p.peer_id)
    }

    /// Mark a chunk as completed.
    pub fn mark_completed(&self, chunk_key: &str, peer_id: &PeerId, bytes_downloaded: u64) {
        // Remove from scheduled
        self.scheduled.write().remove(chunk_key);

        // Update peer info
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            if peer.current_load > 0 {
                peer.current_load -= 1;
            }
            peer.total_bytes += bytes_downloaded;
            peer.success_rate = (peer.success_rate * 0.9) + 0.1; // Increase success rate
        }

        // Update stats
        let mut stats = self.stats.write();
        stats.completed_chunks += 1;
        if stats.pending_chunks > 0 {
            stats.pending_chunks -= 1;
        }
    }

    /// Mark a chunk as failed and optionally retry.
    pub fn mark_failed(&self, chunk_key: &str, peer_id: &PeerId, retry: bool) {
        let mut scheduled = self.scheduled.write();

        if let Some(mut chunk) = scheduled.remove(chunk_key) {
            chunk.retry_count += 1;

            if retry && chunk.retry_count < 3 {
                // Re-add to pending queue
                self.pending_queue.write().push_back(chunk);
            } else {
                // Permanently failed
                let mut stats = self.stats.write();
                stats.failed_chunks += 1;
                if stats.pending_chunks > 0 {
                    stats.pending_chunks -= 1;
                }
            }
        }

        // Update peer info
        if let Some(peer) = self.peers.write().get_mut(peer_id) {
            if peer.current_load > 0 {
                peer.current_load -= 1;
            }
            peer.success_rate = (peer.success_rate * 0.9) + 0.0; // Decrease success rate
        }
    }

    /// Get statistics.
    pub fn stats(&self) -> SchedulerStats {
        self.stats.read().clone()
    }

    /// Get number of available peers.
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Get number of pending chunks.
    pub fn pending_count(&self) -> usize {
        self.pending_queue.read().len()
    }
}

impl Clone for ChunkScheduler {
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy,
            peers: Arc::clone(&self.peers),
            pending_queue: Arc::clone(&self.pending_queue),
            scheduled: Arc::clone(&self.scheduled),
            rr_counter: Arc::clone(&self.rr_counter),
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_request_new() {
        let req = ChunkRequest::new("content_123".to_string(), 5, 4096);
        assert_eq!(req.content_id, "content_123");
        assert_eq!(req.chunk_index, 5);
        assert_eq!(req.chunk_size, 4096);
        assert_eq!(req.priority, 128);
    }

    #[test]
    fn test_chunk_request_with_priority() {
        let req = ChunkRequest::new("content_123".to_string(), 5, 4096).with_priority(255);
        assert_eq!(req.priority, 255);
    }

    #[test]
    fn test_chunk_request_key() {
        let req = ChunkRequest::new("content_123".to_string(), 5, 4096);
        assert_eq!(req.key(), "content_123:5");
    }

    #[test]
    fn test_peer_info_new() {
        let peer_id = PeerId::random();
        let info = PeerInfo::new(peer_id, 100);
        assert_eq!(info.latency_ms, 100);
        assert_eq!(info.current_load, 0);
        assert!(info.can_accept());
    }

    #[test]
    fn test_peer_info_can_accept() {
        let peer_id = PeerId::random();
        let mut info = PeerInfo::new(peer_id, 100);
        info.max_concurrent = 2;

        assert!(info.can_accept());
        info.current_load = 1;
        assert!(info.can_accept());
        info.current_load = 2;
        assert!(!info.can_accept());
    }

    #[test]
    fn test_peer_info_score() {
        let peer_id = PeerId::random();
        let info = PeerInfo::new(peer_id, 100);
        let score = info.score();
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_scheduler_new() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        assert_eq!(scheduler.peer_count(), 0);
        assert_eq!(scheduler.pending_count(), 0);
    }

    #[test]
    fn test_add_remove_peer() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();

        scheduler.add_peer(peer_id, 100);
        assert_eq!(scheduler.peer_count(), 1);

        scheduler.remove_peer(&peer_id);
        assert_eq!(scheduler.peer_count(), 0);
    }

    #[test]
    fn test_schedule_chunk() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);

        let result = scheduler.schedule_chunk(req);
        assert!(result.is_ok());

        let stats = scheduler.stats();
        assert_eq!(stats.total_scheduled, 1);
        assert_eq!(stats.pending_chunks, 1);
    }

    #[test]
    fn test_schedule_chunk_already_scheduled() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);

        scheduler.schedule_chunk(req.clone()).unwrap();
        let result = scheduler.schedule_chunk(req);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_next_chunk_no_peers() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);
        scheduler.schedule_chunk(req).unwrap();

        assert!(scheduler.get_next_chunk().is_none());
    }

    #[test]
    fn test_get_next_chunk_success() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();
        scheduler.add_peer(peer_id, 100);

        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);
        scheduler.schedule_chunk(req.clone()).unwrap();

        let result = scheduler.get_next_chunk();
        assert!(result.is_some());

        let (chunk, assigned_peer) = result.unwrap();
        assert_eq!(chunk.content_id, req.content_id);
        assert_eq!(assigned_peer, peer_id);
    }

    #[test]
    fn test_mark_completed() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();
        scheduler.add_peer(peer_id, 100);

        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);
        scheduler.schedule_chunk(req.clone()).unwrap();

        let (chunk, assigned_peer) = scheduler.get_next_chunk().unwrap();
        scheduler.mark_completed(&chunk.key(), &assigned_peer, 4096);

        let stats = scheduler.stats();
        assert_eq!(stats.completed_chunks, 1);
        assert_eq!(stats.pending_chunks, 0);
    }

    #[test]
    fn test_mark_failed_with_retry() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();
        scheduler.add_peer(peer_id, 100);

        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);
        scheduler.schedule_chunk(req.clone()).unwrap();

        let (chunk, assigned_peer) = scheduler.get_next_chunk().unwrap();
        scheduler.mark_failed(&chunk.key(), &assigned_peer, true);

        // Should be re-added to pending queue
        assert_eq!(scheduler.pending_count(), 1);
    }

    #[test]
    fn test_mark_failed_no_retry() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();
        scheduler.add_peer(peer_id, 100);

        let req = ChunkRequest::new("content_123".to_string(), 0, 4096);
        scheduler.schedule_chunk(req.clone()).unwrap();

        let (chunk, assigned_peer) = scheduler.get_next_chunk().unwrap();
        scheduler.mark_failed(&chunk.key(), &assigned_peer, false);

        let stats = scheduler.stats();
        assert_eq!(stats.failed_chunks, 1);
        assert_eq!(stats.pending_chunks, 0);
    }

    #[test]
    fn test_completion_rate() {
        let scheduler = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();
        scheduler.add_peer(peer_id, 100);

        // Schedule 4 chunks
        for i in 0..4 {
            let req = ChunkRequest::new("content".to_string(), i, 4096);
            scheduler.schedule_chunk(req).unwrap();
        }

        // Complete 3, fail 1
        for _ in 0..3 {
            if let Some((chunk, peer)) = scheduler.get_next_chunk() {
                scheduler.mark_completed(&chunk.key(), &peer, 4096);
            }
        }

        if let Some((chunk, peer)) = scheduler.get_next_chunk() {
            scheduler.mark_failed(&chunk.key(), &peer, false);
        }

        let stats = scheduler.stats();
        assert_eq!(stats.completion_rate(), 0.75); // 3/4
    }

    #[test]
    fn test_clone() {
        let scheduler1 = ChunkScheduler::new(SchedulingStrategy::LoadBalanced);
        let peer_id = PeerId::random();
        scheduler1.add_peer(peer_id, 100);

        let scheduler2 = scheduler1.clone();
        assert_eq!(scheduler1.peer_count(), scheduler2.peer_count());
    }
}
