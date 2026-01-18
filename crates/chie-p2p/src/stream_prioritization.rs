//! Stream prioritization using HTTP/2-style dependency tree.
//!
//! This module implements HTTP/2 stream prioritization with dependency-based scheduling,
//! stream weights, and fair bandwidth allocation.

use chie_shared::{ChieError, ChieResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Stream identifier
pub type StreamId = u32;

/// Root stream ID (virtual stream all streams can depend on)
pub const ROOT_STREAM_ID: StreamId = 0;

/// Stream priority (1-256, higher = more important)
pub type StreamWeight = u16;

/// Default stream weight
pub const DEFAULT_WEIGHT: StreamWeight = 16;

/// Minimum stream weight
pub const MIN_WEIGHT: StreamWeight = 1;

/// Maximum stream weight
pub const MAX_WEIGHT: StreamWeight = 256;

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is idle (not yet active)
    Idle,
    /// Stream is open and can send/receive data
    Open,
    /// Stream is half-closed (local)
    HalfClosedLocal,
    /// Stream is half-closed (remote)
    HalfClosedRemote,
    /// Stream is closed
    Closed,
}

/// Stream priority information
#[derive(Debug, Clone)]
pub struct StreamPriority {
    /// Stream ID
    pub stream_id: StreamId,
    /// Parent stream ID (dependency)
    pub parent_id: StreamId,
    /// Stream weight (1-256)
    pub weight: StreamWeight,
    /// Whether this stream is exclusive (no siblings)
    pub exclusive: bool,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            stream_id: 0,
            parent_id: ROOT_STREAM_ID,
            weight: DEFAULT_WEIGHT,
            exclusive: false,
        }
    }
}

/// Stream information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct StreamInfo {
    /// Stream ID
    id: StreamId,
    /// Parent stream ID
    parent_id: StreamId,
    /// Stream weight
    weight: StreamWeight,
    /// Stream state
    state: StreamState,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes pending
    bytes_pending: u64,
    /// Creation time
    created_at: Instant,
    /// Last activity time
    last_activity: Instant,
    /// Children stream IDs
    children: Vec<StreamId>,
}

impl StreamInfo {
    fn new(id: StreamId, parent_id: StreamId, weight: StreamWeight) -> Self {
        let now = Instant::now();
        Self {
            id,
            parent_id,
            weight: weight.clamp(MIN_WEIGHT, MAX_WEIGHT),
            state: StreamState::Idle,
            bytes_sent: 0,
            bytes_pending: 0,
            created_at: now,
            last_activity: now,
            children: Vec::new(),
        }
    }
}

/// Stream prioritization manager
pub struct StreamPrioritizer {
    /// All streams
    streams: Arc<RwLock<HashMap<StreamId, StreamInfo>>>,
    /// Configuration
    config: PrioritizerConfig,
    /// Statistics
    stats: Arc<RwLock<PrioritizerStats>>,
}

/// Prioritizer configuration
#[derive(Debug, Clone)]
pub struct PrioritizerConfig {
    /// Maximum number of streams
    pub max_streams: usize,
    /// Stream idle timeout
    pub idle_timeout: Duration,
    /// Enable strict HTTP/2 priority
    pub strict_priority: bool,
}

impl Default for PrioritizerConfig {
    fn default() -> Self {
        Self {
            max_streams: 1000,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            strict_priority: true,
        }
    }
}

/// Prioritizer statistics
#[derive(Debug, Clone, Default)]
pub struct PrioritizerStats {
    /// Total streams created
    pub total_streams: u64,
    /// Active streams
    pub active_streams: u64,
    /// Closed streams
    pub closed_streams: u64,
    /// Total bytes scheduled
    pub total_bytes: u64,
    /// Scheduling decisions made
    pub scheduling_decisions: u64,
}

impl StreamPrioritizer {
    /// Create new stream prioritizer
    pub fn new(config: PrioritizerConfig) -> Self {
        let mut streams = HashMap::new();

        // Insert root stream
        streams.insert(
            ROOT_STREAM_ID,
            StreamInfo {
                id: ROOT_STREAM_ID,
                parent_id: ROOT_STREAM_ID,
                weight: DEFAULT_WEIGHT,
                state: StreamState::Open,
                bytes_sent: 0,
                bytes_pending: 0,
                created_at: Instant::now(),
                last_activity: Instant::now(),
                children: Vec::new(),
            },
        );

        Self {
            streams: Arc::new(RwLock::new(streams)),
            config,
            stats: Arc::new(RwLock::new(PrioritizerStats::default())),
        }
    }

    /// Create a new stream with priority
    pub fn create_stream(&self, priority: StreamPriority) -> ChieResult<()> {
        let mut streams = self.streams.write();

        // Exclude root stream from count
        if streams.len() > self.config.max_streams {
            return Err(ChieError::resource_exhausted("Maximum streams reached"));
        }

        if streams.contains_key(&priority.stream_id) {
            return Err(ChieError::already_exists("Stream already exists"));
        }

        // Validate parent exists
        if !streams.contains_key(&priority.parent_id) {
            return Err(ChieError::not_found("Parent stream does not exist"));
        }

        // Handle exclusive dependency
        if priority.exclusive {
            // Move all siblings to be children of new stream
            if let Some(parent) = streams.get_mut(&priority.parent_id) {
                let siblings: Vec<StreamId> = parent.children.clone();
                parent.children.clear();
                parent.children.push(priority.stream_id);

                // Create new stream first
                let mut new_stream =
                    StreamInfo::new(priority.stream_id, priority.parent_id, priority.weight);
                new_stream.children = siblings.clone();
                streams.insert(priority.stream_id, new_stream);

                // Update siblings to point to new stream as parent
                for sibling in siblings {
                    if let Some(s) = streams.get_mut(&sibling) {
                        s.parent_id = priority.stream_id;
                    }
                }
            }
        } else {
            // Non-exclusive: just add to parent's children
            let stream = StreamInfo::new(priority.stream_id, priority.parent_id, priority.weight);
            streams.insert(priority.stream_id, stream);

            if let Some(parent) = streams.get_mut(&priority.parent_id) {
                parent.children.push(priority.stream_id);
            }
        }

        let mut stats = self.stats.write();
        stats.total_streams += 1;
        stats.active_streams += 1;

        Ok(())
    }

    /// Update stream priority
    pub fn update_priority(&self, priority: StreamPriority) -> ChieResult<()> {
        let mut streams = self.streams.write();

        if !streams.contains_key(&priority.stream_id) {
            return Err(ChieError::not_found("Stream does not exist"));
        }

        if !streams.contains_key(&priority.parent_id) {
            return Err(ChieError::not_found("Parent stream does not exist"));
        }

        // Prevent circular dependencies
        if self.would_create_cycle(&streams, priority.stream_id, priority.parent_id) {
            return Err(ChieError::validation("Would create circular dependency"));
        }

        // Remove from old parent's children
        if let Some(stream) = streams.get(&priority.stream_id).cloned() {
            if let Some(old_parent) = streams.get_mut(&stream.parent_id) {
                old_parent.children.retain(|&id| id != priority.stream_id);
            }
        }

        // Handle exclusive
        if priority.exclusive {
            if let Some(parent) = streams.get_mut(&priority.parent_id) {
                let siblings: Vec<StreamId> = parent.children.clone();
                parent.children.clear();
                parent.children.push(priority.stream_id);

                // Update stream
                if let Some(stream) = streams.get_mut(&priority.stream_id) {
                    stream.parent_id = priority.parent_id;
                    stream.weight = priority.weight.clamp(MIN_WEIGHT, MAX_WEIGHT);
                    stream
                        .children
                        .extend(siblings.iter().filter(|&&id| id != priority.stream_id));
                }

                // Update siblings
                for sibling in siblings {
                    if sibling != priority.stream_id {
                        if let Some(s) = streams.get_mut(&sibling) {
                            s.parent_id = priority.stream_id;
                        }
                    }
                }
            }
        } else {
            // Update stream
            if let Some(stream) = streams.get_mut(&priority.stream_id) {
                stream.parent_id = priority.parent_id;
                stream.weight = priority.weight.clamp(MIN_WEIGHT, MAX_WEIGHT);
            }

            // Add to new parent
            if let Some(parent) = streams.get_mut(&priority.parent_id) {
                if !parent.children.contains(&priority.stream_id) {
                    parent.children.push(priority.stream_id);
                }
            }
        }

        Ok(())
    }

    /// Check if dependency would create cycle
    fn would_create_cycle(
        &self,
        streams: &HashMap<StreamId, StreamInfo>,
        stream_id: StreamId,
        new_parent_id: StreamId,
    ) -> bool {
        if new_parent_id == stream_id {
            return true;
        }

        let mut visited = std::collections::HashSet::new();
        let mut current = new_parent_id;

        while current != ROOT_STREAM_ID {
            if current == stream_id {
                return true;
            }

            if visited.contains(&current) {
                return true;
            }
            visited.insert(current);

            if let Some(stream) = streams.get(&current) {
                current = stream.parent_id;
            } else {
                break;
            }
        }

        false
    }

    /// Update stream state
    pub fn update_state(&self, stream_id: StreamId, state: StreamState) -> ChieResult<()> {
        let mut streams = self.streams.write();

        let stream = streams
            .get_mut(&stream_id)
            .ok_or_else(|| ChieError::not_found("Stream not found"))?;

        stream.state = state;
        stream.last_activity = Instant::now();

        if state == StreamState::Closed {
            let mut stats = self.stats.write();
            stats.active_streams = stats.active_streams.saturating_sub(1);
            stats.closed_streams += 1;
        }

        Ok(())
    }

    /// Add pending bytes for stream
    pub fn add_pending_bytes(&self, stream_id: StreamId, bytes: u64) -> ChieResult<()> {
        let mut streams = self.streams.write();

        let stream = streams
            .get_mut(&stream_id)
            .ok_or_else(|| ChieError::not_found("Stream not found"))?;

        stream.bytes_pending += bytes;
        stream.last_activity = Instant::now();

        Ok(())
    }

    /// Record bytes sent for stream
    pub fn record_bytes_sent(&self, stream_id: StreamId, bytes: u64) -> ChieResult<()> {
        let mut streams = self.streams.write();

        let stream = streams
            .get_mut(&stream_id)
            .ok_or_else(|| ChieError::not_found("Stream not found"))?;

        stream.bytes_sent += bytes;
        stream.bytes_pending = stream.bytes_pending.saturating_sub(bytes);
        stream.last_activity = Instant::now();

        let mut stats = self.stats.write();
        stats.total_bytes += bytes;

        Ok(())
    }

    /// Get next stream to schedule (based on priority tree)
    pub fn next_stream(&self) -> Option<StreamId> {
        let streams = self.streams.read();
        let mut stats = self.stats.write();
        stats.scheduling_decisions += 1;

        // Use weighted fair scheduling from root
        self.schedule_from_node(&streams, ROOT_STREAM_ID)
    }

    /// Schedule from a node in the priority tree
    #[allow(clippy::only_used_in_recursion)]
    fn schedule_from_node(
        &self,
        streams: &HashMap<StreamId, StreamInfo>,
        node_id: StreamId,
    ) -> Option<StreamId> {
        let node = streams.get(&node_id)?;

        // If this node has pending data and is not root, return it
        if node_id != ROOT_STREAM_ID && node.bytes_pending > 0 && node.state == StreamState::Open {
            return Some(node_id);
        }

        // Otherwise, check children using weighted round-robin
        if node.children.is_empty() {
            return None;
        }

        // Calculate total weight of children with pending data
        let mut weighted_children = Vec::new();
        for &child_id in &node.children {
            if let Some(child) = streams.get(&child_id) {
                if child.state == StreamState::Open {
                    weighted_children.push((child_id, child.weight as u64));
                }
            }
        }

        if weighted_children.is_empty() {
            return None;
        }

        // Sort by weight (descending) then by stream ID (for determinism)
        weighted_children.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

        // Try each child in weight order
        for (child_id, _) in weighted_children {
            if let Some(result) = self.schedule_from_node(streams, child_id) {
                return Some(result);
            }
        }

        None
    }

    /// Get all streams with pending data, ordered by priority
    pub fn get_pending_streams(&self) -> Vec<StreamId> {
        let streams = self.streams.read();
        let mut pending = Vec::new();

        for (&id, stream) in streams.iter() {
            if id != ROOT_STREAM_ID && stream.bytes_pending > 0 && stream.state == StreamState::Open
            {
                pending.push(id);
            }
        }

        // Sort by effective weight (considering parent chain)
        pending.sort_by_cached_key(|&id| {
            std::cmp::Reverse(self.calculate_effective_weight(&streams, id))
        });

        pending
    }

    /// Calculate effective weight considering parent chain
    fn calculate_effective_weight(
        &self,
        streams: &HashMap<StreamId, StreamInfo>,
        stream_id: StreamId,
    ) -> u64 {
        let mut weight = 1u64;
        let mut current = stream_id;

        while current != ROOT_STREAM_ID {
            if let Some(stream) = streams.get(&current) {
                weight *= stream.weight as u64;
                current = stream.parent_id;
            } else {
                break;
            }
        }

        weight
    }

    /// Clean up idle streams
    pub fn cleanup_idle_streams(&self) -> usize {
        let mut streams = self.streams.write();
        let now = Instant::now();
        let mut removed = 0;

        let to_remove: Vec<StreamId> = streams
            .iter()
            .filter(|&(&id, s)| {
                id != ROOT_STREAM_ID
                    && s.state == StreamState::Closed
                    && now.duration_since(s.last_activity) > self.config.idle_timeout
            })
            .map(|(&id, _)| id)
            .collect();

        for id in to_remove {
            if let Some(stream) = streams.remove(&id) {
                // Remove from parent's children
                if let Some(parent) = streams.get_mut(&stream.parent_id) {
                    parent.children.retain(|&child_id| child_id != id);
                }

                // Reparent children to this stream's parent
                for &child_id in &stream.children {
                    if let Some(child) = streams.get_mut(&child_id) {
                        child.parent_id = stream.parent_id;
                        if let Some(parent) = streams.get_mut(&stream.parent_id) {
                            parent.children.push(child_id);
                        }
                    }
                }

                removed += 1;
            }
        }

        removed
    }

    /// Get stream count
    pub fn stream_count(&self) -> usize {
        self.streams.read().len().saturating_sub(1) // Exclude root
    }

    /// Get statistics
    pub fn stats(&self) -> PrioritizerStats {
        self.stats.read().clone()
    }

    /// Get stream info
    pub fn get_stream(&self, stream_id: StreamId) -> Option<StreamPriority> {
        let streams = self.streams.read();
        streams.get(&stream_id).map(|s| StreamPriority {
            stream_id: s.id,
            parent_id: s.parent_id,
            weight: s.weight,
            exclusive: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_stream() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        let priority = StreamPriority {
            stream_id: 1,
            parent_id: ROOT_STREAM_ID,
            weight: 16,
            exclusive: false,
        };

        assert!(prioritizer.create_stream(priority).is_ok());
        assert_eq!(prioritizer.stream_count(), 1);
    }

    #[test]
    fn test_exclusive_dependency() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        // Create stream 1
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        // Create stream 2 as sibling
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 2,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        // Create stream 3 as exclusive child of root
        // This should make 1 and 2 children of 3
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 3,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: true,
            })
            .unwrap();

        assert_eq!(prioritizer.stream_count(), 3);
    }

    #[test]
    fn test_update_priority() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 2,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        // Update stream 2 to depend on stream 1
        assert!(
            prioritizer
                .update_priority(StreamPriority {
                    stream_id: 2,
                    parent_id: 1,
                    weight: 32,
                    exclusive: false,
                })
                .is_ok()
        );
    }

    #[test]
    fn test_circular_dependency_prevention() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 2,
                parent_id: 1,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        // Try to make stream 1 depend on stream 2 (would create cycle)
        assert!(
            prioritizer
                .update_priority(StreamPriority {
                    stream_id: 1,
                    parent_id: 2,
                    weight: 16,
                    exclusive: false,
                })
                .is_err()
        );
    }

    #[test]
    fn test_stream_scheduling() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        // Create two streams with different weights
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 64, // High weight
                exclusive: false,
            })
            .unwrap();

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 2,
                parent_id: ROOT_STREAM_ID,
                weight: 16, // Low weight
                exclusive: false,
            })
            .unwrap();

        // Add pending data
        prioritizer.update_state(1, StreamState::Open).unwrap();
        prioritizer.update_state(2, StreamState::Open).unwrap();
        prioritizer.add_pending_bytes(1, 1000).unwrap();
        prioritizer.add_pending_bytes(2, 1000).unwrap();

        // Higher weight stream should be scheduled first
        let next = prioritizer.next_stream();
        assert_eq!(next, Some(1));
    }

    #[test]
    fn test_pending_streams() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        for i in 1..=5 {
            prioritizer
                .create_stream(StreamPriority {
                    stream_id: i,
                    parent_id: ROOT_STREAM_ID,
                    weight: (i * 10) as u16,
                    exclusive: false,
                })
                .unwrap();
            prioritizer.update_state(i, StreamState::Open).unwrap();
            prioritizer.add_pending_bytes(i, 100).unwrap();
        }

        let pending = prioritizer.get_pending_streams();
        assert_eq!(pending.len(), 5);
        // Should be ordered by weight (descending)
        assert_eq!(pending[0], 5); // Weight 50
    }

    #[test]
    fn test_bytes_tracking() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        prioritizer.update_state(1, StreamState::Open).unwrap();
        prioritizer.add_pending_bytes(1, 1000).unwrap();
        prioritizer.record_bytes_sent(1, 400).unwrap();

        let stats = prioritizer.stats();
        assert_eq!(stats.total_bytes, 400);
    }

    #[test]
    fn test_stream_states() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        assert!(prioritizer.update_state(1, StreamState::Open).is_ok());
        assert!(
            prioritizer
                .update_state(1, StreamState::HalfClosedLocal)
                .is_ok()
        );
        assert!(prioritizer.update_state(1, StreamState::Closed).is_ok());

        let stats = prioritizer.stats();
        assert_eq!(stats.closed_streams, 1);
    }

    #[test]
    fn test_cleanup_idle_streams() {
        let config = PrioritizerConfig {
            max_streams: 100,
            idle_timeout: Duration::from_millis(10),
            strict_priority: true,
        };
        let prioritizer = StreamPrioritizer::new(config);

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        prioritizer.update_state(1, StreamState::Closed).unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let removed = prioritizer.cleanup_idle_streams();
        assert_eq!(removed, 1);
        assert_eq!(prioritizer.stream_count(), 0);
    }

    #[test]
    fn test_max_streams_limit() {
        let config = PrioritizerConfig {
            max_streams: 2, // Only 2 streams (plus root = 3 total)
            ..Default::default()
        };
        let prioritizer = StreamPrioritizer::new(config);

        assert!(
            prioritizer
                .create_stream(StreamPriority {
                    stream_id: 1,
                    parent_id: ROOT_STREAM_ID,
                    weight: 16,
                    exclusive: false,
                })
                .is_ok()
        );

        assert!(
            prioritizer
                .create_stream(StreamPriority {
                    stream_id: 2,
                    parent_id: ROOT_STREAM_ID,
                    weight: 16,
                    exclusive: false,
                })
                .is_ok()
        );

        // Third stream should fail
        assert!(
            prioritizer
                .create_stream(StreamPriority {
                    stream_id: 3,
                    parent_id: ROOT_STREAM_ID,
                    weight: 16,
                    exclusive: false,
                })
                .is_err()
        );
    }

    #[test]
    fn test_weight_clamping() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        // Weight above MAX should be clamped
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 500, // Above MAX_WEIGHT (256)
                exclusive: false,
            })
            .unwrap();

        let stream = prioritizer.get_stream(1).unwrap();
        assert_eq!(stream.weight, MAX_WEIGHT);
    }

    #[test]
    fn test_get_stream_info() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 42,
                parent_id: ROOT_STREAM_ID,
                weight: 32,
                exclusive: false,
            })
            .unwrap();

        let info = prioritizer.get_stream(42).unwrap();
        assert_eq!(info.stream_id, 42);
        assert_eq!(info.parent_id, ROOT_STREAM_ID);
        assert_eq!(info.weight, 32);
    }

    #[test]
    fn test_stats_tracking() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        prioritizer.update_state(1, StreamState::Open).unwrap();
        prioritizer.add_pending_bytes(1, 100).unwrap();
        let _ = prioritizer.next_stream();

        let stats = prioritizer.stats();
        assert_eq!(stats.total_streams, 1);
        assert_eq!(stats.active_streams, 1);
        assert_eq!(stats.scheduling_decisions, 1);
    }

    #[test]
    fn test_hierarchical_weights() {
        let prioritizer = StreamPrioritizer::new(PrioritizerConfig::default());

        // Create parent
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 64,
                exclusive: false,
            })
            .unwrap();

        // Create child with high weight
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 2,
                parent_id: 1,
                weight: 128,
                exclusive: false,
            })
            .unwrap();

        // Create sibling to parent with low weight
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 3,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        prioritizer.update_state(1, StreamState::Open).unwrap();
        prioritizer.update_state(2, StreamState::Open).unwrap();
        prioritizer.update_state(3, StreamState::Open).unwrap();

        prioritizer.add_pending_bytes(2, 100).unwrap();
        prioritizer.add_pending_bytes(3, 100).unwrap();

        let pending = prioritizer.get_pending_streams();
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn test_reparenting_on_cleanup() {
        let config = PrioritizerConfig {
            max_streams: 100,
            idle_timeout: Duration::from_millis(10),
            strict_priority: true,
        };
        let prioritizer = StreamPrioritizer::new(config);

        // Create parent stream 1
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 1,
                parent_id: ROOT_STREAM_ID,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        // Create child stream 2
        prioritizer
            .create_stream(StreamPriority {
                stream_id: 2,
                parent_id: 1,
                weight: 16,
                exclusive: false,
            })
            .unwrap();

        // Close parent stream 1
        prioritizer.update_state(1, StreamState::Closed).unwrap();

        std::thread::sleep(Duration::from_millis(20));

        // Cleanup should reparent stream 2 to root
        let removed = prioritizer.cleanup_idle_streams();
        assert_eq!(removed, 1);

        // Stream 2 should still exist
        let stream2 = prioritizer.get_stream(2).unwrap();
        assert_eq!(stream2.parent_id, ROOT_STREAM_ID);
    }
}
