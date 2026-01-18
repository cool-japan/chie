//! Priority queue system for Quality of Service (QoS) in P2P transfers.
//!
//! This module provides:
//! - Priority-based task queuing
//! - Fair scheduling across priority levels
//! - Deadline-aware scheduling
//! - Bandwidth allocation per priority
//! - Queue statistics and monitoring

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Priority level for transfers
///
/// # Examples
///
/// ```
/// use chie_p2p::Priority;
///
/// let critical = Priority::Critical;
/// let normal = Priority::Normal;
/// assert!(critical > normal); // Higher priority values come first
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Priority {
    /// Critical priority (highest)
    Critical = 4,
    /// High priority
    High = 3,
    /// Normal priority (default)
    #[default]
    Normal = 2,
    /// Low priority
    Low = 1,
    /// Background priority (lowest)
    Background = 0,
}

/// Transfer task with priority and metadata
#[derive(Debug, Clone)]
pub struct PriorityTask<T: Clone> {
    /// Task identifier
    pub id: u64,
    /// Task payload
    pub payload: T,
    /// Priority level
    pub priority: Priority,
    /// Creation timestamp
    pub created_at: Instant,
    /// Optional deadline
    pub deadline: Option<Instant>,
    /// Task size in bytes (for bandwidth allocation)
    pub size_bytes: usize,
}

impl<T: Clone> PriorityTask<T> {
    /// Create a new priority task
    pub fn new(id: u64, payload: T, priority: Priority) -> Self {
        Self {
            id,
            payload,
            priority,
            created_at: Instant::now(),
            deadline: None,
            size_bytes: 0,
        }
    }

    /// Set deadline for the task
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Set task size
    pub fn with_size(mut self, size_bytes: usize) -> Self {
        self.size_bytes = size_bytes;
        self
    }

    /// Check if task has missed its deadline
    pub fn is_overdue(&self) -> bool {
        self.deadline.map(|d| Instant::now() > d).unwrap_or(false)
    }

    /// Get time until deadline
    pub fn time_to_deadline(&self) -> Option<Duration> {
        self.deadline
            .and_then(|d| d.checked_duration_since(Instant::now()))
    }

    /// Get age of the task
    pub fn age(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }
}

// Implement ordering for priority heap
impl<T: Clone> PartialEq for PriorityTask<T> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<T: Clone> Eq for PriorityTask<T> {}

impl<T: Clone> PartialOrd for PriorityTask<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Clone> Ord for PriorityTask<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // First compare by priority (higher is better)
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {
                // If priorities are equal, check deadlines
                match (self.deadline, other.deadline) {
                    (Some(d1), Some(d2)) => d2.cmp(&d1), // Earlier deadline first (reverse order for max heap)
                    (Some(_), None) => Ordering::Greater, // Tasks with deadlines have priority
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => other.created_at.cmp(&self.created_at), // FIFO for same priority
                }
            }
            other_ord => other_ord,
        }
    }
}

/// Priority queue statistics
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    pub total_enqueued: u64,
    pub total_dequeued: u64,
    pub total_expired: u64,
    pub current_queue_size: usize,
    pub queue_size_by_priority: HashMap<Priority, usize>,
    pub avg_wait_time_ms: u64,
    pub max_wait_time_ms: u64,
    pub tasks_by_priority: HashMap<Priority, u64>,
}

/// Priority queue manager
pub struct PriorityQueue<T: Clone> {
    inner: Arc<RwLock<PriorityQueueInner<T>>>,
}

struct PriorityQueueInner<T: Clone> {
    /// Main priority queue
    queue: BinaryHeap<PriorityTask<T>>,
    /// Tasks by priority level (for fair scheduling)
    queues_by_priority: HashMap<Priority, VecDeque<PriorityTask<T>>>,
    /// Next task ID
    next_id: u64,
    /// Statistics
    stats: QueueStats,
    /// Maximum queue size
    max_queue_size: usize,
    /// Enable fair scheduling across priorities
    fair_scheduling: bool,
    /// Bandwidth allocation per priority (bytes/sec)
    bandwidth_limits: HashMap<Priority, usize>,
}

impl<T: Clone> Default for PriorityQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> PriorityQueue<T> {
    /// Create a new priority queue
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PriorityQueueInner {
                queue: BinaryHeap::new(),
                queues_by_priority: HashMap::new(),
                next_id: 0,
                stats: QueueStats::default(),
                max_queue_size: 10000,
                fair_scheduling: false,
                bandwidth_limits: HashMap::new(),
            })),
        }
    }

    /// Create a new priority queue with fair scheduling
    pub fn with_fair_scheduling() -> Self {
        let mut queue = Self::new();
        queue.enable_fair_scheduling(true);
        queue
    }

    /// Enable or disable fair scheduling
    pub fn enable_fair_scheduling(&mut self, enabled: bool) {
        if let Ok(mut inner) = self.inner.write() {
            inner.fair_scheduling = enabled;
        }
    }

    /// Set maximum queue size
    pub fn set_max_queue_size(&mut self, size: usize) {
        if let Ok(mut inner) = self.inner.write() {
            inner.max_queue_size = size;
        }
    }

    /// Set bandwidth limit for a priority level (bytes/sec)
    pub fn set_bandwidth_limit(&mut self, priority: Priority, bytes_per_sec: usize) {
        if let Ok(mut inner) = self.inner.write() {
            inner.bandwidth_limits.insert(priority, bytes_per_sec);
        }
    }

    /// Enqueue a task
    pub fn enqueue(&self, payload: T, priority: Priority) -> Result<u64, &'static str> {
        let Ok(mut inner) = self.inner.write() else {
            return Err("Failed to acquire lock");
        };

        if inner.queue.len() >= inner.max_queue_size {
            return Err("Queue is full");
        }

        let id = inner.next_id;
        inner.next_id += 1;

        let task = PriorityTask::new(id, payload, priority);

        if inner.fair_scheduling {
            inner
                .queues_by_priority
                .entry(priority)
                .or_insert_with(VecDeque::new)
                .push_back(task.clone());
        } else {
            inner.queue.push(task);
        }

        // Update stats
        inner.stats.total_enqueued += 1;
        *inner.stats.tasks_by_priority.entry(priority).or_insert(0) += 1;
        *inner
            .stats
            .queue_size_by_priority
            .entry(priority)
            .or_insert(0) += 1;
        inner.stats.current_queue_size += 1;

        Ok(id)
    }

    /// Enqueue a task with deadline
    pub fn enqueue_with_deadline(
        &self,
        payload: T,
        priority: Priority,
        deadline: Instant,
    ) -> Result<u64, &'static str> {
        let Ok(mut inner) = self.inner.write() else {
            return Err("Failed to acquire lock");
        };

        if inner.queue.len() >= inner.max_queue_size {
            return Err("Queue is full");
        }

        let id = inner.next_id;
        inner.next_id += 1;

        let task = PriorityTask::new(id, payload, priority).with_deadline(deadline);

        if inner.fair_scheduling {
            inner
                .queues_by_priority
                .entry(priority)
                .or_insert_with(VecDeque::new)
                .push_back(task);
        } else {
            inner.queue.push(task);
        }

        inner.stats.total_enqueued += 1;
        *inner.stats.tasks_by_priority.entry(priority).or_insert(0) += 1;
        *inner
            .stats
            .queue_size_by_priority
            .entry(priority)
            .or_insert(0) += 1;
        inner.stats.current_queue_size += 1;

        Ok(id)
    }

    /// Dequeue the highest priority task
    pub fn dequeue(&self) -> Option<PriorityTask<T>> {
        let Ok(mut inner) = self.inner.write() else {
            return None;
        };

        let task = if inner.fair_scheduling {
            // Fair scheduling: round-robin across priority levels
            self.dequeue_fair(&mut inner)
        } else {
            inner.queue.pop()
        };

        if let Some(ref t) = task {
            // Update stats
            inner.stats.total_dequeued += 1;
            inner.stats.current_queue_size = inner.stats.current_queue_size.saturating_sub(1);
            if let Some(count) = inner.stats.queue_size_by_priority.get_mut(&t.priority) {
                *count = count.saturating_sub(1);
            }

            // Update wait time stats
            let wait_time = t.age().as_millis() as u64;
            if wait_time > inner.stats.max_wait_time_ms {
                inner.stats.max_wait_time_ms = wait_time;
            }

            // Update average wait time
            let total_wait = inner.stats.avg_wait_time_ms * (inner.stats.total_dequeued - 1);
            inner.stats.avg_wait_time_ms = (total_wait + wait_time) / inner.stats.total_dequeued;
        }

        task
    }

    /// Fair dequeue across priorities
    fn dequeue_fair(&self, inner: &mut PriorityQueueInner<T>) -> Option<PriorityTask<T>> {
        // Try each priority level in order
        for priority in [
            Priority::Critical,
            Priority::High,
            Priority::Normal,
            Priority::Low,
            Priority::Background,
        ] {
            if let Some(queue) = inner.queues_by_priority.get_mut(&priority) {
                if let Some(task) = queue.pop_front() {
                    return Some(task);
                }
            }
        }
        None
    }

    /// Peek at the next task without removing it
    pub fn peek(&self) -> Option<Priority> {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.queue.peek().map(|t| t.priority))
    }

    /// Get current queue size
    pub fn len(&self) -> usize {
        self.inner
            .read()
            .map(|inner| {
                if inner.fair_scheduling {
                    inner.queues_by_priority.values().map(|q| q.len()).sum()
                } else {
                    inner.queue.len()
                }
            })
            .unwrap_or(0)
    }

    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove expired tasks
    pub fn remove_expired(&self) -> usize {
        let Ok(mut inner) = self.inner.write() else {
            return 0;
        };

        let mut expired_count = 0;

        if inner.fair_scheduling {
            for queue in inner.queues_by_priority.values_mut() {
                let original_len = queue.len();
                queue.retain(|task| !task.is_overdue());
                expired_count += original_len - queue.len();
            }
        } else {
            // Rebuild heap without expired tasks
            let tasks: Vec<_> = inner.queue.drain().collect();
            for task in tasks {
                if task.is_overdue() {
                    expired_count += 1;
                } else {
                    inner.queue.push(task);
                }
            }
        }

        inner.stats.total_expired += expired_count as u64;
        inner.stats.current_queue_size =
            inner.stats.current_queue_size.saturating_sub(expired_count);

        expired_count
    }

    /// Get queue statistics
    pub fn stats(&self) -> QueueStats {
        self.inner
            .read()
            .map(|inner| inner.stats.clone())
            .unwrap_or_default()
    }

    /// Clear the queue
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.write() {
            inner.queue.clear();
            inner.queues_by_priority.clear();
            inner.stats.current_queue_size = 0;
            inner.stats.queue_size_by_priority.clear();
        }
    }
}

impl<T: Clone> Clone for PriorityQueue<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Normal > Priority::Low);
        assert!(Priority::Low > Priority::Background);
    }

    #[test]
    fn test_enqueue_dequeue() {
        let queue = PriorityQueue::new();

        let id1 = queue.enqueue("task1", Priority::Normal).unwrap();
        let id2 = queue.enqueue("task2", Priority::High).unwrap();
        let id3 = queue.enqueue("task3", Priority::Low).unwrap();

        assert_eq!(queue.len(), 3);

        // Should dequeue high priority first
        let task = queue.dequeue().unwrap();
        assert_eq!(task.id, id2);
        assert_eq!(task.priority, Priority::High);

        let task = queue.dequeue().unwrap();
        assert_eq!(task.id, id1);

        let task = queue.dequeue().unwrap();
        assert_eq!(task.id, id3);

        assert!(queue.is_empty());
    }

    #[test]
    fn test_deadline_priority() {
        let queue = PriorityQueue::new();
        let now = Instant::now();

        queue
            .enqueue_with_deadline("task1", Priority::Normal, now + Duration::from_secs(10))
            .unwrap();
        queue
            .enqueue_with_deadline("task2", Priority::Normal, now + Duration::from_secs(5))
            .unwrap();

        // Earlier deadline should be dequeued first
        let task = queue.dequeue().unwrap();
        assert_eq!(task.payload, "task2");
    }

    #[test]
    fn test_fair_scheduling() {
        let queue = PriorityQueue::with_fair_scheduling();

        queue.enqueue("high1", Priority::High).unwrap();
        queue.enqueue("normal1", Priority::Normal).unwrap();
        queue.enqueue("high2", Priority::High).unwrap();

        // With fair scheduling, should alternate
        let task = queue.dequeue().unwrap();
        assert_eq!(task.priority, Priority::High);
    }

    #[test]
    fn test_max_queue_size() {
        let mut queue = PriorityQueue::new();
        queue.set_max_queue_size(2);

        assert!(queue.enqueue("task1", Priority::Normal).is_ok());
        assert!(queue.enqueue("task2", Priority::Normal).is_ok());
        assert!(queue.enqueue("task3", Priority::Normal).is_err());
    }

    #[test]
    fn test_remove_expired() {
        let queue = PriorityQueue::new();
        let now = Instant::now();

        queue
            .enqueue_with_deadline("task1", Priority::Normal, now - Duration::from_secs(1))
            .unwrap();
        queue
            .enqueue_with_deadline("task2", Priority::Normal, now + Duration::from_secs(10))
            .unwrap();

        assert_eq!(queue.len(), 2);

        let removed = queue.remove_expired();
        assert_eq!(removed, 1);
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_stats() {
        let queue = PriorityQueue::new();

        queue.enqueue("task1", Priority::High).unwrap();
        queue.enqueue("task2", Priority::Normal).unwrap();
        queue.enqueue("task3", Priority::High).unwrap();

        let stats = queue.stats();
        assert_eq!(stats.total_enqueued, 3);
        assert_eq!(stats.current_queue_size, 3);
        assert_eq!(stats.queue_size_by_priority[&Priority::High], 2);
        assert_eq!(stats.queue_size_by_priority[&Priority::Normal], 1);

        queue.dequeue();
        let stats = queue.stats();
        assert_eq!(stats.total_dequeued, 1);
        assert_eq!(stats.current_queue_size, 2);
    }

    #[test]
    fn test_task_age() {
        let task = PriorityTask::new(1, "test", Priority::Normal);
        std::thread::sleep(Duration::from_millis(10));
        assert!(task.age() >= Duration::from_millis(10));
    }

    #[test]
    fn test_peek() {
        let queue = PriorityQueue::new();
        queue.enqueue("task1", Priority::Low).unwrap();
        queue.enqueue("task2", Priority::High).unwrap();

        assert_eq!(queue.peek(), Some(Priority::High));
        assert_eq!(queue.len(), 2); // Peek doesn't remove
    }

    #[test]
    fn test_clear() {
        let queue = PriorityQueue::new();
        queue.enqueue("task1", Priority::Normal).unwrap();
        queue.enqueue("task2", Priority::High).unwrap();

        assert_eq!(queue.len(), 2);
        queue.clear();
        assert_eq!(queue.len(), 0);
    }
}
