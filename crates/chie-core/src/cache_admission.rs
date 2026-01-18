//! Cache admission policies for intelligent caching decisions.
//!
//! This module implements various cache admission policies that determine
//! whether new items should be admitted to the cache based on their predicted
//! value. This helps prevent cache pollution from items that are unlikely
//! to be accessed again.
//!
//! # Implemented Policies
//!
//! - **TinyLFU**: Tiny Least Frequently Used with Count-Min Sketch
//! - **SLRU**: Segmented LRU with probationary and protected segments
//!
//! # Example
//!
//! ```rust
//! use chie_core::cache_admission::{TinyLFU, AdmissionPolicy};
//!
//! let mut policy = TinyLFU::new(1000, 4);
//!
//! // Record accesses
//! policy.record_access("item1");
//! policy.record_access("item1");
//! policy.record_access("item2");
//!
//! // Check if item should be admitted (comparing with victim)
//! if policy.should_admit("new_item", "victim_item") {
//!     println!("Admit new_item to cache");
//! } else {
//!     println!("Keep victim_item in cache");
//! }
//! ```

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// Admission policy trait.
pub trait AdmissionPolicy<K> {
    /// Record an access to a key.
    fn record_access(&mut self, key: &K);

    /// Check if a new key should be admitted, potentially evicting a victim.
    ///
    /// Returns true if new_key should replace victim_key.
    fn should_admit(&self, new_key: &K, victim_key: &K) -> bool;

    /// Reset the policy state.
    fn reset(&mut self);
}

/// TinyLFU admission policy using Count-Min Sketch.
///
/// TinyLFU uses a compact frequency sketch to estimate item access frequencies
/// with minimal memory overhead. It's particularly effective for preventing
/// cache pollution from one-hit wonders.
pub struct TinyLFU {
    /// Count-Min Sketch for frequency estimation.
    sketch: CountMinSketch,
    /// Doorkeeper Bloom filter for very recent items.
    doorkeeper: DoorKeeper,
    /// Sample size for reset.
    sample_size: usize,
    /// Current sample count.
    samples: usize,
}

impl TinyLFU {
    /// Create a new TinyLFU policy.
    ///
    /// # Arguments
    /// * `capacity` - Expected number of unique items
    /// * `hash_functions` - Number of hash functions for sketch (typically 4)
    #[must_use]
    #[inline]
    pub fn new(capacity: usize, hash_functions: usize) -> Self {
        Self {
            sketch: CountMinSketch::new(capacity, hash_functions),
            doorkeeper: DoorKeeper::new(capacity),
            sample_size: capacity * 10,
            samples: 0,
        }
    }

    /// Get estimated frequency for a key.
    #[must_use]
    #[inline]
    pub fn estimate_frequency<K: Hash>(&self, key: &K) -> u32 {
        self.sketch.estimate(key)
    }
}

impl<K: Hash> AdmissionPolicy<K> for TinyLFU {
    fn record_access(&mut self, key: &K) {
        // Add to doorkeeper first
        self.doorkeeper.insert(key);

        // Increment in sketch
        self.sketch.increment(key);

        // Check if we need to reset (aging)
        self.samples += 1;
        if self.samples >= self.sample_size {
            self.sketch.halve();
            self.samples = 0;
        }
    }

    fn should_admit(&self, new_key: &K, victim_key: &K) -> bool {
        let new_in_doorkeeper = self.doorkeeper.might_contain(new_key);
        let victim_in_doorkeeper = self.doorkeeper.might_contain(victim_key);

        // If only new_key is recent, admit it
        if new_in_doorkeeper && !victim_in_doorkeeper {
            return true;
        }

        // If only victim is recent, keep it
        if !new_in_doorkeeper && victim_in_doorkeeper {
            return false;
        }

        // Both recent or both not recent: compare frequencies
        let new_freq = self.sketch.estimate(new_key);
        let victim_freq = self.sketch.estimate(victim_key);

        new_freq > victim_freq
    }

    fn reset(&mut self) {
        self.sketch.reset();
        self.doorkeeper.reset();
        self.samples = 0;
    }
}

/// Count-Min Sketch for frequency estimation.
struct CountMinSketch {
    /// Sketch table (rows × columns).
    table: Vec<Vec<u32>>,
    /// Number of hash functions (rows).
    depth: usize,
    /// Width of each row.
    width: usize,
}

impl CountMinSketch {
    /// Create a new Count-Min Sketch.
    fn new(capacity: usize, depth: usize) -> Self {
        let width = capacity.next_power_of_two();
        let table = vec![vec![0; width]; depth];

        Self {
            table,
            depth,
            width,
        }
    }

    /// Increment count for a key.
    fn increment<K: Hash>(&mut self, key: &K) {
        for i in 0..self.depth {
            let hash = self.hash(key, i);
            let index = (hash as usize) % self.width;
            self.table[i][index] = self.table[i][index].saturating_add(1);
        }
    }

    /// Estimate frequency for a key.
    fn estimate<K: Hash>(&self, key: &K) -> u32 {
        (0..self.depth)
            .map(|i| {
                let hash = self.hash(key, i);
                let index = (hash as usize) % self.width;
                self.table[i][index]
            })
            .min()
            .unwrap_or(0)
    }

    /// Halve all counts (aging).
    fn halve(&mut self) {
        for row in &mut self.table {
            for count in row {
                *count /= 2;
            }
        }
    }

    /// Reset all counts.
    fn reset(&mut self) {
        for row in &mut self.table {
            row.fill(0);
        }
    }

    /// Hash function with seed.
    fn hash<K: Hash>(&self, key: &K, seed: usize) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        seed.hash(&mut hasher);
        hasher.finish()
    }
}

/// Simple Bloom filter for doorkeeper.
struct DoorKeeper {
    bits: Vec<bool>,
    size: usize,
}

impl DoorKeeper {
    fn new(capacity: usize) -> Self {
        let size = capacity.next_power_of_two();
        Self {
            bits: vec![false; size],
            size,
        }
    }

    fn insert<K: Hash>(&mut self, key: &K) {
        let hash = self.hash(key);
        let index = (hash as usize) % self.size;
        self.bits[index] = true;
    }

    fn might_contain<K: Hash>(&self, key: &K) -> bool {
        let hash = self.hash(key);
        let index = (hash as usize) % self.size;
        self.bits[index]
    }

    fn reset(&mut self) {
        self.bits.fill(false);
    }

    fn hash<K: Hash>(&self, key: &K) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }
}

/// SLRU (Segmented LRU) admission policy.
///
/// SLRU divides the cache into two segments:
/// - Probationary segment: New items start here
/// - Protected segment: Frequently accessed items are promoted here
pub struct SLRU<K: Eq + Hash + Clone> {
    /// Probationary segment.
    probationary: HashMap<K, u64>,
    /// Protected segment.
    protected: HashMap<K, u64>,
    /// Protected segment size ratio (0.0 to 1.0).
    #[allow(dead_code)]
    protected_ratio: f64,
    /// Access counter.
    counter: u64,
}

impl<K: Eq + Hash + Clone> SLRU<K> {
    /// Create a new SLRU policy.
    ///
    /// # Arguments
    /// * `protected_ratio` - Ratio of protected segment (e.g., 0.8 = 80% protected)
    #[must_use]
    #[inline]
    pub fn new(protected_ratio: f64) -> Self {
        Self {
            probationary: HashMap::new(),
            protected: HashMap::new(),
            protected_ratio: protected_ratio.clamp(0.0, 1.0),
            counter: 0,
        }
    }

    /// Check if key is in protected segment.
    #[must_use]
    #[inline]
    pub fn is_protected(&self, key: &K) -> bool {
        self.protected.contains_key(key)
    }

    /// Get segment for a key.
    #[must_use]
    #[inline]
    pub fn get_segment(&self, key: &K) -> Option<Segment> {
        if self.protected.contains_key(key) {
            Some(Segment::Protected)
        } else if self.probationary.contains_key(key) {
            Some(Segment::Probationary)
        } else {
            None
        }
    }
}

/// Cache segment in SLRU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// Probationary segment (new items).
    Probationary,
    /// Protected segment (frequently accessed).
    Protected,
}

impl<K: Eq + Hash + Clone> AdmissionPolicy<K> for SLRU<K> {
    fn record_access(&mut self, key: &K) {
        self.counter += 1;

        // Check if in probationary
        if self.probationary.contains_key(key) {
            // Promote to protected
            self.probationary.remove(key);
            self.protected.insert(key.clone(), self.counter);
        } else if self.protected.contains_key(key) {
            // Update access time
            self.protected.insert(key.clone(), self.counter);
        } else {
            // New item, add to probationary
            self.probationary.insert(key.clone(), self.counter);
        }
    }

    fn should_admit(&self, new_key: &K, victim_key: &K) -> bool {
        match (self.get_segment(new_key), self.get_segment(victim_key)) {
            (_, Some(Segment::Probationary)) => true, // Always replace probationary
            (Some(Segment::Protected), Some(Segment::Protected)) => {
                // Compare access times
                let new_time = self.protected.get(new_key).copied().unwrap_or(0);
                let victim_time = self.protected.get(victim_key).copied().unwrap_or(0);
                new_time > victim_time
            }
            (Some(Segment::Probationary), Some(Segment::Protected)) => false,
            _ => true, // Default to admit
        }
    }

    fn reset(&mut self) {
        self.probationary.clear();
        self.protected.clear();
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tinylfu_basic() {
        let mut policy = TinyLFU::new(100, 4);

        // Record multiple accesses to "hot"
        for _ in 0..10 {
            policy.record_access(&"hot");
        }

        // Record single access to "cold"
        policy.record_access(&"cold");

        // "hot" should be admitted over "cold"
        assert!(policy.should_admit(&"hot", &"cold"));
        assert!(!policy.should_admit(&"cold", &"hot"));
    }

    #[test]
    fn test_tinylfu_doorkeeper() {
        let mut policy = TinyLFU::new(100, 4);

        // Recently accessed item should be admitted
        policy.record_access(&"recent");
        assert!(policy.should_admit(&"recent", &"victim"));
    }

    #[test]
    fn test_tinylfu_frequency_estimation() {
        let mut policy = TinyLFU::new(100, 4);

        for _ in 0..5 {
            policy.record_access(&"item");
        }

        let freq = policy.estimate_frequency(&"item");
        assert!(freq >= 5);
    }

    #[test]
    fn test_slru_promotion() {
        let mut policy: SLRU<&str> = SLRU::new(0.8);

        // Add item
        policy.record_access(&"item");
        assert_eq!(policy.get_segment(&"item"), Some(Segment::Probationary));

        // Access again - should promote
        policy.record_access(&"item");
        assert_eq!(policy.get_segment(&"item"), Some(Segment::Protected));
    }

    #[test]
    fn test_slru_admission() {
        let mut policy: SLRU<&str> = SLRU::new(0.8);

        // Create protected item
        policy.record_access(&"protected");
        policy.record_access(&"protected");

        // Create probationary item
        policy.record_access(&"probationary");

        // Should always replace probationary
        assert!(policy.should_admit(&"new", &"probationary"));

        // Should not easily replace protected
        assert!(!policy.should_admit(&"probationary", &"protected"));
    }

    #[test]
    fn test_count_min_sketch() {
        let mut sketch = CountMinSketch::new(100, 4);

        sketch.increment(&"key1");
        sketch.increment(&"key1");
        sketch.increment(&"key1");

        assert_eq!(sketch.estimate(&"key1"), 3);
        assert_eq!(sketch.estimate(&"key2"), 0);
    }

    #[test]
    fn test_count_min_sketch_halving() {
        let mut sketch = CountMinSketch::new(100, 4);

        for _ in 0..10 {
            sketch.increment(&"key");
        }

        assert_eq!(sketch.estimate(&"key"), 10);

        sketch.halve();
        assert_eq!(sketch.estimate(&"key"), 5);
    }

    #[test]
    fn test_doorkeeper() {
        let mut doorkeeper = DoorKeeper::new(100);

        doorkeeper.insert(&"item");
        assert!(doorkeeper.might_contain(&"item"));

        doorkeeper.reset();
        assert!(!doorkeeper.might_contain(&"item"));
    }
}
