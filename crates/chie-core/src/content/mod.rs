//! Content management for CHIE Protocol.
//!
//! This module provides content metadata management with LRU caching,
//! search capabilities, and statistics tracking.

use crate::utils::LruCache;
use chie_shared::{ContentCategory, ContentMetadata};
use std::path::PathBuf;

/// Content storage manager with LRU-cached metadata.
#[derive(Debug)]
pub struct ContentManager {
    /// LRU-cached content metadata.
    metadata_cache: LruCache<String, ContentMetadata>,

    /// Local storage path.
    storage_path: PathBuf,

    /// Statistics.
    stats: ContentManagerStats,
}

/// Statistics for content manager operations.
#[derive(Debug, Default, Clone)]
pub struct ContentManagerStats {
    /// Total cache hits.
    pub cache_hits: u64,

    /// Total cache misses.
    pub cache_misses: u64,

    /// Total metadata cached.
    pub total_cached: u64,

    /// Total searches performed.
    pub total_searches: u64,
}

impl ContentManagerStats {
    /// Calculate cache hit rate.
    #[inline]
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

impl Default for ContentManager {
    fn default() -> Self {
        Self::new(PathBuf::from("."))
    }
}

impl ContentManager {
    /// Create a new content manager with default cache capacity (1000 entries).
    #[must_use]
    pub fn new(storage_path: PathBuf) -> Self {
        Self::with_capacity(storage_path, 1000)
    }

    /// Create a new content manager with specified cache capacity.
    #[must_use]
    pub fn with_capacity(storage_path: PathBuf, capacity: usize) -> Self {
        Self {
            metadata_cache: LruCache::new(capacity),
            storage_path,
            stats: ContentManagerStats::default(),
        }
    }

    /// Get the storage path.
    #[inline]
    pub fn storage_path(&self) -> &std::path::Path {
        &self.storage_path
    }

    /// Cache content metadata.
    #[inline]
    pub fn cache_metadata(&mut self, cid: String, metadata: ContentMetadata) {
        self.metadata_cache.put(cid, metadata);
        self.stats.total_cached += 1;
    }

    /// Get cached metadata.
    #[inline]
    pub fn get_metadata(&mut self, cid: &str) -> Option<&ContentMetadata> {
        let result = self.metadata_cache.get(&cid.to_string());
        if result.is_some() {
            self.stats.cache_hits += 1;
        } else {
            self.stats.cache_misses += 1;
        }
        result
    }

    /// Get cached metadata without updating statistics (immutable).
    #[inline]
    pub fn peek_metadata(&self, cid: &str) -> Option<&ContentMetadata> {
        self.metadata_cache.peek(&cid.to_string())
    }

    /// Remove metadata from cache.
    #[inline]
    pub fn remove_metadata(&mut self, cid: &str) -> Option<ContentMetadata> {
        self.metadata_cache.remove(&cid.to_string())
    }

    /// Clear all cached metadata.
    #[inline]
    pub fn clear_cache(&mut self) {
        self.metadata_cache.clear();
    }

    /// Get the number of cached items.
    #[inline]
    pub fn cached_count(&self) -> usize {
        self.metadata_cache.len()
    }

    /// Calculate total storage used by all cached content.
    #[inline]
    pub fn total_storage_used(&self) -> u64 {
        self.metadata_cache.iter().map(|(_, m)| m.size_bytes).sum()
    }

    /// Get statistics.
    #[inline]
    pub fn stats(&self) -> &ContentManagerStats {
        &self.stats
    }

    /// Reset statistics.
    #[inline]
    pub fn reset_stats(&mut self) {
        self.stats = ContentManagerStats::default();
    }

    /// Search content by category.
    #[inline]
    pub fn search_by_category(&mut self, category: ContentCategory) -> Vec<&ContentMetadata> {
        self.stats.total_searches += 1;
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| metadata.category == category)
            .map(|(_, metadata)| metadata)
            .collect()
    }

    /// Search content by tag.
    #[inline]
    pub fn search_by_tag(&mut self, tag: &str) -> Vec<&ContentMetadata> {
        self.stats.total_searches += 1;
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| metadata.tags.iter().any(|t| t == tag))
            .map(|(_, metadata)| metadata)
            .collect()
    }

    /// Search content by text (title or description).
    #[inline]
    pub fn search_by_text(&mut self, query: &str) -> Vec<&ContentMetadata> {
        self.stats.total_searches += 1;
        let query_lower = query.to_lowercase();
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| {
                metadata.title.to_lowercase().contains(&query_lower)
                    || metadata.description.to_lowercase().contains(&query_lower)
            })
            .map(|(_, metadata)| metadata)
            .collect()
    }

    /// Get all cached content sorted by size (descending).
    pub fn get_largest_content(&self, limit: usize) -> Vec<&ContentMetadata> {
        let mut content: Vec<_> = self.metadata_cache.iter().map(|(_, m)| m).collect();
        content.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        content.into_iter().take(limit).collect()
    }

    /// Get all cached content sorted by creation time (newest first).
    pub fn get_newest_content(&self, limit: usize) -> Vec<&ContentMetadata> {
        let mut content: Vec<_> = self.metadata_cache.iter().map(|(_, m)| m).collect();
        content.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        content.into_iter().take(limit).collect()
    }

    /// Check if content exists in cache.
    #[inline]
    pub fn has_metadata(&self, cid: &str) -> bool {
        self.metadata_cache.peek(&cid.to_string()).is_some()
    }

    /// Get multiple content metadata by CIDs.
    ///
    /// Note: This method updates access statistics for each lookup.
    pub fn get_multiple(&mut self, cids: &[String]) -> Vec<String> {
        cids.iter()
            .filter(|cid| self.get_metadata(cid).is_some())
            .cloned()
            .collect()
    }

    /// Batch cache multiple metadata entries.
    ///
    /// More efficient than calling cache_metadata repeatedly.
    pub fn cache_batch(&mut self, items: Vec<(String, ContentMetadata)>) {
        let count = items.len() as u64;
        for (cid, metadata) in items {
            self.metadata_cache.put(cid, metadata);
        }
        self.stats.total_cached += count;
    }

    /// Batch remove multiple metadata entries.
    ///
    /// Returns the number of items actually removed.
    pub fn remove_batch(&mut self, cids: &[String]) -> usize {
        cids.iter()
            .filter_map(|cid| self.metadata_cache.remove(&cid.to_string()))
            .count()
    }

    /// Search with multiple filters combined.
    ///
    /// Returns content that matches ALL specified criteria.
    pub fn search_filtered(
        &mut self,
        category: Option<ContentCategory>,
        tag: Option<&str>,
        min_size: Option<u64>,
        max_size: Option<u64>,
    ) -> Vec<&ContentMetadata> {
        self.stats.total_searches += 1;
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| {
                // Category filter
                if let Some(cat) = category {
                    if metadata.category != cat {
                        return false;
                    }
                }

                // Tag filter
                if let Some(t) = tag {
                    if !metadata.tags.iter().any(|tag| tag == t) {
                        return false;
                    }
                }

                // Size filters
                if let Some(min) = min_size {
                    if metadata.size_bytes < min {
                        return false;
                    }
                }
                if let Some(max) = max_size {
                    if metadata.size_bytes > max {
                        return false;
                    }
                }

                true
            })
            .map(|(_, metadata)| metadata)
            .collect()
    }

    /// Get content by price range.
    pub fn search_by_price_range(
        &mut self,
        min_price: u64,
        max_price: u64,
    ) -> Vec<&ContentMetadata> {
        self.stats.total_searches += 1;
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| metadata.price >= min_price && metadata.price <= max_price)
            .map(|(_, metadata)| metadata)
            .collect()
    }

    /// Get content by size range.
    pub fn search_by_size_range(
        &mut self,
        min_bytes: u64,
        max_bytes: u64,
    ) -> Vec<&ContentMetadata> {
        self.stats.total_searches += 1;
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| {
                metadata.size_bytes >= min_bytes && metadata.size_bytes <= max_bytes
            })
            .map(|(_, metadata)| metadata)
            .collect()
    }

    /// Get all content CIDs currently cached.
    #[inline]
    pub fn get_all_cids(&self) -> Vec<String> {
        self.metadata_cache
            .iter()
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// Get count of content by category.
    pub fn count_by_category(&self, category: ContentCategory) -> usize {
        self.metadata_cache
            .iter()
            .filter(|(_, metadata)| metadata.category == category)
            .count()
    }

    /// Get total size of all cached content.
    #[inline]
    pub fn total_content_size(&self) -> u64 {
        self.total_storage_used()
    }

    /// Get average content size.
    pub fn average_content_size(&self) -> u64 {
        let count = self.cached_count();
        if count == 0 {
            0
        } else {
            self.total_storage_used() / count as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chie_shared::{ContentCategory, ContentStatus};
    use std::path::PathBuf;

    fn create_test_metadata(cid: &str, size_bytes: u64, chunk_count: u64) -> ContentMetadata {
        ContentMetadata {
            id: uuid::Uuid::new_v4(),
            cid: cid.to_string(),
            title: format!("Test Content {}", cid),
            description: "Test description".to_string(),
            category: ContentCategory::ThreeDModels,
            tags: vec!["test".to_string()],
            size_bytes,
            chunk_count,
            price: 100,
            creator_id: uuid::Uuid::new_v4(),
            status: ContentStatus::Active,
            preview_images: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_content_manager_new() {
        let path = PathBuf::from("/tmp/chie-test");
        let manager = ContentManager::new(path.clone());

        assert_eq!(manager.storage_path(), path.as_path());
        assert_eq!(manager.total_storage_used(), 0);
    }

    #[test]
    fn test_cache_and_get_metadata() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata = create_test_metadata("QmTest123", 1024, 1);

        manager.cache_metadata("QmTest123".to_string(), metadata.clone());

        let retrieved = manager.get_metadata("QmTest123");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().cid, "QmTest123");
        assert_eq!(retrieved.unwrap().size_bytes, 1024);
        assert_eq!(manager.stats().cache_hits, 1);
        assert_eq!(manager.stats().cache_misses, 0);
    }

    #[test]
    fn test_get_nonexistent_metadata() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let result = manager.get_metadata("QmNonexistent");
        assert!(result.is_none());
        assert_eq!(manager.stats().cache_misses, 1);
    }

    #[test]
    fn test_total_storage_used() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata1 = create_test_metadata("QmTest1", 1024, 1);
        let metadata2 = create_test_metadata("QmTest2", 2048, 2);

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);

        assert_eq!(manager.total_storage_used(), 1024 + 2048);
    }

    #[test]
    fn test_content_manager_default() {
        let mut manager = ContentManager::default();

        assert_eq!(manager.total_storage_used(), 0);
        assert!(manager.get_metadata("any").is_none());
    }

    #[test]
    fn test_lru_cache_eviction() {
        let mut manager = ContentManager::with_capacity(PathBuf::from("/tmp/chie-test"), 2);

        let metadata1 = create_test_metadata("QmTest1", 1024, 1);
        let metadata2 = create_test_metadata("QmTest2", 2048, 2);
        let metadata3 = create_test_metadata("QmTest3", 3072, 3);

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        // QmTest1 should be evicted
        assert_eq!(manager.cached_count(), 2);
        assert!(manager.peek_metadata("QmTest2").is_some());
        assert!(manager.peek_metadata("QmTest3").is_some());
    }

    #[test]
    fn test_stats_tracking() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata = create_test_metadata("QmTest", 1024, 1);
        manager.cache_metadata("QmTest".to_string(), metadata);

        assert_eq!(manager.stats().total_cached, 1);

        // Hit
        manager.get_metadata("QmTest");
        assert_eq!(manager.stats().cache_hits, 1);

        // Miss
        manager.get_metadata("QmNonexistent");
        assert_eq!(manager.stats().cache_misses, 1);

        assert_eq!(manager.stats().hit_rate(), 0.5);

        manager.reset_stats();
        assert_eq!(manager.stats().cache_hits, 0);
        assert_eq!(manager.stats().cache_misses, 0);
    }

    #[test]
    fn test_search_by_category() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.category = ContentCategory::ThreeDModels;

        let mut metadata2 = create_test_metadata("QmTest2", 2048, 2);
        metadata2.category = ContentCategory::Audio;

        let mut metadata3 = create_test_metadata("QmTest3", 3072, 3);
        metadata3.category = ContentCategory::ThreeDModels;

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        let results = manager.search_by_category(ContentCategory::ThreeDModels);
        assert_eq!(results.len(), 2);
        assert_eq!(manager.stats().total_searches, 1);
    }

    #[test]
    fn test_search_by_tag() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.tags = vec!["rust".to_string(), "programming".to_string()];

        let mut metadata2 = create_test_metadata("QmTest2", 2048, 2);
        metadata2.tags = vec!["python".to_string(), "programming".to_string()];

        let mut metadata3 = create_test_metadata("QmTest3", 3072, 3);
        metadata3.tags = vec!["rust".to_string(), "web".to_string()];

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        let rust_results = manager.search_by_tag("rust");
        assert_eq!(rust_results.len(), 2);

        let programming_results = manager.search_by_tag("programming");
        assert_eq!(programming_results.len(), 2);
    }

    #[test]
    fn test_search_by_text() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.title = "Rust Programming Tutorial".to_string();
        metadata1.description = "Learn Rust from scratch".to_string();

        let mut metadata2 = create_test_metadata("QmTest2", 2048, 2);
        metadata2.title = "Python Data Science".to_string();
        metadata2.description = "Data analysis with Python".to_string();

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);

        let rust_results = manager.search_by_text("rust");
        assert_eq!(rust_results.len(), 1);
        assert_eq!(rust_results[0].cid, "QmTest1");

        let data_results = manager.search_by_text("data");
        assert_eq!(data_results.len(), 1);
        assert_eq!(data_results[0].cid, "QmTest2");
    }

    #[test]
    fn test_get_largest_content() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata1 = create_test_metadata("QmTest1", 1024, 1);
        let metadata2 = create_test_metadata("QmTest2", 3072, 3);
        let metadata3 = create_test_metadata("QmTest3", 2048, 2);

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        let largest = manager.get_largest_content(2);
        assert_eq!(largest.len(), 2);
        assert_eq!(largest[0].size_bytes, 3072);
        assert_eq!(largest[1].size_bytes, 2048);
    }

    #[test]
    fn test_get_newest_content() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.created_at = chrono::Utc::now() - chrono::Duration::days(2);

        let mut metadata2 = create_test_metadata("QmTest2", 2048, 2);
        metadata2.created_at = chrono::Utc::now();

        let mut metadata3 = create_test_metadata("QmTest3", 3072, 3);
        metadata3.created_at = chrono::Utc::now() - chrono::Duration::days(1);

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        let newest = manager.get_newest_content(2);
        assert_eq!(newest.len(), 2);
        assert_eq!(newest[0].cid, "QmTest2");
        assert_eq!(newest[1].cid, "QmTest3");
    }

    #[test]
    fn test_remove_and_clear() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata1 = create_test_metadata("QmTest1", 1024, 1);
        let metadata2 = create_test_metadata("QmTest2", 2048, 2);

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);

        assert_eq!(manager.cached_count(), 2);

        let removed = manager.remove_metadata("QmTest1");
        assert!(removed.is_some());
        assert_eq!(manager.cached_count(), 1);

        manager.clear_cache();
        assert_eq!(manager.cached_count(), 0);
    }

    #[test]
    fn test_has_metadata() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata = create_test_metadata("QmTest1", 1024, 1);
        manager.cache_metadata("QmTest1".to_string(), metadata);

        assert!(manager.has_metadata("QmTest1"));
        assert!(!manager.has_metadata("QmNonexistent"));
    }

    #[test]
    fn test_get_multiple() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let metadata1 = create_test_metadata("QmTest1", 1024, 1);
        let metadata2 = create_test_metadata("QmTest2", 2048, 2);

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);

        let cids = vec![
            "QmTest1".to_string(),
            "QmNonexistent".to_string(),
            "QmTest2".to_string(),
        ];
        let found = manager.get_multiple(&cids);

        // Should return only found CIDs (2 out of 3)
        assert_eq!(found.len(), 2);
        assert!(found.contains(&"QmTest1".to_string()));
        assert!(found.contains(&"QmTest2".to_string()));
    }

    #[test]
    fn test_cache_batch() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let items = vec![
            (
                "QmTest1".to_string(),
                create_test_metadata("QmTest1", 1024, 1),
            ),
            (
                "QmTest2".to_string(),
                create_test_metadata("QmTest2", 2048, 2),
            ),
            (
                "QmTest3".to_string(),
                create_test_metadata("QmTest3", 3072, 3),
            ),
        ];

        manager.cache_batch(items);

        assert_eq!(manager.cached_count(), 3);
        assert_eq!(manager.stats().total_cached, 3);
        assert!(manager.has_metadata("QmTest1"));
        assert!(manager.has_metadata("QmTest2"));
        assert!(manager.has_metadata("QmTest3"));
    }

    #[test]
    fn test_remove_batch() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        manager.cache_metadata(
            "QmTest1".to_string(),
            create_test_metadata("QmTest1", 1024, 1),
        );
        manager.cache_metadata(
            "QmTest2".to_string(),
            create_test_metadata("QmTest2", 2048, 2),
        );
        manager.cache_metadata(
            "QmTest3".to_string(),
            create_test_metadata("QmTest3", 3072, 3),
        );

        let to_remove = vec![
            "QmTest1".to_string(),
            "QmTest2".to_string(),
            "QmNonexistent".to_string(),
        ];
        let removed_count = manager.remove_batch(&to_remove);

        assert_eq!(removed_count, 2);
        assert_eq!(manager.cached_count(), 1);
        assert!(manager.has_metadata("QmTest3"));
        assert!(!manager.has_metadata("QmTest1"));
    }

    #[test]
    fn test_search_filtered() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.category = ContentCategory::ThreeDModels;
        metadata1.tags = vec!["premium".to_string()];

        let mut metadata2 = create_test_metadata("QmTest2", 2048 * 1024, 2);
        metadata2.category = ContentCategory::ThreeDModels;
        metadata2.tags = vec!["premium".to_string()];

        let mut metadata3 = create_test_metadata("QmTest3", 5120 * 1024, 3);
        metadata3.category = ContentCategory::Audio;
        metadata3.tags = vec!["premium".to_string()];

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        // Filter by category and size
        let results = manager.search_filtered(
            Some(ContentCategory::ThreeDModels),
            Some("premium"),
            Some(1024 * 1024),
            Some(10 * 1024 * 1024),
        );

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cid, "QmTest2");
    }

    #[test]
    fn test_search_by_price_range() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.price = 50;

        let mut metadata2 = create_test_metadata("QmTest2", 2048, 2);
        metadata2.price = 150;

        let mut metadata3 = create_test_metadata("QmTest3", 3072, 3);
        metadata3.price = 250;

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        let results = manager.search_by_price_range(100, 200);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cid, "QmTest2");
    }

    #[test]
    fn test_search_by_size_range() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        manager.cache_metadata(
            "QmTest1".to_string(),
            create_test_metadata("QmTest1", 1024, 1),
        );
        manager.cache_metadata(
            "QmTest2".to_string(),
            create_test_metadata("QmTest2", 2048, 2),
        );
        manager.cache_metadata(
            "QmTest3".to_string(),
            create_test_metadata("QmTest3", 5120, 5),
        );

        let results = manager.search_by_size_range(2000, 3000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cid, "QmTest2");
    }

    #[test]
    fn test_get_all_cids() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        manager.cache_metadata(
            "QmTest1".to_string(),
            create_test_metadata("QmTest1", 1024, 1),
        );
        manager.cache_metadata(
            "QmTest2".to_string(),
            create_test_metadata("QmTest2", 2048, 2),
        );

        let cids = manager.get_all_cids();
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&"QmTest1".to_string()));
        assert!(cids.contains(&"QmTest2".to_string()));
    }

    #[test]
    fn test_count_by_category() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        let mut metadata1 = create_test_metadata("QmTest1", 1024, 1);
        metadata1.category = ContentCategory::ThreeDModels;

        let mut metadata2 = create_test_metadata("QmTest2", 2048, 2);
        metadata2.category = ContentCategory::ThreeDModels;

        let mut metadata3 = create_test_metadata("QmTest3", 3072, 3);
        metadata3.category = ContentCategory::Audio;

        manager.cache_metadata("QmTest1".to_string(), metadata1);
        manager.cache_metadata("QmTest2".to_string(), metadata2);
        manager.cache_metadata("QmTest3".to_string(), metadata3);

        assert_eq!(manager.count_by_category(ContentCategory::ThreeDModels), 2);
        assert_eq!(manager.count_by_category(ContentCategory::Audio), 1);
        assert_eq!(manager.count_by_category(ContentCategory::Scripts), 0);
    }

    #[test]
    fn test_average_content_size() {
        let mut manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));

        manager.cache_metadata(
            "QmTest1".to_string(),
            create_test_metadata("QmTest1", 1000, 1),
        );
        manager.cache_metadata(
            "QmTest2".to_string(),
            create_test_metadata("QmTest2", 2000, 2),
        );
        manager.cache_metadata(
            "QmTest3".to_string(),
            create_test_metadata("QmTest3", 3000, 3),
        );

        assert_eq!(manager.average_content_size(), 2000);
    }

    #[test]
    fn test_average_content_size_empty() {
        let manager = ContentManager::new(PathBuf::from("/tmp/chie-test"));
        assert_eq!(manager.average_content_size(), 0);
    }
}
