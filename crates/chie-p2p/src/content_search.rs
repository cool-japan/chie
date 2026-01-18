//! Network-wide content search using DHT and full-text indexing.
//!
//! This module provides distributed content search capabilities across the P2P network,
//! enabling users to discover content based on keywords, metadata, and filters.

use chie_shared::ChieResult;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Search query
#[derive(Debug, Clone)]
pub struct SearchQuery {
    /// Search keywords
    pub keywords: Vec<String>,
    /// Metadata filters
    pub filters: HashMap<String, String>,
    /// Maximum results
    pub limit: usize,
    /// Result offset for pagination
    pub offset: usize,
    /// Sort order
    pub sort_by: SortOrder,
}

/// Sort order for search results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortOrder {
    /// Relevance score (default)
    Relevance,
    /// Creation time (newest first)
    NewestFirst,
    /// Creation time (oldest first)
    OldestFirst,
    /// Popularity (most popular first)
    Popularity,
    /// File size (largest first)
    SizeDescending,
    /// File size (smallest first)
    SizeAscending,
}

/// Search result
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Content ID
    pub content_id: String,
    /// Content title
    pub title: String,
    /// Content description
    pub description: String,
    /// Metadata
    pub metadata: HashMap<String, String>,
    /// Relevance score (0.0-1.0)
    pub score: f64,
    /// Providers with this content
    pub providers: Vec<String>,
    /// Content size in bytes
    pub size: u64,
    /// Creation timestamp
    pub created_at: Instant,
    /// Popularity score
    pub popularity: u64,
}

/// Indexed content for search
#[derive(Debug, Clone)]
struct IndexedContent {
    /// Content ID
    content_id: String,
    /// Title
    title: String,
    /// Description
    description: String,
    /// Metadata
    metadata: HashMap<String, String>,
    /// Keywords (normalized)
    keywords: HashSet<String>,
    /// Providers
    providers: HashSet<String>,
    /// Size in bytes
    size: u64,
    /// Creation time
    created_at: Instant,
    /// Popularity (view count)
    popularity: u64,
    /// Last updated
    last_updated: Instant,
}

/// Search index configuration
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// Maximum indexed items
    pub max_indexed_items: usize,
    /// Index TTL for content
    pub index_ttl: Duration,
    /// Minimum keyword length
    pub min_keyword_length: usize,
    /// Enable fuzzy matching
    pub enable_fuzzy: bool,
    /// Fuzzy match threshold (0.0-1.0)
    pub fuzzy_threshold: f64,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_indexed_items: 100_000,
            index_ttl: Duration::from_secs(3600 * 24), // 24 hours
            min_keyword_length: 3,
            enable_fuzzy: true,
            fuzzy_threshold: 0.7,
        }
    }
}

/// Content search index
pub struct ContentSearch {
    /// Configuration
    config: SearchConfig,
    /// Indexed content
    index: Arc<RwLock<HashMap<String, IndexedContent>>>,
    /// Keyword to content mapping
    keyword_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Statistics
    stats: Arc<RwLock<SearchStats>>,
}

/// Search statistics
#[derive(Debug, Clone, Default)]
pub struct SearchStats {
    /// Total searches performed
    pub total_searches: u64,
    /// Total indexed items
    pub indexed_items: u64,
    /// Average search time (ms)
    pub avg_search_time: f64,
    /// Cache hits
    pub cache_hits: u64,
    /// Popular keywords
    pub popular_keywords: HashMap<String, u64>,
}

impl ContentSearch {
    /// Create new content search index
    pub fn new(config: SearchConfig) -> Self {
        Self {
            config,
            index: Arc::new(RwLock::new(HashMap::new())),
            keyword_index: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SearchStats::default())),
        }
    }

    /// Index content for search
    pub fn index_content(
        &self,
        content_id: String,
        title: String,
        description: String,
        metadata: HashMap<String, String>,
        provider_id: String,
        size: u64,
    ) -> ChieResult<()> {
        let mut index = self.index.write();
        let mut keyword_index = self.keyword_index.write();
        let mut stats = self.stats.write();

        // Extract and normalize keywords
        let keywords = self.extract_keywords(&title, &description, &metadata);

        // Create or update indexed content
        let content = index
            .entry(content_id.clone())
            .or_insert_with(|| IndexedContent {
                content_id: content_id.clone(),
                title: title.clone(),
                description: description.clone(),
                metadata: metadata.clone(),
                keywords: keywords.clone(),
                providers: HashSet::new(),
                size,
                created_at: Instant::now(),
                popularity: 0,
                last_updated: Instant::now(),
            });

        // Update fields
        content.title = title;
        content.description = description;
        content.metadata = metadata;
        content.keywords = keywords.clone();
        content.providers.insert(provider_id);
        content.size = size;
        content.last_updated = Instant::now();

        // Update keyword index
        for keyword in keywords {
            keyword_index
                .entry(keyword)
                .or_default()
                .insert(content_id.clone());
        }

        stats.indexed_items = index.len() as u64;

        // Cleanup old entries if needed
        if index.len() > self.config.max_indexed_items {
            self.cleanup_old_entries_locked(&mut index, &mut keyword_index);
        }

        Ok(())
    }

    /// Search for content
    pub fn search(&self, query: SearchQuery) -> Vec<SearchResult> {
        let start_time = Instant::now();
        let mut stats = self.stats.write();
        stats.total_searches += 1;

        // Track popular keywords
        for keyword in &query.keywords {
            *stats.popular_keywords.entry(keyword.clone()).or_insert(0) += 1;
        }

        drop(stats);

        let index = self.index.read();
        let keyword_index = self.keyword_index.read();

        // Find matching content IDs
        let mut matching_ids = HashSet::new();

        if query.keywords.is_empty() {
            // No keywords - return all
            matching_ids.extend(index.keys().cloned());
        } else {
            // Find content matching keywords
            for keyword in &query.keywords {
                let normalized = self.normalize_keyword(keyword);

                // Direct match
                if let Some(ids) = keyword_index.get(&normalized) {
                    matching_ids.extend(ids.iter().cloned());
                }

                // Fuzzy match if enabled
                if self.config.enable_fuzzy {
                    for (indexed_keyword, ids) in keyword_index.iter() {
                        let similarity = self.calculate_similarity(&normalized, indexed_keyword);
                        if similarity >= self.config.fuzzy_threshold {
                            matching_ids.extend(ids.iter().cloned());
                        }
                    }
                }
            }
        }

        // Score and filter results
        let mut results: Vec<SearchResult> = matching_ids
            .iter()
            .filter_map(|content_id| {
                let content = index.get(content_id)?;

                // Apply metadata filters
                for (key, value) in &query.filters {
                    if content.metadata.get(key) != Some(value) {
                        return None;
                    }
                }

                // Calculate relevance score
                let score = self.calculate_relevance_score(content, &query.keywords);

                Some(SearchResult {
                    content_id: content.content_id.clone(),
                    title: content.title.clone(),
                    description: content.description.clone(),
                    metadata: content.metadata.clone(),
                    score,
                    providers: content.providers.iter().cloned().collect(),
                    size: content.size,
                    created_at: content.created_at,
                    popularity: content.popularity,
                })
            })
            .collect();

        // Sort results
        match query.sort_by {
            SortOrder::Relevance => {
                results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
            }
            SortOrder::NewestFirst => {
                results.sort_by(|a, b| b.created_at.cmp(&a.created_at));
            }
            SortOrder::OldestFirst => {
                results.sort_by(|a, b| a.created_at.cmp(&b.created_at));
            }
            SortOrder::Popularity => {
                results.sort_by(|a, b| b.popularity.cmp(&a.popularity));
            }
            SortOrder::SizeDescending => {
                results.sort_by(|a, b| b.size.cmp(&a.size));
            }
            SortOrder::SizeAscending => {
                results.sort_by(|a, b| a.size.cmp(&b.size));
            }
        }

        // Apply pagination
        let results: Vec<_> = results
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();

        // Update stats
        let search_time = start_time.elapsed().as_secs_f64() * 1000.0;
        let mut stats = self.stats.write();
        stats.avg_search_time = 0.9 * stats.avg_search_time + 0.1 * search_time;

        drop(stats);
        drop(index);
        drop(keyword_index);

        results
    }

    /// Record content view for popularity tracking
    pub fn record_view(&self, content_id: &str) -> ChieResult<()> {
        let mut index = self.index.write();
        if let Some(content) = index.get_mut(content_id) {
            content.popularity += 1;
        }
        Ok(())
    }

    /// Add provider to content
    pub fn add_provider(&self, content_id: &str, provider_id: String) -> ChieResult<()> {
        let mut index = self.index.write();
        if let Some(content) = index.get_mut(content_id) {
            content.providers.insert(provider_id);
        }
        Ok(())
    }

    /// Remove provider from content
    pub fn remove_provider(&self, content_id: &str, provider_id: &str) -> ChieResult<()> {
        let mut index = self.index.write();
        if let Some(content) = index.get_mut(content_id) {
            content.providers.remove(provider_id);

            // Remove content if no providers left
            if content.providers.is_empty() {
                index.remove(content_id);
            }
        }
        Ok(())
    }

    /// Extract keywords from text
    fn extract_keywords(
        &self,
        title: &str,
        description: &str,
        metadata: &HashMap<String, String>,
    ) -> HashSet<String> {
        let mut keywords = HashSet::new();

        // Extract from title
        for word in title.split_whitespace() {
            let normalized = self.normalize_keyword(word);
            if normalized.len() >= self.config.min_keyword_length {
                keywords.insert(normalized);
            }
        }

        // Extract from description
        for word in description.split_whitespace() {
            let normalized = self.normalize_keyword(word);
            if normalized.len() >= self.config.min_keyword_length {
                keywords.insert(normalized);
            }
        }

        // Extract from metadata
        for value in metadata.values() {
            for word in value.split_whitespace() {
                let normalized = self.normalize_keyword(word);
                if normalized.len() >= self.config.min_keyword_length {
                    keywords.insert(normalized);
                }
            }
        }

        keywords
    }

    /// Normalize keyword for indexing
    fn normalize_keyword(&self, keyword: &str) -> String {
        keyword.to_lowercase().trim().to_string()
    }

    /// Calculate string similarity (Levenshtein-based)
    fn calculate_similarity(&self, s1: &str, s2: &str) -> f64 {
        if s1 == s2 {
            return 1.0;
        }
        if s1.is_empty() || s2.is_empty() {
            return 0.0;
        }

        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);

        // Simple character overlap similarity
        let common_chars: HashSet<char> = s1.chars().filter(|c| s2.contains(*c)).collect();
        let overlap = common_chars.len() as f64;

        overlap / max_len as f64
    }

    /// Calculate relevance score for content
    fn calculate_relevance_score(&self, content: &IndexedContent, keywords: &[String]) -> f64 {
        if keywords.is_empty() {
            return 1.0;
        }

        let mut total_score = 0.0;
        let mut matches = 0;

        for keyword in keywords {
            let normalized = self.normalize_keyword(keyword);

            // Exact match in keywords
            if content.keywords.contains(&normalized) {
                total_score += 1.0;
                matches += 1;
            } else if self.config.enable_fuzzy {
                // Fuzzy match
                for content_keyword in &content.keywords {
                    let similarity = self.calculate_similarity(&normalized, content_keyword);
                    if similarity >= self.config.fuzzy_threshold {
                        total_score += similarity;
                        matches += 1;
                        break;
                    }
                }
            }
        }

        if matches == 0 {
            return 0.0;
        }

        total_score / keywords.len() as f64
    }

    /// Cleanup old entries (already holds locks)
    fn cleanup_old_entries_locked(
        &self,
        index: &mut HashMap<String, IndexedContent>,
        keyword_index: &mut HashMap<String, HashSet<String>>,
    ) {
        let now = Instant::now();

        // Find expired content
        let expired: Vec<String> = index
            .iter()
            .filter(|(_, content)| now.duration_since(content.last_updated) > self.config.index_ttl)
            .map(|(id, _)| id.clone())
            .collect();

        // Remove expired content
        for content_id in expired {
            if let Some(content) = index.remove(&content_id) {
                // Remove from keyword index
                for keyword in content.keywords {
                    if let Some(ids) = keyword_index.get_mut(&keyword) {
                        ids.remove(&content_id);
                        if ids.is_empty() {
                            keyword_index.remove(&keyword);
                        }
                    }
                }
            }
        }
    }

    /// Cleanup old entries
    pub fn cleanup(&self) -> usize {
        let mut index = self.index.write();
        let mut keyword_index = self.keyword_index.write();
        let initial_count = index.len();

        self.cleanup_old_entries_locked(&mut index, &mut keyword_index);

        initial_count - index.len()
    }

    /// Get statistics
    pub fn stats(&self) -> SearchStats {
        self.stats.read().clone()
    }

    /// Get content by ID
    pub fn get_content(&self, content_id: &str) -> Option<SearchResult> {
        let index = self.index.read();
        let content = index.get(content_id)?;

        Some(SearchResult {
            content_id: content.content_id.clone(),
            title: content.title.clone(),
            description: content.description.clone(),
            metadata: content.metadata.clone(),
            score: 1.0,
            providers: content.providers.iter().cloned().collect(),
            size: content.size,
            created_at: content.created_at,
            popularity: content.popularity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_content() {
        let search = ContentSearch::new(SearchConfig::default());

        let result = search.index_content(
            "content1".to_string(),
            "Test Content".to_string(),
            "A test description".to_string(),
            HashMap::new(),
            "provider1".to_string(),
            1024,
        );

        assert!(result.is_ok());
        assert_eq!(search.stats().indexed_items, 1);
    }

    #[test]
    fn test_search_by_keyword() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Rust Programming".to_string(),
                "Learn Rust".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        let query = SearchQuery {
            keywords: vec!["rust".to_string()],
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Relevance,
        };

        let results = search.search(query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content_id, "content1");
    }

    #[test]
    fn test_fuzzy_search() {
        let config = SearchConfig {
            enable_fuzzy: true,
            fuzzy_threshold: 0.5,
            ..Default::default()
        };
        let search = ContentSearch::new(config);

        search
            .index_content(
                "content1".to_string(),
                "Python Programming".to_string(),
                "Learn Python".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        let query = SearchQuery {
            keywords: vec!["pyton".to_string()], // Typo
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Relevance,
        };

        let results = search.search(query);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_metadata_filter() {
        let search = ContentSearch::new(SearchConfig::default());

        let mut metadata1 = HashMap::new();
        metadata1.insert("type".to_string(), "video".to_string());

        let mut metadata2 = HashMap::new();
        metadata2.insert("type".to_string(), "document".to_string());

        search
            .index_content(
                "content1".to_string(),
                "Video Tutorial".to_string(),
                "A video".to_string(),
                metadata1.clone(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        search
            .index_content(
                "content2".to_string(),
                "Tutorial Document".to_string(),
                "A document".to_string(),
                metadata2,
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        let mut filters = HashMap::new();
        filters.insert("type".to_string(), "video".to_string());

        let query = SearchQuery {
            keywords: vec!["tutorial".to_string()],
            filters,
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Relevance,
        };

        let results = search.search(query);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content_id, "content1");
    }

    #[test]
    fn test_sort_by_popularity() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Content One".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        search
            .index_content(
                "content2".to_string(),
                "Content Two".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        // Make content2 more popular
        search.record_view("content2").unwrap();
        search.record_view("content2").unwrap();

        let query = SearchQuery {
            keywords: vec![],
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Popularity,
        };

        let results = search.search(query);
        assert_eq!(results[0].content_id, "content2");
    }

    #[test]
    fn test_pagination() {
        let search = ContentSearch::new(SearchConfig::default());

        for i in 0..10 {
            search
                .index_content(
                    format!("content{}", i),
                    format!("Content {}", i),
                    "Description".to_string(),
                    HashMap::new(),
                    "provider1".to_string(),
                    1024,
                )
                .unwrap();
        }

        let query = SearchQuery {
            keywords: vec![],
            filters: HashMap::new(),
            limit: 3,
            offset: 5,
            sort_by: SortOrder::Relevance,
        };

        let results = search.search(query);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_add_remove_provider() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Test".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        search
            .add_provider("content1", "provider2".to_string())
            .unwrap();

        let content = search.get_content("content1").unwrap();
        assert_eq!(content.providers.len(), 2);

        search.remove_provider("content1", "provider1").unwrap();

        let content = search.get_content("content1").unwrap();
        assert_eq!(content.providers.len(), 1);
    }

    #[test]
    fn test_cleanup_old_entries() {
        let config = SearchConfig {
            index_ttl: Duration::from_millis(10),
            ..Default::default()
        };
        let search = ContentSearch::new(config);

        search
            .index_content(
                "content1".to_string(),
                "Test".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let cleaned = search.cleanup();
        assert_eq!(cleaned, 1);
    }

    #[test]
    fn test_keyword_extraction() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Rust Programming Language Tutorial".to_string(),
                "Learn Rust programming".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        let query = SearchQuery {
            keywords: vec!["language".to_string()],
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Relevance,
        };

        let results = search.search(query);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_record_view() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Test".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        search.record_view("content1").unwrap();

        let content = search.get_content("content1").unwrap();
        assert_eq!(content.popularity, 1);
    }

    #[test]
    fn test_empty_search() {
        let search = ContentSearch::new(SearchConfig::default());

        for i in 0..5 {
            search
                .index_content(
                    format!("content{}", i),
                    format!("Content {}", i),
                    "Description".to_string(),
                    HashMap::new(),
                    "provider1".to_string(),
                    1024,
                )
                .unwrap();
        }

        let query = SearchQuery {
            keywords: vec![],
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Relevance,
        };

        let results = search.search(query);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_stats_tracking() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Test".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        let query = SearchQuery {
            keywords: vec!["test".to_string()],
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::Relevance,
        };

        search.search(query);

        let stats = search.stats();
        assert_eq!(stats.total_searches, 1);
        assert_eq!(stats.indexed_items, 1);
    }

    #[test]
    fn test_sort_by_size() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Small".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                100,
            )
            .unwrap();

        search
            .index_content(
                "content2".to_string(),
                "Large".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1000,
            )
            .unwrap();

        let query = SearchQuery {
            keywords: vec![],
            filters: HashMap::new(),
            limit: 10,
            offset: 0,
            sort_by: SortOrder::SizeDescending,
        };

        let results = search.search(query);
        assert_eq!(results[0].content_id, "content2");
        assert_eq!(results[1].content_id, "content1");
    }

    #[test]
    fn test_remove_content_when_no_providers() {
        let search = ContentSearch::new(SearchConfig::default());

        search
            .index_content(
                "content1".to_string(),
                "Test".to_string(),
                "Description".to_string(),
                HashMap::new(),
                "provider1".to_string(),
                1024,
            )
            .unwrap();

        search.remove_provider("content1", "provider1").unwrap();

        assert!(search.get_content("content1").is_none());
    }
}
