//! Peer recommendation system for discovering optimal connections.
//!
//! This module implements collaborative filtering and similarity-based algorithms
//! to recommend peers that are likely to provide good service based on various metrics.

use chie_shared::ChieResult;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Recommendation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendationStrategy {
    /// Collaborative filtering based on content overlap
    CollaborativeFiltering,
    /// Content-based recommendations
    ContentBased,
    /// Geographic proximity
    Geographic,
    /// Performance-based
    Performance,
    /// Hybrid approach
    Hybrid,
}

/// Peer similarity metric
#[derive(Debug, Clone)]
pub struct PeerSimilarity {
    /// Peer ID
    pub peer_id: String,
    /// Similarity score (0.0-1.0)
    pub score: f64,
    /// Contributing factors
    pub factors: HashMap<String, f64>,
}

/// Recommendation result
#[derive(Debug, Clone)]
pub struct Recommendation {
    /// Recommended peer ID
    pub peer_id: String,
    /// Recommendation score (0.0-1.0)
    pub score: f64,
    /// Confidence in recommendation
    pub confidence: f64,
    /// Reason for recommendation
    pub reason: String,
}

/// Peer interaction record
#[derive(Debug, Clone)]
struct PeerInteraction {
    /// Content accessed
    content_ids: HashSet<String>,
    /// Last interaction time
    last_interaction: Instant,
    /// Total interactions
    interaction_count: u64,
    /// Success rate
    success_rate: f64,
    /// Average latency (ms)
    avg_latency: f64,
    /// Geographic location (lat, lon)
    location: Option<(f64, f64)>,
}

/// Recommender configuration
#[derive(Debug, Clone)]
pub struct RecommenderConfig {
    /// Maximum recommendations to return
    pub max_recommendations: usize,
    /// Minimum similarity score threshold
    pub min_similarity_score: f64,
    /// Interaction history window
    pub history_window: Duration,
    /// Weight for content similarity
    pub content_weight: f64,
    /// Weight for performance
    pub performance_weight: f64,
    /// Weight for geographic proximity
    pub geographic_weight: f64,
    /// Minimum interactions before recommending
    pub min_interactions: u64,
}

impl Default for RecommenderConfig {
    fn default() -> Self {
        Self {
            max_recommendations: 10,
            min_similarity_score: 0.3,
            history_window: Duration::from_secs(86400), // 24 hours
            content_weight: 0.4,
            performance_weight: 0.4,
            geographic_weight: 0.2,
            min_interactions: 5,
        }
    }
}

/// Peer recommender system
pub struct PeerRecommender {
    /// Configuration
    config: RecommenderConfig,
    /// Peer interaction records
    interactions: Arc<RwLock<HashMap<String, PeerInteraction>>>,
    /// User interaction history (user_id -> peer_ids)
    user_history: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Statistics
    stats: Arc<RwLock<RecommenderStats>>,
}

/// Recommender statistics
#[derive(Debug, Clone, Default)]
pub struct RecommenderStats {
    /// Total recommendations generated
    pub total_recommendations: u64,
    /// Total interactions recorded
    pub total_interactions: u64,
    /// Average recommendation score
    pub avg_recommendation_score: f64,
    /// Cache hits
    pub cache_hits: u64,
}

impl PeerRecommender {
    /// Create new recommender
    pub fn new(config: RecommenderConfig) -> Self {
        Self {
            config,
            interactions: Arc::new(RwLock::new(HashMap::new())),
            user_history: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RecommenderStats::default())),
        }
    }

    /// Record peer interaction
    pub fn record_interaction(
        &self,
        user_id: &str,
        peer_id: &str,
        content_id: &str,
        success: bool,
        latency_ms: f64,
        location: Option<(f64, f64)>,
    ) -> ChieResult<()> {
        let mut interactions = self.interactions.write();
        let mut user_history = self.user_history.write();
        let mut stats = self.stats.write();

        // Update user history
        user_history
            .entry(user_id.to_string())
            .or_default()
            .insert(peer_id.to_string());

        // Update peer interaction
        let interaction =
            interactions
                .entry(peer_id.to_string())
                .or_insert_with(|| PeerInteraction {
                    content_ids: HashSet::new(),
                    last_interaction: Instant::now(),
                    interaction_count: 0,
                    success_rate: 0.0,
                    avg_latency: 0.0,
                    location,
                });

        interaction.content_ids.insert(content_id.to_string());
        interaction.last_interaction = Instant::now();
        interaction.interaction_count += 1;

        // Update success rate (exponential moving average)
        let alpha = 0.1;
        let success_val = if success { 1.0 } else { 0.0 };
        interaction.success_rate = alpha * success_val + (1.0 - alpha) * interaction.success_rate;

        // Update average latency (exponential moving average)
        interaction.avg_latency = alpha * latency_ms + (1.0 - alpha) * interaction.avg_latency;

        if let Some(loc) = location {
            interaction.location = Some(loc);
        }

        stats.total_interactions += 1;

        Ok(())
    }

    /// Get recommendations for a user
    pub fn recommend(
        &self,
        user_id: &str,
        strategy: RecommendationStrategy,
        exclude_peers: &[String],
    ) -> Vec<Recommendation> {
        let mut stats = self.stats.write();
        stats.total_recommendations += 1;

        let user_history = self.user_history.read();
        let interactions = self.interactions.read();

        // Get user's peer history
        let user_peers = match user_history.get(user_id) {
            Some(peers) => peers,
            None => return Vec::new(),
        };

        // Calculate recommendations based on strategy
        let mut recommendations = match strategy {
            RecommendationStrategy::CollaborativeFiltering => {
                self.collaborative_filtering(user_id, user_peers, &interactions, exclude_peers)
            }
            RecommendationStrategy::ContentBased => {
                self.content_based(user_peers, &interactions, exclude_peers)
            }
            RecommendationStrategy::Geographic => {
                self.geographic_based(user_peers, &interactions, exclude_peers)
            }
            RecommendationStrategy::Performance => {
                self.performance_based(&interactions, exclude_peers)
            }
            RecommendationStrategy::Hybrid => {
                self.hybrid_recommendations(user_id, user_peers, &interactions, exclude_peers)
            }
        };

        // Sort by score and limit
        recommendations.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        recommendations.truncate(self.config.max_recommendations);

        // Update stats
        if !recommendations.is_empty() {
            let avg_score: f64 =
                recommendations.iter().map(|r| r.score).sum::<f64>() / recommendations.len() as f64;
            stats.avg_recommendation_score = 0.9 * stats.avg_recommendation_score + 0.1 * avg_score;
        }

        recommendations
    }

    /// Collaborative filtering recommendations
    fn collaborative_filtering(
        &self,
        _user_id: &str,
        user_peers: &HashSet<String>,
        interactions: &HashMap<String, PeerInteraction>,
        exclude_peers: &[String],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();
        let exclude_set: HashSet<_> = exclude_peers.iter().map(|s| s.as_str()).collect();

        // Find peers with similar content access patterns
        for (peer_id, interaction) in interactions.iter() {
            if exclude_set.contains(peer_id.as_str())
                || user_peers.contains(peer_id)
                || interaction.interaction_count < self.config.min_interactions
            {
                continue;
            }

            // Calculate content overlap with user's peers
            let mut total_similarity = 0.0;
            let mut count = 0;

            for user_peer_id in user_peers {
                if let Some(user_peer_interaction) = interactions.get(user_peer_id) {
                    let similarity = self.calculate_jaccard_similarity(
                        &interaction.content_ids,
                        &user_peer_interaction.content_ids,
                    );
                    total_similarity += similarity;
                    count += 1;
                }
            }

            if count > 0 {
                let avg_similarity = total_similarity / count as f64;
                if avg_similarity >= self.config.min_similarity_score {
                    recommendations.push(Recommendation {
                        peer_id: peer_id.clone(),
                        score: avg_similarity,
                        confidence: (count as f64 / user_peers.len() as f64).min(1.0),
                        reason: format!(
                            "Similar content access patterns (similarity: {:.2})",
                            avg_similarity
                        ),
                    });
                }
            }
        }

        recommendations
    }

    /// Content-based recommendations
    fn content_based(
        &self,
        user_peers: &HashSet<String>,
        interactions: &HashMap<String, PeerInteraction>,
        exclude_peers: &[String],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();
        let exclude_set: HashSet<_> = exclude_peers.iter().map(|s| s.as_str()).collect();

        // Aggregate user's content interests
        let mut user_content: HashSet<String> = HashSet::new();
        for peer_id in user_peers {
            if let Some(interaction) = interactions.get(peer_id) {
                user_content.extend(interaction.content_ids.iter().cloned());
            }
        }

        // Find peers with overlapping content
        for (peer_id, interaction) in interactions.iter() {
            if exclude_set.contains(peer_id.as_str())
                || user_peers.contains(peer_id)
                || interaction.interaction_count < self.config.min_interactions
            {
                continue;
            }

            let similarity =
                self.calculate_jaccard_similarity(&user_content, &interaction.content_ids);

            if similarity >= self.config.min_similarity_score {
                recommendations.push(Recommendation {
                    peer_id: peer_id.clone(),
                    score: similarity,
                    confidence: (interaction.content_ids.len() as f64 / 100.0).min(1.0),
                    reason: format!("Shared content interests (overlap: {:.2})", similarity),
                });
            }
        }

        recommendations
    }

    /// Geographic-based recommendations
    fn geographic_based(
        &self,
        user_peers: &HashSet<String>,
        interactions: &HashMap<String, PeerInteraction>,
        exclude_peers: &[String],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();
        let exclude_set: HashSet<_> = exclude_peers.iter().map(|s| s.as_str()).collect();

        // Calculate average user location
        let mut user_locations: Vec<(f64, f64)> = Vec::new();
        for peer_id in user_peers {
            if let Some(interaction) = interactions.get(peer_id) {
                if let Some(loc) = interaction.location {
                    user_locations.push(loc);
                }
            }
        }

        if user_locations.is_empty() {
            return recommendations;
        }

        let avg_lat =
            user_locations.iter().map(|(lat, _)| lat).sum::<f64>() / user_locations.len() as f64;
        let avg_lon =
            user_locations.iter().map(|(_, lon)| lon).sum::<f64>() / user_locations.len() as f64;

        // Find nearby peers
        for (peer_id, interaction) in interactions.iter() {
            if exclude_set.contains(peer_id.as_str())
                || user_peers.contains(peer_id)
                || interaction.location.is_none()
                || interaction.interaction_count < self.config.min_interactions
            {
                continue;
            }

            if let Some((lat, lon)) = interaction.location {
                let distance = self.haversine_distance(avg_lat, avg_lon, lat, lon);
                // Convert distance to similarity score (closer = higher score)
                let max_distance = 20000.0; // 20,000 km
                let similarity = (1.0 - (distance / max_distance)).max(0.0);

                if similarity >= self.config.min_similarity_score {
                    recommendations.push(Recommendation {
                        peer_id: peer_id.clone(),
                        score: similarity,
                        confidence: 0.8,
                        reason: format!("Geographic proximity ({:.0} km away)", distance),
                    });
                }
            }
        }

        recommendations
    }

    /// Performance-based recommendations
    fn performance_based(
        &self,
        interactions: &HashMap<String, PeerInteraction>,
        exclude_peers: &[String],
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();
        let exclude_set: HashSet<_> = exclude_peers.iter().map(|s| s.as_str()).collect();

        for (peer_id, interaction) in interactions.iter() {
            if exclude_set.contains(peer_id.as_str())
                || interaction.interaction_count < self.config.min_interactions
            {
                continue;
            }

            // Normalize success rate (already 0-1)
            let success_score = interaction.success_rate;

            // Normalize latency (lower is better, cap at 1000ms)
            let latency_score = (1.0 - (interaction.avg_latency / 1000.0).min(1.0)).max(0.0);

            // Combined performance score
            let score = (success_score + latency_score) / 2.0;

            if score >= self.config.min_similarity_score {
                recommendations.push(Recommendation {
                    peer_id: peer_id.clone(),
                    score,
                    confidence: (interaction.interaction_count as f64 / 100.0).min(1.0),
                    reason: format!(
                        "High performance (success: {:.0}%, latency: {:.0}ms)",
                        interaction.success_rate * 100.0,
                        interaction.avg_latency
                    ),
                });
            }
        }

        recommendations
    }

    /// Hybrid recommendations combining multiple strategies
    fn hybrid_recommendations(
        &self,
        user_id: &str,
        user_peers: &HashSet<String>,
        interactions: &HashMap<String, PeerInteraction>,
        exclude_peers: &[String],
    ) -> Vec<Recommendation> {
        let mut combined_scores: HashMap<String, (f64, String, f64)> = HashMap::new();

        // Get recommendations from each strategy
        let collab_recs =
            self.collaborative_filtering(user_id, user_peers, interactions, exclude_peers);
        let content_recs = self.content_based(user_peers, interactions, exclude_peers);
        let geo_recs = self.geographic_based(user_peers, interactions, exclude_peers);
        let perf_recs = self.performance_based(interactions, exclude_peers);

        // Combine scores
        for rec in collab_recs {
            let entry =
                combined_scores
                    .entry(rec.peer_id.clone())
                    .or_insert((0.0, String::new(), 0.0));
            entry.0 += rec.score * self.config.content_weight;
            entry.1 = rec.reason;
            entry.2 = rec.confidence;
        }

        for rec in content_recs {
            let entry =
                combined_scores
                    .entry(rec.peer_id.clone())
                    .or_insert((0.0, String::new(), 0.0));
            entry.0 += rec.score * self.config.content_weight;
            if entry.1.is_empty() {
                entry.1 = rec.reason;
            }
            entry.2 = entry.2.max(rec.confidence);
        }

        for rec in geo_recs {
            let entry =
                combined_scores
                    .entry(rec.peer_id.clone())
                    .or_insert((0.0, String::new(), 0.0));
            entry.0 += rec.score * self.config.geographic_weight;
            if entry.1.is_empty() {
                entry.1 = rec.reason;
            }
            entry.2 = entry.2.max(rec.confidence);
        }

        for rec in perf_recs {
            let entry =
                combined_scores
                    .entry(rec.peer_id.clone())
                    .or_insert((0.0, String::new(), 0.0));
            entry.0 += rec.score * self.config.performance_weight;
            if entry.1.is_empty() {
                entry.1 = rec.reason;
            }
            entry.2 = entry.2.max(rec.confidence);
        }

        // Convert to recommendations
        combined_scores
            .into_iter()
            .filter(|(_, (score, _, _))| *score >= self.config.min_similarity_score)
            .map(|(peer_id, (score, reason, confidence))| Recommendation {
                peer_id,
                score,
                confidence,
                reason: if reason.is_empty() {
                    format!("Hybrid score: {:.2}", score)
                } else {
                    reason
                },
            })
            .collect()
    }

    /// Calculate Jaccard similarity between two sets
    fn calculate_jaccard_similarity(&self, set1: &HashSet<String>, set2: &HashSet<String>) -> f64 {
        if set1.is_empty() && set2.is_empty() {
            return 1.0;
        }
        if set1.is_empty() || set2.is_empty() {
            return 0.0;
        }

        let intersection = set1.intersection(set2).count() as f64;
        let union = set1.union(set2).count() as f64;

        intersection / union
    }

    /// Calculate Haversine distance between two points (in km)
    fn haversine_distance(&self, lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = lat1.to_radians();
        let lat2_rad = lat2.to_radians();
        let delta_lat = (lat2 - lat1).to_radians();
        let delta_lon = (lon2 - lon1).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }

    /// Get similar peers to a given peer
    pub fn find_similar_peers(&self, peer_id: &str, limit: usize) -> Vec<PeerSimilarity> {
        let interactions = self.interactions.read();

        let target_interaction = match interactions.get(peer_id) {
            Some(interaction) => interaction,
            None => return Vec::new(),
        };

        let mut similarities = Vec::new();

        for (other_peer_id, other_interaction) in interactions.iter() {
            if other_peer_id == peer_id {
                continue;
            }

            let mut factors = HashMap::new();

            // Content similarity
            let content_sim = self.calculate_jaccard_similarity(
                &target_interaction.content_ids,
                &other_interaction.content_ids,
            );
            factors.insert("content".to_string(), content_sim);

            // Performance similarity
            let perf_diff =
                (target_interaction.success_rate - other_interaction.success_rate).abs();
            let perf_sim = 1.0 - perf_diff;
            factors.insert("performance".to_string(), perf_sim);

            // Geographic similarity
            let geo_sim = if let (Some(loc1), Some(loc2)) =
                (target_interaction.location, other_interaction.location)
            {
                let distance = self.haversine_distance(loc1.0, loc1.1, loc2.0, loc2.1);
                (1.0 - (distance / 20000.0)).max(0.0)
            } else {
                0.5
            };
            factors.insert("geographic".to_string(), geo_sim);

            // Overall similarity (weighted average)
            let overall_score = content_sim * 0.5 + perf_sim * 0.3 + geo_sim * 0.2;

            similarities.push(PeerSimilarity {
                peer_id: other_peer_id.clone(),
                score: overall_score,
                factors,
            });
        }

        similarities.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        similarities.truncate(limit);

        similarities
    }

    /// Get statistics
    pub fn stats(&self) -> RecommenderStats {
        self.stats.read().clone()
    }

    /// Clear old interaction history
    pub fn cleanup_old_interactions(&self) -> usize {
        let mut interactions = self.interactions.write();
        let now = Instant::now();
        let initial_count = interactions.len();

        interactions.retain(|_, interaction| {
            now.duration_since(interaction.last_interaction) < self.config.history_window
        });

        initial_count - interactions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_interaction() {
        let recommender = PeerRecommender::new(RecommenderConfig::default());

        let result = recommender.record_interaction(
            "user1",
            "peer1",
            "content1",
            true,
            50.0,
            Some((37.7749, -122.4194)),
        );

        assert!(result.is_ok());
        assert_eq!(recommender.stats().total_interactions, 1);
    }

    #[test]
    fn test_collaborative_filtering() {
        let config = RecommenderConfig {
            min_interactions: 1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        // User1 interacts with peer1 and peer2
        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();
        recommender
            .record_interaction("user1", "peer2", "content1", true, 50.0, None)
            .unwrap();

        // Peer3 has similar content to peer1
        recommender
            .record_interaction("user2", "peer3", "content1", true, 50.0, None)
            .unwrap();

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::CollaborativeFiltering, &[]);

        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_content_based_recommendations() {
        let config = RecommenderConfig {
            min_interactions: 1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();
        recommender
            .record_interaction("user2", "peer2", "content1", true, 50.0, None)
            .unwrap();

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::ContentBased, &[]);

        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_geographic_recommendations() {
        let config = RecommenderConfig {
            min_interactions: 1,
            min_similarity_score: 0.1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        // User's peers in San Francisco
        recommender
            .record_interaction(
                "user1",
                "peer1",
                "content1",
                true,
                50.0,
                Some((37.7749, -122.4194)),
            )
            .unwrap();

        // Another peer nearby
        recommender
            .record_interaction(
                "user2",
                "peer2",
                "content2",
                true,
                50.0,
                Some((37.8, -122.4)),
            )
            .unwrap();

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::Geographic, &[]);

        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_performance_recommendations() {
        let config = RecommenderConfig {
            min_interactions: 1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        // High-performance peer
        recommender
            .record_interaction("user1", "peer1", "content1", true, 20.0, None)
            .unwrap();

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::Performance, &[]);

        // Should recommend peer1 based on performance
        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_hybrid_recommendations() {
        let config = RecommenderConfig {
            min_interactions: 1,
            min_similarity_score: 0.1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        recommender
            .record_interaction(
                "user1",
                "peer1",
                "content1",
                true,
                50.0,
                Some((37.7749, -122.4194)),
            )
            .unwrap();
        recommender
            .record_interaction(
                "user2",
                "peer2",
                "content1",
                true,
                30.0,
                Some((37.8, -122.4)),
            )
            .unwrap();

        let recommendations = recommender.recommend("user1", RecommendationStrategy::Hybrid, &[]);

        assert!(!recommendations.is_empty());
    }

    #[test]
    fn test_exclude_peers() {
        let config = RecommenderConfig {
            min_interactions: 1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();
        recommender
            .record_interaction("user2", "peer2", "content1", true, 50.0, None)
            .unwrap();

        let recommendations = recommender.recommend(
            "user1",
            RecommendationStrategy::ContentBased,
            &["peer2".to_string()],
        );

        assert!(recommendations.iter().all(|r| r.peer_id != "peer2"));
    }

    #[test]
    fn test_find_similar_peers() {
        let config = RecommenderConfig {
            min_interactions: 1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();
        recommender
            .record_interaction("user2", "peer2", "content1", true, 50.0, None)
            .unwrap();

        let similar = recommender.find_similar_peers("peer1", 5);

        assert!(!similar.is_empty());
        assert_eq!(similar[0].peer_id, "peer2");
    }

    #[test]
    fn test_jaccard_similarity() {
        let recommender = PeerRecommender::new(RecommenderConfig::default());

        let set1: HashSet<String> = vec!["a".to_string(), "b".to_string(), "c".to_string()]
            .into_iter()
            .collect();
        let set2: HashSet<String> = vec!["b".to_string(), "c".to_string(), "d".to_string()]
            .into_iter()
            .collect();

        let similarity = recommender.calculate_jaccard_similarity(&set1, &set2);

        // Intersection: {b, c} = 2, Union: {a, b, c, d} = 4
        assert!((similarity - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_haversine_distance() {
        let recommender = PeerRecommender::new(RecommenderConfig::default());

        // San Francisco to Los Angeles
        let distance = recommender.haversine_distance(37.7749, -122.4194, 34.0522, -118.2437);

        // Should be approximately 559 km
        assert!(distance > 500.0 && distance < 600.0);
    }

    #[test]
    fn test_max_recommendations_limit() {
        let config = RecommenderConfig {
            max_recommendations: 2,
            min_interactions: 1,
            min_similarity_score: 0.0,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        // Create multiple interactions
        for i in 1..=10 {
            recommender
                .record_interaction("user1", "peer1", "content1", true, 50.0, None)
                .unwrap();
            recommender
                .record_interaction("user2", &format!("peer{}", i), "content1", true, 50.0, None)
                .unwrap();
        }

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::ContentBased, &[]);

        assert!(recommendations.len() <= 2);
    }

    #[test]
    fn test_min_similarity_threshold() {
        let config = RecommenderConfig {
            min_similarity_score: 0.9,
            min_interactions: 1,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();
        recommender
            .record_interaction("user2", "peer2", "content2", true, 50.0, None)
            .unwrap();

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::ContentBased, &[]);

        // Should not recommend peer2 due to low similarity
        assert!(recommendations.is_empty());
    }

    #[test]
    fn test_cleanup_old_interactions() {
        let config = RecommenderConfig {
            history_window: Duration::from_millis(10),
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let cleaned = recommender.cleanup_old_interactions();
        assert_eq!(cleaned, 1);
    }

    #[test]
    fn test_stats_tracking() {
        let recommender = PeerRecommender::new(RecommenderConfig::default());

        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();

        let stats = recommender.stats();
        assert_eq!(stats.total_interactions, 1);
    }

    #[test]
    fn test_min_interactions_threshold() {
        let config = RecommenderConfig {
            min_interactions: 10,
            ..Default::default()
        };
        let recommender = PeerRecommender::new(config);

        // Single interaction (below threshold)
        recommender
            .record_interaction("user1", "peer1", "content1", true, 50.0, None)
            .unwrap();
        recommender
            .record_interaction("user2", "peer2", "content1", true, 50.0, None)
            .unwrap();

        let recommendations =
            recommender.recommend("user1", RecommendationStrategy::ContentBased, &[]);

        // Should not recommend due to insufficient interactions
        assert!(recommendations.is_empty());
    }

    #[test]
    fn test_empty_user_history() {
        let recommender = PeerRecommender::new(RecommenderConfig::default());

        let recommendations =
            recommender.recommend("unknown_user", RecommendationStrategy::Hybrid, &[]);

        assert!(recommendations.is_empty());
    }
}
