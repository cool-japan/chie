//! Shared types, errors, and utilities for CHIE Protocol.
//!
//! This crate provides common types and utilities used across all CHIE Protocol components:
//! - Core protocol types (content, bandwidth proofs, chunks)
//! - Error types for protocol operations
//! - Database conversion traits
//! - Utility functions for common operations
//! - JSON schema generation (optional)
//!
//! # Examples
//!
//! ## Creating Content Metadata
//!
//! ```
//! use chie_shared::{ContentMetadataBuilder, ContentCategory, ContentStatus};
//! use uuid::Uuid;
//!
//! let creator_id = Uuid::new_v4();
//! let metadata = ContentMetadataBuilder::new()
//!     .cid("QmExampleCID123")
//!     .title("My 3D Model")
//!     .description("A high-quality 3D model")
//!     .category(ContentCategory::ThreeDModels)
//!     .add_tag("blender")
//!     .add_tag("game-ready")
//!     .size_bytes(5 * 1024 * 1024) // 5 MB
//!     .price(1000)
//!     .creator_id(creator_id)
//!     .status(ContentStatus::Active)
//!     .build()
//!     .expect("Failed to build metadata");
//!
//! assert!(metadata.is_valid());
//! assert_eq!(metadata.size_mb(), 5.0);
//! ```
//!
//! ## Building a Bandwidth Proof
//!
//! ```
//! use chie_shared::BandwidthProofBuilder;
//!
//! let proof = BandwidthProofBuilder::new()
//!     .content_cid("QmTest123")
//!     .chunk_index(0)
//!     .bytes_transferred(262144) // 256 KB
//!     .provider_peer_id("12D3KooProvider")
//!     .requester_peer_id("12D3KooRequester")
//!     .provider_public_key(vec![1u8; 32])
//!     .requester_public_key(vec![2u8; 32])
//!     .provider_signature(vec![3u8; 64])
//!     .requester_signature(vec![4u8; 64])
//!     .challenge_nonce(vec![5u8; 32])
//!     .chunk_hash(vec![6u8; 32])
//!     .timestamps(1000, 1250) // 250ms latency
//!     .build()
//!     .expect("Failed to build proof");
//!
//! assert!(proof.is_valid());
//! assert!(proof.meets_quality_threshold());
//! assert_eq!(proof.bandwidth_bps(), 1048576.0); // ~1 MB/s
//! ```
//!
//! ## Creating a Chunk Request
//!
//! ```
//! use chie_shared::{ChunkRequest, generate_nonce};
//!
//! let request = ChunkRequest::new(
//!     "QmExampleContent",
//!     0,
//!     generate_nonce(),
//!     "12D3KooRequester",
//!     [1u8; 32],
//! );
//!
//! assert!(request.is_timestamp_valid());
//! ```
//!
//! ## Using Utility Functions
//!
//! ```
//! use chie_shared::{format_bytes, format_points, calculate_demand_multiplier};
//!
//! // Format bytes for display
//! assert_eq!(format_bytes(1_048_576), "1.00 MB");
//!
//! // Format points with thousands separator
//! assert_eq!(format_points(1_234_567), "1,234,567");
//!
//! // Calculate reward multiplier based on demand/supply
//! let multiplier = calculate_demand_multiplier(100, 50);
//! assert_eq!(multiplier, 3.0); // High demand = 3x multiplier
//! ```
//!
//! ## Working with Cache Statistics
//!
//! ```
//! use chie_shared::CacheStats;
//!
//! // Create cache statistics
//! let stats = CacheStats::new(50, 100, 80, 20);
//! println!("Hit rate: {:.2}%", stats.hit_rate * 100.0);
//! println!("Fill: {:.2}%", stats.fill_percentage() * 100.0);
//! println!("Efficiency: {:.2}", stats.efficiency_score());
//! ```
//!
//! ## Tracking Performance Metrics
//!
//! ```
//! use chie_shared::{OperationStats, BandwidthMetrics};
//!
//! // Operation timing statistics
//! let ops_stats = OperationStats::new(100, 5000.0, 10.0, 200.0);
//! println!("Average: {:.2}ms", ops_stats.avg_duration_ms);
//! println!("Throughput: {:.2} ops/sec", ops_stats.ops_per_second());
//!
//! // Bandwidth metrics
//! let bw_metrics = BandwidthMetrics::new(1_000_000, 1000.0, 10, 2_000_000.0);
//! println!("Average: {:.2} Mbps", bw_metrics.avg_mbps());
//! println!("Peak: {:.2} Mbps", bw_metrics.peak_mbps());
//! ```
//!
//! ## Managing User Quotas
//!
//! ```
//! use chie_shared::{UserQuota, StorageQuota, BandwidthQuota, RateLimitQuota};
//!
//! // Create storage quota
//! let storage = StorageQuota::new(
//!     10 * 1024 * 1024 * 1024, // 10 GB total
//!     5 * 1024 * 1024 * 1024,  // 5 GB used
//!     1 * 1024 * 1024 * 1024,  // 1 GB reserved
//! );
//! println!("Storage available: {} GB", storage.available_bytes() / (1024 * 1024 * 1024));
//! println!("Utilization: {:.1}%", storage.utilization() * 100.0);
//!
//! // Create bandwidth quota (100 GB/month)
//! let bandwidth = BandwidthQuota::new(
//!     100 * 1024 * 1024 * 1024, // 100 GB total
//!     50 * 1024 * 1024 * 1024,  // 50 GB used
//!     30 * 24 * 60 * 60,        // 30 days in seconds
//!     chie_shared::now_ms() as u64,
//! );
//! println!("Bandwidth remaining: {} GB", bandwidth.remaining_bytes() / (1024 * 1024 * 1024));
//!
//! // Create rate limit quota (100 requests/minute)
//! let rate_limit = RateLimitQuota::new(100, 45, 60, chie_shared::now_ms() as u64);
//! println!("Requests remaining: {}", rate_limit.remaining_requests());
//! ```
//!
//! ## Batch Operations
//!
//! ```
//! use chie_shared::{BatchProofSubmission, BandwidthProof, BandwidthProofBuilder};
//!
//! // Create multiple proofs
//! let proof1 = BandwidthProofBuilder::new()
//!     .content_cid("QmTest1")
//!     .chunk_index(0)
//!     .bytes_transferred(262144)
//!     .provider_peer_id("12D3Koo1")
//!     .requester_peer_id("12D3Koo2")
//!     .provider_public_key(vec![1u8; 32])
//!     .requester_public_key(vec![2u8; 32])
//!     .provider_signature(vec![3u8; 64])
//!     .requester_signature(vec![4u8; 64])
//!     .challenge_nonce(vec![5u8; 32])
//!     .chunk_hash(vec![6u8; 32])
//!     .timestamps(1000, 1250)
//!     .build()
//!     .expect("Failed to build proof");
//!
//! // Submit proofs in batch
//! let batch = BatchProofSubmission::new(vec![proof1], "12D3Koo1");
//! println!("Batch contains {} proofs", batch.proof_count());
//! println!("Total bytes: {}", batch.total_bytes_transferred());
//! ```

pub mod config;
pub mod constants;
pub mod conversions;
pub mod encoding;
pub mod errors;
pub mod messages;
pub mod result;
#[cfg(feature = "schema")]
pub mod schema;
pub mod types;
pub mod utils;

pub use config::*;
pub use constants::*;
pub use conversions::*;
pub use encoding::*;
pub use errors::*;
pub use messages::*;
pub use result::*;
#[cfg(feature = "schema")]
pub use schema::*;
pub use types::*;
pub use utils::*;

// Re-export test helpers for use in other crates
#[cfg(test)]
pub use types::bandwidth::test_helpers;
