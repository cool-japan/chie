//! Core protocol logic for CHIE Protocol.
//!
//! This crate provides the main node implementation and content management for the
//! CHIE (Collective Hybrid Intelligence Ecosystem) protocol - a decentralized content
//! distribution system with incentive mechanisms.
//!
//! # Overview
//!
//! The chie-core crate contains the fundamental building blocks for running a CHIE node:
//!
//! - **Node Management** ([`node`]): Core node implementation for handling content and proofs
//! - **Storage** ([`storage`]): Chunk-based storage system with encryption support
//! - **Protocol** ([`protocol`]): Bandwidth proof protocol and validation
//! - **Content Management** ([`content`]): Content metadata caching and management
//! - **Cryptography** ([`chunk_encryption`]): Per-chunk encryption utilities
//! - **Analytics** ([`analytics`]): Performance metrics and statistics tracking
//! - **Utilities** ([`utils`]): Helper functions for common operations
//!
//! # Quick Start
//!
//! ```no_run
//! use chie_core::{ContentNode, NodeConfig, PinnedContent};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a node with storage
//!     let config = NodeConfig {
//!         storage_path: PathBuf::from("./chie-data"),
//!         max_storage_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
//!         max_bandwidth_bps: 100 * 1024 * 1024 / 8,   // 100 Mbps
//!         coordinator_url: "https://coordinator.chie.network".to_string(),
//!     };
//!
//!     let mut node = ContentNode::with_storage(config).await?;
//!
//!     // Pin content for distribution
//!     let content = PinnedContent {
//!         cid: "QmExample123".to_string(),
//!         size_bytes: 1024 * 1024,
//!         encryption_key: [0u8; 32],
//!         predicted_revenue_per_gb: 10.0,
//!     };
//!     node.pin_content(content);
//!
//!     println!("Node public key: {:?}", node.public_key());
//!     println!("Pinned content count: {}", node.pinned_count());
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! ## Content Storage
//!
//! The storage system splits content into chunks, encrypts each chunk individually,
//! and stores them with cryptographic verification:
//!
//! ```no_run
//! use chie_core::{ChunkStorage, split_into_chunks};
//! use chie_crypto::{generate_key, generate_nonce};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage_path = PathBuf::from("./storage");
//! let max_bytes = 10 * 1024 * 1024 * 1024; // 10 GB
//!
//! let mut storage = ChunkStorage::new(storage_path, max_bytes).await?;
//!
//! // Split and store content
//! let data = b"Hello, CHIE Protocol!";
//! let chunks = split_into_chunks(data, 1024);
//! let key = generate_key();
//! let nonce = generate_nonce();
//!
//! storage.pin_content("QmTest", &chunks, &key, &nonce).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Bandwidth Proof Protocol
//!
//! Nodes earn rewards by serving content and generating cryptographically-signed
//! bandwidth proofs:
//!
//! ```no_run
//! use chie_core::{create_chunk_request, create_bandwidth_proof};
//! use chie_crypto::KeyPair;
//!
//! # fn example() {
//! let requester_keypair = KeyPair::generate();
//! let provider_keypair = KeyPair::generate();
//!
//! // Create a chunk request with challenge nonce
//! let request = create_chunk_request(
//!     "QmContent123".to_string(),
//!     0, // chunk index
//!     "requester-peer-id".to_string(),
//!     requester_keypair.public_key(),
//! );
//!
//! // Provider serves chunk and signs response
//! // Requester verifies and co-signs
//! // Both submit dual-signed proof to coordinator
//! # }
//! ```
//!
//! ## Performance Optimization
//!
//! The crate includes several performance optimization features:
//!
//! - **Chunk Prefetching** ([`prefetch`]): Predict and preload chunks based on access patterns
//! - **Tiered Storage** ([`tiered_storage`]): Hot/warm/cold storage tiers for cost optimization
//! - **Rate Limiting** ([`ratelimit`]): Per-peer bandwidth throttling
//! - **Content Deduplication** ([`dedup`]): Avoid storing duplicate chunks
//! - **Garbage Collection** ([`gc`]): Remove unprofitable content automatically
//!
//! # Module Overview
//!
//! - [`adaptive_ratelimit`] - Adaptive rate limiting with dynamic adjustments
//! - [`analytics`] - Performance metrics and earnings tracking
//! - [`anomaly`] - Anomaly detection for fraud prevention
//! - [`auto_repair`] - Automatic data integrity repair for corrupted chunks
//! - [`backup`] - Storage backup and recovery utilities
//! - [`batch`] - Batch processing utilities
//! - [`cache`] - Advanced caching with TTL and memory management
//! - [`cache_invalidation`] - Distributed cache invalidation notifications
//! - [`chunk_encryption`] - Encrypted chunk data structures
//! - [`circuit_breaker`] - Circuit breaker pattern for resilient service calls
//! - [`compression`] - Content compression utilities
//! - [`connection_multiplexing`] - HTTP connection pooling and multiplexing for coordinator communication
//! - [`content`] - Content metadata management
//! - [`content_aware_cache`] - Content-aware cache sizing with intelligent management
//! - [`content_router`] - Content routing optimizer
//! - [`custom_exporters`] - Custom metrics exporters (StatsD, InfluxDB)
//! - [`dedup`] - Content deduplication
//! - [`gc`] - Garbage collection for storage
//! - [`health`] - Health check system for node monitoring
//! - [`http_pool`] - HTTP connection pooling utilities
//! - [`integrity`] - Content integrity verification
//! - [`lifecycle`] - Content lifecycle events and webhooks
//! - [`metrics`] - Prometheus-compatible metrics exporter
//! - [`network_diag`] - Network diagnostics and monitoring
//! - [`node`] - Core node implementation
//! - [`peer_selection`] - Intelligent peer selection and ranking
//! - [`pinning`] - Selective pinning optimizer
//! - [`popularity`] - Content popularity tracking
//! - [`prefetch`] - Chunk prefetching
//! - [`profiler`] - Performance profiling and timing utilities
//! - [`proof_submit`] - Proof submission with retry logic
//! - [`protocol`] - Bandwidth proof protocol
//! - [`qos`] - Quality of Service with priority-based scheduling
//! - [`quic_transport`] - QUIC transport integration for modern, efficient networking
//! - [`ratelimit`] - Rate limiting
//! - [`reputation`] - Peer reputation tracking
//! - [`resource_mgmt`] - Advanced resource management and monitoring
//! - [`storage`] - Chunk storage backend
//! - [`storage_health`] - Storage health monitoring with predictive failure detection
//! - [`streaming`] - Streaming utilities for large content
//! - [`tiered_storage`] - Multi-tier storage system
//! - [`tracing`] - OpenTelemetry tracing integration for distributed observability
//! - [`utils`] - Utility functions
//! - [`validation`] - Content and proof validation utilities

pub mod adaptive_ratelimit;
pub mod adaptive_retry;
pub mod alerting;
pub mod analytics;
pub mod anomaly;
pub mod auto_repair;
pub mod backup;
pub mod bandwidth_estimation;
pub mod batch;
pub mod cache;
pub mod cache_admission;
pub mod cache_invalidation;
pub mod cache_warming;
pub mod checkpoint;
pub mod chunk_encryption;
pub mod circuit_breaker;
pub mod compression;
pub mod config;
pub mod connection_multiplexing;
pub mod content;
pub mod content_aware_cache;
pub mod content_router;
pub mod custom_exporters;
pub mod dashboard;
pub mod dedup;
pub mod degradation;
pub mod events;
pub mod expiration;
pub mod forecasting;
pub mod gc;
pub mod geo_selection;
pub mod health;
pub mod http_pool;
pub mod integrity;
pub mod lifecycle;
pub mod logging;
pub mod metrics;
pub mod metrics_exporter;
pub mod network_diag;
pub mod node;
pub mod orchestrator;
pub mod partial_chunk;
pub mod peer_selection;
pub mod pinning;
pub mod popularity;
pub mod prefetch;
pub mod priority_eviction;
pub mod profiler;
pub mod proof_submit;
pub mod protocol;
pub mod qos;
pub mod quic_transport;
pub mod ratelimit;
pub mod reputation;
pub mod request_pipeline;
pub mod resource_mgmt;
mod serde_helpers;
pub mod storage;
pub mod storage_health;
pub mod streaming;
pub mod streaming_verification;
pub mod system_coordinator;
pub mod test_utils;
pub mod tier_migration;
pub mod tiered_cache;
pub mod tiered_storage;
pub mod tracing;
pub mod transaction;
pub mod utils;
pub mod validation;
pub mod wal;

pub use adaptive_ratelimit::*;
pub use adaptive_retry::*;
pub use alerting::*;
pub use analytics::*;
pub use anomaly::*;
pub use auto_repair::*;
pub use backup::*;
// bandwidth_estimation module available via `chie_core::bandwidth_estimation::`
// (not glob re-exported to avoid conflict with ratelimit::BandwidthStats)
pub use batch::*;
pub use cache::*;
pub use cache_admission::*;
pub use cache_invalidation::*;
pub use cache_warming::*;
pub use checkpoint::*;
pub use chunk_encryption::*;
pub use circuit_breaker::*;
pub use compression::*;
pub use config::*;
pub use connection_multiplexing::*;
pub use content::*;
pub use content_aware_cache::*;
pub use content_router::*;
// custom_exporters module available via `chie_core::custom_exporters::`
// (not glob re-exported to avoid conflict with metrics_exporter::MetricValue)
pub use dashboard::*;
pub use dedup::*;
pub use degradation::*;
pub use events::*;
pub use expiration::*;
pub use forecasting::*;
pub use gc::*;
pub use geo_selection::*;
pub use health::*;
pub use http_pool::*;
pub use integrity::*;
pub use lifecycle::*;
pub use logging::*;
pub use metrics::*;
pub use metrics_exporter::*;
pub use network_diag::*;
pub use node::*;
pub use orchestrator::*;
pub use partial_chunk::*;
pub use peer_selection::*;
pub use pinning::*;
pub use popularity::*;
pub use prefetch::*;
pub use priority_eviction::*;
pub use profiler::*;
pub use proof_submit::*;
pub use protocol::*;
pub use qos::*;
// quic_transport module available via `chie_core::quic_transport::`
// (not glob re-exported to avoid type conflicts with network modules)
pub use ratelimit::*;
pub use reputation::*;
pub use request_pipeline::*;
pub use resource_mgmt::*;
pub use storage::*;
pub use storage_health::*;
pub use streaming::*;
pub use streaming_verification::*;
// system_coordinator module available via `chie_core::system_coordinator::`
// (not glob re-exported to avoid conflict with dashboard::SystemStatus)
pub use test_utils::*;
// tiered_cache module available via `chie_core::tiered_cache::`
// (not glob re-exported to avoid conflict with cache::TieredCache)
pub use tier_migration::*;
pub use tiered_storage::*;
// tracing module available via `chie_core::tracing::`
// (not glob re-exported to avoid conflicts)
pub use transaction::*;
pub use utils::*;
pub use validation::*;
pub use wal::*;
