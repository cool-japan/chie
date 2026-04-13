//! CHIE Protocol - Decentralized, privacy-preserving file sharing with zero-knowledge proofs.
//!
//! This is the meta crate that re-exports all CHIE Protocol components for convenient access.
//!
//! # Overview
//!
//! CHIE (Collective Hybrid Intelligence Ecosystem) is a decentralized content distribution
//! system with cryptographic incentive mechanisms. This crate provides a unified API to all
//! CHIE components:
//!
//! - **[`shared`]**: Common types, errors, and utilities
//! - **[`crypto`]**: Cryptographic primitives (encryption, signatures, ZK proofs)
//! - **[`core`]**: Node implementation and content management
//! - **[`p2p`]**: P2P networking layer using rust-libp2p
//!
//! # Quick Start
//!
//! ```ignore
//! use chie::prelude::*;
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a content node
//!     let config = NodeConfig {
//!         storage_path: PathBuf::from("./chie-data"),
//!         max_storage_bytes: 50 * 1024 * 1024 * 1024, // 50 GB
//!         max_bandwidth_bps: 100 * 1024 * 1024 / 8,   // 100 Mbps
//!         coordinator_url: "https://coordinator.chie.network".to_string(),
//!     };
//!
//!     let mut node = ContentNode::with_storage(config).await?;
//!
//!     // Generate cryptographic keys
//!     let keypair = KeyPair::generate();
//!     println!("Public key: {:?}", keypair.public_key());
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! ## Cryptography
//!
//! ```
//! use chie::crypto::{KeyPair, generate_key, generate_nonce, encrypt, decrypt};
//!
//! // Generate keys
//! let keypair = KeyPair::generate();
//! let encryption_key = generate_key();
//! let nonce = generate_nonce();
//!
//! // Encrypt/decrypt data
//! let plaintext = b"Hello, CHIE!";
//! let ciphertext = encrypt(plaintext, &encryption_key, &nonce).unwrap();
//! let decrypted = decrypt(&ciphertext, &encryption_key, &nonce).unwrap();
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```
//!
//! ## Content Management
//!
//! ```ignore
//! use chie::shared::{ContentMetadataBuilder, ContentCategory, ContentStatus};
//! use uuid::Uuid;
//!
//! let metadata = ContentMetadataBuilder::new()
//!     .cid("QmExampleCID123")
//!     .title("My Content")
//!     .description("A sample content item")
//!     .category(ContentCategory::ThreeDModels)
//!     .size_bytes(1024 * 1024)
//!     .price(100)
//!     .creator_id(Uuid::new_v4())
//!     .status(ContentStatus::Active)
//!     .build()
//!     .expect("Failed to build metadata");
//! ```
//!
//! ## P2P Networking
//!
//! ```
//! use chie::p2p::{CompressionManager, CompressionAlgorithm, CompressionLevel};
//!
//! // Use at least 1024 bytes so the manager's minimum-size threshold is met
//! // and actual LZ4 compression/decompression is exercised.
//! let manager = CompressionManager::new(CompressionAlgorithm::Lz4, CompressionLevel::Fast);
//! let data = vec![0u8; 2048]; // 2 KiB of zeros — highly compressible
//! let compressed = manager.compress(&data).expect("compression failed");
//! let decompressed = manager.decompress(&compressed).expect("decompression failed");
//! assert_eq!(data.as_slice(), decompressed.as_slice());
//! ```
//!
//! # Module Structure
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`shared`] | Common types, constants, errors, and utilities |
//! | [`crypto`] | Cryptographic primitives and protocols |
//! | [`core`] | Node implementation, storage, and protocol logic |
//! | [`p2p`] | P2P networking, discovery, and gossip |

#![cfg_attr(docsrs, feature(doc_cfg))]

/// Re-export of `chie-shared` - Common types, errors, and utilities.
pub use chie_shared as shared;

/// Re-export of `chie-crypto` - Cryptographic primitives and protocols.
pub use chie_crypto as crypto;

/// Re-export of `chie-core` - Core node implementation and content management.
pub use chie_core as core;

/// Re-export of `chie-p2p` - P2P networking layer.
pub use chie_p2p as p2p;

/// Prelude module for convenient imports.
///
/// Import everything commonly needed with:
/// ```
/// use chie::prelude::*;
/// ```
pub mod prelude {
    // ========================================
    // From chie-shared
    // ========================================

    // Types
    pub use chie_shared::{
        BandwidthProof, BandwidthProofBuilder, BatchProofSubmission, ChunkRequest, ChunkResponse,
        ContentCategory, ContentMetadata, ContentMetadataBuilder, ContentStatus,
    };

    // Errors
    pub use chie_shared::{ChieError, ChieResult};

    // Utilities
    pub use chie_shared::generate_nonce as shared_generate_nonce;
    pub use chie_shared::{calculate_demand_multiplier, format_bytes, format_points, now_ms};

    // Config
    pub use chie_shared::{NetworkConfig, StorageConfig};

    // Metrics
    pub use chie_shared::{BandwidthMetrics, CacheStats, OperationStats};

    // Quotas
    pub use chie_shared::{BandwidthQuota, RateLimitQuota, StorageQuota, UserQuota};

    // ========================================
    // From chie-crypto
    // ========================================

    // Core crypto types
    pub use chie_crypto::{KeyPair, PublicKey, SecretKey};

    // Encryption
    pub use chie_crypto::{EncryptionError, decrypt, encrypt, generate_key, generate_nonce};

    // Hashing
    pub use chie_crypto::{Hash, hash};

    // Signing
    pub use chie_crypto::signing::{SignatureBytes, SigningError, verify};

    // Key exchange
    pub use chie_crypto::{KeyExchange, SharedSecret};

    // ========================================
    // From chie-core
    // ========================================

    // Node
    pub use chie_core::{ContentNode, NodeConfig, PinnedContent};

    // Storage
    pub use chie_core::{ChunkStorage, split_into_chunks};

    // Protocol
    pub use chie_core::{create_bandwidth_proof, create_chunk_request};

    // Analytics
    pub use chie_core::AnalyticsCollector;

    // Cache
    pub use chie_core::TieredCache;

    // Health
    pub use chie_core::{HealthChecker, HealthStatus};

    // ========================================
    // From chie-p2p
    // ========================================

    // Compression
    pub use chie_p2p::{CompressionAlgorithm, CompressionLevel, CompressionManager};

    // Priority
    pub use chie_p2p::{Priority, PriorityQueue};

    // Discovery
    pub use chie_p2p::{BootstrapManager, ContentRouter, DiscoveryConfig};

    // Gossip
    pub use chie_p2p::{ContentAnnouncement, ContentAnnouncementGossip, GossipConfig};

    // Health
    pub use chie_p2p::HealthMonitor;

    // Metrics
    pub use chie_p2p::MetricsCollector;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_access() {
        // Verify all modules are accessible
        let _ = shared::ContentCategory::ThreeDModels;
        let _ = crypto::generate_key();
    }

    #[test]
    fn test_prelude_imports() {
        use crate::prelude::*;

        // Verify prelude types are available
        let key = generate_key();
        assert_eq!(key.len(), 32);

        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 12);
    }
}
