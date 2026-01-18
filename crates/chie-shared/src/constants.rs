//! Protocol constants for CHIE.

// Protocol version constants
/// Current protocol version.
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Bandwidth proof protocol ID.
pub const BANDWIDTH_PROOF_PROTOCOL: &str = "/chie/bandwidth-proof/1.0.0";

/// Content announcement protocol ID.
pub const CONTENT_ANNOUNCEMENT_PROTOCOL: &str = "/chie/content-announce/1.0.0";

// Network constants
/// Default DHT query timeout (30 seconds in milliseconds).
pub const DHT_QUERY_TIMEOUT_MS: u64 = 30_000;

/// Maximum peers to return in DHT query.
pub const MAX_DHT_PEERS: usize = 20;

/// Peer reputation decay rate (per day).
pub const REPUTATION_DECAY_RATE: f32 = 0.01;

/// Minimum reputation score (0.0).
pub const MIN_REPUTATION: f32 = 0.0;

/// Maximum reputation score (100.0).
pub const MAX_REPUTATION: f32 = 100.0;

/// Default reputation for new peers.
pub const DEFAULT_REPUTATION: f32 = 50.0;

// Reward constants
/// Base reward: 10 points per GB.
pub const BASE_POINTS_PER_GB: f64 = 10.0;

/// Maximum demand multiplier (3x).
pub const MAX_DEMAND_MULTIPLIER: f64 = 3.0;

/// Minimum demand multiplier (0.5x).
pub const MIN_DEMAND_MULTIPLIER: f64 = 0.5;

/// Latency penalty threshold (500ms).
pub const LATENCY_PENALTY_THRESHOLD_MS: u32 = 500;

/// Latency penalty multiplier (0.5x if above threshold).
pub const LATENCY_PENALTY_MULTIPLIER: f64 = 0.5;

/// Platform fee percentage (10%).
pub const PLATFORM_FEE_PERCENTAGE: f64 = 0.10;

/// Creator share percentage (20%).
pub const CREATOR_SHARE_PERCENTAGE: f64 = 0.20;

// Storage and bandwidth limits
/// Minimum free disk space required (1 GB).
pub const MIN_FREE_DISK_SPACE: u64 = 1024 * 1024 * 1024;

/// Default storage allocation (10 GB).
pub const DEFAULT_STORAGE_ALLOCATION: u64 = 10 * 1024 * 1024 * 1024;

/// Default bandwidth limit (100 Mbps).
pub const DEFAULT_BANDWIDTH_LIMIT_BPS: u64 = 100 * 1_000_000;

/// Maximum concurrent transfers per node.
pub const MAX_CONCURRENT_TRANSFERS: usize = 10;

/// Chunk request timeout (10 seconds in milliseconds).
pub const CHUNK_REQUEST_TIMEOUT_MS: u64 = 10_000;

// Rate limiting
/// Maximum proofs per peer per hour.
pub const MAX_PROOFS_PER_PEER_PER_HOUR: u32 = 1000;

/// Maximum failed requests before temporary ban.
pub const MAX_FAILED_REQUESTS: u32 = 10;

/// Temporary ban duration (1 hour in seconds).
pub const TEMP_BAN_DURATION_SECS: u64 = 3600;

/// Permanent ban threshold (repeated temp bans).
pub const PERMANENT_BAN_THRESHOLD: u32 = 3;

// Anomaly detection thresholds
/// Z-score threshold for anomaly detection.
pub const ANOMALY_Z_SCORE_THRESHOLD: f64 = 3.0;

/// Minimum samples required for statistical analysis.
pub const MIN_SAMPLES_FOR_STATS: usize = 30;

/// Maximum bandwidth deviation percentage.
pub const MAX_BANDWIDTH_DEVIATION_PERCENT: f64 = 200.0;

// Cache and database
/// Nonce cache TTL (10 minutes in seconds).
pub const NONCE_CACHE_TTL_SECS: u64 = 600;

/// Maximum nonce cache size.
pub const MAX_NONCE_CACHE_SIZE: usize = 100_000;

/// Database connection pool size.
pub const DB_POOL_SIZE: u32 = 10;

/// Database query timeout (30 seconds).
pub const DB_QUERY_TIMEOUT_SECS: u64 = 30;

// Content limits
/// Maximum preview images per content.
pub const MAX_PREVIEW_IMAGES: usize = 10;

/// Maximum file size for preview image (5 MB).
pub const MAX_PREVIEW_IMAGE_SIZE: usize = 5 * 1024 * 1024;

/// Minimum price for content (1 point).
pub const MIN_CONTENT_PRICE: u64 = 1;

/// Maximum price for content (1 million points).
pub const MAX_CONTENT_PRICE: u64 = 1_000_000;

// User and account limits
/// Minimum username length.
pub const MIN_USERNAME_LENGTH: usize = 3;

/// Maximum username length.
pub const MAX_USERNAME_LENGTH: usize = 20;

/// Minimum password length.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum password length.
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Maximum email length.
pub const MAX_EMAIL_LENGTH: usize = 254;

/// Maximum API keys per user.
pub const MAX_API_KEYS_PER_USER: usize = 5;

// Pagination defaults
/// Default page size for list queries.
pub const DEFAULT_PAGE_SIZE: u64 = 20;

/// Maximum page size for list queries.
pub const MAX_PAGE_SIZE: u64 = 100;

// Retry and backoff
/// Maximum retry attempts for proof submission.
pub const MAX_PROOF_SUBMISSION_RETRIES: u32 = 3;

/// Base backoff delay in milliseconds.
pub const BASE_BACKOFF_DELAY_MS: u64 = 1000;

/// Maximum backoff delay in milliseconds.
pub const MAX_BACKOFF_DELAY_MS: u64 = 60_000;

// Gossipsub topic names
/// Topic for content announcements.
pub const GOSSIPSUB_CONTENT_ANNOUNCE_TOPIC: &str = "chie/content/announce";

/// Topic for peer discovery.
pub const GOSSIPSUB_PEER_DISCOVERY_TOPIC: &str = "chie/peer/discovery";

/// Topic for demand updates.
pub const GOSSIPSUB_DEMAND_UPDATE_TOPIC: &str = "chie/demand/update";

// Metrics and monitoring
/// Metrics collection interval (60 seconds).
pub const METRICS_COLLECTION_INTERVAL_SECS: u64 = 60;

/// Metrics retention period (7 days).
pub const METRICS_RETENTION_DAYS: u32 = 7;

/// Health check interval (30 seconds).
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

// Garbage collection
/// Minimum content age for garbage collection (30 days in seconds).
pub const MIN_CONTENT_AGE_FOR_GC_SECS: u64 = 30 * 24 * 3600;

/// Minimum seeder count before unpinning.
pub const MIN_SEEDER_COUNT: u32 = 3;

/// Profitability check interval (24 hours in seconds).
pub const PROFITABILITY_CHECK_INTERVAL_SECS: u64 = 24 * 3600;

// Worker configuration
/// Maximum parallel encryption jobs.
pub const MAX_PARALLEL_ENCRYPTION_JOBS: usize = 4;

/// Job retry attempts.
pub const JOB_RETRY_ATTEMPTS: u32 = 3;

/// Job timeout (10 minutes in seconds).
pub const JOB_TIMEOUT_SECS: u64 = 600;
