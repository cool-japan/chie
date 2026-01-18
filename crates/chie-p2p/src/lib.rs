//! P2P networking layer for CHIE Protocol.
//!
//! This crate provides the P2P networking functionality using rust-libp2p,
//! including the custom bandwidth proof protocol.
//!
//! # Features
//!
//! - **P2P Networking**: Built on rust-libp2p with support for TCP, QUIC, and WebRTC transports
//! - **Bandwidth Management**: Token bucket throttling, estimation, and proof-of-bandwidth protocol
//! - **Peer Discovery**: DHT-based discovery, mDNS for LAN, bootstrap nodes, and peer exchange (PEX)
//! - **Content Distribution**: Gossipsub for announcements, mesh simulation for testing
//! - **Quality of Service**: Priority queuing, load balancing, peer selection optimization
//! - **Security**: Blocklist/allowlist, circuit breaker pattern, reputation system
//! - **Monitoring**: Health checks, metrics collection, network state monitoring, analytics
//!
//! # Quick Start
//!
//! ```rust
//! use chie_p2p::{
//!     CompressionManager, CompressionAlgorithm, CompressionLevel,
//!     PriorityQueue, Priority,
//! };
//!
//! // Compression example
//! let manager = CompressionManager::new(CompressionAlgorithm::Lz4, CompressionLevel::Fast);
//! let data = b"Hello, CHIE Protocol! This is a test message.";
//! let compressed = manager.compress(data).unwrap();
//! let decompressed = manager.decompress(&compressed).unwrap();
//! assert_eq!(data.as_slice(), decompressed.as_slice());
//!
//! // Priority queue example
//! let queue = PriorityQueue::new();
//! queue.enqueue("critical-task", Priority::Critical).unwrap();
//! queue.enqueue("normal-task", Priority::Normal).unwrap();
//! let task = queue.dequeue().unwrap();
//! assert_eq!(task.payload, "critical-task"); // Critical tasks come first
//! ```
//!
//! # Module Overview
//!
//! - [`adaptive_chunk_size`]: Adaptive chunk size negotiation based on network performance
//! - [`adaptive_replication`]: Adaptive content replication based on popularity and network conditions
//! - [`adaptive_routing`]: Adaptive routing optimization with path selection
//! - [`adaptive_timeout`]: Dynamic timeout adjustment based on network conditions
//! - [`analytics`]: Network topology and performance analytics
//! - [`anti_sybil_pow`]: Anti-Sybil protection using proof-of-work challenges
//! - [`aqm`]: Active Queue Management with CoDel and PIE algorithms for congestion control
//! - [`auto_tuning`]: Automatic parameter tuning based on network conditions
//! - [`bandwidth_fairness`]: Fair bandwidth allocation across peers
//! - [`backward_compat`]: Backward compatibility layer for protocol evolution
//! - [`bandwidth`]: Bandwidth estimation and statistics
//! - [`bandwidth_prediction`]: Bandwidth prediction and forecasting using time series analysis
//! - [`bandwidth_proof`]: Bandwidth proof verification for the CHIE protocol
//! - [`bandwidth_scheduler`]: Time-based bandwidth scheduling for off-peak optimization
//! - [`bandwidth_token`]: Token-based economic system for bandwidth allocation and rewards
//! - [`blocklist`]: Peer access control with blocklist/allowlist
//! - [`cache`]: Advanced caching with TTL and multiple eviction policies
//! - [`cache_invalidation`]: Distributed cache invalidation and propagation system
//! - [`cert_pinning`]: Certificate pinning for enhanced peer security
//! - [`chunk_scheduler`]: Chunk scheduler for optimized parallel downloads
//! - [`circuit_breaker`]: Circuit breaker pattern for failure protection
//! - [`codec`]: Message serialization (bincode/JSON)
//! - [`compression`]: Data compression with multiple algorithms
//! - [`connection_manager`]: Unified connection lifecycle management
//! - [`connection_optimizer`]: Connection pool optimization strategies
//! - [`connection_pool`]: Connection pooling and reuse
//! - [`connection_prewarming`]: Connection prewarming and predictive management
//! - [`connection_quality_predictor`]: Predict connection quality before establishing connections
//! - [`connection_scheduler`]: Intelligent peer connection scheduling for optimized resource usage
//! - [`content_lifecycle`]: Content lifecycle management from creation to deletion
//! - [`content_migration`]: Content migration for load balancing and optimization
//! - [`content_popularity`]: Content popularity tracking for optimized caching
//! - [`content_search`]: Network-wide content search with full-text indexing
//! - [`content_routing`]: DHT-based content discovery and routing
//! - [`dht_replication`]: DHT replication factor enforcement for fault tolerance
//! - [`discovery`]: Peer discovery and bootstrap management
//! - [`discovery_enhanced`]: Enhanced peer discovery with quality scoring and topology awareness
//! - [`erasure_coding`]: Reed-Solomon erasure coding for efficient data redundancy
//! - [`geo_load_balancer`]: Geographic load balancing with zone awareness
//! - [`gossip`]: Content announcements via Gossipsub
//! - [`graceful_shutdown`]: Graceful shutdown with connection draining
//! - [`health`]: Connection health monitoring
//! - [`hybrid_cdn_p2p`]: Hybrid CDN/P2P controller for intelligent delivery path selection
//! - [`integrity`]: Data integrity verification and corruption detection
//! - [`keepalive`]: Connection keepalive with configurable intervals and timeout detection
//! - [`load_balancer`]: Load balancing across peers
//! - [`malicious_peer_detector`]: Malicious peer detection and automatic banning
//! - [`mesh`]: Mesh network simulation for testing
//! - [`merkle_tree`]: Merkle tree content verification with cryptographic integrity proofs
//! - [`metrics`]: Metrics collection and reporting
//! - [`metrics_export`]: Prometheus metrics export and observability
//! - [`nat`]: NAT traversal and relay support
//! - [`network_coordinator`]: Holistic network management coordinating all P2P subsystems
//! - [`network_diagnostics`]: Real-time network quality measurement (latency, jitter, packet loss)
//! - [`network_events`]: Unified event system for network observability
//! - [`network_state`]: Network state monitoring
//! - [`nonce_manager`]: Nonce management for secure bandwidth proof protocol
//! - [`partition_detector`]: Network partition detection and recovery
//! - [`peer_capabilities`]: Peer capability advertisement and discovery
//! - [`peer_churn`]: Peer churn detection and management
//! - [`peer_clustering`]: Geographic and network-based peer clustering
//! - [`peer_diversity`]: Automatic peer diversity maintenance for network resilience
//! - [`peer_quality_prediction`]: ML-inspired peer quality prediction models
//! - [`peer_reconnect`]: Automatic peer reconnection with exponential backoff
//! - [`peer_selector`]: Peer selection optimization
//! - [`persistence`]: Peer store persistence
//! - [`pex`]: Peer exchange protocol
//! - [`pool_warmup`]: Connection pool warmup for reducing startup latency
//! - [`prefetch`]: Smart prefetching system for predictive content loading
//! - [`priority_queue`]: Priority-based task scheduling
//! - [`progress_stream`]: Transfer progress streaming for UI updates
//! - [`protocol`]: Protocol versioning and negotiation
//! - [`protocol_compression`]: Protocol message compression for efficient wire transmission
//! - [`protocol_upgrade`]: Protocol upgrade negotiation for seamless transitions
//! - [`pubsub`]: Publish-subscribe system for real-time network updates
//! - [`range_request`]: HTTP-style range request support for partial content delivery
//! - [`relay_coordinator`]: Unified relay network management integrating optimizer, rewards, and economics
//! - [`relay_economics`]: Economics simulator for testing relay incentive mechanisms
//! - [`relay_optimizer`]: Multi-hop relay optimization for efficient routing
//! - [`relay_reward_manager`]: Reward management and payment processing for relay nodes
//! - [`request_multiplexing`]: Multiplexed request pipelining for concurrent requests
//! - [`rate_limiter`]: Per-peer request rate limiting for DoS protection
//! - [`peer_recommender`]: Peer recommendation system using collaborative filtering
//! - [`reputation`]: Peer reputation system
//! - [`reputation_decay`]: Time-based reputation decay and recovery
//! - [`resilience`]: Resilience patterns (retry, bulkhead, graceful degradation, chaos)
//! - [`split_brain`]: Split-brain prevention with quorum-based consensus
//! - [`stream_prioritization`]: HTTP/2-style stream prioritization with dependency trees
//! - [`streaming_helpers`]: HLS/DASH streaming protocol helpers for video delivery
//! - [`sybil_detection`]: Sybil attack detection for identifying malicious peer networks
//! - [`throttle`]: Bandwidth throttling
//! - [`tls_mutual_auth`]: TLS mutual authentication for encrypted peer communication
//! - [`topology_optimizer`]: Network topology analysis and optimization
//! - [`topology_routing`]: Topology-aware routing with multi-hop path optimization
//! - [`traffic_analysis_resistance`]: Traffic analysis resistance for enhanced privacy
//! - [`traffic_shaper`]: Traffic shaping and QoS with congestion control
//! - [`transport`]: Transport layer configuration
//! - [`webrtc`]: WebRTC support for browser nodes

pub mod adaptive_chunk_size;
pub mod adaptive_replication;
pub mod adaptive_routing;
pub mod adaptive_timeout;
pub mod analytics;
pub mod anti_sybil_pow;
pub mod aqm;
pub mod auto_tuning;
pub mod backward_compat;
pub mod bandwidth;
pub mod bandwidth_auction;
pub mod bandwidth_fairness;
pub mod bandwidth_market_maker;
pub mod bandwidth_prediction;
pub mod bandwidth_proof;
pub mod bandwidth_scheduler;
pub mod bandwidth_token;
pub mod blocklist;
pub mod cache;
pub mod cache_invalidation;
pub mod cert_pinning;
pub mod chunk_scheduler;
pub mod circuit_breaker;
pub mod codec;
pub mod compression;
pub mod connection_manager;
pub mod connection_optimizer;
pub mod connection_pool;
pub mod connection_prewarming;
pub mod connection_quality_predictor;
pub mod connection_scheduler;
pub mod content_lifecycle;
pub mod content_migration;
pub mod content_pinning;
pub mod content_popularity;
pub mod content_routing;
pub mod content_search;
pub mod content_verification;
pub mod dht_replication;
pub mod discovery;
pub mod discovery_enhanced;
pub mod epidemic_broadcast;
pub mod erasure_coding;
pub mod geo_load_balancer;
pub mod gossip;
pub mod graceful_shutdown;
pub mod health;
pub mod hybrid_cdn_p2p;
pub mod integrity;
pub mod keepalive;
pub mod load_balancer;
pub mod malicious_peer_detector;
pub mod merkle_tree;
pub mod mesh;
pub mod metrics;
pub mod metrics_export;
pub mod multi_source_download;
pub mod nat;
pub mod network_coordinator;
pub mod network_diagnostics;
pub mod network_events;
pub mod network_state;
pub mod node;
pub mod nonce_manager;
pub mod partition_detector;
pub mod peer_capabilities;
pub mod peer_churn;
pub mod peer_clustering;
pub mod peer_diversity;
pub mod peer_health_predictor;
pub mod peer_load_predictor;
pub mod peer_quality_prediction;
pub mod peer_recommender;
pub mod peer_reconnect;
pub mod peer_scoring;
pub mod peer_selector;
pub mod performance_analyzer;
pub mod persistence;
pub mod pex;
pub mod pool_warmup;
pub mod prefetch;
pub mod priority_queue;
pub mod progress_stream;
pub mod protocol;
pub mod protocol_compression;
pub mod protocol_upgrade;
pub mod pubsub;
pub mod range_request;
pub mod rate_limiter;
pub mod relay_coordinator;
pub mod relay_economics;
pub mod relay_optimizer;
pub mod relay_reward_manager;
pub mod reputation;
pub mod reputation_decay;
pub mod request_multiplexing;
pub mod resilience;
mod serde_helpers;
pub mod session_manager;
pub mod split_brain;
pub mod stream_prioritization;
pub mod streaming_helpers;
pub mod sybil_detection;
pub mod throttle;
pub mod tls_mutual_auth;
pub mod topology_optimizer;
pub mod topology_routing;
pub mod traffic_analysis_resistance;
pub mod traffic_shaper;
pub mod transfer_checkpoint;
pub mod transport;
pub mod webrtc;

pub use adaptive_chunk_size::{
    AdaptiveChunkSize, ChunkSizeConfig, ChunkSizeStats, ChunkSizeStrategy, PeerChunkSummary,
};
pub use adaptive_replication::{
    AdaptiveReplicationManager, PeerCapacity, ReplicationAction, ReplicationConfig,
    ReplicationMetadata, ReplicationStats, ReplicationStrategy,
};
pub use adaptive_routing::{
    AdaptiveRouter, AdaptiveRoutingConfig, Path, PathScoreWeights, PathStats, RoutingStats,
    RoutingStrategy,
};
pub use adaptive_timeout::{AdaptiveTimeoutManager, TimeoutConfig, TimeoutStats};
pub use analytics::{
    BandwidthStats as AnalyticsBandwidthStats, HealthScore, NetworkAnalytics, NetworkTrends,
    PeerActivity, TopologyMetrics,
};
pub use anti_sybil_pow::{
    AntiSybilConfig, AntiSybilManager, AntiSybilStats, DifficultyLevel, PoWChallenge, PoWSolution,
    solve_challenge,
};
pub use aqm::{AQMAlgorithm, AQMConfig, AQMController, AQMStats};
pub use auto_tuning::{
    AutoTuner, AutoTuningConfig, AutoTuningStats, NetworkCondition as TuningNetworkCondition,
    TuningRecommendations,
};
pub use backward_compat::{
    BackwardCompatManager, CompatStats, DefaultTranslator, FeatureFlag, MessageTranslator,
    Version as CompatVersion, VersionedMessage,
};
pub use bandwidth::{BandwidthEstimatorConfig, BandwidthEstimatorManager, BandwidthStats};
pub use bandwidth_auction::{
    Allocation, AuctionConfig, AuctionState, AuctionStats, BandwidthAuction, Bid, BidType,
};
pub use bandwidth_fairness::{
    AllocationPolicy, BandwidthFairnessController, FairnessConfig, FairnessStats,
};
pub use bandwidth_market_maker::{
    BandwidthMarketMaker, BidRecommendation, MarketCondition, MarketMakerConfig, MarketMakerStats,
    MarketStrategy,
};
pub use bandwidth_prediction::{
    BandwidthPrediction, BandwidthPredictor, BandwidthTrend, PredictionStrategy, PredictorConfig,
    PredictorStats,
};
pub use bandwidth_proof::{
    BandwidthProofVerifier, ProofRecord, VerificationConfig, VerificationError, VerificationStats,
};
pub use bandwidth_scheduler::{
    BandwidthAllocation, BandwidthPriority, BandwidthSchedule, BandwidthScheduler, ScheduleConfig,
    SchedulerStats as BandwidthSchedulerStats, TimeWindow,
};
pub use bandwidth_token::{
    BandwidthTokenSystem, TokenBalance, TokenConfig, TokenOperation, TokenStats, TokenTransaction,
};
pub use blocklist::{AccessMode, BlockReason, BlocklistManager, BlocklistStats};
pub use cache::{Cache, CacheConfig, CacheStats, EvictionPolicy};
pub use cache_invalidation::{
    CacheInvalidation, InvalidationEvent, InvalidationPattern, InvalidationStats, InvalidationType,
};
pub use cert_pinning::{
    CertificatePinner, HashAlgorithm as CertHashAlgorithm, Pin, PinPolicy, PinStats, PinViolation,
};
pub use chunk_scheduler::{
    ChunkRequest, ChunkScheduler, PeerInfo as SchedulerPeerInfo, SchedulerError, SchedulerStats,
    SchedulingStrategy,
};
pub use circuit_breaker::{
    CircuitBreakerConfig, CircuitBreakerManager, CircuitBreakerStats, CircuitCheck, CircuitState,
};
pub use codec::*;
pub use compression::{
    CompressedData, CompressionAlgorithm, CompressionLevel, CompressionManager, CompressionStats,
};
pub use connection_manager::{
    ConnectionDecision, ConnectionManager, ConnectionManagerConfig, ConnectionManagerStats,
    PeerInfo,
};
pub use connection_optimizer::{
    ConnectionOptimizer, ConnectionState as OptimizerConnectionState, OptimizationAction,
    OptimizationParams, OptimizationStrategy, OptimizerStats,
};
pub use connection_pool::{
    ConnectionPool, ConnectionPoolConfig, ConnectionPoolStats, PoolError, PooledConnection,
};
pub use connection_prewarming::{
    ConnectionPattern, ConnectionStats as PrewarmConnectionStats, ConnectionStatus,
    MigrationStrategy, PathInfo, PrewarmingManager, PrewarmingStats,
};
pub use connection_quality_predictor::{
    ConnectionQualityPredictor, PredictionModel as ConnectionPredictionModel,
    PredictorConfig as ConnectionPredictorConfig, PredictorStats as ConnectionPredictorStats,
    QualityPrediction,
};
pub use connection_scheduler::{
    ConnectionPriority, ConnectionScheduler, ScheduledConnection, SchedulerConfig,
    SchedulerStats as ConnectionSchedulerStats, SchedulingStrategy as ConnectionSchedulingStrategy,
};
pub use content_lifecycle::{
    ContentLifecycle, ContentLifecycleManager, LifecyclePolicy, LifecycleStage, LifecycleStats,
    LifecycleTransition,
};
pub use content_migration::{
    ContentMigrationManager, Migration, MigrationConfig, MigrationState, MigrationStats,
    MigrationTrigger,
};
pub use content_pinning::{
    PinPriority, PinStatus, PinnedContent, PinningConfig, PinningManager, PinningStats,
};
pub use content_popularity::{
    ContentPopularity, PopularityStats, PopularityTracker, TrackingConfig,
};
pub use content_routing::{
    ContentRecord, ContentRouter, RoutingConfig, RoutingError, RoutingStats as ContentRoutingStats,
};
pub use content_search::{
    ContentSearch, SearchConfig, SearchQuery, SearchResult, SearchStats, SortOrder,
};
pub use content_verification::{
    PipelineConfig, PipelineStats, VerificationPipeline, VerificationPriority, VerificationResult,
    VerificationStatus, VerificationTask,
};
pub use dht_replication::{
    ContentPriority, ContentReplicationStatus, DhtReplicationManager, DhtReplicationStats,
    ReplicaInfo, ReplicationConfig as DhtReplicationConfig,
};
pub use discovery::{
    BootstrapError, BootstrapHealth, BootstrapManager, BootstrapNodeInfo, BootstrapSource,
    BootstrapStats, ContentAdvertisement, ContentAdvertisementManager, ContentAdvertisementStats,
    ContentProvider, ContentQuery, DiscoveredPeers, DiscoveryConfig, ENV_BOOTSTRAP_DNS,
    ENV_BOOTSTRAP_NODES, cid_to_dht_key, load_bootstrap_dns_from_env, load_bootstrap_from_env,
    load_static_bootstrap_nodes,
};
pub use discovery_enhanced::{
    DiscoveryEnhanced, DiscoveryStats, EnhancedPeerInfo, GeoLocation,
    PeerQuality as EnhancedPeerQuality, ReplacementStrategy,
    SelectionStrategy as DiscoverySelectionStrategy, TopologyPosition,
};
pub use epidemic_broadcast::{
    BroadcastConfig, BroadcastStats, EpidemicBroadcaster, EpidemicMessage, EpidemicStrategy,
    MessageState,
};
pub use erasure_coding::{ErasureCoder, ErasureConfig, ErasureError, ErasureStats};
pub use geo_load_balancer::{
    GeoLoadBalancer, GeoLoadBalancerStats, GeoLocation as LoadBalancerGeoLocation, GeoNode, GeoZone,
};
pub use gossip::{
    AnnouncementType, AnnouncementValidator, CONTENT_ANNOUNCEMENT_TOPIC, ContentAnnouncement,
    ContentAnnouncementGossip, GossipConfig, GossipError, GossipMessageResult, GossipStats,
    MAX_ANNOUNCEMENT_SIZE, PROVIDER_STATUS_TOPIC, ProviderAnnouncement, ReceivedAnnouncement,
};
pub use graceful_shutdown::{
    ShutdownConfig, ShutdownManager, ShutdownMode, ShutdownStage, ShutdownStats,
};
pub use health::{HealthCheck, HealthConfig, HealthMonitor, HealthMonitorStats, HealthStatus};
pub use hybrid_cdn_p2p::{
    ContentMetadata, DecisionPolicy, DeliveryDecision, DeliveryMethod, HybridConfig,
    HybridController, HybridStats, NetworkConditions,
};
pub use integrity::{
    ChunkVerification, HashAlgorithm, IntegrityChecker, IntegrityConfig, IntegrityResult,
    IntegrityStats,
};
pub use keepalive::{
    ConnectionState as KeepaliveConnectionState, KeepaliveConfig, KeepaliveError, KeepaliveEvent,
    KeepaliveManager, KeepaliveMessage, KeepaliveStats, PeerId,
};
pub use load_balancer::{
    LoadBalancer, LoadBalancerStats, LoadBalancingAlgorithm, PeerLoad, SessionAffinity,
};
pub use malicious_peer_detector::{
    BanStatus, DetectionScore, DetectorConfig, DetectorStats, Evidence, MaliciousBehavior,
    MaliciousPeerDetector,
};
pub use merkle_tree::{HASH_SIZE, Hash, MerkleProof, MerkleStats, MerkleTree, MerkleTreeManager};
pub use mesh::{
    CustomScenarioFn, MeshConfig, MeshError, MeshScenario, MeshSimulation, MeshStats, NodeStats,
    SimulatedTransfer, VirtualNode,
};
pub use metrics::{
    AtomicCounter, BandwidthMetrics, ConnectionMetrics, ConnectionSnapshot, LatencyMetrics,
    LatencyStats, MetricsCollector, MetricsConfig, MetricsReport, PeerMetrics, ProtocolMetrics,
    create_metrics_collector,
};
pub use metrics_export::{
    ExporterStats, Histogram, HistogramBucket, MetricLabel, MetricType, MetricValue,
    MetricsExporter, NetworkVisualization, Profiler, TracingSpan, VisualizationEdge,
    VisualizationNode,
};
pub use multi_source_download::{
    DownloadSession, DownloaderConfig, DownloaderStats, MultiSourceDownloader, SourceInfo,
};
pub use nat::*;
pub use network_coordinator::{
    CoordinatorConfig, CoordinatorMetrics, NetworkCoordinator, OptimizationGoal, Recommendation,
    RecommendationType, SystemHealth,
};
pub use network_diagnostics::{
    DiagnosticsConfig, DiagnosticsStats, NetworkDiagnostics, NetworkQuality, QualityDistribution,
    QualityMetrics,
};
pub use network_events::{
    EventCallback, EventCategory, EventFilter, EventManagerConfig, EventSeverity, EventStats,
    NetworkEvent, NetworkEventManager, SubscriptionId, TimestampedEvent,
};
pub use network_state::{
    HealthThresholds, NetworkCondition, NetworkMetrics, NetworkState, NetworkStateMonitor,
    NetworkStateStats, PeerStatus, StateChangeEvent,
};
pub use node::*;
pub use nonce_manager::{NonceConfig, NonceError, NonceInfo, NonceManager, NonceStats};
pub use partition_detector::{
    PartitionDetector, PartitionDetectorConfig, PartitionInfo, PartitionState, PartitionStats,
};
pub use peer_capabilities::{
    Capability, CapabilityConfig, CapabilityManager, CapabilityMetadata, CapabilityRequirement,
    CapabilityStats, PeerCapabilities,
};
pub use peer_churn::{ChurnConfig, ChurnHandler, ChurnLevel, ChurnStats, PeerEvent, PeerStability};
pub use peer_clustering::{
    ClusteringConfig, ClusteringMethod, ClusteringStats, GeoCoordinate, PeerCluster,
    PeerClusteringManager, PeerLocationInfo,
};
pub use peer_diversity::{
    BandwidthClass, DiversityConfig, DiversityDimension, DiversityRecommendation, DiversityStats,
    GeographicRegion, LatencyClass, PeerDiversityInfo, PeerDiversityManager,
};
pub use peer_health_predictor::{BehaviorPattern, HealthPrediction, PeerHealthPredictor};
pub use peer_load_predictor::{
    LoadPrediction, LoadPredictorConfig, LoadPredictorStats, LoadTrend, PeerLoadPredictor,
    PredictionModel as LoadPredictionModel,
};
pub use peer_quality_prediction::{
    PeerQualityPredictor, PredictionModel, PredictorConfig as QualityPredictorConfig,
    PredictorStats as QualityPredictorStats, QualityMetric,
    QualityPrediction as PeerQualityPrediction,
};
pub use peer_recommender::{
    PeerRecommender, PeerSimilarity, Recommendation as PeerRecommendation, RecommendationStrategy,
    RecommenderConfig, RecommenderStats,
};
pub use peer_reconnect::{
    ReconnectPriority, ReconnectionConfig, ReconnectionManager, ReconnectionState,
    ReconnectionStats,
};
pub use peer_scoring::{
    PeerMetrics as ScoringPeerMetrics, PeerScorer, ScoreWeights, ScorerConfig, ScorerStats,
};
pub use peer_selector::{
    PeerQuality, PeerSelector, SelectionStrategy, SelectionWeights, SelectorStats,
};
pub use performance_analyzer::{
    AnalyzerConfig, Bottleneck, BottleneckType, PerformanceAnalyzer, PerformanceStats,
    PerformanceTrend, TrendDirection,
};
pub use persistence::{
    PeerStore, PeerStoreStats, PersistedPeer, PersistenceError, PersistenceResult,
};
pub use pex::{
    DEFAULT_PEX_INTERVAL, MAX_ADDRS_PER_PEER, MAX_PEERS_PER_MESSAGE, MIN_PEX_INTERVAL_PER_PEER,
    PexConfig, PexError, PexHints, PexManager, PexMessage, PexMessageType, PexPeerEntry,
    PexPeerInfo, PexResponse, PexStats,
};
pub use pool_warmup::{
    PoolWarmup, WarmupConfig, WarmupPeer, WarmupPriority, WarmupResult, WarmupStats,
};
pub use prefetch::{
    PrefetchConfig, PrefetchManager, PrefetchReason, PrefetchRecommendation, PrefetchStats,
    PrefetchStrategy,
};
pub use priority_queue::{Priority, PriorityQueue, PriorityTask, QueueStats};
pub use progress_stream::{
    ProgressEvent, ProgressStreamConfig, ProgressStreamManager, TransferProgress,
};
pub use protocol::{
    CURRENT_VERSION, DeprecationInfo, MIN_SUPPORTED_VERSION, NegotiationResult, NodeCapabilities,
    ProtocolFeature, ProtocolSession, ProtocolVersion, UpgradeError, UpgradeManager, UpgradeStep,
    VersionNegotiator, VersionParseError, VersionRequest, VersionResponse,
};
pub use protocol_compression::{
    CompressionResult, MessageCompressionAlgorithm, MessageType, ProtocolCompressionConfig,
    ProtocolCompressionStats, ProtocolCompressor,
};
pub use protocol_upgrade::{
    ProtocolCapabilities, ProtocolId, ProtocolUpgradeManager,
    ProtocolVersion as UpgradeProtocolVersion, UpgradeConfig, UpgradeRequest, UpgradeResponse,
    UpgradeState, UpgradeStats,
};
pub use pubsub::{
    Message as PubSubMessage, MessagePriority as PubSubMessagePriority, PubSubConfig,
    PubSubManager, PubSubStats, SubscriptionInfo, Topic,
};
pub use range_request::{
    ByteRange, RangeError, RangeRequest, RangeRequestHandler, RangeResponse, RangeStats,
};
pub use rate_limiter::{
    RateLimitDecision, RateLimitType, RateLimiter, RateLimiterConfig, RateLimiterStats,
};
pub use relay_coordinator::{
    RelayCoordinator, RelayCoordinatorConfig, RelayCoordinatorStats, RelayHealth,
    RelayHealthStatus, RelayTransferRequest, RelayTransferResult,
};
pub use relay_economics::{
    OperatingCosts, RelayEconomicsSimulator, SimulatedRelay, SimulationConfig, SimulationResults,
    TrafficPattern,
};
pub use relay_optimizer::{
    PathWeights, RelayCapability, RelayOptimizer, RelayOptimizerConfig, RelayOptimizerStats,
    RelayPath, RelayStats,
};
pub use relay_reward_manager::{
    PaymentRequest, PaymentStatus, RelayEarnings, RelayRewardManager, RewardCalculation,
    RewardConfig, RewardManagerStats,
};
pub use reputation::*;
pub use reputation_decay::{
    DecayConfig, DecayStats, ReputationDecayManager, ReputationError, ReputationRecord,
};
pub use request_multiplexing::{
    MultiplexConfig, MultiplexError, MultiplexStats, MultiplexedRequest, MultiplexedResponse,
    RequestId, RequestMultiplexer, RequestPriority,
};
pub use resilience::{
    Bulkhead, BulkheadConfig, BulkheadError, BulkheadStats, ChaosConfig, ChaosEngineer, ChaosError,
    ChaosFault, ChaosStats, DegradationLevel, DegradationStats, GracefulDegradation, RetryExecutor,
    RetryPolicy, RetryStats, RetryStrategy,
};
pub use session_manager::{
    Session, SessionConfig, SessionId, SessionManager, SessionState, SessionStats,
};
pub use split_brain::{
    ConflictResolution, LeaderState, NetworkMode, PartitionEvent, QuorumConfig,
    SplitBrainPrevention,
};
pub use stream_prioritization::{
    DEFAULT_WEIGHT, MAX_WEIGHT, MIN_WEIGHT, PrioritizerConfig, PrioritizerStats, ROOT_STREAM_ID,
    StreamId, StreamPrioritizer, StreamPriority, StreamState, StreamWeight,
};
pub use streaming_helpers::{
    DashSegment, HlsSegment, QualityLevel, StreamingHelper, StreamingProtocol, StreamingStats,
};
pub use sybil_detection::{
    DetectionConfig, DetectionStats, SuspiciousFlag, SybilDetector, SybilGroup,
};
pub use throttle::{
    BandwidthThrottle, PeerThrottle, PeerTransferStats, SharedBandwidthThrottle, ThrottleConfig,
    ThrottleReason, ThrottleResult, ThrottleStats, TokenBucket, create_throttle,
};
pub use tls_mutual_auth::{
    AuthResult, CertificateManager, PeerCertificate, TlsAuthenticator, TlsConfig, TlsVersion,
    ValidationResult,
};
pub use topology_optimizer::{
    ConnectionRecommendation, OptimizationGoal as TopologyOptimizationGoal,
    PeerMetrics as TopologyPeerMetrics, TopologyHealth, TopologyOptimizer, TopologyOptimizerStats,
};
pub use topology_routing::{
    Route, RouteMetrics, RoutingStrategy as TopologyRoutingStrategy, TopologyRouter,
    TopologyRouterStats,
};
pub use traffic_analysis_resistance::{
    DummyTrafficConfig, ObfuscatedMessage, ObfuscationConfig, ObfuscationStats, PaddingStrategy,
    TimingStrategy, TrafficObfuscator, calculate_optimal_padding, normalize_packet_size,
};
pub use traffic_shaper::{
    CongestionAlgorithm, CongestionController, CongestionState, ContentType, FairQueue,
    FairQueueStats, TrafficClass, TrafficFlow, TrafficShaper, TrafficShaperConfig,
    TrafficShaperStats,
};
pub use transfer_checkpoint::{
    Checkpoint, CheckpointConfig, CheckpointManager, CheckpointStats, TransferState,
};
pub use transport::{
    TransportConfig, TransportStats, TransportType, parse_transport_type, quic_listen_addr,
    quic_listen_addr_v6, quic_to_tcp, tcp_listen_addr, tcp_listen_addr_v6, tcp_to_quic,
    webrtc_listen_addr, webrtc_listen_addr_v6,
};
pub use webrtc::{
    BrowserClientHelper, ConnectionState, IceCandidate, IceServer, SdpMessage, SdpType,
    SignalingMessage, SignalingServer, WebRtcConfig, WebRtcError, WebRtcPeerInfo, WebRtcResult,
    WebRtcStats, default_stun_servers, is_webrtc_addr, to_webrtc_addr,
};
