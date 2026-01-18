//! Background job workers for CHIE Protocol.

pub mod chunked_upload;
pub mod encryption_pipeline;
pub mod health;
pub mod ipfs;
pub mod ipfs_pinning;
pub mod moderation;
pub mod parallel;
pub mod progress;
pub mod queue;
pub mod retry;
pub mod s3;

pub use chunked_upload::{
    ChunkReader, ChunkUploader, ChunkedUploadConfig, ChunkedUploadError, ChunkedUploadManager,
    UploadProgress, UploadState, UploadStatus,
};
pub use health::{
    CheckFn, ComponentHealth, GracefulShutdown, HealthCheck, HealthChecker, HealthStatus,
    TaskGuard, WorkerMetrics, redis_checker,
};
pub use ipfs::{IpfsClient, IpfsConfig, IpfsError};
pub use ipfs_pinning::{
    PinResult, PinStatus, PinningClient, PinningConfig, PinningError, PinningService,
};
pub use moderation::{
    BatchModerator, ContentModerator, HashBlocklist, ModerationConfig, ModerationError,
    ModerationFlag, ModerationResult, ModerationStats,
};
pub use parallel::{
    MultiQueueWorkerPool, SharedStats, ShutdownHandle, WorkerPool, WorkerPoolBuilder,
    WorkerPoolConfig, WorkerPoolStats,
};
pub use progress::{JobProgress, ProgressReporter, ProgressTracker};
pub use queue::{Job, JobQueue, JobStatus, QueueConfig, QueueError, QueueStats, Worker};
pub use retry::{
    RetryConfig, RetryContext, RetryError, retry, retry_with_context, retry_with_policy,
};
pub use s3::{MultipartUpload, S3Client, S3Config, S3Error};
