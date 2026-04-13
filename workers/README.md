# workers

Background job workers for the CHIE Protocol.

**Version**: 0.2.0 | **Status**: Stable | **Tests**: 50+ passing | **Public items**: 73

## Overview

This crate contains background workers that handle asynchronous tasks:
- **Encryption Pipeline**: Process uploaded content (encrypt, chunk, upload to IPFS)
- **IPFS Pinning**: Manage content availability across IPFS network
- **Chunked Upload**: Multi-part upload management with resumable sessions
- **Content Moderation**: ClamAV, AI-based, and zip-bomb detection
- **Parallel Processing**: Concurrent job execution and batching
- **Progress Tracking**: Real-time job progress reporting
- **Health Checks**: Worker liveness and graceful shutdown
- **Retry Logic**: Exponential backoff with dead-letter queue support
- **S3 Integration**: AWS S3 upload/download operations
- **IPFS Client**: Direct IPFS node interaction

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Job Queue (Redis)                       │
└─────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────────┐    ┌─────────────────────┐
│ EncryptionPipeline  │    │  IpfsPinningWorker  │
│                     │    │                     │
│ 1. Download from S3 │    │ Pin/Unpin CIDs      │
│ 2. Encrypt content  │    │ Priority scheduling │
│ 3. Upload to IPFS   │    │                     │
│ 4. Store key in DB  │    │                     │
│ 5. Delete temp S3   │    │                     │
└─────────────────────┘    └─────────────────────┘
```

## Modules

### encryption_pipeline.rs

Processes newly uploaded content:

```rust
use workers::encryption_pipeline::{EncryptionPipeline, EncryptionJob};

let pipeline = EncryptionPipeline::new();

let job = EncryptionJob {
    content_id: uuid::Uuid::new_v4(),
    s3_key: "uploads/temp/abc123.zip".to_string(),
};

let result = pipeline.process(job).await?;
// ProcessedContent { cid: "Qm...", size_bytes: 1024000, chunk_count: 4 }
```

**Pipeline Steps**:
1. Download raw file from S3 temporary storage
2. Generate encryption key (ChaCha20-Poly1305)
3. Encrypt entire content
4. Upload encrypted data to IPFS
5. Store encryption key in PostgreSQL (associated with content_id)
6. Delete temporary S3 file

### ipfs_pinning.rs

Manages IPFS pinning for content availability:

```rust
use workers::ipfs_pinning::{IpfsPinningWorker, PinningJob};

let worker = IpfsPinningWorker::new();

// Pin with priority (higher = more important)
let job = PinningJob {
    cid: "QmExample...".to_string(),
    priority: 10,
};
worker.pin(job).await?;

// Unpin when content is removed
worker.unpin("QmExample...").await?;
```

## Job Queue Design

Jobs are processed via Redis-backed queues:

```
Queue: chie:jobs:encryption
├── Job 1: { content_id: "uuid1", s3_key: "uploads/temp/a.zip" }
├── Job 2: { content_id: "uuid2", s3_key: "uploads/temp/b.zip" }
└── ...

Queue: chie:jobs:pinning
├── Job 1: { cid: "Qm...", priority: 10 }
├── Job 2: { cid: "Qm...", priority: 5 }
└── ...
```

## Content Processing Flow

```
Creator Portal                Workers                    Storage
     │                           │                          │
     │ Upload file ──────────────────────────────────────► S3
     │                           │                          │
     │ POST /api/content ─────► │                          │
     │                           │                          │
     │ ◄─── { content_id } ───── │                          │
     │                           │                          │
     │                           │ Process job              │
     │                           │ - Download from S3 ◄──── │
     │                           │ - Encrypt                │
     │                           │ - Upload to IPFS ──────► │ IPFS
     │                           │ - Store key ───────────► │ PostgreSQL
     │                           │ - Delete S3 ────────────►│
     │                           │                          │
     │ Content ready             │                          │
```

## Configuration

```rust
EncryptionConfig {
    chunk_size: 256 * 1024,      // 256 KB
    s3_bucket: "chie-uploads",
    s3_region: "ap-northeast-1",
    ipfs_api: "http://localhost:5001",
}

PinningConfig {
    ipfs_api: "http://localhost:5001",
    replication_factor: 3,
    gc_interval_hours: 24,
}
```

## Modules

All 12 modules are fully implemented with 0 stubs.

| Module | Purpose |
|--------|---------|
| `chunked_upload.rs` | Multi-part upload manager with resumable session support |
| `encryption_pipeline.rs` | Content encryption pipeline (download, encrypt, IPFS upload) |
| `health.rs` | Worker health checks and graceful shutdown |
| `ipfs_pinning.rs` | IPFS pinning service integration |
| `ipfs.rs` | Direct IPFS node client |
| `moderation.rs` | Content moderation (ClamAV, AI, zip bomb detection) |
| `parallel.rs` | Concurrent job execution and batching |
| `progress.rs` | Job progress tracking and reporting |
| `queue.rs` | Redis job queue with dead letter support |
| `retry.rs` | Exponential backoff retry logic |
| `s3.rs` | AWS S3 upload/download integration |
| `lib.rs` | Crate root and public re-exports |

## Dependencies

```toml
chie-crypto = { path = "../crates/chie-crypto" }
uuid = "1"
anyhow = "1"
tracing = "0.1"
tokio = { version = "1", features = ["full"] }
redis = "0.25"
aws-sdk-s3 = "1"
```

## Statistics

- **SLoC**: 4,344 code lines across 12 Rust files
- **Public items**: 73
- **Test suite**: 50+ passing tests

