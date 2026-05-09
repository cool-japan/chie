//! Content encryption pipeline worker.

use anyhow::{anyhow, Result};
use chie_crypto::{encrypt, generate_key, generate_nonce};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;

use crate::ipfs::IpfsClient;
use crate::s3::S3Client;

/// Encryption job to process.
#[derive(Debug)]
pub struct EncryptionJob {
    /// Content ID.
    pub content_id: uuid::Uuid,

    /// S3 key of the uploaded file.
    pub s3_key: String,
}

/// Processed content result.
#[derive(Debug)]
pub struct ProcessedContent {
    /// IPFS CID of the encrypted content.
    pub cid: String,

    /// Size in bytes.
    pub size_bytes: u64,

    /// Number of chunks.
    pub chunk_count: u64,
}

/// In-memory key store used when no DB pool is available (e.g., in tests).
type KeyStore = Arc<Mutex<HashMap<uuid::Uuid, Vec<u8>>>>;

/// Encryption pipeline worker.
pub struct EncryptionPipeline {
    /// Optional S3 client for real storage operations.
    s3: Option<S3Client>,
    /// Optional IPFS client for content pinning.
    ipfs: Option<IpfsClient>,
    /// Optional database pool for persisting encryption keys.
    db: Option<sqlx::PgPool>,
    /// In-memory fallback key store (used when `db` is None).
    key_store: KeyStore,
}

impl EncryptionPipeline {
    /// Create a new encryption pipeline with no external clients.
    ///
    /// In this mode all operations fall back to safe in-process defaults
    /// suitable for unit tests.
    pub fn new() -> Self {
        Self {
            s3: None,
            ipfs: None,
            db: None,
            key_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attach an S3 client, IPFS client, and database pool.
    ///
    /// Returns `self` for method-chaining convenience.
    pub fn with_clients(
        mut self,
        s3: S3Client,
        ipfs: IpfsClient,
        db: sqlx::PgPool,
    ) -> Self {
        self.s3 = Some(s3);
        self.ipfs = Some(ipfs);
        self.db = Some(db);
        self
    }

    /// Process a content encryption job.
    pub async fn process(&self, job: EncryptionJob) -> Result<ProcessedContent> {
        tracing::info!("Processing encryption job: content_id={}", job.content_id);

        // 1. Download from S3
        let raw_data = self.download_from_s3(&job.s3_key).await?;

        // 2. Generate encryption key and nonce
        let key = generate_key();
        let nonce = generate_nonce();

        // 3. Encrypt the data
        let encrypted_data = encrypt(&raw_data, &key, &nonce)?;

        // 4. Upload to IPFS
        let cid = self.upload_to_ipfs(&encrypted_data).await?;

        // 5. Store encryption key in database
        self.store_encryption_key(job.content_id, &key).await?;

        // 6. Delete temporary S3 file
        self.delete_from_s3(&job.s3_key).await?;

        Ok(ProcessedContent {
            cid,
            size_bytes: encrypted_data.len() as u64,
            chunk_count: (encrypted_data.len() / 262144 + 1) as u64, // 256KB chunks
        })
    }

    /// Download raw content from S3.
    ///
    /// Falls back to a synthetic 1 KiB zero-byte buffer when no S3 client is
    /// configured (test / offline mode).
    async fn download_from_s3(&self, key: &str) -> Result<Vec<u8>> {
        match &self.s3 {
            Some(s3) => {
                tracing::debug!("Downloading from S3: key={}", key);
                s3.download(key)
                    .await
                    .map_err(|e| anyhow!("S3 download failed for key '{}': {}", key, e))
            }
            None => {
                tracing::debug!(
                    "No S3 client configured, returning synthetic data for key={}",
                    key
                );
                Ok(vec![0u8; 1024])
            }
        }
    }

    /// Upload encrypted data to IPFS and return the CID.
    ///
    /// Falls back to a deterministic placeholder CID derived via BLAKE3 when
    /// no IPFS client is configured (test / offline mode).
    async fn upload_to_ipfs(&self, data: &[u8]) -> Result<String> {
        match &self.ipfs {
            Some(ipfs) => {
                tracing::debug!("Uploading {} bytes to IPFS", data.len());
                let response = ipfs
                    .add(data.to_vec(), None)
                    .await
                    .map_err(|e| anyhow!("IPFS upload failed: {}", e))?;
                tracing::info!("Uploaded to IPFS: cid={}", response.hash);
                Ok(response.hash)
            }
            None => {
                let hash = blake3::hash(data);
                let cid = format!("Qm{}", hex::encode(&hash.as_bytes()[..16]));
                tracing::debug!("No IPFS client configured, returning placeholder CID: {}", cid);
                Ok(cid)
            }
        }
    }

    /// Persist the per-content encryption key.
    ///
    /// Writes to the `content` table's `encryption_key` column when a DB pool
    /// is available, otherwise stores in the in-memory fallback map.
    async fn store_encryption_key(
        &self,
        content_id: uuid::Uuid,
        key: &[u8; 32],
    ) -> Result<()> {
        match &self.db {
            Some(db) => {
                tracing::debug!("Storing encryption key to DB for content_id={}", content_id);
                sqlx::query(
                    "UPDATE content SET encryption_key = $1 WHERE id = $2",
                )
                .bind(key.as_slice())
                .bind(content_id)
                .execute(db)
                .await
                .map_err(|e| {
                    anyhow!(
                        "Failed to store encryption key for content_id={}: {}",
                        content_id,
                        e
                    )
                })?;
                Ok(())
            }
            None => {
                tracing::debug!(
                    "No DB pool configured, storing encryption key in-memory for content_id={}",
                    content_id
                );
                let mut store = self.key_store.lock().map_err(|e| {
                    anyhow!("Key store mutex poisoned: {}", e)
                })?;
                store.insert(content_id, key.to_vec());
                Ok(())
            }
        }
    }

    /// Delete the temporary (unencrypted) S3 object.
    ///
    /// No-ops when no S3 client is configured (test / offline mode).
    async fn delete_from_s3(&self, key: &str) -> Result<()> {
        match &self.s3 {
            Some(s3) => {
                tracing::debug!("Deleting from S3: key={}", key);
                s3.delete(key)
                    .await
                    .map_err(|e| anyhow!("S3 delete failed for key '{}': {}", key, e))
            }
            None => {
                tracing::debug!(
                    "No S3 client configured, skipping S3 delete for key={}",
                    key
                );
                Ok(())
            }
        }
    }
}

impl Default for EncryptionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_process_no_clients_succeeds() {
        let pipeline = EncryptionPipeline::new();
        let job = EncryptionJob {
            content_id: uuid::Uuid::new_v4(),
            s3_key: "content/test/raw".to_string(),
        };
        let result = pipeline.process(job).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        let content = result.expect("result should be Ok");
        assert!(!content.cid.is_empty());
        assert!(content.size_bytes > 0);
        assert!(content.chunk_count >= 1);
    }

    #[tokio::test]
    async fn test_store_encryption_key_in_memory() {
        let pipeline = EncryptionPipeline::new();
        let content_id = uuid::Uuid::new_v4();
        let key = [42u8; 32];

        let result = pipeline.store_encryption_key(content_id, &key).await;
        assert!(result.is_ok());

        // Verify the key is retrievable from the in-memory store.
        let store = pipeline
            .key_store
            .lock()
            .expect("key store lock should succeed");
        let stored = store.get(&content_id).expect("key should be present");
        assert_eq!(stored, &key.to_vec());
    }

    #[tokio::test]
    async fn test_upload_to_ipfs_no_client_returns_deterministic_cid() {
        let pipeline = EncryptionPipeline::new();
        let data = b"test payload";

        let cid1 = pipeline
            .upload_to_ipfs(data)
            .await
            .expect("should return placeholder CID");
        let cid2 = pipeline
            .upload_to_ipfs(data)
            .await
            .expect("should return placeholder CID");

        assert_eq!(cid1, cid2, "CID must be deterministic for the same data");
        assert!(cid1.starts_with("Qm"), "CID should start with Qm prefix");
    }

    #[test]
    fn test_ipfs_client_creates_ok() {
        let config = crate::ipfs::IpfsConfig::default();
        let client = IpfsClient::new(config);
        assert!(client.is_ok());
    }
}
