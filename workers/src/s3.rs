//! S3 client for CHIE Protocol.
//!
//! Provides S3 operations for content storage:
//! - Upload content chunks
//! - Download content
//! - Multipart uploads for large files
//! - Pre-signed URL generation

use aws_config::BehaviorVersion;
use aws_sdk_s3::{Client, config::Region, presigning::PresigningConfig, primitives::ByteStream};
use std::time::Duration;
use thiserror::Error;

/// S3 client error.
#[derive(Debug, Error)]
pub enum S3Error {
    #[error("S3 operation failed: {0}")]
    OperationFailed(String),

    #[error("Object not found: {bucket}/{key}")]
    NotFound { bucket: String, key: String },

    #[error("Upload failed: {0}")]
    UploadFailed(String),

    #[error("Download failed: {0}")]
    DownloadFailed(String),

    #[error("Presigning failed: {0}")]
    PresigningFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// S3 client configuration.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region.
    pub region: String,
    /// Custom endpoint (for S3-compatible services like MinIO).
    pub endpoint: Option<String>,
    /// Path style access (required for some S3-compatible services).
    pub path_style: bool,
    /// Default presigned URL expiration.
    pub presign_expiration: Duration,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            bucket: "chie-content".to_string(),
            region: "ap-northeast-1".to_string(),
            endpoint: None,
            path_style: false,
            presign_expiration: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// S3 client for CHIE operations.
pub struct S3Client {
    client: Client,
    config: S3Config,
}

impl S3Client {
    /// Create a new S3 client with default AWS configuration.
    pub async fn new(config: S3Config) -> Result<Self, S3Error> {
        let region = Region::new(config.region.clone());

        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region)
            .load()
            .await;

        let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&aws_config);

        if let Some(endpoint) = &config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        if config.path_style {
            s3_config_builder = s3_config_builder.force_path_style(true);
        }

        let client = Client::from_conf(s3_config_builder.build());

        Ok(Self { client, config })
    }

    /// Create a client with custom credentials.
    pub async fn with_credentials(
        config: S3Config,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self, S3Error> {
        let credentials = aws_credential_types::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "chie-s3-client",
        );

        let region = Region::new(config.region.clone());

        let mut s3_config_builder = aws_sdk_s3::config::Builder::new()
            .region(region)
            .credentials_provider(credentials);

        if let Some(endpoint) = &config.endpoint {
            s3_config_builder = s3_config_builder.endpoint_url(endpoint);
        }

        if config.path_style {
            s3_config_builder = s3_config_builder.force_path_style(true);
        }

        let client = Client::from_conf(s3_config_builder.build());

        Ok(Self { client, config })
    }

    /// Upload data to S3.
    pub async fn upload(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<String, S3Error> {
        let body = ByteStream::from(data);

        let mut request = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .body(body);

        if let Some(ct) = content_type {
            request = request.content_type(ct);
        }

        request
            .send()
            .await
            .map_err(|e| S3Error::UploadFailed(e.to_string()))?;

        Ok(format!("s3://{}/{}", self.config.bucket, key))
    }

    /// Upload content chunk with metadata.
    pub async fn upload_chunk(
        &self,
        content_id: &str,
        chunk_index: u64,
        data: Vec<u8>,
    ) -> Result<String, S3Error> {
        let key = format!("content/{}/chunks/{:08}", content_id, chunk_index);
        self.upload(&key, data, Some("application/octet-stream"))
            .await
    }

    /// Download data from S3.
    pub async fn download(&self, key: &str) -> Result<Vec<u8>, S3Error> {
        let response = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let err_str = e.to_string();
                if err_str.contains("NoSuchKey") {
                    S3Error::NotFound {
                        bucket: self.config.bucket.clone(),
                        key: key.to_string(),
                    }
                } else {
                    S3Error::DownloadFailed(err_str)
                }
            })?;

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| S3Error::DownloadFailed(e.to_string()))?
            .into_bytes();

        Ok(bytes.to_vec())
    }

    /// Download a content chunk.
    pub async fn download_chunk(
        &self,
        content_id: &str,
        chunk_index: u64,
    ) -> Result<Vec<u8>, S3Error> {
        let key = format!("content/{}/chunks/{:08}", content_id, chunk_index);
        self.download(&key).await
    }

    /// Check if an object exists.
    pub async fn exists(&self, key: &str) -> Result<bool, S3Error> {
        match self
            .client
            .head_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("NotFound") || err_str.contains("NoSuchKey") {
                    Ok(false)
                } else {
                    Err(S3Error::OperationFailed(err_str))
                }
            }
        }
    }

    /// Delete an object.
    pub async fn delete(&self, key: &str) -> Result<(), S3Error> {
        self.client
            .delete_object()
            .bucket(&self.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| S3Error::OperationFailed(e.to_string()))?;

        Ok(())
    }

    /// Delete all chunks for a content item.
    pub async fn delete_content(&self, content_id: &str) -> Result<u32, S3Error> {
        let prefix = format!("content/{}/", content_id);
        let mut deleted = 0;

        let list = self
            .client
            .list_objects_v2()
            .bucket(&self.config.bucket)
            .prefix(&prefix)
            .send()
            .await
            .map_err(|e| S3Error::OperationFailed(e.to_string()))?;

        if let Some(contents) = list.contents {
            for object in contents {
                if let Some(key) = object.key {
                    self.delete(&key).await?;
                    deleted += 1;
                }
            }
        }

        Ok(deleted)
    }

    /// Generate a presigned URL for downloading.
    pub async fn presign_download(
        &self,
        key: &str,
        expires_in: Option<Duration>,
    ) -> Result<String, S3Error> {
        let expires = expires_in.unwrap_or(self.config.presign_expiration);

        let presigning_config = PresigningConfig::builder()
            .expires_in(expires)
            .build()
            .map_err(|e| S3Error::PresigningFailed(e.to_string()))?;

        let presigned = self
            .client
            .get_object()
            .bucket(&self.config.bucket)
            .key(key)
            .presigned(presigning_config)
            .await
            .map_err(|e| S3Error::PresigningFailed(e.to_string()))?;

        Ok(presigned.uri().to_string())
    }

    /// Generate a presigned URL for uploading.
    pub async fn presign_upload(
        &self,
        key: &str,
        expires_in: Option<Duration>,
    ) -> Result<String, S3Error> {
        let expires = expires_in.unwrap_or(self.config.presign_expiration);

        let presigning_config = PresigningConfig::builder()
            .expires_in(expires)
            .build()
            .map_err(|e| S3Error::PresigningFailed(e.to_string()))?;

        let presigned = self
            .client
            .put_object()
            .bucket(&self.config.bucket)
            .key(key)
            .presigned(presigning_config)
            .await
            .map_err(|e| S3Error::PresigningFailed(e.to_string()))?;

        Ok(presigned.uri().to_string())
    }

    /// Get the bucket name.
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// Get the configuration.
    pub fn config(&self) -> &S3Config {
        &self.config
    }
}

/// Multipart upload helper for large files.
pub struct MultipartUpload<'a> {
    client: &'a S3Client,
    key: String,
    upload_id: String,
    parts: Vec<aws_sdk_s3::types::CompletedPart>,
    part_number: i32,
}

impl<'a> MultipartUpload<'a> {
    /// Start a new multipart upload.
    pub async fn start(client: &'a S3Client, key: &str) -> Result<MultipartUpload<'a>, S3Error> {
        let response = client
            .client
            .create_multipart_upload()
            .bucket(&client.config.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| S3Error::UploadFailed(e.to_string()))?;

        let upload_id = response
            .upload_id()
            .ok_or_else(|| S3Error::UploadFailed("No upload ID returned".to_string()))?
            .to_string();

        Ok(MultipartUpload {
            client,
            key: key.to_string(),
            upload_id,
            parts: Vec::new(),
            part_number: 1,
        })
    }

    /// Upload a part.
    pub async fn upload_part(&mut self, data: Vec<u8>) -> Result<(), S3Error> {
        let body = ByteStream::from(data);

        let response = self
            .client
            .client
            .upload_part()
            .bucket(&self.client.config.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .part_number(self.part_number)
            .body(body)
            .send()
            .await
            .map_err(|e| S3Error::UploadFailed(e.to_string()))?;

        let e_tag = response
            .e_tag()
            .ok_or_else(|| S3Error::UploadFailed("No ETag returned".to_string()))?
            .to_string();

        self.parts.push(
            aws_sdk_s3::types::CompletedPart::builder()
                .e_tag(e_tag)
                .part_number(self.part_number)
                .build(),
        );

        self.part_number += 1;
        Ok(())
    }

    /// Complete the multipart upload.
    pub async fn complete(self) -> Result<String, S3Error> {
        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(self.parts))
            .build();

        self.client
            .client
            .complete_multipart_upload()
            .bucket(&self.client.config.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|e| S3Error::UploadFailed(e.to_string()))?;

        Ok(format!("s3://{}/{}", self.client.config.bucket, self.key))
    }

    /// Abort the multipart upload.
    pub async fn abort(self) -> Result<(), S3Error> {
        self.client
            .client
            .abort_multipart_upload()
            .bucket(&self.client.config.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .send()
            .await
            .map_err(|e| S3Error::OperationFailed(e.to_string()))?;

        Ok(())
    }

    /// Get the current part number.
    pub fn part_count(&self) -> i32 {
        self.part_number - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_config_default() {
        let config = S3Config::default();
        assert_eq!(config.bucket, "chie-content");
        assert_eq!(config.region, "ap-northeast-1");
        assert!(!config.path_style);
    }

    #[test]
    fn test_chunk_key_format() {
        let content_id = "abc123";
        let chunk_index = 42u64;
        let key = format!("content/{}/chunks/{:08}", content_id, chunk_index);
        assert_eq!(key, "content/abc123/chunks/00000042");
    }
}
