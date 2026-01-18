//! IPFS pinning service integration.
//!
//! Supports multiple pinning services:
//! - Pinata
//! - Web3.Storage
//! - Infura IPFS
//! - NFT.Storage

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Pinning service configuration.
#[derive(Debug, Clone)]
pub struct PinningConfig {
    /// Service type.
    pub service: PinningService,
    /// API endpoint.
    pub api_url: String,
    /// API key/token.
    pub api_key: String,
    /// Optional API secret (for services that require it).
    pub api_secret: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
    /// Maximum file size for direct upload (bytes).
    pub max_direct_upload_size: u64,
}

impl Default for PinningConfig {
    fn default() -> Self {
        Self {
            service: PinningService::Pinata,
            api_url: "https://api.pinata.cloud".to_string(),
            api_key: String::new(),
            api_secret: None,
            timeout: Duration::from_secs(300),
            max_direct_upload_size: 100 * 1024 * 1024, // 100MB
        }
    }
}

/// Supported pinning services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PinningService {
    /// Pinata (pinata.cloud)
    Pinata,
    /// Web3.Storage
    Web3Storage,
    /// Infura IPFS
    Infura,
    /// NFT.Storage
    NftStorage,
    /// Custom/self-hosted
    Custom,
}

impl std::fmt::Display for PinningService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pinata => write!(f, "Pinata"),
            Self::Web3Storage => write!(f, "Web3.Storage"),
            Self::Infura => write!(f, "Infura"),
            Self::NftStorage => write!(f, "NFT.Storage"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// Pin status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PinStatus {
    /// Pin request received.
    Queued,
    /// Pinning in progress.
    Pinning,
    /// Successfully pinned.
    Pinned,
    /// Pin failed.
    Failed,
}

/// Pin job result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinResult {
    /// IPFS CID.
    pub cid: String,
    /// Pin status.
    pub status: PinStatus,
    /// Size in bytes.
    pub size: u64,
    /// Pin timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Service-specific pin ID.
    pub pin_id: Option<String>,
}

/// Pinning service error.
#[derive(Debug, Error)]
pub enum PinningError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error: {status} - {message}")]
    Api { status: u16, message: String },

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Rate limited")]
    RateLimited,

    #[error("File too large: {size} bytes (max: {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("Invalid CID: {0}")]
    InvalidCid(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// IPFS pinning service client.
pub struct PinningClient {
    config: PinningConfig,
    client: reqwest::Client,
}

impl PinningClient {
    /// Create a new pinning client.
    pub fn new(config: PinningConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Pin content by CID.
    pub async fn pin_by_cid(
        &self,
        cid: &str,
        name: Option<&str>,
    ) -> Result<PinResult, PinningError> {
        match self.config.service {
            PinningService::Pinata => self.pinata_pin_by_hash(cid, name).await,
            PinningService::Infura => self.infura_pin_by_hash(cid).await,
            _ => {
                warn!("{} requires direct file upload", self.config.service);
                Ok(PinResult {
                    cid: cid.to_string(),
                    status: PinStatus::Failed,
                    size: 0,
                    timestamp: chrono::Utc::now(),
                    pin_id: None,
                })
            }
        }
    }

    /// Upload and pin data directly.
    pub async fn pin_data(
        &self,
        data: &[u8],
        name: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<PinResult, PinningError> {
        if data.len() as u64 > self.config.max_direct_upload_size {
            return Err(PinningError::FileTooLarge {
                size: data.len() as u64,
                max: self.config.max_direct_upload_size,
            });
        }

        match self.config.service {
            PinningService::Pinata => self.pinata_pin_file(data, name, metadata).await,
            PinningService::Web3Storage => self.web3storage_pin_file(data, name).await,
            PinningService::Infura => self.infura_pin_file(data, name).await,
            PinningService::NftStorage => self.nftstorage_pin_file(data, name).await,
            PinningService::Custom => self.custom_pin_file(data, name).await,
        }
    }

    /// Unpin content.
    pub async fn unpin(&self, cid: &str) -> Result<(), PinningError> {
        match self.config.service {
            PinningService::Pinata => self.pinata_unpin(cid).await,
            PinningService::Infura => self.infura_unpin(cid).await,
            _ => {
                warn!("{} doesn't support unpinning", self.config.service);
                Ok(())
            }
        }
    }

    /// Get pin status.
    pub async fn get_pin_status(&self, cid: &str) -> Result<PinStatus, PinningError> {
        match self.config.service {
            PinningService::Pinata => self.pinata_get_status(cid).await,
            PinningService::Infura => self.infura_get_status(cid).await,
            _ => Ok(PinStatus::Pinned), // Assume pinned for services without status API
        }
    }

    // ==================== Pinata Implementation ====================

    async fn pinata_pin_by_hash(
        &self,
        cid: &str,
        name: Option<&str>,
    ) -> Result<PinResult, PinningError> {
        let url = format!("{}/pinning/pinByHash", self.config.api_url);

        #[derive(Serialize)]
        struct PinByHashRequest<'a> {
            #[serde(rename = "hashToPin")]
            hash_to_pin: &'a str,
            #[serde(rename = "pinataMetadata", skip_serializing_if = "Option::is_none")]
            metadata: Option<PinataMetadata<'a>>,
        }

        #[derive(Serialize)]
        struct PinataMetadata<'a> {
            name: &'a str,
        }

        let metadata = name.map(|n| PinataMetadata { name: n });
        let body = PinByHashRequest {
            hash_to_pin: cid,
            metadata,
        };

        let response = self
            .client
            .post(&url)
            .header("pinata_api_key", &self.config.api_key)
            .header(
                "pinata_secret_api_key",
                self.config.api_secret.as_deref().unwrap_or(""),
            )
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            debug!("Successfully pinned {} to Pinata", cid);
            Ok(PinResult {
                cid: cid.to_string(),
                status: PinStatus::Queued,
                size: 0,
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else if status.as_u16() == 401 {
            Err(PinningError::AuthenticationFailed)
        } else if status.as_u16() == 429 {
            Err(PinningError::RateLimited)
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn pinata_pin_file(
        &self,
        data: &[u8],
        name: &str,
        _metadata: Option<HashMap<String, String>>,
    ) -> Result<PinResult, PinningError> {
        let url = format!("{}/pinning/pinFileToIPFS", self.config.api_url);

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(data.to_vec()).file_name(name.to_string()),
        );

        let response = self
            .client
            .post(&url)
            .header("pinata_api_key", &self.config.api_key)
            .header(
                "pinata_secret_api_key",
                self.config.api_secret.as_deref().unwrap_or(""),
            )
            .multipart(form)
            .send()
            .await?;

        #[derive(Deserialize)]
        struct PinataResponse {
            #[serde(rename = "IpfsHash")]
            ipfs_hash: String,
            #[serde(rename = "PinSize")]
            pin_size: u64,
        }

        let status = response.status();
        if status.is_success() {
            let result: PinataResponse = response.json().await?;
            info!(
                "Pinned {} bytes to Pinata: {}",
                result.pin_size, result.ipfs_hash
            );
            Ok(PinResult {
                cid: result.ipfs_hash,
                status: PinStatus::Pinned,
                size: result.pin_size,
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn pinata_unpin(&self, cid: &str) -> Result<(), PinningError> {
        let url = format!("{}/pinning/unpin/{}", self.config.api_url, cid);

        let response = self
            .client
            .delete(&url)
            .header("pinata_api_key", &self.config.api_key)
            .header(
                "pinata_secret_api_key",
                self.config.api_secret.as_deref().unwrap_or(""),
            )
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            info!("Unpinned {} from Pinata", cid);
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn pinata_get_status(&self, cid: &str) -> Result<PinStatus, PinningError> {
        let url = format!(
            "{}/data/pinList?hashContains={}&status=all",
            self.config.api_url, cid
        );

        let response = self
            .client
            .get(&url)
            .header("pinata_api_key", &self.config.api_key)
            .header(
                "pinata_secret_api_key",
                self.config.api_secret.as_deref().unwrap_or(""),
            )
            .send()
            .await?;

        #[derive(Deserialize)]
        struct PinataListResponse {
            rows: Vec<serde_json::Value>,
        }

        let status = response.status();
        if status.is_success() {
            let result: PinataListResponse = response.json().await?;
            if result.rows.is_empty() {
                Ok(PinStatus::Failed)
            } else {
                Ok(PinStatus::Pinned)
            }
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    // ==================== Infura Implementation ====================

    async fn infura_pin_by_hash(&self, cid: &str) -> Result<PinResult, PinningError> {
        let url = format!("{}/api/v0/pin/add?arg={}", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.config.api_key, self.config.api_secret.as_ref())
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(PinResult {
                cid: cid.to_string(),
                status: PinStatus::Pinned,
                size: 0,
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn infura_pin_file(&self, data: &[u8], _name: &str) -> Result<PinResult, PinningError> {
        let url = format!("{}/api/v0/add?pin=true", self.config.api_url);

        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(data.to_vec()));

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.config.api_key, self.config.api_secret.as_ref())
            .multipart(form)
            .send()
            .await?;

        #[derive(Deserialize)]
        struct InfuraAddResponse {
            #[serde(rename = "Hash")]
            hash: String,
            #[serde(rename = "Size")]
            size: String,
        }

        let status = response.status();
        if status.is_success() {
            let result: InfuraAddResponse = response.json().await?;
            Ok(PinResult {
                cid: result.hash,
                status: PinStatus::Pinned,
                size: result.size.parse().unwrap_or(0),
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn infura_unpin(&self, cid: &str) -> Result<(), PinningError> {
        let url = format!("{}/api/v0/pin/rm?arg={}", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.config.api_key, self.config.api_secret.as_ref())
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            info!("Unpinned {} from Infura", cid);
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn infura_get_status(&self, cid: &str) -> Result<PinStatus, PinningError> {
        let url = format!("{}/api/v0/pin/ls?arg={}", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.config.api_key, self.config.api_secret.as_ref())
            .send()
            .await?;

        if response.status().is_success() {
            Ok(PinStatus::Pinned)
        } else {
            Ok(PinStatus::Failed)
        }
    }

    // ==================== Other Services ====================

    async fn web3storage_pin_file(
        &self,
        data: &[u8],
        name: &str,
    ) -> Result<PinResult, PinningError> {
        let url = format!("{}/upload", self.config.api_url);

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(data.to_vec()).file_name(name.to_string()),
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .multipart(form)
            .send()
            .await?;

        #[derive(Deserialize)]
        struct Web3Response {
            cid: String,
        }

        let status = response.status();
        if status.is_success() {
            let result: Web3Response = response.json().await?;
            Ok(PinResult {
                cid: result.cid,
                status: PinStatus::Pinned,
                size: data.len() as u64,
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn nftstorage_pin_file(
        &self,
        data: &[u8],
        name: &str,
    ) -> Result<PinResult, PinningError> {
        let url = format!("{}/upload", self.config.api_url);

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(data.to_vec()).file_name(name.to_string()),
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .multipart(form)
            .send()
            .await?;

        #[derive(Deserialize)]
        struct NftStorageResponse {
            value: NftStorageValue,
        }

        #[derive(Deserialize)]
        struct NftStorageValue {
            cid: String,
            size: u64,
        }

        let status = response.status();
        if status.is_success() {
            let result: NftStorageResponse = response.json().await?;
            Ok(PinResult {
                cid: result.value.cid,
                status: PinStatus::Pinned,
                size: result.value.size,
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn custom_pin_file(&self, data: &[u8], name: &str) -> Result<PinResult, PinningError> {
        let url = format!("{}/upload", self.config.api_url);

        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(data.to_vec()).file_name(name.to_string()),
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .multipart(form)
            .send()
            .await?;

        #[derive(Deserialize)]
        struct CustomResponse {
            cid: String,
            size: u64,
        }

        let status = response.status();
        if status.is_success() {
            let result: CustomResponse = response.json().await?;
            Ok(PinResult {
                cid: result.cid,
                status: PinStatus::Pinned,
                size: result.size,
                timestamp: chrono::Utc::now(),
                pin_id: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(PinningError::Api {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = PinningConfig::default();
        assert_eq!(config.service, PinningService::Pinata);
        assert_eq!(config.timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_pinning_service_display() {
        assert_eq!(PinningService::Pinata.to_string(), "Pinata");
        assert_eq!(PinningService::Web3Storage.to_string(), "Web3.Storage");
        assert_eq!(PinningService::Infura.to_string(), "Infura");
    }
}
