//! IPFS client for CHIE Protocol.
//!
//! Provides IPFS operations via the HTTP API:
//! - Add content
//! - Pin/unpin content
//! - Get content by CID
//! - Check pin status

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

/// Default IPFS API endpoint.
pub const DEFAULT_IPFS_API: &str = "http://127.0.0.1:5001";

/// IPFS client error.
#[derive(Debug, Error)]
pub enum IpfsError {
    #[error("IPFS API error: {0}")]
    ApiError(String),

    #[error("Content not found: {cid}")]
    NotFound { cid: String },

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Timeout")]
    Timeout,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
}

/// IPFS client configuration.
#[derive(Debug, Clone)]
pub struct IpfsConfig {
    /// IPFS API URL.
    pub api_url: String,
    /// Request timeout.
    pub timeout: Duration,
    /// Maximum content size to add (in bytes).
    pub max_add_size: u64,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            api_url: DEFAULT_IPFS_API.to_string(),
            timeout: Duration::from_secs(30),
            max_add_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// Response from IPFS add command.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddResponse {
    /// Content identifier (CID).
    pub hash: String,
    /// Name/path of the added content.
    pub name: String,
    /// Size in bytes.
    pub size: String,
}

/// Response from IPFS pin ls command.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PinLsResponse {
    /// Map of CID to pin info.
    pub keys: std::collections::HashMap<String, PinInfo>,
}

/// Pin information.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PinInfo {
    /// Pin type (recursive, direct, etc.).
    #[serde(rename = "Type")]
    pub pin_type: String,
}

/// Response from IPFS id command.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IdResponse {
    /// Peer ID.
    #[serde(rename = "ID")]
    pub id: String,
    /// Public key.
    pub public_key: String,
    /// Addresses.
    pub addresses: Vec<String>,
    /// Agent version.
    pub agent_version: String,
}

/// Response from IPFS version command.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VersionResponse {
    /// IPFS version.
    pub version: String,
    /// Commit hash.
    pub commit: String,
    /// Repository version.
    pub repo: String,
}

/// IPFS client.
pub struct IpfsClient {
    client: Client,
    config: IpfsConfig,
}

impl IpfsClient {
    /// Create a new IPFS client.
    pub fn new(config: IpfsConfig) -> Result<Self, IpfsError> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| IpfsError::ConnectionFailed(e.to_string()))?;

        Ok(Self { client, config })
    }

    /// Create a client with default configuration.
    pub fn default_client() -> Result<Self, IpfsError> {
        Self::new(IpfsConfig::default())
    }

    /// Get the API URL.
    pub fn api_url(&self) -> &str {
        &self.config.api_url
    }

    /// Check if IPFS node is available.
    pub async fn is_available(&self) -> bool {
        self.version().await.is_ok()
    }

    /// Get IPFS version.
    pub async fn version(&self) -> Result<VersionResponse, IpfsError> {
        let url = format!("{}/api/v0/version", self.config.api_url);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Version check failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))
    }

    /// Get node identity.
    pub async fn id(&self) -> Result<IdResponse, IpfsError> {
        let url = format!("{}/api/v0/id", self.config.api_url);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "ID request failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))
    }

    /// Add content to IPFS.
    pub async fn add(&self, data: Vec<u8>, name: Option<&str>) -> Result<AddResponse, IpfsError> {
        if data.len() as u64 > self.config.max_add_size {
            return Err(IpfsError::ApiError(format!(
                "Content size {} exceeds maximum {}",
                data.len(),
                self.config.max_add_size
            )));
        }

        let url = format!("{}/api/v0/add", self.config.api_url);

        let filename = name.unwrap_or("file");
        let part = reqwest::multipart::Part::bytes(data).file_name(filename.to_string());
        let form = reqwest::multipart::Form::new().part("file", part);

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Add failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))
    }

    /// Get content by CID.
    pub async fn cat(&self, cid: &str) -> Result<Vec<u8>, IpfsError> {
        let url = format!("{}/api/v0/cat?arg={}", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if response.status().as_u16() == 500 {
            // IPFS returns 500 for not found
            return Err(IpfsError::NotFound {
                cid: cid.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Cat failed: {}",
                response.status()
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))
    }

    /// Pin content.
    pub async fn pin_add(&self, cid: &str, recursive: bool) -> Result<(), IpfsError> {
        let url = format!(
            "{}/api/v0/pin/add?arg={}&recursive={}",
            self.config.api_url, cid, recursive
        );

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Pin add failed: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Unpin content.
    pub async fn pin_rm(&self, cid: &str) -> Result<(), IpfsError> {
        let url = format!("{}/api/v0/pin/rm?arg={}", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Pin remove failed: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Check if content is pinned.
    pub async fn is_pinned(&self, cid: &str) -> Result<bool, IpfsError> {
        let url = format!("{}/api/v0/pin/ls?arg={}&type=all", self.config.api_url, cid);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if response.status().as_u16() == 500 {
            // Not pinned
            return Ok(false);
        }

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Pin ls failed: {}",
                response.status()
            )));
        }

        let result: PinLsResponse = response
            .json()
            .await
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))?;

        Ok(result.keys.contains_key(cid))
    }

    /// List all pinned content.
    pub async fn pin_ls(&self) -> Result<PinLsResponse, IpfsError> {
        let url = format!("{}/api/v0/pin/ls?type=all", self.config.api_url);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Pin ls failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))
    }

    /// Garbage collect unpinned content.
    pub async fn repo_gc(&self) -> Result<(), IpfsError> {
        let url = format!("{}/api/v0/repo/gc", self.config.api_url);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Repo GC failed: {}",
                response.status()
            )));
        }

        Ok(())
    }

    /// Get stats about the IPFS repo.
    pub async fn repo_stat(&self) -> Result<RepoStatResponse, IpfsError> {
        let url = format!("{}/api/v0/repo/stat", self.config.api_url);

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(|e| IpfsError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(IpfsError::ApiError(format!(
                "Repo stat failed: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| IpfsError::InvalidResponse(e.to_string()))
    }
}

/// Repo statistics.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RepoStatResponse {
    /// Number of objects.
    pub num_objects: u64,
    /// Repo size in bytes.
    pub repo_size: u64,
    /// Storage max (if set).
    pub storage_max: u64,
    /// Repo path.
    pub repo_path: String,
    /// Version.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = IpfsConfig::default();
        assert_eq!(config.api_url, "http://127.0.0.1:5001");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_client_creation() {
        let config = IpfsConfig::default();
        let client = IpfsClient::new(config);
        assert!(client.is_ok());
    }
}
