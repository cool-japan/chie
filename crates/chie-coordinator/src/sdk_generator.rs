//! SDK code generation from OpenAPI specification.
//!
//! This module provides SDK generation capabilities for multiple programming languages:
//! - Python (requests library)
//! - JavaScript/TypeScript (fetch API)
//! - Rust (reqwest)
//! - Go (net/http)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported SDK languages.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SdkLanguage {
    /// Python SDK using requests library.
    Python,
    /// JavaScript SDK using fetch API.
    JavaScript,
    /// TypeScript SDK with type definitions.
    TypeScript,
    /// Rust SDK using reqwest.
    Rust,
    /// Go SDK using net/http.
    Go,
}

impl SdkLanguage {
    /// Get the file extension for this language.
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::JavaScript => "js",
            Self::TypeScript => "ts",
            Self::Rust => "rs",
            Self::Go => "go",
        }
    }

    /// Get the package manager for this language.
    #[allow(dead_code)]
    pub fn package_manager(&self) -> &'static str {
        match self {
            Self::Python => "pip",
            Self::JavaScript | Self::TypeScript => "npm",
            Self::Rust => "cargo",
            Self::Go => "go",
        }
    }
}

/// SDK generator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    /// Base URL for the API.
    pub base_url: String,
    /// Package name.
    pub package_name: String,
    /// Package version.
    pub version: String,
    /// Include authentication helpers.
    pub include_auth: bool,
    /// Include error handling.
    pub include_errors: bool,
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.chie.network".to_string(),
            package_name: "chie-client".to_string(),
            version: "0.1.0".to_string(),
            include_auth: true,
            include_errors: true,
        }
    }
}

/// SDK generator.
pub struct SdkGenerator {
    config: SdkConfig,
}

impl SdkGenerator {
    /// Create a new SDK generator with the given configuration.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }

    /// Create a new SDK generator with default configuration.
    pub fn default() -> Self {
        Self::new(SdkConfig::default())
    }

    /// Generate SDK code for the specified language.
    pub fn generate(&self, language: SdkLanguage) -> String {
        match language {
            SdkLanguage::Python => self.generate_python(),
            SdkLanguage::JavaScript => self.generate_javascript(),
            SdkLanguage::TypeScript => self.generate_typescript(),
            SdkLanguage::Rust => self.generate_rust(),
            SdkLanguage::Go => self.generate_go(),
        }
    }

    /// Generate all SDK files as a map of filename to content.
    pub fn generate_all(&self) -> HashMap<String, String> {
        let mut files = HashMap::new();

        for lang in &[
            SdkLanguage::Python,
            SdkLanguage::JavaScript,
            SdkLanguage::TypeScript,
            SdkLanguage::Rust,
            SdkLanguage::Go,
        ] {
            let filename = format!("{}.{}", self.config.package_name, lang.extension());
            files.insert(filename, self.generate(*lang));
        }

        // Add README
        files.insert("README.md".to_string(), self.generate_readme());

        files
    }

    /// Generate Python SDK.
    fn generate_python(&self) -> String {
        format!(
            r##"""
CHIE Protocol Python SDK
Version: {}
"""

import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass


class ChieError(Exception):
    """Base exception for CHIE API errors."""
    pass


class ChieAuthError(ChieError):
    """Authentication error."""
    pass


class ChieAPIError(ChieError):
    """API request error."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {{status_code}}: {{message}}")


@dataclass
class ChieConfig:
    """CHIE API configuration."""
    base_url: str = "{}"
    api_key: Optional[str] = None
    timeout: int = 30


class ChieClient:
    """CHIE Protocol API Client."""

    def __init__(self, config: Optional[ChieConfig] = None):
        """Initialize the client with optional configuration."""
        self.config = config or ChieConfig()
        self.session = requests.Session()
        if self.config.api_key:
            self.session.headers.update({{"Authorization": f"Bearer {{self.config.api_key}}"}})

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an HTTP request to the API."""
        url = f"{{self.config.base_url}}{{endpoint}}"
        kwargs.setdefault("timeout", self.config.timeout)

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise ChieAuthError("Authentication failed")
            raise ChieAPIError(e.response.status_code, str(e))
        except requests.exceptions.RequestException as e:
            raise ChieError(f"Request failed: {{e}}")

    def get_platform_stats(self) -> Dict[str, Any]:
        """Get platform-wide statistics."""
        return self._request("GET", "/api/stats/platform")

    def list_content(self, category: Optional[str] = None, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        """List available content with optional filtering."""
        params = {{"page": page, "limit": limit}}
        if category:
            params["category"] = category
        return self._request("GET", "/api/content", params=params)

    def get_content(self, content_id: str) -> Dict[str, Any]:
        """Get content details by ID."""
        return self._request("GET", f"/api/content/{{content_id}}")

    def register_content(self, cid: str, title: str, size_bytes: int, price: int, **kwargs) -> Dict[str, Any]:
        """Register new content (requires authentication)."""
        data = {{
            "cid": cid,
            "title": title,
            "size_bytes": size_bytes,
            "price": price,
            **kwargs
        }}
        return self._request("POST", "/api/content/register", json=data)

    def submit_proof(self, proof_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a bandwidth proof."""
        return self._request("POST", "/api/proofs", json=proof_data)

    def get_current_user(self) -> Dict[str, Any]:
        """Get current authenticated user information."""
        return self._request("GET", "/api/me")

    def get_user_stats(self) -> Dict[str, Any]:
        """Get current user's statistics."""
        return self._request("GET", "/api/me/stats")


# Example usage:
if __name__ == "__main__":
    # Initialize client
    client = ChieClient(ChieConfig(api_key="your-api-key-here"))

    # Get platform stats
    stats = client.get_platform_stats()
    print(f"Platform stats: {{stats}}")

    # List content
    content = client.list_content(category="3D_MODELS", limit=10)
    print(f"Found {{len(content.get('items', []))}} items")
"##,
            self.config.version, self.config.base_url
        )
    }

    /// Generate JavaScript SDK.
    fn generate_javascript(&self) -> String {
        format!(
            r##"/**
 * CHIE Protocol JavaScript SDK
 * Version: {}
 */

class ChieError extends Error {{
  constructor(message) {{
    super(message);
    this.name = 'ChieError';
  }}
}}

class ChieAuthError extends ChieError {{
  constructor(message = 'Authentication failed') {{
    super(message);
    this.name = 'ChieAuthError';
  }}
}}

class ChieAPIError extends ChieError {{
  constructor(statusCode, message) {{
    super(`HTTP ${{statusCode}}: ${{message}}`);
    this.name = 'ChieAPIError';
    this.statusCode = statusCode;
  }}
}}

class ChieClient {{
  constructor(config = {{}}) {{
    this.baseUrl = config.baseUrl || '{}';
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 30000;
  }}

  async _request(method, endpoint, options = {{}}) {{
    const url = `${{this.baseUrl}}${{endpoint}}`;
    const headers = {{
      'Content-Type': 'application/json',
      ...options.headers,
    }};

    if (this.apiKey) {{
      headers['Authorization'] = `Bearer ${{this.apiKey}}`;
    }}

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {{
      const response = await fetch(url, {{
        method,
        headers,
        signal: controller.signal,
        ...options,
      }});

      clearTimeout(timeoutId);

      if (!response.ok) {{
        if (response.status === 401) {{
          throw new ChieAuthError();
        }}
        throw new ChieAPIError(response.status, await response.text());
      }}

      return await response.json();
    }} catch (error) {{
      clearTimeout(timeoutId);
      if (error instanceof ChieError) throw error;
      throw new ChieError(`Request failed: ${{error.message}}`);
    }}
  }}

  async getPlatformStats() {{
    return this._request('GET', '/api/stats/platform');
  }}

  async listContent({{ category, page = 1, limit = 20 }} = {{}}) {{
    const params = new URLSearchParams({{ page, limit }});
    if (category) params.append('category', category);
    return this._request('GET', `/api/content?${{params}}`);
  }}

  async getContent(contentId) {{
    return this._request('GET', `/api/content/${{contentId}}`);
  }}

  async registerContent({{ cid, title, size_bytes, price, ...rest }}) {{
    return this._request('POST', '/api/content/register', {{
      body: JSON.stringify({{ cid, title, size_bytes, price, ...rest }}),
    }});
  }}

  async submitProof(proofData) {{
    return this._request('POST', '/api/proofs', {{
      body: JSON.stringify(proofData),
    }});
  }}

  async getCurrentUser() {{
    return this._request('GET', '/api/me');
  }}

  async getUserStats() {{
    return this._request('GET', '/api/me/stats');
  }}
}}

// Export for Node.js and browser
if (typeof module !== 'undefined' && module.exports) {{
  module.exports = {{ ChieClient, ChieError, ChieAuthError, ChieAPIError }};
}}

// Example usage:
// const client = new ChieClient({{ apiKey: 'your-api-key-here' }});
// const stats = await client.getPlatformStats();
// console.log('Platform stats:', stats);
"##,
            self.config.version, self.config.base_url
        )
    }

    /// Generate TypeScript SDK.
    fn generate_typescript(&self) -> String {
        format!(
            r##"/**
 * CHIE Protocol TypeScript SDK
 * Version: {}
 */

export interface ChieConfig {{
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
}}

export interface PlatformStats {{
  total_users: number;
  active_users_24h: number;
  total_nodes: number;
  active_nodes: number;
  total_content: number;
  total_bandwidth_gb: number;
  bandwidth_24h_gb: number;
}}

export interface ContentItem {{
  id: string;
  cid: string;
  title: string;
  size_bytes: number;
  price: number;
  category?: string;
  created_at: string;
}}

export interface ContentList {{
  items: ContentItem[];
  page: number;
  limit: number;
  total: number;
}}

export interface ProofData {{
  provider_key: string;
  requester_key: string;
  content_cid: string;
  chunk_index: number;
  bytes_transferred: number;
  latency_ms: number;
  challenge_nonce: string;
  provider_signature: string;
  requester_signature: string;
  timestamp: number;
}}

export class ChieError extends Error {{
  constructor(message: string) {{
    super(message);
    this.name = 'ChieError';
  }}
}}

export class ChieAuthError extends ChieError {{
  constructor(message: string = 'Authentication failed') {{
    super(message);
    this.name = 'ChieAuthError';
  }}
}}

export class ChieAPIError extends ChieError {{
  constructor(public statusCode: number, message: string) {{
    super(`HTTP ${{statusCode}}: ${{message}}`);
    this.name = 'ChieAPIError';
  }}
}}

export class ChieClient {{
  private baseUrl: string;
  private apiKey?: string;
  private timeout: number;

  constructor(config: ChieConfig = {{}}) {{
    this.baseUrl = config.baseUrl || '{}';
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 30000;
  }}

  private async request<T>(
    method: string,
    endpoint: string,
    options: RequestInit = {{}}
  ): Promise<T> {{
    const url = `${{this.baseUrl}}${{endpoint}}`;
    const headers: HeadersInit = {{
      'Content-Type': 'application/json',
      ...options.headers,
    }};

    if (this.apiKey) {{
      headers['Authorization'] = `Bearer ${{this.apiKey}}`;
    }}

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {{
      const response = await fetch(url, {{
        method,
        headers,
        signal: controller.signal,
        ...options,
      }});

      clearTimeout(timeoutId);

      if (!response.ok) {{
        if (response.status === 401) {{
          throw new ChieAuthError();
        }}
        throw new ChieAPIError(response.status, await response.text());
      }}

      return await response.json();
    }} catch (error) {{
      clearTimeout(timeoutId);
      if (error instanceof ChieError) throw error;
      throw new ChieError(`Request failed: ${{(error as Error).message}}`);
    }}
  }}

  async getPlatformStats(): Promise<PlatformStats> {{
    return this.request<PlatformStats>('GET', '/api/stats/platform');
  }}

  async listContent(params?: {{
    category?: string;
    page?: number;
    limit?: number;
  }}): Promise<ContentList> {{
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.append('page', params.page.toString());
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.category) searchParams.append('category', params.category);

    const query = searchParams.toString();
    return this.request<ContentList>('GET', `/api/content${{query ? `?${{query}}` : ''}}`);
  }}

  async getContent(contentId: string): Promise<ContentItem> {{
    return this.request<ContentItem>('GET', `/api/content/${{contentId}}`);
  }}

  async registerContent(data: {{
    cid: string;
    title: string;
    size_bytes: number;
    price: number;
    description?: string;
    category?: string;
    tags?: string[];
  }}): Promise<{{ success: boolean; content_id?: string; message: string }}> {{
    return this.request('POST', '/api/content/register', {{
      body: JSON.stringify(data),
    }});
  }}

  async submitProof(proofData: ProofData): Promise<{{
    accepted: boolean;
    proof_id?: string;
    reward_points?: number;
    error?: string;
  }}> {{
    return this.request('POST', '/api/proofs', {{
      body: JSON.stringify(proofData),
    }});
  }}

  async getCurrentUser(): Promise<{{ user_id: string; peer_id?: string; role: string }}> {{
    return this.request('GET', '/api/me');
  }}

  async getUserStats(): Promise<Record<string, unknown>> {{
    return this.request('GET', '/api/me/stats');
  }}
}}

// Example usage:
// const client = new ChieClient({{ apiKey: 'your-api-key-here' }});
// const stats = await client.getPlatformStats();
// console.log('Platform stats:', stats);
"##,
            self.config.version, self.config.base_url
        )
    }

    /// Generate Rust SDK.
    fn generate_rust(&self) -> String {
        format!(
            r##"//! CHIE Protocol Rust SDK
//! Version: {}

use reqwest::{{Client, Error as ReqwestError}};
use serde::{{Deserialize, Serialize}};
use std::time::Duration;

/// CHIE API client configuration.
#[derive(Debug, Clone)]
pub struct ChieConfig {{
    pub base_url: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
}}

impl Default for ChieConfig {{
    fn default() -> Self {{
        Self {{
            base_url: "{}".to_string(),
            api_key: None,
            timeout: Duration::from_secs(30),
        }}
    }}
}}

/// CHIE API error types.
#[derive(Debug, thiserror::Error)]
pub enum ChieError {{
    #[error("Authentication failed")]
    AuthError,
    #[error("API error ({{0}}): {{1}}")]
    ApiError(u16, String),
    #[error("Request failed: {{0}}")]
    RequestError(#[from] ReqwestError),
}}

/// Platform statistics response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformStats {{
    pub total_users: i64,
    pub active_users_24h: i64,
    pub total_nodes: i64,
    pub active_nodes: i64,
    pub total_content: i64,
    pub total_bandwidth_gb: f64,
    pub bandwidth_24h_gb: f64,
}}

/// Content item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentItem {{
    pub id: String,
    pub cid: String,
    pub title: String,
    pub size_bytes: u64,
    pub price: u64,
    pub category: Option<String>,
    pub created_at: String,
}}

/// CHIE Protocol API client.
pub struct ChieClient {{
    client: Client,
    config: ChieConfig,
}}

impl ChieClient {{
    /// Create a new client with the given configuration.
    pub fn new(config: ChieConfig) -> Result<Self, ChieError> {{
        let mut builder = Client::builder().timeout(config.timeout);

        if let Some(api_key) = &config.api_key {{
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {{}}", api_key).parse().unwrap(),
            );
            builder = builder.default_headers(headers);
        }}

        Ok(Self {{
            client: builder.build()?,
            config,
        }})
    }}

    /// Create a new client with default configuration.
    pub fn default() -> Result<Self, ChieError> {{
        Self::new(ChieConfig::default())
    }}

    /// Get platform-wide statistics.
    pub async fn get_platform_stats(&self) -> Result<PlatformStats, ChieError> {{
        let url = format!("{{}}/api/stats/platform", self.config.base_url);
        let response = self.client.get(&url).send().await?;

        if response.status() == 401 {{
            return Err(ChieError::AuthError);
        }}

        if !response.status().is_success() {{
            let status = response.status().as_u16();
            let text = response.text().await?;
            return Err(ChieError::ApiError(status, text));
        }}

        Ok(response.json().await?)
    }}

    /// List available content with optional filtering.
    pub async fn list_content(
        &self,
        category: Option<&str>,
        page: Option<u32>,
        limit: Option<u32>,
    ) -> Result<serde_json::Value, ChieError> {{
        let mut url = format!("{{}}/api/content", self.config.base_url);
        let mut params = vec![];

        if let Some(cat) = category {{
            params.push(format!("category={{}}", cat));
        }}
        if let Some(p) = page {{
            params.push(format!("page={{}}", p));
        }}
        if let Some(l) = limit {{
            params.push(format!("limit={{}}", l));
        }}

        if !params.is_empty() {{
            url.push_str(&format!("?{{}}", params.join("&")));
        }}

        let response = self.client.get(&url).send().await?;
        self.handle_response(response).await
    }}

    /// Get content details by ID.
    pub async fn get_content(&self, content_id: &str) -> Result<ContentItem, ChieError> {{
        let url = format!("{{}}/api/content/{{}}", self.config.base_url, content_id);
        let response = self.client.get(&url).send().await?;
        self.handle_response(response).await
    }}

    /// Submit a bandwidth proof.
    pub async fn submit_proof(
        &self,
        proof_data: &serde_json::Value,
    ) -> Result<serde_json::Value, ChieError> {{
        let url = format!("{{}}/api/proofs", self.config.base_url);
        let response = self.client.post(&url).json(proof_data).send().await?;
        self.handle_response(response).await
    }}

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ChieError> {{
        if response.status() == 401 {{
            return Err(ChieError::AuthError);
        }}

        if !response.status().is_success() {{
            let status = response.status().as_u16();
            let text = response.text().await?;
            return Err(ChieError::ApiError(status, text));
        }}

        Ok(response.json().await?)
    }}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn test_config_default() {{
        let config = ChieConfig::default();
        assert_eq!(config.base_url, "{}");
        assert_eq!(config.timeout, Duration::from_secs(30));
    }}
}}
"##,
            self.config.version, self.config.base_url, self.config.base_url
        )
    }

    /// Generate Go SDK.
    fn generate_go(&self) -> String {
        format!(
            r##"// CHIE Protocol Go SDK
// Version: {}

package chie

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds the CHIE API client configuration.
type Config struct {{
	BaseURL string
	APIKey  string
	Timeout time.Duration
}}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {{
	return &Config{{
		BaseURL: "{}",
		Timeout: 30 * time.Second,
	}}
}}

// Error types
type Error struct {{
	StatusCode int
	Message    string
}}

func (e *Error) Error() string {{
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}}

// Client is the CHIE API client.
type Client struct {{
	config     *Config
	httpClient *http.Client
}}

// NewClient creates a new CHIE API client.
func NewClient(config *Config) *Client {{
	if config == nil {{
		config = DefaultConfig()
	}}

	return &Client{{
		config: config,
		httpClient: &http.Client{{
			Timeout: config.Timeout,
		}},
	}}
}}

// PlatformStats represents platform-wide statistics.
type PlatformStats struct {{
	TotalUsers       int64   `json:"total_users"`
	ActiveUsers24h   int64   `json:"active_users_24h"`
	TotalNodes       int64   `json:"total_nodes"`
	ActiveNodes      int64   `json:"active_nodes"`
	TotalContent     int64   `json:"total_content"`
	TotalBandwidthGB float64 `json:"total_bandwidth_gb"`
	Bandwidth24hGB   float64 `json:"bandwidth_24h_gb"`
}}

// ContentItem represents a content item.
type ContentItem struct {{
	ID        string  `json:"id"`
	CID       string  `json:"cid"`
	Title     string  `json:"title"`
	SizeBytes uint64  `json:"size_bytes"`
	Price     uint64  `json:"price"`
	Category  *string `json:"category,omitempty"`
	CreatedAt string  `json:"created_at"`
}}

func (c *Client) request(method, endpoint string, body interface{{}}, result interface{{}}) error {{
	url := c.config.BaseURL + endpoint

	var reqBody io.Reader
	if body != nil {{
		jsonData, err := json.Marshal(body)
		if err != nil {{
			return err
		}}
		reqBody = bytes.NewBuffer(jsonData)
	}}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {{
		return err
	}}

	req.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {{
		req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	}}

	resp, err := c.httpClient.Do(req)
	if err != nil {{
		return err
	}}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {{
		return &Error{{StatusCode: 401, Message: "Authentication failed"}}
	}}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {{
		bodyBytes, _ := io.ReadAll(resp.Body)
		return &Error{{StatusCode: resp.StatusCode, Message: string(bodyBytes)}}
	}}

	if result != nil {{
		return json.NewDecoder(resp.Body).Decode(result)
	}}

	return nil
}}

// GetPlatformStats retrieves platform-wide statistics.
func (c *Client) GetPlatformStats() (*PlatformStats, error) {{
	var stats PlatformStats
	err := c.request("GET", "/api/stats/platform", nil, &stats)
	if err != nil {{
		return nil, err
	}}
	return &stats, nil
}}

// ListContent lists available content with optional filtering.
func (c *Client) ListContent(category *string, page, limit int) (map[string]interface{{}}, error) {{
	endpoint := fmt.Sprintf("/api/content?page=%d&limit=%d", page, limit)
	if category != nil {{
		endpoint += fmt.Sprintf("&category=%s", *category)
	}}

	var result map[string]interface{{}}
	err := c.request("GET", endpoint, nil, &result)
	if err != nil {{
		return nil, err
	}}
	return result, nil
}}

// GetContent retrieves content details by ID.
func (c *Client) GetContent(contentID string) (*ContentItem, error) {{
	var content ContentItem
	err := c.request("GET", "/api/content/"+contentID, nil, &content)
	if err != nil {{
		return nil, err
	}}
	return &content, nil
}}

// SubmitProof submits a bandwidth proof.
func (c *Client) SubmitProof(proofData map[string]interface{{}}) (map[string]interface{{}}, error) {{
	var result map[string]interface{{}}
	err := c.request("POST", "/api/proofs", proofData, &result)
	if err != nil {{
		return nil, err
	}}
	return result, nil
}}

// Example usage:
// client := chie.NewClient(&chie.Config{{APIKey: "your-api-key-here"}})
// stats, err := client.GetPlatformStats()
// if err != nil {{
//     log.Fatal(err)
// }}
// fmt.Printf("Platform stats: %+v\n", stats)
"##,
            self.config.version, self.config.base_url
        )
    }

    /// Generate README documentation.
    fn generate_readme(&self) -> String {
        format!(
            r##"# {} - CHIE Protocol SDK

Version: {}

Official SDK for the CHIE Protocol Coordinator API.

## Installation

### Python
```bash
pip install {}
```

### JavaScript/TypeScript
```bash
npm install {}
```

### Rust
```toml
[dependencies]
{} = "{}"
```

### Go
```bash
go get github.com/chie-protocol/{}
```

## Quick Start

### Python
```python
from chie import ChieClient, ChieConfig

client = ChieClient(ChieConfig(api_key="your-api-key-here"))
stats = client.get_platform_stats()
print(f"Total users: {{stats['total_users']}}")
```

### JavaScript
```javascript
import {{ ChieClient }} from '{}';

const client = new ChieClient({{ apiKey: 'your-api-key-here' }});
const stats = await client.getPlatformStats();
console.log(`Total users: ${{stats.total_users}}`);
```

### TypeScript
```typescript
import {{ ChieClient, ChieConfig }} from '{}';

const config: ChieConfig = {{ apiKey: 'your-api-key-here' }};
const client = new ChieClient(config);
const stats = await client.getPlatformStats();
console.log(`Total users: ${{stats.total_users}}`);
```

### Rust
```rust
use chie::{{ChieClient, ChieConfig}};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {{
    let config = ChieConfig {{
        api_key: Some("your-api-key-here".to_string()),
        ..Default::default()
    }};

    let client = ChieClient::new(config)?;
    let stats = client.get_platform_stats().await?;
    println!("Total users: {{}}", stats.total_users);
    Ok(())
}}
```

### Go
```go
import "github.com/chie-protocol/{}"

client := chie.NewClient(&chie.Config{{APIKey: "your-api-key-here"}})
stats, err := client.GetPlatformStats()
if err != nil {{
    log.Fatal(err)
}}
fmt.Printf("Total users: %d\n", stats.TotalUsers)
```

## Features

- ✅ Full API coverage
- ✅ Type-safe interfaces
- ✅ Authentication support
- ✅ Error handling
- ✅ Timeout configuration
- ✅ Comprehensive documentation

## API Methods

### Platform Statistics
- `getPlatformStats()` - Get platform-wide statistics

### Content Management
- `listContent(options)` - List available content
- `getContent(id)` - Get content details
- `registerContent(data)` - Register new content (requires auth)

### Bandwidth Proofs
- `submitProof(data)` - Submit bandwidth proof

### User Information
- `getCurrentUser()` - Get current user info (requires auth)
- `getUserStats()` - Get user statistics (requires auth)

## Configuration

All SDKs support the following configuration options:

- `baseUrl` - API base URL (default: {})
- `apiKey` - API authentication key
- `timeout` - Request timeout in seconds/milliseconds

## Authentication

To use authenticated endpoints, provide your API key when creating the client:

```javascript
const client = new ChieClient({{ apiKey: 'your-api-key-here' }});
```

## Error Handling

All SDKs provide error handling with specific error types:

- `ChieAuthError` - Authentication failures
- `ChieAPIError` - API errors with status codes
- `ChieError` - General errors

## Support

- Documentation: https://docs.chie.network
- API Reference: https://api.chie.network/api-docs
- Issues: https://github.com/chie-protocol/sdk/issues

## License

Proprietary - See LICENSE file for details
"##,
            self.config.package_name,
            self.config.version,
            self.config.package_name,
            self.config.package_name,
            self.config.package_name,
            self.config.version,
            self.config.package_name,
            self.config.package_name,
            self.config.package_name,
            self.config.package_name,
            self.config.base_url
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_language_extension() {
        assert_eq!(SdkLanguage::Python.extension(), "py");
        assert_eq!(SdkLanguage::JavaScript.extension(), "js");
        assert_eq!(SdkLanguage::TypeScript.extension(), "ts");
        assert_eq!(SdkLanguage::Rust.extension(), "rs");
        assert_eq!(SdkLanguage::Go.extension(), "go");
    }

    #[test]
    fn test_sdk_language_package_manager() {
        assert_eq!(SdkLanguage::Python.package_manager(), "pip");
        assert_eq!(SdkLanguage::JavaScript.package_manager(), "npm");
        assert_eq!(SdkLanguage::TypeScript.package_manager(), "npm");
        assert_eq!(SdkLanguage::Rust.package_manager(), "cargo");
        assert_eq!(SdkLanguage::Go.package_manager(), "go");
    }

    #[test]
    fn test_sdk_generator_creation() {
        let generator = SdkGenerator::default();
        assert_eq!(generator.config.package_name, "chie-client");
        assert_eq!(generator.config.version, "0.1.0");
    }

    #[test]
    fn test_generate_all() {
        let generator = SdkGenerator::default();
        let files = generator.generate_all();

        // Should have 6 files: 5 language SDKs + README
        assert_eq!(files.len(), 6);
        assert!(files.contains_key("README.md"));
    }

    #[test]
    fn test_python_sdk_generation() {
        let generator = SdkGenerator::default();
        let code = generator.generate_python();

        assert!(code.contains("class ChieClient"));
        assert!(code.contains("def get_platform_stats"));
    }

    #[test]
    fn test_javascript_sdk_generation() {
        let generator = SdkGenerator::default();
        let code = generator.generate_javascript();

        assert!(code.contains("class ChieClient"));
        assert!(code.contains("async getPlatformStats"));
    }

    #[test]
    fn test_typescript_sdk_generation() {
        let generator = SdkGenerator::default();
        let code = generator.generate_typescript();

        assert!(code.contains("export class ChieClient"));
        assert!(code.contains("async getPlatformStats"));
        assert!(code.contains("interface PlatformStats"));
    }

    #[test]
    fn test_rust_sdk_generation() {
        let generator = SdkGenerator::default();
        let code = generator.generate_rust();

        assert!(code.contains("pub struct ChieClient"));
        assert!(code.contains("pub async fn get_platform_stats"));
    }

    #[test]
    fn test_go_sdk_generation() {
        let generator = SdkGenerator::default();
        let code = generator.generate_go();

        assert!(code.contains("type Client struct"));
        assert!(code.contains("func (c *Client) GetPlatformStats"));
    }
}
