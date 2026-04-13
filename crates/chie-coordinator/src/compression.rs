//! Response Compression Middleware
//!
//! Provides automatic response compression with support for:
//! - gzip compression (RFC 1952)
//! - brotli compression (RFC 7932)
//! - Content negotiation via Accept-Encoding header
//! - Configurable compression levels
//! - Size thresholds to avoid compressing small responses

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// Gzip compression
    Gzip,
    /// Brotli compression
    Brotli,
    /// No compression
    None,
}

impl CompressionAlgorithm {
    /// Get the content-encoding header value
    pub fn as_str(&self) -> &'static str {
        match self {
            CompressionAlgorithm::Gzip => "gzip",
            CompressionAlgorithm::Brotli => "br",
            CompressionAlgorithm::None => "identity",
        }
    }

    /// Parse from Accept-Encoding header value
    pub fn from_accept_encoding(accept_encoding: &str) -> Self {
        // Parse quality values and select best algorithm
        let mut has_gzip = false;
        let mut has_brotli = false;
        let mut gzip_quality = 0.0;
        let mut brotli_quality = 0.0;

        for encoding in accept_encoding.split(',') {
            let encoding = encoding.trim();

            // Parse quality value if present
            let (name, quality) = match encoding.find(";q=") {
                Some(pos) => {
                    let quality_str = &encoding[pos + 3..];
                    let quality = quality_str.trim().parse::<f32>().unwrap_or(1.0);
                    (&encoding[..pos], quality)
                }
                None => (encoding, 1.0),
            };

            let name = name.trim();

            match name.to_lowercase().as_str() {
                "gzip" => {
                    has_gzip = true;
                    gzip_quality = quality;
                }
                "br" | "brotli" => {
                    has_brotli = true;
                    brotli_quality = quality;
                }
                _ => {}
            }
        }

        // Prefer brotli if quality is higher or equal
        if has_brotli && brotli_quality >= gzip_quality {
            CompressionAlgorithm::Brotli
        } else if has_gzip {
            CompressionAlgorithm::Gzip
        } else {
            CompressionAlgorithm::None
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// Minimum response size to compress (bytes)
    pub min_size: usize,
    /// Maximum response size to compress (bytes)
    pub max_size: usize,
    /// Gzip compression level (0-9)
    pub gzip_level: u32,
    /// Brotli compression level (0-11)
    pub brotli_level: u32,
    /// Whether to enable gzip
    pub enable_gzip: bool,
    /// Whether to enable brotli
    pub enable_brotli: bool,
    /// Content types to compress
    pub compress_content_types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            min_size: 1024,             // 1 KB
            max_size: 10 * 1024 * 1024, // 10 MB
            gzip_level: 6,              // Default level
            brotli_level: 4,            // Default level
            enable_gzip: true,
            enable_brotli: true,
            compress_content_types: vec![
                "text/html".to_string(),
                "text/css".to_string(),
                "text/javascript".to_string(),
                "application/javascript".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "text/xml".to_string(),
                "text/plain".to_string(),
                "application/octet-stream".to_string(),
            ],
        }
    }
}

/// Compression manager
pub struct CompressionManager {
    config: CompressionConfig,
}

impl CompressionManager {
    /// Create new compression manager
    pub fn new(config: CompressionConfig) -> Self {
        Self { config }
    }

    /// Check if content type should be compressed
    pub fn should_compress_content_type(&self, content_type: Option<&str>) -> bool {
        if let Some(content_type) = content_type {
            let content_type_base = content_type
                .split(';')
                .next()
                .unwrap_or(content_type)
                .trim();
            self.config
                .compress_content_types
                .iter()
                .any(|ct| ct == content_type_base)
        } else {
            false
        }
    }

    /// Check if response should be compressed
    pub fn should_compress(&self, headers: &HeaderMap, body_size: usize) -> bool {
        // Check size thresholds
        if body_size < self.config.min_size || body_size > self.config.max_size {
            return false;
        }

        // Check if already encoded
        if headers.contains_key(header::CONTENT_ENCODING) {
            return false;
        }

        // Check content type
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        self.should_compress_content_type(content_type)
    }

    /// Determine best compression algorithm
    pub fn determine_algorithm(&self, accept_encoding: Option<&str>) -> CompressionAlgorithm {
        if let Some(accept_encoding) = accept_encoding {
            let algo = CompressionAlgorithm::from_accept_encoding(accept_encoding);

            match algo {
                CompressionAlgorithm::Brotli if !self.config.enable_brotli => {
                    if self.config.enable_gzip {
                        CompressionAlgorithm::Gzip
                    } else {
                        CompressionAlgorithm::None
                    }
                }
                CompressionAlgorithm::Gzip if !self.config.enable_gzip => {
                    CompressionAlgorithm::None
                }
                _ => algo,
            }
        } else {
            CompressionAlgorithm::None
        }
    }

    /// Compress data using gzip (oxiarc-deflate)
    pub fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let level = self.config.gzip_level.min(9) as u8;
        oxiarc_deflate::gzip_compress(data, level).map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Compress data using brotli (oxiarc-brotli)
    pub fn compress_brotli(&self, data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let quality = self.config.brotli_level.min(11);
        oxiarc_brotli::compress(data, quality).map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// Compress data using the specified algorithm
    pub fn compress(
        &self,
        data: &[u8],
        algorithm: CompressionAlgorithm,
    ) -> Result<Vec<u8>, std::io::Error> {
        match algorithm {
            CompressionAlgorithm::Gzip => self.compress_gzip(data),
            CompressionAlgorithm::Brotli => self.compress_brotli(data),
            CompressionAlgorithm::None => Ok(data.to_vec()),
        }
    }
}

/// Middleware to compress responses
pub async fn compression_middleware(
    State(manager): State<Arc<CompressionManager>>,
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Get Accept-Encoding header (clone to avoid borrow issues)
    let accept_encoding = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Process request
    let response = next.run(request).await;

    // Extract parts before consuming response
    let (parts, body) = response.into_parts();
    let headers = parts.headers.clone();
    let status = parts.status;

    // Check if we should compress
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Failed to read response body for compression: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read response body".to_string(),
            ));
        }
    };

    // Determine if we should compress
    if !manager.should_compress(&headers, body_bytes.len()) {
        debug!(
            "Skipping compression (size: {}, content-type: {:?})",
            body_bytes.len(),
            headers.get(header::CONTENT_TYPE)
        );
        let mut response = Response::new(Body::from(body_bytes));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return Ok(response);
    }

    // Determine compression algorithm
    let algorithm = manager.determine_algorithm(accept_encoding.as_deref());

    if algorithm == CompressionAlgorithm::None {
        debug!("No compression algorithm selected");
        let mut response = Response::new(Body::from(body_bytes));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return Ok(response);
    }

    // Compress the response
    let compressed = match manager.compress(&body_bytes, algorithm) {
        Ok(compressed) => compressed,
        Err(e) => {
            warn!("Compression failed: {}", e);
            // Return uncompressed response on error
            let mut response = Response::new(Body::from(body_bytes));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            return Ok(response);
        }
    };

    let compressed_len = compressed.len();
    let compression_ratio = (compressed_len as f64 / body_bytes.len() as f64) * 100.0;
    debug!(
        "Compressed {} bytes to {} bytes ({:.1}%) using {}",
        body_bytes.len(),
        compressed_len,
        compression_ratio,
        algorithm.as_str()
    );

    // Build compressed response
    let mut response = Response::new(Body::from(compressed));
    *response.status_mut() = status;
    *response.headers_mut() = headers;

    // Add compression headers
    response.headers_mut().insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(algorithm.as_str()),
    );

    // Update content length
    if let Ok(len_value) = HeaderValue::from_str(&compressed_len.to_string()) {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, len_value);
    }

    // Add Vary header to indicate content encoding varies
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));

    // Record metrics
    crate::metrics::record_compression_used(algorithm.as_str());
    crate::metrics::record_compression_ratio(compression_ratio);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_algorithm_parsing() {
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding("gzip"),
            CompressionAlgorithm::Gzip
        );
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding("br"),
            CompressionAlgorithm::Brotli
        );
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding("gzip, br"),
            CompressionAlgorithm::Brotli
        );
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding("gzip;q=0.8, br;q=0.9"),
            CompressionAlgorithm::Brotli
        );
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding("br;q=0.5, gzip;q=0.8"),
            CompressionAlgorithm::Gzip
        );
    }

    #[test]
    fn test_should_compress_content_type() {
        let manager = CompressionManager::new(CompressionConfig::default());

        assert!(manager.should_compress_content_type(Some("application/json")));
        assert!(manager.should_compress_content_type(Some("text/html")));
        assert!(manager.should_compress_content_type(Some("text/html; charset=utf-8")));
        assert!(!manager.should_compress_content_type(Some("image/png")));
        assert!(!manager.should_compress_content_type(None));
    }

    #[test]
    fn test_gzip_compression() {
        let manager = CompressionManager::new(CompressionConfig::default());
        let data = b"Hello, World! ".repeat(100);

        let compressed = manager.compress_gzip(&data).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_brotli_compression() {
        let manager = CompressionManager::new(CompressionConfig::default());
        let data = b"Hello, World! ".repeat(100);

        let compressed = manager.compress_brotli(&data).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_compression_algorithm_string() {
        assert_eq!(CompressionAlgorithm::Gzip.as_str(), "gzip");
        assert_eq!(CompressionAlgorithm::Brotli.as_str(), "br");
        assert_eq!(CompressionAlgorithm::None.as_str(), "identity");
    }

    #[test]
    fn test_determine_algorithm_with_disabled() {
        let config = CompressionConfig {
            enable_brotli: false,
            ..Default::default()
        };

        let manager = CompressionManager::new(config);
        assert_eq!(
            manager.determine_algorithm(Some("br, gzip")),
            CompressionAlgorithm::Gzip
        );
    }
}
