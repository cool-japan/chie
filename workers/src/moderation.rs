//! Content moderation checks for CHIE Protocol.
//!
//! This module provides:
//! - Hash-based content blocking (blocklist)
//! - Content type detection and validation
//! - External moderation API integration
//! - Automatic flagging of suspicious content

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Moderation error.
#[derive(Debug, Error)]
pub enum ModerationError {
    #[error("Content blocked: {reason}")]
    ContentBlocked { reason: String },

    #[error("Content type not allowed: {content_type}")]
    ContentTypeNotAllowed { content_type: String },

    #[error("Content hash blocked: {hash}")]
    HashBlocked { hash: String },

    #[error("External moderation failed: {0}")]
    ExternalCheckFailed(String),

    #[error("Content too large: {size} bytes (max: {max} bytes)")]
    ContentTooLarge { size: u64, max: u64 },

    #[error("Moderation service unavailable")]
    ServiceUnavailable,

    #[error("Invalid content: {0}")]
    InvalidContent(String),
}

/// Moderation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationResult {
    /// Whether content passed moderation.
    pub passed: bool,
    /// Content hash.
    pub content_hash: String,
    /// Detected content type.
    pub content_type: Option<String>,
    /// Moderation flags raised.
    pub flags: Vec<ModerationFlag>,
    /// Confidence score (0.0-1.0).
    pub confidence: f64,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

impl ModerationResult {
    /// Create a passing result.
    pub fn pass(content_hash: String) -> Self {
        Self {
            passed: true,
            content_hash,
            content_type: None,
            flags: Vec::new(),
            confidence: 1.0,
            processing_time_ms: 0,
            metadata: None,
        }
    }

    /// Create a failing result.
    pub fn fail(content_hash: String, flags: Vec<ModerationFlag>) -> Self {
        Self {
            passed: false,
            content_hash,
            content_type: None,
            flags,
            confidence: 1.0,
            processing_time_ms: 0,
            metadata: None,
        }
    }
}

/// Moderation flag categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModerationFlag {
    /// Known blocked hash.
    BlockedHash,
    /// Suspicious content type.
    SuspiciousContentType,
    /// Content exceeds size limit.
    ExceedsSizeLimit,
    /// Potential malware detected.
    PotentialMalware,
    /// Executable content.
    ExecutableContent,
    /// Encrypted/obfuscated content.
    EncryptedContent,
    /// Content flagged by external service.
    ExternalFlagged,
    /// Duplicate content.
    DuplicateContent,
    /// High-risk file extension.
    HighRiskExtension,
    /// Unknown content type.
    UnknownContentType,
    /// Potential zip bomb (decompression bomb) detected.
    ZipBomb,
    /// Nested archive detected (archive within archive).
    NestedArchive,
}

/// Moderation configuration.
#[derive(Debug, Clone)]
pub struct ModerationConfig {
    /// Maximum content size (bytes).
    pub max_content_size: u64,
    /// Allowed content types (MIME types).
    pub allowed_content_types: Vec<String>,
    /// Blocked file extensions.
    pub blocked_extensions: Vec<String>,
    /// Enable external moderation API.
    pub enable_external_api: bool,
    /// External API endpoint.
    pub external_api_url: Option<String>,
    /// External API timeout.
    pub external_api_timeout: Duration,
    /// Enable hash blocklist checking.
    pub enable_blocklist: bool,
    /// Minimum confidence threshold.
    pub confidence_threshold: f64,
    /// Enable zip bomb detection.
    pub enable_zip_bomb_detection: bool,
    /// Maximum decompression ratio (compressed size / decompressed size).
    pub max_compression_ratio: f64,
    /// Maximum nesting depth for archives.
    pub max_archive_depth: u32,
    /// Maximum decompressed size (bytes).
    pub max_decompressed_size: u64,
}

impl Default for ModerationConfig {
    fn default() -> Self {
        Self {
            max_content_size: 5 * 1024 * 1024 * 1024, // 5 GB
            allowed_content_types: vec![
                "image/jpeg".to_string(),
                "image/png".to_string(),
                "image/gif".to_string(),
                "image/webp".to_string(),
                "video/mp4".to_string(),
                "video/webm".to_string(),
                "audio/mpeg".to_string(),
                "audio/ogg".to_string(),
                "application/pdf".to_string(),
                "application/zip".to_string(),
                "text/plain".to_string(),
                "application/octet-stream".to_string(),
            ],
            blocked_extensions: vec![
                ".exe".to_string(),
                ".bat".to_string(),
                ".cmd".to_string(),
                ".com".to_string(),
                ".scr".to_string(),
                ".pif".to_string(),
                ".msi".to_string(),
                ".dll".to_string(),
                ".vbs".to_string(),
                ".js".to_string(),
                ".jar".to_string(),
                ".ps1".to_string(),
            ],
            enable_external_api: false,
            external_api_url: None,
            external_api_timeout: Duration::from_secs(30),
            enable_blocklist: true,
            confidence_threshold: 0.8,
            enable_zip_bomb_detection: true,
            max_compression_ratio: 100.0, // 100:1 ratio is suspicious
            max_archive_depth: 3,         // Maximum 3 levels of nesting
            max_decompressed_size: 10 * 1024 * 1024 * 1024, // 10 GB max decompressed
        }
    }
}

/// Hash blocklist for known bad content.
#[derive(Debug, Default)]
pub struct HashBlocklist {
    /// Set of blocked hashes (BLAKE3).
    blocked: HashSet<String>,
    /// Set of flagged hashes (for review).
    flagged: HashSet<String>,
}

impl HashBlocklist {
    /// Create a new blocklist.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a hash to the blocklist.
    pub fn block(&mut self, hash: &str) {
        self.blocked.insert(hash.to_lowercase());
    }

    /// Add multiple hashes to the blocklist.
    pub fn block_many(&mut self, hashes: &[String]) {
        for hash in hashes {
            self.block(hash);
        }
    }

    /// Flag a hash for review.
    pub fn flag(&mut self, hash: &str) {
        self.flagged.insert(hash.to_lowercase());
    }

    /// Check if a hash is blocked.
    pub fn is_blocked(&self, hash: &str) -> bool {
        self.blocked.contains(&hash.to_lowercase())
    }

    /// Check if a hash is flagged.
    pub fn is_flagged(&self, hash: &str) -> bool {
        self.flagged.contains(&hash.to_lowercase())
    }

    /// Remove a hash from the blocklist.
    pub fn unblock(&mut self, hash: &str) {
        self.blocked.remove(&hash.to_lowercase());
    }

    /// Get blocklist size.
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// Get flagged count.
    pub fn flagged_count(&self) -> usize {
        self.flagged.len()
    }
}

/// Result of zip bomb heuristic check.
#[derive(Debug, Clone)]
pub enum ZipBombCheck {
    /// Content appears safe.
    Safe,
    /// Suspiciously high compression ratio.
    HighCompressionRatio(f64),
    /// Claimed decompressed size exceeds limit.
    ExceedsDecompressedSize(u64),
    /// Nested archive detected at given depth.
    NestedArchive(u32),
    /// Error during check (not necessarily a bomb).
    Error(String),
}

/// Content moderator.
pub struct ContentModerator {
    config: ModerationConfig,
    blocklist: Arc<RwLock<HashBlocklist>>,
    #[allow(dead_code)]
    http_client: Option<reqwest::Client>,
}

impl ContentModerator {
    /// Create a new content moderator.
    pub fn new(config: ModerationConfig) -> Self {
        let http_client = if config.enable_external_api {
            Some(
                reqwest::Client::builder()
                    .timeout(config.external_api_timeout)
                    .build()
                    .expect("Failed to create HTTP client"),
            )
        } else {
            None
        };

        Self {
            config,
            blocklist: Arc::new(RwLock::new(HashBlocklist::new())),
            http_client,
        }
    }

    /// Create with a shared blocklist.
    pub fn with_blocklist(config: ModerationConfig, blocklist: Arc<RwLock<HashBlocklist>>) -> Self {
        let http_client = if config.enable_external_api {
            Some(
                reqwest::Client::builder()
                    .timeout(config.external_api_timeout)
                    .build()
                    .expect("Failed to create HTTP client"),
            )
        } else {
            None
        };

        Self {
            config,
            blocklist,
            http_client,
        }
    }

    /// Moderate content.
    pub async fn moderate(
        &self,
        content: &[u8],
        filename: Option<&str>,
    ) -> Result<ModerationResult, ModerationError> {
        let start = std::time::Instant::now();
        let mut flags = Vec::new();

        // Check size
        if content.len() as u64 > self.config.max_content_size {
            return Err(ModerationError::ContentTooLarge {
                size: content.len() as u64,
                max: self.config.max_content_size,
            });
        }

        // Calculate content hash
        let content_hash = self.hash_content(content);

        // Check blocklist
        if self.config.enable_blocklist {
            let blocklist = self.blocklist.read().await;
            if blocklist.is_blocked(&content_hash) {
                return Err(ModerationError::HashBlocked { hash: content_hash });
            }
            if blocklist.is_flagged(&content_hash) {
                flags.push(ModerationFlag::ExternalFlagged);
            }
        }

        // Check file extension
        if let Some(name) = filename {
            let lower_name = name.to_lowercase();
            for ext in &self.config.blocked_extensions {
                if lower_name.ends_with(ext) {
                    flags.push(ModerationFlag::HighRiskExtension);
                    break;
                }
            }
        }

        // Detect content type
        let content_type = self.detect_content_type(content);

        // Check if content type is allowed
        if let Some(ct) = &content_type {
            if !self.is_content_type_allowed(ct) {
                flags.push(ModerationFlag::SuspiciousContentType);
            }
        } else {
            flags.push(ModerationFlag::UnknownContentType);
        }

        // Check for executable content
        if self.is_executable(content) {
            flags.push(ModerationFlag::ExecutableContent);
        }

        // Check for zip bomb / decompression bomb
        if self.config.enable_zip_bomb_detection {
            if let Some(ct) = &content_type {
                if ct == "application/zip"
                    || ct == "application/x-tar"
                    || ct == "application/gzip"
                    || ct == "application/x-7z-compressed"
                    || ct == "application/x-rar-compressed"
                {
                    match self.check_zip_bomb(content, 0) {
                        ZipBombCheck::Safe => {}
                        ZipBombCheck::HighCompressionRatio(ratio) => {
                            warn!("Suspicious compression ratio: {:.2}:1", ratio);
                            flags.push(ModerationFlag::ZipBomb);
                        }
                        ZipBombCheck::ExceedsDecompressedSize(size) => {
                            warn!("Decompressed size too large: {} bytes", size);
                            flags.push(ModerationFlag::ZipBomb);
                        }
                        ZipBombCheck::NestedArchive(depth) => {
                            warn!("Nested archive depth: {}", depth);
                            flags.push(ModerationFlag::NestedArchive);
                        }
                        ZipBombCheck::Error(e) => {
                            debug!("Zip bomb check error: {}", e);
                            // Don't flag as bomb, but log the error
                        }
                    }
                }
            }
        }

        // Calculate confidence based on flags
        let confidence = self.calculate_confidence(&flags);

        let processing_time_ms = start.elapsed().as_millis() as u64;

        // Determine if content passes
        let passed = flags.is_empty() || confidence >= self.config.confidence_threshold;

        if !passed {
            warn!(
                "Content failed moderation: hash={}, flags={:?}",
                content_hash, flags
            );
        } else {
            debug!("Content passed moderation: hash={}", content_hash);
        }

        Ok(ModerationResult {
            passed,
            content_hash,
            content_type,
            flags,
            confidence,
            processing_time_ms,
            metadata: None,
        })
    }

    /// Moderate content by hash only (quick check).
    pub async fn quick_check(&self, content_hash: &str) -> ModerationResult {
        let blocklist = self.blocklist.read().await;

        let mut flags = Vec::new();
        if blocklist.is_blocked(content_hash) {
            flags.push(ModerationFlag::BlockedHash);
        }
        if blocklist.is_flagged(content_hash) {
            flags.push(ModerationFlag::ExternalFlagged);
        }

        ModerationResult {
            passed: flags.is_empty(),
            content_hash: content_hash.to_string(),
            content_type: None,
            flags,
            confidence: 1.0,
            processing_time_ms: 0,
            metadata: None,
        }
    }

    /// Block a content hash.
    pub async fn block_hash(&self, hash: &str, reason: &str) {
        let mut blocklist = self.blocklist.write().await;
        blocklist.block(hash);
        info!("Blocked content hash: {} (reason: {})", hash, reason);
    }

    /// Flag a content hash for review.
    pub async fn flag_hash(&self, hash: &str, reason: &str) {
        let mut blocklist = self.blocklist.write().await;
        blocklist.flag(hash);
        info!("Flagged content hash: {} (reason: {})", hash, reason);
    }

    /// Unblock a content hash.
    pub async fn unblock_hash(&self, hash: &str) {
        let mut blocklist = self.blocklist.write().await;
        blocklist.unblock(hash);
        info!("Unblocked content hash: {}", hash);
    }

    /// Calculate content hash (BLAKE3).
    fn hash_content(&self, content: &[u8]) -> String {
        let hash = blake3::hash(content);
        hash.to_hex().to_string()
    }

    /// Detect content type using magic bytes.
    fn detect_content_type(&self, content: &[u8]) -> Option<String> {
        if content.len() < 4 {
            return None;
        }

        // Check magic bytes
        match &content[..4] {
            // Images
            [0xFF, 0xD8, 0xFF, _] => Some("image/jpeg".to_string()),
            [0x89, 0x50, 0x4E, 0x47] => Some("image/png".to_string()),
            [0x47, 0x49, 0x46, 0x38] => Some("image/gif".to_string()),
            // Video
            [0x00, 0x00, 0x00, 0x1C] | [0x00, 0x00, 0x00, 0x20] => Some("video/mp4".to_string()),
            // Audio
            [0x49, 0x44, 0x33, _] | [0xFF, 0xFB, _, _] => Some("audio/mpeg".to_string()),
            // PDF
            [0x25, 0x50, 0x44, 0x46] => Some("application/pdf".to_string()),
            // Zip/archives
            [0x50, 0x4B, 0x03, 0x04] => Some("application/zip".to_string()),
            // WebP
            _ if content.len() >= 12 && &content[0..4] == b"RIFF" && &content[8..12] == b"WEBP" => {
                Some("image/webp".to_string())
            }
            // WebM
            _ if content.len() >= 4 && content[0..4] == [0x1A, 0x45, 0xDF, 0xA3] => {
                Some("video/webm".to_string())
            }
            // Ogg
            _ if content.len() >= 4 && &content[0..4] == b"OggS" => Some("audio/ogg".to_string()),
            _ => {
                // Check for text
                if content.iter().take(1024).all(|&b| b.is_ascii() || b > 127) {
                    Some("text/plain".to_string())
                } else {
                    Some("application/octet-stream".to_string())
                }
            }
        }
    }

    /// Check if content type is allowed.
    fn is_content_type_allowed(&self, content_type: &str) -> bool {
        self.config
            .allowed_content_types
            .iter()
            .any(|ct| content_type.starts_with(ct))
    }

    /// Check if content appears to be executable.
    fn is_executable(&self, content: &[u8]) -> bool {
        if content.len() < 4 {
            return false;
        }

        // Check for common executable signatures
        match &content[..2] {
            // DOS/Windows executable
            [0x4D, 0x5A] => true,
            // ELF (Linux)
            [0x7F, 0x45] if content.len() >= 4 && content[2..4] == [0x4C, 0x46] => true,
            // Mach-O (macOS)
            [0xFE, 0xED] | [0xCE, 0xFA] | [0xCF, 0xFA] => true,
            _ => false,
        }
    }

    /// Calculate confidence score based on flags.
    fn calculate_confidence(&self, flags: &[ModerationFlag]) -> f64 {
        if flags.is_empty() {
            return 1.0;
        }

        let mut penalty = 0.0;
        for flag in flags {
            penalty += match flag {
                ModerationFlag::BlockedHash => 1.0,
                ModerationFlag::ExecutableContent => 0.8,
                ModerationFlag::PotentialMalware => 0.9,
                ModerationFlag::HighRiskExtension => 0.5,
                ModerationFlag::SuspiciousContentType => 0.3,
                ModerationFlag::ExternalFlagged => 0.7,
                ModerationFlag::UnknownContentType => 0.1,
                _ => 0.2,
            };
        }

        (1.0_f64 - penalty).max(0.0)
    }

    /// Get blocklist statistics.
    pub async fn stats(&self) -> ModerationStats {
        let blocklist = self.blocklist.read().await;
        ModerationStats {
            blocked_hashes: blocklist.blocked_count(),
            flagged_hashes: blocklist.flagged_count(),
        }
    }

    /// Check content for zip bomb / decompression bomb indicators.
    ///
    /// This performs a heuristic analysis without actually decompressing:
    /// - Checks compression ratio by comparing header metadata
    /// - Detects nested archives
    /// - Validates claimed sizes against limits
    fn check_zip_bomb(&self, content: &[u8], depth: u32) -> ZipBombCheck {
        if depth > self.config.max_archive_depth {
            return ZipBombCheck::NestedArchive(depth);
        }

        // ZIP file detection (PK header)
        if content.len() >= 4 && content[0..4] == [0x50, 0x4B, 0x03, 0x04] {
            return self.check_zip_bomb_zip(content, depth);
        }

        // GZIP detection (1F 8B)
        if content.len() >= 2 && content[0..2] == [0x1F, 0x8B] {
            return self.check_zip_bomb_gzip(content);
        }

        ZipBombCheck::Safe
    }

    /// Check ZIP file for bomb indicators.
    fn check_zip_bomb_zip(&self, content: &[u8], depth: u32) -> ZipBombCheck {
        // Parse ZIP local file headers to get sizes
        // Without actually decompressing, we check the claimed sizes in headers
        let mut total_compressed: u64 = 0;
        let mut total_uncompressed: u64 = 0;
        let mut offset = 0;
        let mut file_count = 0;

        while offset + 30 <= content.len() {
            // Check for local file header signature
            if content[offset..offset + 4] != [0x50, 0x4B, 0x03, 0x04] {
                break;
            }

            // Read compressed size (offset 18, 4 bytes, little-endian)
            let compressed_size = u32::from_le_bytes([
                content[offset + 18],
                content[offset + 19],
                content[offset + 20],
                content[offset + 21],
            ]) as u64;

            // Read uncompressed size (offset 22, 4 bytes, little-endian)
            let uncompressed_size = u32::from_le_bytes([
                content[offset + 22],
                content[offset + 23],
                content[offset + 24],
                content[offset + 25],
            ]) as u64;

            // Read filename length (offset 26, 2 bytes)
            let filename_len =
                u16::from_le_bytes([content[offset + 26], content[offset + 27]]) as usize;

            // Read extra field length (offset 28, 2 bytes)
            let extra_len =
                u16::from_le_bytes([content[offset + 28], content[offset + 29]]) as usize;

            total_compressed += compressed_size;
            total_uncompressed += uncompressed_size;

            // Check for nested archives (check file extension in filename)
            if filename_len > 0 && offset + 30 + filename_len <= content.len() {
                let filename_bytes = &content[offset + 30..offset + 30 + filename_len];
                if let Ok(filename) = std::str::from_utf8(filename_bytes) {
                    let lower = filename.to_lowercase();
                    if lower.ends_with(".zip")
                        || lower.ends_with(".gz")
                        || lower.ends_with(".tar")
                        || lower.ends_with(".7z")
                        || lower.ends_with(".rar")
                    {
                        // Potential nested archive - increment depth check
                        if depth + 1 > self.config.max_archive_depth {
                            return ZipBombCheck::NestedArchive(depth + 1);
                        }
                    }
                }
            }

            // Move to next header
            let header_size = 30 + filename_len + extra_len + compressed_size as usize;
            if offset + header_size > content.len() {
                break;
            }
            offset += header_size;
            file_count += 1;

            // Limit iterations to prevent DoS
            if file_count > 10000 {
                break;
            }
        }

        // Check total uncompressed size
        if total_uncompressed > self.config.max_decompressed_size {
            return ZipBombCheck::ExceedsDecompressedSize(total_uncompressed);
        }

        // Check compression ratio
        if total_compressed > 0 {
            let ratio = total_uncompressed as f64 / total_compressed as f64;
            if ratio > self.config.max_compression_ratio {
                return ZipBombCheck::HighCompressionRatio(ratio);
            }
        }

        ZipBombCheck::Safe
    }

    /// Check GZIP file for bomb indicators.
    fn check_zip_bomb_gzip(&self, content: &[u8]) -> ZipBombCheck {
        // GZIP stores the original uncompressed size in the last 4 bytes
        if content.len() < 4 {
            return ZipBombCheck::Safe;
        }

        let uncompressed_size = u32::from_le_bytes([
            content[content.len() - 4],
            content[content.len() - 3],
            content[content.len() - 2],
            content[content.len() - 1],
        ]) as u64;

        // GZIP header is minimum 10 bytes
        let compressed_size = content.len().saturating_sub(10) as u64;

        // Check total uncompressed size
        if uncompressed_size > self.config.max_decompressed_size {
            return ZipBombCheck::ExceedsDecompressedSize(uncompressed_size);
        }

        // Check compression ratio
        if compressed_size > 0 {
            let ratio = uncompressed_size as f64 / compressed_size as f64;
            if ratio > self.config.max_compression_ratio {
                return ZipBombCheck::HighCompressionRatio(ratio);
            }
        }

        ZipBombCheck::Safe
    }
}

/// Moderation statistics.
#[derive(Debug, Clone)]
pub struct ModerationStats {
    /// Number of blocked hashes.
    pub blocked_hashes: usize,
    /// Number of flagged hashes.
    pub flagged_hashes: usize,
}

/// Batch moderation helper.
pub struct BatchModerator {
    moderator: Arc<ContentModerator>,
    #[allow(dead_code)]
    max_concurrent: usize,
}

impl BatchModerator {
    /// Create a new batch moderator.
    pub fn new(moderator: ContentModerator, max_concurrent: usize) -> Self {
        Self {
            moderator: Arc::new(moderator),
            max_concurrent,
        }
    }

    /// Moderate multiple content items.
    pub async fn moderate_batch(
        &self,
        items: Vec<(Vec<u8>, Option<String>)>,
    ) -> Vec<Result<ModerationResult, ModerationError>> {
        let mut results = Vec::with_capacity(items.len());

        for (content, filename) in items {
            let result = self.moderator.moderate(&content, filename.as_deref()).await;
            results.push(result);
        }

        results
    }

    /// Quick check batch of hashes.
    pub async fn quick_check_batch(&self, hashes: &[String]) -> Vec<ModerationResult> {
        let mut results = Vec::with_capacity(hashes.len());

        for hash in hashes {
            let result = self.moderator.quick_check(hash).await;
            results.push(result);
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_blocklist() {
        let mut blocklist = HashBlocklist::new();

        blocklist.block("abc123");
        blocklist.flag("def456");

        assert!(blocklist.is_blocked("abc123"));
        assert!(blocklist.is_blocked("ABC123")); // Case insensitive
        assert!(!blocklist.is_blocked("xyz789"));
        assert!(blocklist.is_flagged("def456"));

        blocklist.unblock("abc123");
        assert!(!blocklist.is_blocked("abc123"));
    }

    #[tokio::test]
    async fn test_content_moderator() {
        let config = ModerationConfig::default();
        let moderator = ContentModerator::new(config);

        // Test with valid JPEG-like content
        let jpeg_content = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let result = moderator.moderate(&jpeg_content, Some("test.jpg")).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.passed);
        assert_eq!(result.content_type, Some("image/jpeg".to_string()));
    }

    #[tokio::test]
    async fn test_executable_detection() {
        let config = ModerationConfig::default();
        let moderator = ContentModerator::new(config);

        // Test Windows executable
        let exe_content = vec![0x4D, 0x5A, 0x90, 0x00];
        let result = moderator.moderate(&exe_content, Some("test.exe")).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.flags.contains(&ModerationFlag::ExecutableContent));
        assert!(result.flags.contains(&ModerationFlag::HighRiskExtension));
    }

    #[tokio::test]
    async fn test_quick_check() {
        let config = ModerationConfig::default();
        let moderator = ContentModerator::new(config);

        // Block a hash
        moderator.block_hash("testhash123", "test").await;

        // Quick check should detect blocked hash
        let result = moderator.quick_check("testhash123").await;
        assert!(!result.passed);
        assert!(result.flags.contains(&ModerationFlag::BlockedHash));

        // Unknown hash should pass
        let result = moderator.quick_check("unknownhash").await;
        assert!(result.passed);
    }

    #[test]
    fn test_moderation_config_default() {
        let config = ModerationConfig::default();
        assert!(!config.enable_external_api);
        assert!(config.enable_blocklist);
        assert!(!config.allowed_content_types.is_empty());
        assert!(!config.blocked_extensions.is_empty());
    }
}
