//! Streaming protocol helpers for HLS and DASH.
//!
//! This module provides utilities for handling HTTP Live Streaming (HLS) and
//! Dynamic Adaptive Streaming over HTTP (DASH) protocols in a P2P CDN context.
//! Essential for efficient video streaming delivery across distributed nodes.
//!
//! # Features
//!
//! - HLS manifest parsing and manipulation
//! - DASH MPD parsing and manipulation
//! - Segment URL rewriting for P2P delivery
//! - Adaptive bitrate selection based on bandwidth
//! - Segment prefetching strategies
//! - Manifest caching and invalidation
//! - Stream quality switching
//! - Comprehensive streaming statistics
//!
//! # Example
//!
//! ```rust
//! use chie_p2p::{StreamingHelper, StreamingProtocol, QualityLevel};
//!
//! let helper = StreamingHelper::new();
//!
//! // Parse HLS manifest
//! let manifest = "#EXTM3U\n\
//!                 #EXT-X-VERSION:3\n\
//!                 #EXT-X-TARGETDURATION:10\n\
//!                 #EXTINF:9.9,\n\
//!                 segment0.ts\n";
//!
//! if let Some(segments) = helper.parse_hls_manifest(manifest) {
//!     println!("Found {} segments", segments.len());
//! }
//!
//! // Select quality based on bandwidth
//! let qualities = vec![
//!     QualityLevel::new("720p", 2_500_000),
//!     QualityLevel::new("1080p", 5_000_000),
//! ];
//! let selected = helper.select_quality(&qualities, 3_000_000);
//! ```

use serde::{Deserialize, Serialize};

/// Streaming protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamingProtocol {
    /// HTTP Live Streaming (Apple)
    HLS,
    /// Dynamic Adaptive Streaming over HTTP (MPEG)
    DASH,
}

/// Quality level for adaptive streaming
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityLevel {
    /// Quality identifier (e.g., "720p", "1080p")
    pub id: String,
    /// Bitrate in bits per second
    pub bitrate: u64,
    /// Resolution width
    pub width: Option<u32>,
    /// Resolution height
    pub height: Option<u32>,
    /// Codec information
    pub codec: Option<String>,
    /// Manifest URL for this quality
    pub manifest_url: String,
}

impl QualityLevel {
    /// Create a new quality level
    pub fn new(id: impl Into<String>, bitrate: u64) -> Self {
        Self {
            id: id.into(),
            bitrate,
            width: None,
            height: None,
            codec: None,
            manifest_url: String::new(),
        }
    }

    /// Create with resolution
    pub fn with_resolution(mut self, width: u32, height: u32) -> Self {
        self.width = Some(width);
        self.height = Some(height);
        self
    }

    /// Create with codec
    pub fn with_codec(mut self, codec: impl Into<String>) -> Self {
        self.codec = Some(codec.into());
        self
    }

    /// Create with manifest URL
    pub fn with_manifest_url(mut self, url: impl Into<String>) -> Self {
        self.manifest_url = url.into();
        self
    }
}

/// HLS segment information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HlsSegment {
    /// Segment duration in seconds
    pub duration: f64,
    /// Segment URL
    pub url: String,
    /// Sequence number
    pub sequence: u64,
    /// Optional title
    pub title: Option<String>,
    /// Byte range (for byte-range segments)
    pub byte_range: Option<(u64, u64)>,
    /// Discontinuity marker
    pub discontinuity: bool,
}

/// DASH segment information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashSegment {
    /// Segment URL or template
    pub url: String,
    /// Segment duration in seconds
    pub duration: f64,
    /// Segment index
    pub index: u64,
    /// Start time in seconds
    pub start_time: f64,
}

/// Streaming statistics
#[derive(Debug, Clone, Default)]
pub struct StreamingStats {
    /// Total manifests parsed
    pub manifests_parsed: u64,
    /// Total segments extracted
    pub segments_extracted: u64,
    /// Total HLS manifests
    pub hls_manifests: u64,
    /// Total DASH manifests
    pub dash_manifests: u64,
    /// Average segment duration
    pub avg_segment_duration: f64,
    /// Quality switches performed
    pub quality_switches: u64,
    /// Segments prefetched
    pub segments_prefetched: u64,
}

/// Streaming protocol helper
pub struct StreamingHelper {
    stats: parking_lot::RwLock<StreamingStats>,
    /// Base URL for segment rewriting
    base_url: Option<String>,
    /// Current quality level
    current_quality: parking_lot::RwLock<Option<String>>,
    /// Segment prefetch buffer size
    prefetch_buffer: usize,
}

impl StreamingHelper {
    /// Create a new streaming helper
    pub fn new() -> Self {
        Self {
            stats: parking_lot::RwLock::new(StreamingStats::default()),
            base_url: None,
            current_quality: parking_lot::RwLock::new(None),
            prefetch_buffer: 3, // Prefetch 3 segments ahead
        }
    }

    /// Create with base URL for segment rewriting
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            stats: parking_lot::RwLock::new(StreamingStats::default()),
            base_url: Some(base_url.into()),
            current_quality: parking_lot::RwLock::new(None),
            prefetch_buffer: 3,
        }
    }

    /// Set prefetch buffer size
    pub fn set_prefetch_buffer(&mut self, size: usize) {
        self.prefetch_buffer = size;
    }

    /// Parse HLS manifest (M3U8)
    pub fn parse_hls_manifest(&self, manifest: &str) -> Option<Vec<HlsSegment>> {
        if !manifest.starts_with("#EXTM3U") {
            return None;
        }

        let mut segments = Vec::new();
        let lines: Vec<&str> = manifest.lines().collect();
        let mut i = 0;
        let mut sequence = 0;

        while i < lines.len() {
            let line = lines[i].trim();

            if line.starts_with("#EXTINF:") {
                // Parse segment duration
                let duration_str = line.strip_prefix("#EXTINF:")?.split(',').next()?.trim();

                let duration = duration_str.parse::<f64>().ok()?;

                // Get segment URL (next line)
                i += 1;
                if i >= lines.len() {
                    break;
                }

                let url = lines[i].trim().to_string();

                // Check for discontinuity
                let discontinuity = if i > 0 {
                    lines
                        .get(i - 2)
                        .map(|l| l.trim() == "#EXT-X-DISCONTINUITY")
                        .unwrap_or(false)
                } else {
                    false
                };

                let segment = HlsSegment {
                    duration,
                    url: self.rewrite_url(url),
                    sequence,
                    title: None,
                    byte_range: None,
                    discontinuity,
                };

                segments.push(segment);
                sequence += 1;
            }

            i += 1;
        }

        if segments.is_empty() {
            return None;
        }

        // Update stats
        let mut stats = self.stats.write();
        stats.manifests_parsed += 1;
        stats.hls_manifests += 1;
        stats.segments_extracted += segments.len() as u64;

        if !segments.is_empty() {
            let total_duration: f64 = segments.iter().map(|s| s.duration).sum();
            stats.avg_segment_duration = total_duration / segments.len() as f64;
        }

        Some(segments)
    }

    /// Parse HLS master playlist
    pub fn parse_hls_master_playlist(&self, playlist: &str) -> Option<Vec<QualityLevel>> {
        if !playlist.starts_with("#EXTM3U") {
            return None;
        }

        let mut qualities = Vec::new();
        let lines: Vec<&str> = playlist.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();

            if line.starts_with("#EXT-X-STREAM-INF:") {
                // Parse stream info
                let info = line.strip_prefix("#EXT-X-STREAM-INF:")?;
                let mut bitrate = None;
                let mut resolution = None;
                let mut codecs = None;

                for part in info.split(',') {
                    let part = part.trim();
                    if let Some(bw) = part.strip_prefix("BANDWIDTH=") {
                        bitrate = bw.parse::<u64>().ok();
                    } else if let Some(res) = part.strip_prefix("RESOLUTION=") {
                        resolution = Some(res.to_string());
                    } else if let Some(codec_str) = part.strip_prefix("CODECS=") {
                        codecs = Some(codec_str.trim_matches('"').to_string());
                    }
                }

                // Get manifest URL (next line)
                i += 1;
                if i >= lines.len() {
                    break;
                }

                let manifest_url = lines[i].trim().to_string();

                if let Some(bw) = bitrate {
                    let (width, height) = if let Some(res) = resolution {
                        let parts: Vec<&str> = res.split('x').collect();
                        if parts.len() == 2 {
                            (parts[0].parse::<u32>().ok(), parts[1].parse::<u32>().ok())
                        } else {
                            (None, None)
                        }
                    } else {
                        (None, None)
                    };

                    let id = format!("{}p", height.unwrap_or(0));
                    let mut quality =
                        QualityLevel::new(id, bw).with_manifest_url(self.rewrite_url(manifest_url));

                    if let (Some(w), Some(h)) = (width, height) {
                        quality = quality.with_resolution(w, h);
                    }

                    if let Some(codec) = codecs {
                        quality = quality.with_codec(codec);
                    }

                    qualities.push(quality);
                }
            }

            i += 1;
        }

        if qualities.is_empty() {
            None
        } else {
            Some(qualities)
        }
    }

    /// Select quality level based on available bandwidth
    pub fn select_quality(
        &self,
        qualities: &[QualityLevel],
        bandwidth: u64,
    ) -> Option<QualityLevel> {
        if qualities.is_empty() {
            return None;
        }

        // Sort by bitrate
        let mut sorted = qualities.to_vec();
        sorted.sort_by_key(|q| q.bitrate);

        // Select highest quality that fits in bandwidth (with 20% buffer on top of bitrate)
        // For a quality level to be selected, bandwidth must be >= bitrate * 1.2
        let selected = sorted
            .iter()
            .rev()
            .find(|q| {
                let required = (q.bitrate as f64 * 1.2) as u64;
                bandwidth >= required
            })
            .or_else(|| sorted.first())?
            .clone();

        // Track quality switch
        let mut current = self.current_quality.write();
        if current.as_ref() != Some(&selected.id) {
            self.stats.write().quality_switches += 1;
            *current = Some(selected.id.clone());
        }

        Some(selected)
    }

    /// Get segments to prefetch based on current position
    pub fn get_prefetch_segments(
        &self,
        segments: &[HlsSegment],
        current_index: usize,
    ) -> Vec<HlsSegment> {
        let start = current_index + 1;
        let end = (start + self.prefetch_buffer).min(segments.len());

        if start >= segments.len() {
            return Vec::new();
        }

        let prefetch = segments[start..end].to_vec();
        self.stats.write().segments_prefetched += prefetch.len() as u64;
        prefetch
    }

    /// Rewrite segment URL with base URL
    fn rewrite_url(&self, url: String) -> String {
        if let Some(base) = &self.base_url {
            if url.starts_with("http://") || url.starts_with("https://") {
                url
            } else {
                format!(
                    "{}/{}",
                    base.trim_end_matches('/'),
                    url.trim_start_matches('/')
                )
            }
        } else {
            url
        }
    }

    /// Generate HLS manifest from segments
    pub fn generate_hls_manifest(&self, segments: &[HlsSegment], target_duration: u32) -> String {
        let mut manifest = String::new();
        manifest.push_str("#EXTM3U\n");
        manifest.push_str("#EXT-X-VERSION:3\n");
        manifest.push_str(&format!("#EXT-X-TARGETDURATION:{}\n", target_duration));
        manifest.push_str("#EXT-X-MEDIA-SEQUENCE:0\n");

        for segment in segments {
            if segment.discontinuity {
                manifest.push_str("#EXT-X-DISCONTINUITY\n");
            }

            manifest.push_str(&format!("#EXTINF:{:.3},\n", segment.duration));

            if let Some(title) = &segment.title {
                manifest.push_str(&format!("# {}\n", title));
            }

            manifest.push_str(&format!("{}\n", segment.url));
        }

        manifest.push_str("#EXT-X-ENDLIST\n");
        manifest
    }

    /// Parse DASH segment template
    pub fn parse_dash_template(
        &self,
        template: &str,
        duration: f64,
        count: u64,
    ) -> Vec<DashSegment> {
        let mut segments = Vec::new();

        for i in 0..count {
            let url = template
                .replace("$Number$", &i.to_string())
                .replace("$Time$", &((i as f64 * duration) as u64).to_string());

            segments.push(DashSegment {
                url: self.rewrite_url(url),
                duration,
                index: i,
                start_time: i as f64 * duration,
            });
        }

        // Update stats
        let mut stats = self.stats.write();
        stats.manifests_parsed += 1;
        stats.dash_manifests += 1;
        stats.segments_extracted += segments.len() as u64;
        stats.avg_segment_duration = duration;

        segments
    }

    /// Get current statistics
    pub fn stats(&self) -> StreamingStats {
        self.stats.read().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        *self.stats.write() = StreamingStats::default();
    }
}

impl Default for StreamingHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hls_manifest() {
        let helper = StreamingHelper::new();
        let manifest = "\
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXTINF:9.9,
segment0.ts
#EXTINF:9.9,
segment1.ts
#EXT-X-ENDLIST";

        let segments = helper.parse_hls_manifest(manifest).unwrap();
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].duration, 9.9);
        assert_eq!(segments[0].url, "segment0.ts");
        assert_eq!(segments[1].url, "segment1.ts");
    }

    #[test]
    fn test_parse_hls_master_playlist() {
        let helper = StreamingHelper::new();
        let playlist = "\
#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720
720p.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080
1080p.m3u8";

        let qualities = helper.parse_hls_master_playlist(playlist).unwrap();
        assert_eq!(qualities.len(), 2);
        assert_eq!(qualities[0].bitrate, 2_500_000);
        assert_eq!(qualities[0].width, Some(1280));
        assert_eq!(qualities[0].height, Some(720));
        assert_eq!(qualities[1].bitrate, 5_000_000);
    }

    #[test]
    fn test_select_quality() {
        let helper = StreamingHelper::new();
        let qualities = vec![
            QualityLevel::new("360p", 1_000_000),
            QualityLevel::new("720p", 2_500_000),
            QualityLevel::new("1080p", 5_000_000),
        ];

        // Bandwidth: 3 MB/s -> should select 720p (2.5 MB/s with 20% buffer = 2.4 MB/s required)
        let selected = helper.select_quality(&qualities, 3_000_000).unwrap();
        assert_eq!(selected.id, "720p");

        // Bandwidth: 6 MB/s -> should select 1080p
        let selected = helper.select_quality(&qualities, 6_000_000).unwrap();
        assert_eq!(selected.id, "1080p");

        // Low bandwidth -> should select lowest quality
        let selected = helper.select_quality(&qualities, 500_000).unwrap();
        assert_eq!(selected.id, "360p");
    }

    #[test]
    fn test_get_prefetch_segments() {
        let helper = StreamingHelper::new();
        let segments = vec![
            HlsSegment {
                duration: 10.0,
                url: "seg0.ts".to_string(),
                sequence: 0,
                title: None,
                byte_range: None,
                discontinuity: false,
            },
            HlsSegment {
                duration: 10.0,
                url: "seg1.ts".to_string(),
                sequence: 1,
                title: None,
                byte_range: None,
                discontinuity: false,
            },
            HlsSegment {
                duration: 10.0,
                url: "seg2.ts".to_string(),
                sequence: 2,
                title: None,
                byte_range: None,
                discontinuity: false,
            },
            HlsSegment {
                duration: 10.0,
                url: "seg3.ts".to_string(),
                sequence: 3,
                title: None,
                byte_range: None,
                discontinuity: false,
            },
        ];

        let prefetch = helper.get_prefetch_segments(&segments, 0);
        assert_eq!(prefetch.len(), 3);
        assert_eq!(prefetch[0].url, "seg1.ts");
        assert_eq!(prefetch[2].url, "seg3.ts");
    }

    #[test]
    fn test_url_rewriting() {
        let helper = StreamingHelper::with_base_url("https://cdn.example.com/video");
        let manifest = "\
#EXTM3U
#EXTINF:10.0,
segment0.ts";

        let segments = helper.parse_hls_manifest(manifest).unwrap();
        assert_eq!(segments[0].url, "https://cdn.example.com/video/segment0.ts");
    }

    #[test]
    fn test_generate_hls_manifest() {
        let helper = StreamingHelper::new();
        let segments = vec![
            HlsSegment {
                duration: 10.0,
                url: "seg0.ts".to_string(),
                sequence: 0,
                title: None,
                byte_range: None,
                discontinuity: false,
            },
            HlsSegment {
                duration: 10.0,
                url: "seg1.ts".to_string(),
                sequence: 1,
                title: None,
                byte_range: None,
                discontinuity: false,
            },
        ];

        let manifest = helper.generate_hls_manifest(&segments, 10);
        assert!(manifest.contains("#EXTM3U"));
        assert!(manifest.contains("#EXT-X-TARGETDURATION:10"));
        assert!(manifest.contains("seg0.ts"));
        assert!(manifest.contains("seg1.ts"));
        assert!(manifest.contains("#EXT-X-ENDLIST"));
    }

    #[test]
    fn test_parse_dash_template() {
        let helper = StreamingHelper::new();
        let template = "segment_$Number$.m4s";
        let segments = helper.parse_dash_template(template, 4.0, 3);

        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].url, "segment_0.m4s");
        assert_eq!(segments[1].url, "segment_1.m4s");
        assert_eq!(segments[2].url, "segment_2.m4s");
        assert_eq!(segments[1].start_time, 4.0);
    }

    #[test]
    fn test_quality_switch_tracking() {
        let helper = StreamingHelper::new();
        let qualities = vec![
            QualityLevel::new("720p", 2_500_000),
            QualityLevel::new("1080p", 5_000_000),
        ];

        helper.select_quality(&qualities, 3_000_000);
        helper.select_quality(&qualities, 3_000_000); // No switch
        helper.select_quality(&qualities, 6_000_000); // Switch to 1080p

        let stats = helper.stats();
        assert_eq!(stats.quality_switches, 2); // Initial + 1 switch
    }

    #[test]
    fn test_discontinuity_marker() {
        let helper = StreamingHelper::new();
        let manifest = "\
#EXTM3U
#EXTINF:10.0,
segment0.ts
#EXT-X-DISCONTINUITY
#EXTINF:10.0,
segment1.ts";

        let segments = helper.parse_hls_manifest(manifest).unwrap();
        assert!(!segments[0].discontinuity);
        assert!(segments[1].discontinuity);
    }

    #[test]
    fn test_stats() {
        let helper = StreamingHelper::new();
        let manifest = "\
#EXTM3U
#EXTINF:10.0,
segment0.ts
#EXTINF:10.0,
segment1.ts";

        helper.parse_hls_manifest(manifest);

        let stats = helper.stats();
        assert_eq!(stats.manifests_parsed, 1);
        assert_eq!(stats.hls_manifests, 1);
        assert_eq!(stats.segments_extracted, 2);
        assert_eq!(stats.avg_segment_duration, 10.0);
    }

    #[test]
    fn test_reset_stats() {
        let helper = StreamingHelper::new();
        let manifest = "#EXTM3U\n#EXTINF:10.0,\nsegment0.ts";
        helper.parse_hls_manifest(manifest);

        helper.reset_stats();
        let stats = helper.stats();
        assert_eq!(stats.manifests_parsed, 0);
    }
}
