//! Formatting and sanitization utility functions.

use crate::Points;

/// Format bytes as human-readable string (KB, MB, GB, TB).
///
/// # Examples
///
/// ```
/// use chie_shared::format_bytes;
///
/// assert_eq!(format_bytes(500), "500 B");
/// assert_eq!(format_bytes(1024), "1.00 KB");
/// assert_eq!(format_bytes(1_048_576), "1.00 MB");
/// assert_eq!(format_bytes(1_073_741_824), "1.00 GB");
/// assert_eq!(format_bytes(1_099_511_627_776), "1.00 TB");
///
/// // Partial units
/// assert_eq!(format_bytes(1536), "1.50 KB");
/// assert_eq!(format_bytes(2_621_440), "2.50 MB");
/// ```
#[inline]
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format duration in milliseconds as human-readable string.
///
/// # Examples
///
/// ```
/// use chie_shared::format_duration_ms;
///
/// assert_eq!(format_duration_ms(500), "500 ms");
/// assert_eq!(format_duration_ms(1_000), "1.0 seconds");
/// assert_eq!(format_duration_ms(60_000), "1.0 minutes");
/// assert_eq!(format_duration_ms(3_600_000), "1.0 hours");
/// assert_eq!(format_duration_ms(86_400_000), "1.0 days");
///
/// // Partial units
/// assert_eq!(format_duration_ms(1_500), "1.5 seconds");
/// assert_eq!(format_duration_ms(90_000), "1.5 minutes");
/// ```
#[inline]
#[must_use]
pub fn format_duration_ms(ms: u64) -> String {
    const SEC: u64 = 1000;
    const MIN: u64 = SEC * 60;
    const HOUR: u64 = MIN * 60;
    const DAY: u64 = HOUR * 24;

    if ms >= DAY {
        format!("{:.1} days", ms as f64 / DAY as f64)
    } else if ms >= HOUR {
        format!("{:.1} hours", ms as f64 / HOUR as f64)
    } else if ms >= MIN {
        format!("{:.1} minutes", ms as f64 / MIN as f64)
    } else if ms >= SEC {
        format!("{:.1} seconds", ms as f64 / SEC as f64)
    } else {
        format!("{} ms", ms)
    }
}

/// Truncate a string to a maximum length, adding "..." if truncated.
#[inline]
#[must_use]
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut truncated = s
            .chars()
            .take(max_len.saturating_sub(3))
            .collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

/// Sanitize a tag by trimming whitespace and converting to lowercase.
#[inline]
#[must_use]
pub fn sanitize_tag(tag: &str) -> String {
    tag.trim().to_lowercase()
}

/// Validate and sanitize a list of tags.
#[must_use]
pub fn sanitize_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|t| sanitize_tag(t))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Format points with thousands separator.
#[inline]
#[must_use]
pub fn format_points(points: Points) -> String {
    let s = points.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Sanitize string for display (remove control characters).
#[inline]
#[must_use]
pub fn sanitize_string(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .collect()
}

/// Normalize tag for search/comparison.
pub fn normalize_tag(tag: &str) -> String {
    tag.trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// Format bandwidth as string.
pub fn format_bandwidth(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.2} Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.2} Mbps", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.2} Kbps", bps as f64 / 1_000.0)
    } else {
        format!("{} bps", bps)
    }
}

/// Format a ratio as a percentage string.
pub fn format_ratio_as_percentage(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "N/A".to_string();
    }
    format!("{:.2}%", (numerator as f64 / denominator as f64) * 100.0)
}

/// Generate URL-friendly slug from a string.
/// Converts to lowercase, replaces spaces/special chars with hyphens, removes consecutive hyphens.
pub fn generate_slug(text: &str, max_len: usize) -> String {
    let mut slug = text
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c
            } else if c.is_whitespace() || c == '_' || c == '-' {
                '-'
            } else {
                '\0' // Mark for removal
            }
        })
        .filter(|&c| c != '\0')
        .collect::<String>();

    // Remove consecutive hyphens
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }

    // Trim hyphens from ends
    slug = slug.trim_matches('-').to_string();

    // Truncate if needed
    if slug.len() > max_len {
        slug.truncate(max_len);
        slug = slug.trim_end_matches('-').to_string();
    }

    slug
}

/// Generate a short identifier (8 chars) from a CID for display purposes.
/// Takes first 8 characters after "Qm" prefix if present, otherwise first 8 chars.
pub fn cid_to_short_id(cid: &str) -> String {
    if cid.starts_with("Qm") && cid.len() > 10 {
        cid[2..10].to_string()
    } else if cid.len() >= 8 {
        cid[..8].to_string()
    } else {
        cid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(format_bytes(1024_u64 * 1024 * 1024 * 1024), "1.00 TB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration_ms(500), "500 ms");
        assert_eq!(format_duration_ms(1000), "1.0 seconds");
        assert_eq!(format_duration_ms(60_000), "1.0 minutes");
        assert_eq!(format_duration_ms(3_600_000), "1.0 hours");
        assert_eq!(format_duration_ms(86_400_000), "1.0 days");
    }

    #[test]
    fn test_truncate_string() {
        assert_eq!(truncate_string("hello", 10), "hello");
        assert_eq!(truncate_string("hello world", 8), "hello...");
        assert_eq!(truncate_string("hi", 5), "hi");
    }

    #[test]
    fn test_sanitize_tag() {
        assert_eq!(sanitize_tag("  Hello World  "), "hello world");
        assert_eq!(sanitize_tag("Rust"), "rust");
    }

    #[test]
    fn test_sanitize_tags() {
        let tags = vec![
            "  Rust  ".to_string(),
            "GAME".to_string(),
            "  ".to_string(),
            "3D".to_string(),
        ];
        let sanitized = sanitize_tags(&tags);
        assert_eq!(sanitized, vec!["rust", "game", "3d"]);
    }

    #[test]
    fn test_format_points() {
        assert_eq!(format_points(0), "0");
        assert_eq!(format_points(999), "999");
        assert_eq!(format_points(1000), "1,000");
        assert_eq!(format_points(1_000_000), "1,000,000");
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("hello world"), "hello world");
        assert_eq!(sanitize_string("hello\nworld"), "hello\nworld");
        assert_eq!(sanitize_string("hello\x00world"), "helloworld");
    }

    #[test]
    fn test_normalize_tag() {
        assert_eq!(normalize_tag("  Hello World  "), "helloworld");
        assert_eq!(normalize_tag("Rust-2024"), "rust-2024");
        assert_eq!(normalize_tag("Tag_Name"), "tag_name");
        assert_eq!(normalize_tag("Tag@#$Name"), "tagname");
    }

    #[test]
    fn test_format_bandwidth() {
        assert_eq!(format_bandwidth(500), "500 bps");
        assert_eq!(format_bandwidth(10_000), "10.00 Kbps");
        assert_eq!(format_bandwidth(10_000_000), "10.00 Mbps");
        assert_eq!(format_bandwidth(1_000_000_000), "1.00 Gbps");
    }

    #[test]
    fn test_format_ratio_as_percentage() {
        assert_eq!(format_ratio_as_percentage(1, 4), "25.00%");
        assert_eq!(format_ratio_as_percentage(3, 4), "75.00%");
        assert_eq!(format_ratio_as_percentage(5, 0), "N/A");
    }

    #[test]
    fn test_generate_slug() {
        assert_eq!(generate_slug("Hello World", 100), "hello-world");
        assert_eq!(generate_slug("Rust Programming!", 100), "rust-programming");
        assert_eq!(
            generate_slug("Test_With_Underscores", 100),
            "test-with-underscores"
        );
        assert_eq!(generate_slug("  Trim   Spaces  ", 100), "trim-spaces");
        assert_eq!(
            generate_slug("Remove@Special#Chars$", 100),
            "removespecialchars"
        );
        assert_eq!(generate_slug("Multiple---Hyphens", 100), "multiple-hyphens");
        assert_eq!(
            generate_slug("Very Long Title That Exceeds Maximum Length", 20),
            "very-long-title-that"
        );
        assert_eq!(
            generate_slug("---Leading-Trailing---", 100),
            "leading-trailing"
        );
    }

    #[test]
    fn test_cid_to_short_id() {
        assert_eq!(cid_to_short_id("QmExampleCID123456"), "ExampleC");
        assert_eq!(cid_to_short_id("bafybeigdyrzt"), "bafybeig");
        assert_eq!(cid_to_short_id("short"), "short");
        assert_eq!(cid_to_short_id("QmTest"), "QmTest");
    }
}
