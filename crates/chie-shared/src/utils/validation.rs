//! Validation utility functions.

use super::calculations::calculate_bandwidth_mbps;
use super::formatting::sanitize_tag;
use super::time::now_ms;

/// Validate email format (basic check).
///
/// # Examples
///
/// ```
/// use chie_shared::is_valid_email;
///
/// // Valid emails
/// assert!(is_valid_email("user@example.com"));
/// assert!(is_valid_email("test.user@domain.co.uk"));
///
/// // Invalid emails
/// assert!(!is_valid_email("invalid"));
/// assert!(!is_valid_email("@example.com"));
/// assert!(!is_valid_email("user@"));
/// assert!(!is_valid_email("user.example.com")); // Missing @
/// ```
#[inline]
pub fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

/// Validate username (alphanumeric, underscore, hyphen, 3-20 chars).
///
/// # Examples
///
/// ```
/// use chie_shared::is_valid_username;
///
/// // Valid usernames
/// assert!(is_valid_username("alice"));
/// assert!(is_valid_username("bob_123"));
/// assert!(is_valid_username("user-name"));
/// assert!(is_valid_username("test_user_2024"));
///
/// // Invalid usernames
/// assert!(!is_valid_username("ab")); // Too short
/// assert!(!is_valid_username("a".repeat(21).as_str())); // Too long
/// assert!(!is_valid_username("user@name")); // Invalid character
/// assert!(!is_valid_username("user name")); // Spaces not allowed
/// ```
#[inline]
pub fn is_valid_username(username: &str) -> bool {
    if username.len() < 3 || username.len() > 20 {
        return false;
    }

    username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

/// Parse content CID and validate basic format.
///
/// # Examples
///
/// ```
/// use chie_shared::is_valid_cid;
///
/// // Valid CIDs (CIDv0 with Qm prefix)
/// assert!(is_valid_cid("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"));
///
/// // Valid CIDs (CIDv1 with bafy prefix)
/// assert!(is_valid_cid("bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"));
///
/// // Invalid CIDs
/// assert!(!is_valid_cid("invalid"));
/// assert!(!is_valid_cid("Qm123")); // Too short
/// assert!(!is_valid_cid("")); // Empty
/// ```
#[inline]
pub fn is_valid_cid(cid: &str) -> bool {
    // Basic CID validation: should start with 'Qm' or 'bafy' and be alphanumeric
    if cid.is_empty() {
        return false;
    }

    let valid_prefix = cid.starts_with("Qm") || cid.starts_with("bafy") || cid.starts_with("bafk");
    let valid_chars = cid.chars().all(|c| c.is_alphanumeric());

    valid_prefix && valid_chars && cid.len() >= 46
}

/// Check if a peer ID format is valid (basic check).
///
/// # Examples
///
/// ```
/// use chie_shared::is_valid_peer_id;
///
/// // Valid libp2p peer IDs (start with 12D3Koo)
/// assert!(is_valid_peer_id("12D3KooWD3bfmNbuuuM8puncXF4DxDWPTF8vK7X3K8K6z4Q7Q8Qp"));
/// assert!(is_valid_peer_id("12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"));
///
/// // Invalid peer IDs
/// assert!(!is_valid_peer_id("invalid"));
/// assert!(!is_valid_peer_id("Qm123")); // CID, not peer ID
/// assert!(!is_valid_peer_id("12D3Koo")); // Too short
/// ```
#[inline]
pub fn is_valid_peer_id(peer_id: &str) -> bool {
    // libp2p peer IDs typically start with "12D3Koo" and are base58 encoded
    peer_id.starts_with("12D3Koo") && peer_id.len() >= 46
}

/// Check if a string contains only safe characters (no control chars except whitespace).
#[inline]
pub fn is_safe_string(s: &str) -> bool {
    s.chars().all(|c| !c.is_control() || c.is_whitespace())
}

/// Batch validate CIDs and return invalid ones.
pub fn validate_cids_batch(cids: &[String]) -> Vec<String> {
    cids.iter()
        .filter(|cid| !is_valid_cid(cid))
        .cloned()
        .collect()
}

/// Batch validate emails and return invalid ones.
pub fn validate_emails_batch(emails: &[String]) -> Vec<String> {
    emails
        .iter()
        .filter(|email| !is_valid_email(email))
        .cloned()
        .collect()
}

/// Batch validate usernames and return invalid ones.
pub fn validate_usernames_batch(usernames: &[String]) -> Vec<String> {
    usernames
        .iter()
        .filter(|username| !is_valid_username(username))
        .cloned()
        .collect()
}

/// Validate IPv4 address format.
///
/// # Examples
///
/// ```
/// use chie_shared::is_valid_ipv4;
///
/// // Valid IPv4 addresses
/// assert!(is_valid_ipv4("192.168.1.1"));
/// assert!(is_valid_ipv4("10.0.0.1"));
/// assert!(is_valid_ipv4("127.0.0.1"));
/// assert!(is_valid_ipv4("0.0.0.0"));
/// assert!(is_valid_ipv4("255.255.255.255"));
///
/// // Invalid IPv4 addresses
/// assert!(!is_valid_ipv4("256.1.1.1")); // Out of range
/// assert!(!is_valid_ipv4("192.168.1")); // Missing octet
/// assert!(!is_valid_ipv4("192.168.1.1.1")); // Too many octets
/// assert!(!is_valid_ipv4("invalid"));
/// ```
pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    parts.iter().all(|part| part.parse::<u8>().is_ok())
}

/// Validate IPv6 address format (basic check).
pub fn is_valid_ipv6(ip: &str) -> bool {
    // Basic IPv6 validation: contains colons and valid hex characters
    if !ip.contains(':') {
        return false;
    }

    let parts: Vec<&str> = ip.split(':').collect();
    if parts.len() < 3 || parts.len() > 8 {
        return false;
    }

    parts
        .iter()
        .all(|part| part.is_empty() || part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Validate port number.
pub fn is_valid_port(port: u16) -> bool {
    port > 0
}

/// Parse multiaddr and check if it's valid (basic check).
pub fn is_valid_multiaddr(addr: &str) -> bool {
    // libp2p multiaddrs start with / and contain protocol identifiers
    if !addr.starts_with('/') {
        return false;
    }

    let parts: Vec<&str> = addr.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return false;
    }

    // Check for common protocol identifiers
    let valid_protocols = [
        "ip4", "ip6", "tcp", "udp", "quic", "p2p", "ws", "wss", "http", "https",
    ];
    parts.iter().any(|part| valid_protocols.contains(part))
}

/// Validate HTTP/HTTPS URL format.
///
/// # Examples
///
/// ```
/// use chie_shared::is_valid_url;
///
/// // Valid URLs
/// assert!(is_valid_url("https://example.com"));
/// assert!(is_valid_url("http://localhost:8080/api"));
/// assert!(is_valid_url("https://api.example.com/v1/users?id=123"));
///
/// // Invalid URLs
/// assert!(!is_valid_url("ftp://example.com")); // Wrong protocol
/// assert!(!is_valid_url("example.com")); // Missing protocol
/// assert!(!is_valid_url("")); // Empty
/// ```
pub fn is_valid_url(url: &str) -> bool {
    if url.is_empty() || url.len() > 2048 {
        return false;
    }

    url.starts_with("http://") || url.starts_with("https://")
}

/// Verify hex string is valid.
pub fn is_valid_hex(hex: &str) -> bool {
    hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate chunk size is within acceptable range.
pub fn validate_chunk_size(size: usize, min: usize, max: usize) -> bool {
    size >= min && size <= max
}

/// Validate proof timestamp is recent (within tolerance).
pub fn validate_proof_freshness(timestamp_ms: i64, tolerance_ms: i64) -> bool {
    let now = now_ms();
    let age = now - timestamp_ms;
    age >= 0 && age <= tolerance_ms
}

/// Validate latency is within acceptable range.
pub fn validate_latency(latency_ms: u32, max_latency_ms: u32) -> bool {
    latency_ms <= max_latency_ms
}

/// Validate bandwidth is not suspiciously high.
pub fn validate_bandwidth_reasonable(bytes: u64, duration_ms: u64, max_mbps: f64) -> bool {
    if duration_ms == 0 {
        return false;
    }

    let mbps = calculate_bandwidth_mbps(bytes, duration_ms);
    mbps <= max_mbps
}

/// Validate nonce has correct length.
pub fn validate_nonce_length(nonce: &[u8], expected_len: usize) -> bool {
    nonce.len() == expected_len
}

/// Validate signature has correct length.
pub fn validate_signature_length(signature: &[u8], expected_len: usize) -> bool {
    signature.len() == expected_len
}

/// Validate public key has correct length.
pub fn validate_public_key_length(public_key: &[u8], expected_len: usize) -> bool {
    public_key.len() == expected_len
}

/// Validate hash has correct length.
pub fn validate_hash_length(hash: &[u8], expected_len: usize) -> bool {
    hash.len() == expected_len
}

/// Batch validate chunk indices are within bounds.
pub fn validate_chunk_indices_batch(indices: &[u64], max_index: u64) -> Vec<u64> {
    indices
        .iter()
        .filter(|&&idx| idx >= max_index)
        .copied()
        .collect()
}

/// Validate content size is within platform limits.
pub fn validate_content_size_in_range(size: u64, min: u64, max: u64) -> bool {
    size >= min && size <= max
}

/// Validate price is within acceptable range.
pub fn validate_price_range(price: u64, min: u64, max: u64) -> bool {
    price >= min && price <= max
}

/// Sanitize and validate tag.
pub fn validate_and_sanitize_tag(tag: &str, max_len: usize) -> Option<String> {
    let sanitized = sanitize_tag(tag);
    if sanitized.is_empty() || sanitized.len() > max_len {
        None
    } else {
        Some(sanitized)
    }
}

/// Validate all tags in a list and return valid ones.
pub fn validate_tags_list(tags: &[String], max_len: usize, max_count: usize) -> Vec<String> {
    tags.iter()
        .take(max_count)
        .filter_map(|t| validate_and_sanitize_tag(t, max_len))
        .collect()
}

/// Validate Ed25519 signature format (64 bytes).
pub fn validate_ed25519_signature(signature: &[u8]) -> bool {
    validate_signature_length(signature, 64)
}

/// Validate Ed25519 public key format (32 bytes).
pub fn validate_ed25519_public_key(public_key: &[u8]) -> bool {
    validate_public_key_length(public_key, 32)
}

/// Validate BLAKE3 hash format (32 bytes).
pub fn validate_blake3_hash(hash: &[u8]) -> bool {
    validate_hash_length(hash, 32)
}

/// Validate challenge nonce format (32 bytes).
pub fn validate_challenge_nonce(nonce: &[u8]) -> bool {
    validate_nonce_length(nonce, 32)
}

/// Check if an IPv4 address is in a private range.
/// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8.
pub fn is_private_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    let octets: Result<Vec<u8>, _> = parts.iter().map(|s| s.parse()).collect();
    if let Ok(octets) = octets {
        if octets.len() != 4 {
            return false;
        }

        // 10.0.0.0/8
        if octets[0] == 10 {
            return true;
        }

        // 172.16.0.0/12
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return true;
        }

        // 192.168.0.0/16
        if octets[0] == 192 && octets[1] == 168 {
            return true;
        }

        // 127.0.0.0/8 (loopback)
        if octets[0] == 127 {
            return true;
        }

        false
    } else {
        false
    }
}

/// Validate URL-safe string (alphanumeric, dash, underscore)
#[must_use]
#[allow(dead_code)]
pub fn validate_url_safe_string(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Validate that a string is valid JSON
#[must_use]
#[allow(dead_code)]
pub fn validate_json_string(s: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(s).is_ok()
}

/// Validate semantic version format (e.g., "1.2.3", "1.0.0-beta")
#[must_use]
#[allow(dead_code)]
pub fn validate_semver(version: &str) -> bool {
    // Split on dash first to handle prerelease
    let main_prerelease: Vec<&str> = version.splitn(2, '-').collect();
    let main_version = main_prerelease[0];

    // Validate major.minor.patch
    let parts: Vec<&str> = main_version.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // All parts must be numbers
    if !parts
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }

    // If there's a prerelease part, validate it
    if main_prerelease.len() > 1 {
        let prerelease = main_prerelease[1];
        !prerelease.is_empty()
            && prerelease
                .chars()
                .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    } else {
        true
    }
}

/// Validate UUID v4 format
#[must_use]
#[allow(dead_code)]
pub fn validate_uuid_v4(uuid: &str) -> bool {
    if uuid.len() != 36 {
        return false;
    }

    let parts: Vec<&str> = uuid.split('-').collect();
    if parts.len() != 5 {
        return false;
    }

    // Check lengths: 8-4-4-4-12
    if parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return false;
    }

    // Verify version 4 (3rd section should start with 4)
    if !parts[2].starts_with('4') {
        return false;
    }

    // All parts should be valid hex
    parts
        .iter()
        .all(|part| part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Validate hex color code (#RGB or #RRGGBB)
#[must_use]
#[allow(dead_code)]
pub fn validate_hex_color(color: &str) -> bool {
    if !color.starts_with('#') {
        return false;
    }

    let hex = &color[1..];
    (hex.len() == 3 || hex.len() == 6) && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate port number is in valid range (1-65535)
#[must_use]
#[allow(dead_code)]
pub fn validate_port_range(port: u16) -> bool {
    port > 0
}

/// Validate Content-Type/MIME type format
#[must_use]
#[allow(dead_code)]
pub fn validate_content_type(content_type: &str) -> bool {
    let parts: Vec<&str> = content_type.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let type_valid = !parts[0].is_empty()
        && parts[0]
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '+');

    let subtype = parts[1].split(';').next().unwrap_or("");
    let subtype_valid = !subtype.is_empty()
        && subtype
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '+' || c == '.');

    type_valid && subtype_valid
}

/// Validate that a string contains only printable ASCII characters
#[must_use]
#[allow(dead_code)]
pub fn validate_printable_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii() && !c.is_ascii_control())
}

/// Validate base64 string format
#[must_use]
#[allow(dead_code)]
pub fn validate_base64(s: &str) -> bool {
    if s.is_empty() || s.len() % 4 != 0 {
        return false;
    }

    let bytes = s.as_bytes();
    let len = bytes.len();

    for (i, &byte) in bytes.iter().enumerate() {
        let c = byte as char;
        if c == '=' {
            // '=' can only be at the last or second-to-last position
            if i != len - 1 && i != len - 2 {
                return false;
            }
            // If second-to-last is '=', last must also be '='
            if i == len - 2 && bytes[len - 1] != b'=' {
                return false;
            }
        } else if !c.is_alphanumeric() && c != '+' && c != '/' {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user+tag@domain.co.jp"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("test@"));
        assert!(!is_valid_email("test@com"));
    }

    #[test]
    fn test_is_valid_username() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("alice_123"));
        assert!(is_valid_username("alice-bob"));
        assert!(!is_valid_username("ab"));
        assert!(!is_valid_username(&"a".repeat(21)));
        assert!(!is_valid_username("alice bob"));
        assert!(!is_valid_username("alice@bob"));
    }

    #[test]
    fn test_is_valid_cid() {
        assert!(is_valid_cid(
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        ));
        assert!(is_valid_cid(
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        ));
        assert!(!is_valid_cid("invalid"));
        assert!(!is_valid_cid(""));
        assert!(!is_valid_cid("Qm"));
    }

    #[test]
    fn test_is_valid_peer_id() {
        assert!(is_valid_peer_id(
            "12D3KooWRQTwRLgXZfYJnAL8fCF7VBvPgPDJxz3cBdJq9BvZT8bT"
        ));
        assert!(!is_valid_peer_id("invalid"));
        assert!(!is_valid_peer_id("12D3Koo"));
    }

    #[test]
    fn test_is_safe_string() {
        assert!(is_safe_string("hello world"));
        assert!(is_safe_string("hello\nworld"));
        assert!(is_safe_string("hello\tworld"));
        assert!(!is_safe_string("hello\x00world"));
        assert!(!is_safe_string("hello\x01world"));
    }

    #[test]
    fn test_validate_cids_batch() {
        let cids = vec![
            "QmValidCID1234567890123456789012345678901234567890".to_string(),
            "invalid".to_string(),
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
            "".to_string(),
        ];
        let invalid = validate_cids_batch(&cids);
        assert_eq!(invalid.len(), 2);
        assert!(invalid.contains(&"invalid".to_string()));
        assert!(invalid.contains(&"".to_string()));
    }

    #[test]
    fn test_validate_emails_batch() {
        let emails = vec![
            "valid@example.com".to_string(),
            "invalid".to_string(),
            "another@test.org".to_string(),
            "@invalid.com".to_string(),
        ];
        let invalid = validate_emails_batch(&emails);
        assert_eq!(invalid.len(), 2);
    }

    #[test]
    fn test_validate_usernames_batch() {
        let usernames = vec![
            "validuser123".to_string(),
            "ab".to_string(), // too short
            "user_name".to_string(),
            "a".repeat(25), // too long
        ];
        let invalid = validate_usernames_batch(&usernames);
        assert_eq!(invalid.len(), 2);
    }

    #[test]
    fn test_is_valid_ipv4() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("127.0.0.1"));
        assert!(is_valid_ipv4("255.255.255.255"));
        assert!(!is_valid_ipv4("256.1.1.1"));
        assert!(!is_valid_ipv4("192.168.1"));
        assert!(!is_valid_ipv4("192.168.1.1.1"));
        assert!(!is_valid_ipv4("not.an.ip.addr"));
    }

    #[test]
    fn test_is_valid_ipv6() {
        assert!(is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(is_valid_ipv6("2001:db8::1"));
        assert!(is_valid_ipv6("::1"));
        assert!(!is_valid_ipv6("192.168.1.1"));
        assert!(!is_valid_ipv6("not:valid:ipv6:xyz"));
        assert!(!is_valid_ipv6(""));
    }

    #[test]
    fn test_is_valid_port() {
        assert!(is_valid_port(80));
        assert!(is_valid_port(443));
        assert!(is_valid_port(65535));
        assert!(!is_valid_port(0));
    }

    #[test]
    fn test_is_valid_multiaddr() {
        assert!(is_valid_multiaddr("/ip4/127.0.0.1/tcp/4001"));
        assert!(is_valid_multiaddr("/ip6/::1/tcp/4001"));
        assert!(is_valid_multiaddr("/ip4/192.168.1.1/tcp/8080/ws"));
        assert!(!is_valid_multiaddr("invalid"));
        assert!(!is_valid_multiaddr(""));
        assert!(!is_valid_multiaddr("/invalid/address"));
    }

    #[test]
    fn test_is_valid_url() {
        assert!(is_valid_url("https://example.com"));
        assert!(is_valid_url("http://example.com"));
        assert!(is_valid_url("https://example.com/path?query=value"));
        assert!(!is_valid_url("ftp://example.com"));
        assert!(!is_valid_url(""));
        assert!(!is_valid_url("not a url"));
        // Test URL that's too long (> 2048 chars)
        let long_url = format!("https://{}", "a".repeat(3000));
        assert!(!is_valid_url(&long_url));
    }

    #[test]
    fn test_is_valid_hex() {
        assert!(is_valid_hex("deadbeef"));
        assert!(is_valid_hex("0123456789abcdef"));
        assert!(is_valid_hex(""));
        assert!(!is_valid_hex("abc")); // Odd length
        assert!(!is_valid_hex("xyz")); // Invalid characters
    }

    #[test]
    fn test_validate_chunk_size() {
        assert!(validate_chunk_size(1024, 512, 2048));
        assert!(!validate_chunk_size(256, 512, 2048));
        assert!(!validate_chunk_size(4096, 512, 2048));
    }

    #[test]
    fn test_validate_proof_freshness() {
        let now = now_ms();
        assert!(validate_proof_freshness(now, 5000));
        assert!(validate_proof_freshness(now - 1000, 5000));
        assert!(!validate_proof_freshness(now - 10000, 5000));
        assert!(!validate_proof_freshness(now + 1000, 5000));
    }

    #[test]
    fn test_validate_latency() {
        assert!(validate_latency(100, 500));
        assert!(validate_latency(500, 500));
        assert!(!validate_latency(501, 500));
    }

    #[test]
    fn test_validate_bandwidth_reasonable() {
        // 100 MB in 10 seconds = 80 Mbps (reasonable)
        assert!(validate_bandwidth_reasonable(100_000_000, 10_000, 1000.0));

        // 10 GB in 1 second = 80 Gbps (unreasonable for 1000 Mbps limit)
        assert!(!validate_bandwidth_reasonable(
            10_000_000_000,
            1_000,
            1000.0
        ));

        // Zero duration should fail
        assert!(!validate_bandwidth_reasonable(1000, 0, 1000.0));
    }

    #[test]
    fn test_validate_nonce_length() {
        assert!(validate_nonce_length(&[0u8; 32], 32));
        assert!(!validate_nonce_length(&[0u8; 16], 32));
        assert!(!validate_nonce_length(&[0u8; 64], 32));
    }

    #[test]
    fn test_validate_signature_length() {
        assert!(validate_signature_length(&[0u8; 64], 64));
        assert!(!validate_signature_length(&[0u8; 32], 64));
    }

    #[test]
    fn test_validate_public_key_length() {
        assert!(validate_public_key_length(&[0u8; 32], 32));
        assert!(!validate_public_key_length(&[0u8; 64], 32));
    }

    #[test]
    fn test_validate_hash_length() {
        assert!(validate_hash_length(&[0u8; 32], 32));
        assert!(!validate_hash_length(&[0u8; 16], 32));
    }

    #[test]
    fn test_validate_chunk_indices_batch() {
        let indices = vec![0, 1, 5, 10, 15];
        let invalid = validate_chunk_indices_batch(&indices, 10);
        assert_eq!(invalid, vec![10, 15]);

        let all_valid = validate_chunk_indices_batch(&indices, 20);
        assert!(all_valid.is_empty());
    }

    #[test]
    fn test_validate_content_size_in_range() {
        assert!(validate_content_size_in_range(1024, 512, 2048));
        assert!(validate_content_size_in_range(512, 512, 2048));
        assert!(validate_content_size_in_range(2048, 512, 2048));
        assert!(!validate_content_size_in_range(256, 512, 2048));
        assert!(!validate_content_size_in_range(4096, 512, 2048));
    }

    #[test]
    fn test_validate_price_range() {
        assert!(validate_price_range(100, 1, 1000));
        assert!(!validate_price_range(0, 1, 1000));
        assert!(!validate_price_range(1001, 1, 1000));
    }

    #[test]
    fn test_validate_and_sanitize_tag() {
        assert_eq!(
            validate_and_sanitize_tag("  Rust  ", 20),
            Some("rust".to_string())
        );
        assert_eq!(validate_and_sanitize_tag("  ", 20), None);
        assert_eq!(validate_and_sanitize_tag("verylongtagname", 10), None);
    }

    #[test]
    fn test_validate_tags_list() {
        let tags = vec![
            "Rust".to_string(),
            "  Python  ".to_string(),
            "  ".to_string(),
            "JavaScript".to_string(),
            "Go".to_string(),
        ];

        // Empty tag gets filtered out, so we get 4 valid tags
        // but with max_count=3, we take first 3 and filter
        let valid = validate_tags_list(&tags, 20, 3);
        // First 3 are Rust, Python, empty (filtered), so we get rust, python
        // Then we check next item which is JavaScript
        // Actually, the function takes first 3 items then filters, so:
        // Rust -> rust, Python -> python, empty -> None, so we get ["rust", "python"]
        assert_eq!(valid, vec!["rust", "python"]);

        let limited = validate_tags_list(&tags, 20, 2);
        assert_eq!(limited.len(), 2);
    }

    #[test]
    fn test_validate_ed25519_signature() {
        assert!(validate_ed25519_signature(&[0u8; 64]));
        assert!(!validate_ed25519_signature(&[0u8; 32]));
    }

    #[test]
    fn test_validate_ed25519_public_key() {
        assert!(validate_ed25519_public_key(&[0u8; 32]));
        assert!(!validate_ed25519_public_key(&[0u8; 64]));
    }

    #[test]
    fn test_validate_blake3_hash() {
        assert!(validate_blake3_hash(&[0u8; 32]));
        assert!(!validate_blake3_hash(&[0u8; 16]));
    }

    #[test]
    fn test_validate_challenge_nonce() {
        assert!(validate_challenge_nonce(&[0u8; 32]));
        assert!(!validate_challenge_nonce(&[0u8; 16]));
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4("10.0.0.1"));
        assert!(is_private_ipv4("10.255.255.255"));
        assert!(is_private_ipv4("172.16.0.1"));
        assert!(is_private_ipv4("172.31.255.255"));
        assert!(is_private_ipv4("192.168.1.1"));
        assert!(is_private_ipv4("192.168.255.255"));
        assert!(is_private_ipv4("127.0.0.1"));
        assert!(!is_private_ipv4("8.8.8.8"));
        assert!(!is_private_ipv4("1.2.3.4"));
        assert!(!is_private_ipv4("172.15.0.1")); // Not in 172.16.0.0/12
        assert!(!is_private_ipv4("172.32.0.1")); // Not in 172.16.0.0/12
        assert!(!is_private_ipv4("invalid"));
    }

    // New validation helper tests
    #[test]
    fn test_validate_url_safe_string() {
        assert!(validate_url_safe_string("hello-world_123"));
        assert!(validate_url_safe_string("test_slug"));
        assert!(validate_url_safe_string("abc-123"));
        assert!(!validate_url_safe_string(""));
        assert!(!validate_url_safe_string("hello world")); // Space
        assert!(!validate_url_safe_string("test@example")); // Special char
    }

    #[test]
    fn test_validate_json_string() {
        assert!(validate_json_string(r#"{"key": "value"}"#));
        assert!(validate_json_string(r"[1, 2, 3]"));
        assert!(validate_json_string(r"null"));
        assert!(validate_json_string(r"true"));
        assert!(validate_json_string(r"42"));
        assert!(!validate_json_string(r"{invalid}"));
        assert!(!validate_json_string(r"not json"));
    }

    #[test]
    fn test_validate_semver() {
        assert!(validate_semver("1.0.0"));
        assert!(validate_semver("1.2.3"));
        assert!(validate_semver("0.0.1"));
        assert!(validate_semver("1.0.0-beta"));
        assert!(validate_semver("2.1.3-alpha.1"));
        assert!(!validate_semver("1.0")); // Missing patch
        assert!(!validate_semver("1.0.0.0")); // Extra version
        assert!(!validate_semver("a.b.c")); // Not numbers
        assert!(!validate_semver("1.2.")); // Empty patch
    }

    #[test]
    fn test_validate_uuid_v4() {
        assert!(validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000"));
        assert!(validate_uuid_v4("f47ac10b-58cc-4372-a567-0e02b2c3d479"));
        assert!(!validate_uuid_v4("550e8400-e29b-31d4-a716-446655440000")); // Not v4
        assert!(!validate_uuid_v4("550e8400-e29b-41d4-a716")); // Too short
        assert!(!validate_uuid_v4("not-a-uuid"));
        assert!(!validate_uuid_v4("550e8400e29b41d4a716446655440000")); // No dashes
    }

    #[test]
    fn test_validate_hex_color() {
        assert!(validate_hex_color("#FFF"));
        assert!(validate_hex_color("#fff"));
        assert!(validate_hex_color("#FFFFFF"));
        assert!(validate_hex_color("#123abc"));
        assert!(!validate_hex_color("FFF")); // No #
        assert!(!validate_hex_color("#FF")); // Too short
        assert!(!validate_hex_color("#FFFFFFF")); // Too long
        assert!(!validate_hex_color("#GGG")); // Invalid hex
    }

    #[test]
    fn test_validate_port_range() {
        assert!(validate_port_range(1));
        assert!(validate_port_range(80));
        assert!(validate_port_range(8080));
        assert!(validate_port_range(65535));
        assert!(!validate_port_range(0));
    }

    #[test]
    fn test_validate_content_type() {
        assert!(validate_content_type("text/plain"));
        assert!(validate_content_type("application/json"));
        assert!(validate_content_type("image/png"));
        assert!(validate_content_type("text/html; charset=utf-8"));
        assert!(validate_content_type("application/vnd.api+json"));
        assert!(!validate_content_type("invalid"));
        assert!(!validate_content_type("/json")); // No type
        assert!(!validate_content_type("text/")); // No subtype
    }

    #[test]
    fn test_validate_printable_ascii() {
        assert!(validate_printable_ascii("Hello World 123"));
        assert!(validate_printable_ascii("test@example.com"));
        assert!(!validate_printable_ascii("hello\nworld")); // Newline
        assert!(!validate_printable_ascii("test\0null")); // Null byte
        assert!(!validate_printable_ascii("hello\tworld")); // Tab
    }

    #[test]
    fn test_validate_base64() {
        assert!(validate_base64("SGVsbG8=")); // "Hello" in base64
        assert!(validate_base64("YWJjMTIz")); // "abc123" in base64
        assert!(validate_base64("dGVzdA==")); // "test" in base64
        assert!(!validate_base64("invalid!")); // Invalid char
        assert!(!validate_base64("abc")); // Wrong length (not multiple of 4)
        assert!(!validate_base64("ab=c")); // = in wrong position
    }
}
