//! Network and peer utility functions.

/// Extract the peer ID from a libp2p multiaddress string.
/// Example: "/ip4/127.0.0.1/tcp/4001/p2p/QmPeerId" -> "QmPeerId"
///
/// # Examples
///
/// ```
/// use chie_shared::extract_peer_id_from_multiaddr;
///
/// // Extract peer ID from multiaddr with p2p protocol
/// let addr = "/ip4/127.0.0.1/tcp/4001/p2p/QmPeerId123";
/// assert_eq!(
///     extract_peer_id_from_multiaddr(addr),
///     Some("QmPeerId123".to_string())
/// );
///
/// // Extract peer ID from multiaddr with ipfs protocol
/// let addr = "/ip4/192.168.1.1/tcp/4001/ipfs/12D3KooTest";
/// assert_eq!(
///     extract_peer_id_from_multiaddr(addr),
///     Some("12D3KooTest".to_string())
/// );
///
/// // No peer ID in multiaddr
/// let addr = "/ip4/127.0.0.1/tcp/4001";
/// assert_eq!(extract_peer_id_from_multiaddr(addr), None);
/// ```
#[must_use]
pub fn extract_peer_id_from_multiaddr(multiaddr: &str) -> Option<String> {
    multiaddr
        .split('/')
        .skip_while(|&s| s != "p2p" && s != "ipfs")
        .nth(1)
        .map(ToString::to_string)
}

/// Validate peer ID format (basic check for IPFS/libp2p peer IDs).
/// Checks if it starts with common prefixes and has reasonable length.
#[must_use]
pub fn is_valid_peer_id_format(peer_id: &str) -> bool {
    if peer_id.is_empty() {
        return false;
    }

    // Common peer ID prefixes
    let valid_prefix = peer_id.starts_with("Qm")  // CIDv0
        || peer_id.starts_with("12D3")            // CIDv1 base58btc
        || peer_id.starts_with("bafz"); // CIDv1 base32

    // Reasonable length (peer IDs are typically 40-60 characters)
    let valid_length = (30..=100).contains(&peer_id.len());

    valid_prefix && valid_length && peer_id.chars().all(|c| c.is_alphanumeric())
}

/// Parse bandwidth from string (e.g., "100 Mbps", "1 Gbps").
///
/// # Examples
///
/// ```
/// use chie_shared::parse_bandwidth_str;
///
/// // Parse different bandwidth units
/// assert_eq!(parse_bandwidth_str("100 bps"), Some(100));
/// assert_eq!(parse_bandwidth_str("10 Kbps"), Some(10_000));
/// assert_eq!(parse_bandwidth_str("100 Mbps"), Some(100_000_000));
/// assert_eq!(parse_bandwidth_str("1 Gbps"), Some(1_000_000_000));
///
/// // Case insensitive
/// assert_eq!(parse_bandwidth_str("50 MBPS"), Some(50_000_000));
///
/// // Invalid formats
/// assert_eq!(parse_bandwidth_str("invalid"), None);
/// assert_eq!(parse_bandwidth_str("100"), None); // Missing unit
/// ```
pub fn parse_bandwidth_str(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() != 2 {
        return None;
    }

    let value: f64 = parts[0].parse().ok()?;
    let multiplier = match parts[1] {
        "bps" => 1.0,
        "kbps" => 1_000.0,
        "mbps" => 1_000_000.0,
        "gbps" => 1_000_000_000.0,
        _ => return None,
    };

    Some((value * multiplier) as u64)
}

/// Generate a human-readable session ID.
pub fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Split a vector into chunks of specified size.
/// Returns a vector of vectors, where each inner vector has at most `chunk_size` elements.
pub fn chunk_vec<T: Clone>(items: &[T], chunk_size: usize) -> Vec<Vec<T>> {
    if chunk_size == 0 {
        return vec![];
    }

    items
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_peer_id_from_multiaddr() {
        assert_eq!(
            extract_peer_id_from_multiaddr("/ip4/127.0.0.1/tcp/4001/p2p/QmPeerId"),
            Some("QmPeerId".to_string())
        );
        assert_eq!(
            extract_peer_id_from_multiaddr("/ip4/192.168.1.1/tcp/4001/ipfs/QmTest123"),
            Some("QmTest123".to_string())
        );
        assert_eq!(
            extract_peer_id_from_multiaddr("/ip4/127.0.0.1/tcp/4001"),
            None
        );
        assert_eq!(
            extract_peer_id_from_multiaddr("/p2p/QmSimple"),
            Some("QmSimple".to_string())
        );
    }

    #[test]
    fn test_is_valid_peer_id_format() {
        // Valid CIDv0
        assert!(is_valid_peer_id_format(
            "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N"
        ));

        // Valid CIDv1 base58btc
        assert!(is_valid_peer_id_format(
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        ));

        // Valid CIDv1 base32
        assert!(is_valid_peer_id_format(
            "bafzbeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        ));

        // Invalid - wrong prefix
        assert!(!is_valid_peer_id_format(
            "Xm1234567890123456789012345678901234567890"
        ));

        // Invalid - too short
        assert!(!is_valid_peer_id_format("QmShort"));

        // Invalid - empty
        assert!(!is_valid_peer_id_format(""));

        // Invalid - non-alphanumeric
        assert!(!is_valid_peer_id_format(
            "Qm12345678901234567890123456789012345678-invalid"
        ));
    }

    #[test]
    fn test_parse_bandwidth_str() {
        assert_eq!(parse_bandwidth_str("100 bps"), Some(100));
        assert_eq!(parse_bandwidth_str("10 Kbps"), Some(10_000));
        assert_eq!(parse_bandwidth_str("100 Mbps"), Some(100_000_000));
        assert_eq!(parse_bandwidth_str("1 Gbps"), Some(1_000_000_000));
        assert_eq!(parse_bandwidth_str("invalid"), None);
        assert_eq!(parse_bandwidth_str("100"), None);
    }

    #[test]
    fn test_generate_session_id() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2);
        assert!(uuid::Uuid::parse_str(&id1).is_ok());
    }

    #[test]
    fn test_chunk_vec() {
        let items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let chunks = chunk_vec(&items, 3);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![1, 2, 3]);
        assert_eq!(chunks[1], vec![4, 5, 6]);
        assert_eq!(chunks[2], vec![7, 8, 9]);

        let chunks = chunk_vec(&items, 4);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], vec![1, 2, 3, 4]);
        assert_eq!(chunks[1], vec![5, 6, 7, 8]);
        assert_eq!(chunks[2], vec![9]);

        let chunks = chunk_vec(&items, 0);
        assert_eq!(chunks.len(), 0);

        let empty: Vec<i32> = vec![];
        let chunks = chunk_vec(&empty, 3);
        assert_eq!(chunks.len(), 0);
    }
}
