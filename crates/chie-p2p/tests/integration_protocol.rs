//! Integration tests for protocol versioning and negotiation.

use chie_p2p::{
    CURRENT_VERSION, MIN_SUPPORTED_VERSION, NodeCapabilities, ProtocolVersion, VersionNegotiator,
    VersionRequest,
};

#[test]
fn test_version_parsing() {
    let versions = vec![
        ("1.0.0", (1, 0, 0)),
        ("1.2.3", (1, 2, 3)),
        ("2.0.0", (2, 0, 0)),
        ("10.20.30", (10, 20, 30)),
    ];

    for (version_str, (major, minor, patch)) in versions {
        let version = ProtocolVersion::parse(version_str).unwrap();
        assert_eq!(version.major, major);
        assert_eq!(version.minor, minor);
        assert_eq!(version.patch, patch);
    }
}

#[test]
fn test_version_comparison() {
    let v1 = ProtocolVersion::new(1, 0, 0);
    let v2 = ProtocolVersion::new(2, 0, 0);
    let v1_1 = ProtocolVersion::new(1, 1, 0);

    assert!(v1 < v2);
    assert!(v1 < v1_1);
    assert!(v1_1 < v2);
    assert!(v2 > v1);
}

#[test]
fn test_version_compatibility() {
    let v1_0 = ProtocolVersion::new(1, 0, 0);
    let v1_5 = ProtocolVersion::new(1, 5, 0);
    let v2_0 = ProtocolVersion::new(2, 0, 0);

    // Same major version, v1_5 >= v1_0
    assert!(v1_5.is_compatible_with(&v1_0));

    // Different major version
    assert!(!v2_0.is_compatible_with(&v1_0));
    assert!(!v1_0.is_compatible_with(&v2_0));

    // Can't be compatible with higher version in same major
    assert!(!v1_0.is_compatible_with(&v1_5));
}

#[test]
fn test_version_communication() {
    let v1_0 = ProtocolVersion::new(1, 0, 0);
    let v1_5 = ProtocolVersion::new(1, 5, 0);
    let v2_0 = ProtocolVersion::new(2, 0, 0);

    // Same major version
    assert!(v1_5.can_communicate_with(&v1_0));
    assert!(v1_0.can_communicate_with(&v1_5));

    // Different major version
    assert!(!v2_0.can_communicate_with(&v1_0));
    assert!(!v1_0.can_communicate_with(&v2_0));
}

#[test]
fn test_version_negotiation() {
    let negotiator = VersionNegotiator::new();
    let request = VersionRequest {
        supported_versions: vec![ProtocolVersion::new(1, 0, 0)],
        current_version: CURRENT_VERSION,
        capabilities: NodeCapabilities::full(),
    };

    let response = negotiator.handle_request(&request);
    assert!(response.success, "Negotiation should succeed");
    assert!(response.selected_version.is_some());
}

#[test]
fn test_capability_compatibility() {
    let caps1 = NodeCapabilities {
        streaming: true,
        compression: true,
        encryption: true,
        relay: true,
        max_chunk_size: 1024 * 1024,
        encryption_algorithms: vec!["chacha20-poly1305".to_string()],
    };

    let caps2 = NodeCapabilities {
        streaming: true,
        compression: false,
        encryption: true,
        relay: true,
        max_chunk_size: 512 * 1024,
        encryption_algorithms: vec!["chacha20-poly1305".to_string()],
    };

    assert!(caps1.is_compatible_with(&caps2));
    assert!(caps2.is_compatible_with(&caps1));

    let common = caps1.common_with(&caps2);
    assert!(common.streaming);
    assert!(!common.compression); // Only one supports it
    assert_eq!(common.max_chunk_size, 512 * 1024); // Min of both
}

#[test]
fn test_incompatible_encryption() {
    let caps1 = NodeCapabilities {
        streaming: true,
        compression: true,
        encryption: true,
        relay: true,
        max_chunk_size: 1024 * 1024,
        encryption_algorithms: vec!["chacha20-poly1305".to_string()],
    };

    let caps2 = NodeCapabilities {
        streaming: true,
        compression: true,
        encryption: true,
        relay: true,
        max_chunk_size: 1024 * 1024,
        encryption_algorithms: vec!["aes-256-gcm".to_string()], // Different algorithm
    };

    // Not compatible because no common encryption algorithms
    assert!(!caps1.is_compatible_with(&caps2));
    assert!(!caps2.is_compatible_with(&caps1));
}

#[test]
fn test_no_encryption_incompatible() {
    let caps1 = NodeCapabilities {
        streaming: true,
        compression: true,
        encryption: false, // No encryption
        relay: true,
        max_chunk_size: 1024 * 1024,
        encryption_algorithms: vec![],
    };

    let caps2 = NodeCapabilities::full();

    // Not compatible because caps1 doesn't support encryption
    assert!(!caps1.is_compatible_with(&caps2));
    assert!(!caps2.is_compatible_with(&caps1));
}

#[test]
fn test_protocol_string() {
    let version = ProtocolVersion::new(1, 2, 3);
    let protocol_str = version.protocol_string();
    assert_eq!(protocol_str, "/chie/bandwidth-proof/1.2.3");
}

#[test]
fn test_version_display() {
    let version = ProtocolVersion::new(1, 2, 3);
    let display = format!("{}", version);
    assert_eq!(display, "1.2.3");
}

#[test]
fn test_version_parsing_errors() {
    assert!(ProtocolVersion::parse("1.2").is_err());
    assert!(ProtocolVersion::parse("1.2.3.4").is_err());
    assert!(ProtocolVersion::parse("a.b.c").is_err());
    assert!(ProtocolVersion::parse("1.2.x").is_err());
    assert!(ProtocolVersion::parse("").is_err());
}

#[test]
fn test_version_ordering() {
    let mut versions = [
        ProtocolVersion::new(1, 5, 0),
        ProtocolVersion::new(1, 0, 0),
        ProtocolVersion::new(2, 0, 0),
        ProtocolVersion::new(1, 2, 3),
    ];

    versions.sort();

    assert_eq!(versions[0], ProtocolVersion::new(1, 0, 0));
    assert_eq!(versions[1], ProtocolVersion::new(1, 2, 3));
    assert_eq!(versions[2], ProtocolVersion::new(1, 5, 0));
    assert_eq!(versions[3], ProtocolVersion::new(2, 0, 0));
}

#[test]
fn test_negotiator_with_custom_versions() {
    let versions = vec![
        ProtocolVersion::new(1, 0, 0),
        ProtocolVersion::new(1, 5, 0),
        ProtocolVersion::new(2, 0, 0),
    ];

    let negotiator = VersionNegotiator::with_versions(versions);
    let request = negotiator.create_request();

    assert_eq!(request.supported_versions.len(), 3);
    assert_eq!(request.current_version, CURRENT_VERSION);
}

#[test]
fn test_negotiator_with_capabilities() {
    let caps = NodeCapabilities {
        streaming: true,
        compression: false,
        encryption: true,
        relay: false,
        max_chunk_size: 512 * 1024,
        encryption_algorithms: vec!["chacha20-poly1305".to_string()],
    };

    let negotiator = VersionNegotiator::new().with_capabilities(caps.clone());
    let request = negotiator.create_request();

    assert_eq!(request.capabilities.streaming, caps.streaming);
    assert_eq!(request.capabilities.compression, caps.compression);
    assert_eq!(request.capabilities.max_chunk_size, caps.max_chunk_size);
}

#[test]
fn test_concurrent_negotiations() {
    use std::thread;

    let handles: Vec<_> = (0..10)
        .map(|_| {
            thread::spawn(|| {
                let negotiator = VersionNegotiator::new();
                let request = VersionRequest {
                    supported_versions: vec![CURRENT_VERSION],
                    current_version: CURRENT_VERSION,
                    capabilities: NodeCapabilities::full(),
                };

                let response = negotiator.handle_request(&request);
                assert!(response.success);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_version_constants() {
    // Verify that CURRENT_VERSION >= MIN_SUPPORTED_VERSION
    assert!(CURRENT_VERSION >= MIN_SUPPORTED_VERSION);

    // Verify that they have the same major version
    assert_eq!(CURRENT_VERSION.major, MIN_SUPPORTED_VERSION.major);
}

#[test]
fn test_capabilities_full() {
    let caps = NodeCapabilities::full();

    assert!(caps.streaming);
    assert!(caps.compression);
    assert!(caps.encryption);
    assert!(caps.relay);
    assert!(caps.max_chunk_size > 0);
    assert!(!caps.encryption_algorithms.is_empty());
}

#[test]
fn test_capabilities_default() {
    let caps = NodeCapabilities::default();

    assert!(!caps.streaming);
    assert!(!caps.compression);
    assert!(!caps.encryption);
    assert!(!caps.relay);
    assert_eq!(caps.max_chunk_size, 0);
    assert!(caps.encryption_algorithms.is_empty());
}

#[test]
fn test_common_capabilities_empty() {
    let caps1 = NodeCapabilities::default();
    let caps2 = NodeCapabilities::full();

    let common = caps1.common_with(&caps2);

    assert!(!common.streaming);
    assert!(!common.compression);
    assert!(!common.encryption);
    assert!(!common.relay);
    assert_eq!(common.max_chunk_size, 0);
    assert!(common.encryption_algorithms.is_empty());
}
