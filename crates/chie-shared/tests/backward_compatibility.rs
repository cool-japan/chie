//! Backward compatibility tests for protocol versioning
//!
//! These tests ensure that newer versions of the protocol can read
//! data serialized by older versions.

use chie_shared::encoding::{BINARY_PROTOCOL_VERSION, BinaryDecoder, BinaryEncoder, MAGIC_BYTES};

#[test]
fn test_protocol_version_1_compatibility() {
    // Simulate old protocol version 1 message
    let mut buf = Vec::new();

    // Write header with version 1
    buf.extend_from_slice(MAGIC_BYTES);
    buf.push(1); // Version 1

    // Verify we can read it
    let mut decoder = BinaryDecoder::new(&buf[..]);
    let version = decoder.read_header().unwrap();
    assert_eq!(version, 1);
}

#[test]
fn test_read_old_format_u32() {
    // Create message with old protocol version
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_BYTES);
    buf.push(1); // Version 1

    // Write some u32 values in little-endian (same as current)
    buf.extend_from_slice(&123u32.to_le_bytes());
    buf.extend_from_slice(&456u32.to_le_bytes());

    // Verify new decoder can read old format
    let mut decoder = BinaryDecoder::new(&buf[..]);
    decoder.read_header().unwrap();
    assert_eq!(decoder.read_u32().unwrap(), 123);
    assert_eq!(decoder.read_u32().unwrap(), 456);
}

#[test]
fn test_read_old_format_string() {
    // Create old format string message
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_BYTES);
    buf.push(1); // Version 1

    // Write string in old format (length prefix + UTF-8 bytes)
    let test_str = "Hello, CHIE v1!";
    buf.extend_from_slice(&(test_str.len() as u32).to_le_bytes());
    buf.extend_from_slice(test_str.as_bytes());

    // Verify new decoder can read old strings
    let mut decoder = BinaryDecoder::new(&buf[..]);
    decoder.read_header().unwrap();
    assert_eq!(decoder.read_string().unwrap(), test_str);
}

#[test]
fn test_reject_future_version() {
    // Create message with future version
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_BYTES);
    buf.push(BINARY_PROTOCOL_VERSION + 1); // Future version

    // Should reject future versions
    let mut decoder = BinaryDecoder::new(&buf[..]);
    let result = decoder.read_header();
    assert!(result.is_err());
}

#[test]
fn test_cross_version_complex_message() {
    // Test a complex message with multiple data types
    let mut old_buf = Vec::new();
    old_buf.extend_from_slice(MAGIC_BYTES);
    old_buf.push(1); // Version 1

    // Write complex data
    old_buf.extend_from_slice(&42u8.to_le_bytes());
    old_buf.extend_from_slice(&12345u32.to_le_bytes());
    old_buf.extend_from_slice(&67890u64.to_le_bytes());
    old_buf.push(1); // true

    let test_str = "test";
    old_buf.extend_from_slice(&(test_str.len() as u32).to_le_bytes());
    old_buf.extend_from_slice(test_str.as_bytes());

    // Read with new decoder
    let mut decoder = BinaryDecoder::new(&old_buf[..]);
    decoder.read_header().unwrap();
    assert_eq!(decoder.read_u8().unwrap(), 42);
    assert_eq!(decoder.read_u32().unwrap(), 12345);
    assert_eq!(decoder.read_u64().unwrap(), 67890);
    assert!(decoder.read_bool().unwrap());
    assert_eq!(decoder.read_string().unwrap(), "test");
}

#[test]
fn test_forward_compatibility_with_unknown_fields() {
    // Test that we can skip unknown fields when reading old messages
    let mut buf = Vec::new();
    let mut encoder = BinaryEncoder::new(&mut buf);
    encoder.write_header().unwrap();

    // Write known fields
    encoder.write_u32(100).unwrap();
    encoder.write_string("known_field").unwrap();

    // Simulate reading with a decoder that only knows about first field
    let mut decoder = BinaryDecoder::new(&buf[..]);
    decoder.read_header().unwrap();
    assert_eq!(decoder.read_u32().unwrap(), 100);

    // Remaining data can be skipped or read as needed
    let remaining = decoder.read_string().unwrap();
    assert_eq!(remaining, "known_field");
}

#[test]
fn test_version_detection() {
    // Test that we can detect and handle different versions
    for version in 1..=BINARY_PROTOCOL_VERSION {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC_BYTES);
        buf.push(version);

        let mut decoder = BinaryDecoder::new(&buf[..]);
        let detected_version = decoder.read_header().unwrap();
        assert_eq!(detected_version, version);
    }
}

#[test]
fn test_magic_bytes_validation() {
    // Test that invalid magic bytes are rejected
    let invalid_magic_variations = vec![b"FAKE", b"CHIX", b"CHI\x00", b"\x00HIE", b"    "];

    for invalid_magic in invalid_magic_variations {
        let mut buf = Vec::new();
        buf.extend_from_slice(invalid_magic);
        buf.push(1);

        let mut decoder = BinaryDecoder::new(&buf[..]);
        assert!(decoder.read_header().is_err());
    }
}

#[test]
fn test_roundtrip_preserves_version() {
    // Test that encoding and decoding preserves version info
    let mut buf = Vec::new();
    let mut encoder = BinaryEncoder::new(&mut buf);
    encoder.write_header().unwrap();
    encoder.write_u32(42).unwrap();

    let mut decoder = BinaryDecoder::new(&buf[..]);
    let version = decoder.read_header().unwrap();
    assert_eq!(version, BINARY_PROTOCOL_VERSION);
    assert_eq!(decoder.version(), BINARY_PROTOCOL_VERSION);
}

#[test]
fn test_version_specific_encoder() {
    // Test creating encoder with specific version
    let mut buf = Vec::new();
    let mut encoder = BinaryEncoder::with_version(&mut buf, 1);
    encoder.write_header().unwrap();

    let mut decoder = BinaryDecoder::new(&buf[..]);
    let version = decoder.read_header().unwrap();
    assert_eq!(version, 1);
}

#[test]
fn test_batch_compatibility() {
    use chie_shared::encoding::{BatchDecoder, BatchEncoder};

    // Test that batch encoding is version-aware
    let strings = vec!["test1", "test2", "test3"];
    let encoded = BatchEncoder::encode_strings(&strings).unwrap();

    // Verify header is present
    assert!(encoded.starts_with(MAGIC_BYTES));
    assert_eq!(encoded[4], BINARY_PROTOCOL_VERSION);

    // Decode and verify
    let decoded = BatchDecoder::decode_strings(&encoded).unwrap();
    assert_eq!(decoded.len(), strings.len());
}
