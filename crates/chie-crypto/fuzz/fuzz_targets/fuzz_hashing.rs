//! Fuzzing harness for BLAKE3 hashing

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::hash;

fuzz_target!(|data: &[u8]| {
    // Hash the input
    let hash1 = hash(data);

    // Hash again with same input - should produce same output
    let hash2 = hash(data);
    assert_eq!(hash1, hash2);

    // Hash output should always be 32 bytes
    assert_eq!(hash1.len(), 32);

    // Different input should (almost certainly) produce different hash
    if !data.is_empty() {
        let mut modified = data.to_vec();
        modified[0] ^= 0x01;
        let hash3 = hash(&modified);
        // With overwhelming probability, hashes should differ
        if data.len() > 1 || data[0] != 0x01 {
            assert_ne!(hash1, hash3);
        }
    }
});
