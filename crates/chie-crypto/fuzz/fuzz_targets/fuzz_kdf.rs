//! Fuzzing harness for HKDF key derivation

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::KeyDerivation;

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte for IKM
    if data.is_empty() {
        return;
    }

    // Split input into IKM, salt, and info
    let split_point_1 = data.len() / 3;
    let split_point_2 = 2 * data.len() / 3;

    let ikm = &data[..split_point_1.max(1)];
    let salt = if split_point_2 > split_point_1 {
        Some(&data[split_point_1..split_point_2])
    } else {
        None
    };
    let info = &data[split_point_2..];

    // Create KDF
    let kdf = KeyDerivation::new(ikm, salt);

    // Derive keys of various lengths
    for length in [16, 32, 64, 128] {
        if let Ok(okm1) = kdf.derive_bytes(info, length) {
            assert_eq!(okm1.len(), length);

            // Derive again with same parameters - should be deterministic
            if let Ok(okm2) = kdf.derive_bytes(info, length) {
                assert_eq!(okm1, okm2);
            }

            // Different info should produce different output
            let different_info = b"different";
            if info != different_info {
                if let Ok(okm3) = kdf.derive_bytes(different_info, length) {
                    // Should be different (with overwhelming probability)
                    assert_ne!(okm1, okm3);
                }
            }
        }
    }
});
