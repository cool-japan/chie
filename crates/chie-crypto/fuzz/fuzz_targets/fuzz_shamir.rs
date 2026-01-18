//! Fuzzing harness for Shamir Secret Sharing

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::{reconstruct_key_32, split_key_32};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for secret
    if data.len() < 32 {
        return;
    }

    let secret: [u8; 32] = data[0..32].try_into().unwrap();

    // Test various threshold configurations
    for (threshold, num_shares) in [(2, 3), (3, 5), (5, 10)] {
        if let Ok(shares) = split_key_32(&secret, threshold, num_shares) {
            assert_eq!(shares.len(), num_shares);

            // Reconstruct with threshold shares
            if let Ok(reconstructed) = reconstruct_key_32(&shares[0..threshold]) {
                assert_eq!(reconstructed, secret);
            }

            // Reconstruct with all shares
            if let Ok(reconstructed_all) = reconstruct_key_32(&shares) {
                assert_eq!(reconstructed_all, secret);
            }

            // Test with different subsets
            if threshold > 1 && num_shares >= threshold {
                let subset = &shares[1..=threshold];
                if let Ok(reconstructed_subset) = reconstruct_key_32(subset) {
                    assert_eq!(reconstructed_subset, secret);
                }
            }
        }
    }
});
