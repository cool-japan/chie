//! Fuzzing harness for Pedersen commitments

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::pedersen;

fuzz_target!(|data: &[u8]| {
    // Need at least 8 bytes for a u64 value
    if data.len() < 8 {
        return;
    }

    let value = u64::from_le_bytes(data[0..8].try_into().unwrap());

    // Create commitment
    let (commitment, opening) = pedersen::commit(value);

    // Verify commitment
    assert!(pedersen::verify(&commitment, value, &opening));

    // Wrong value should fail
    if value != value.wrapping_add(1) {
        assert!(!pedersen::verify(&commitment, value.wrapping_add(1), &opening));
    }

    // Test homomorphic property if we have enough data
    if data.len() >= 16 {
        let value2 = u64::from_le_bytes(data[8..16].try_into().unwrap());

        // Skip if addition would overflow
        if let Some(sum) = value.checked_add(value2) {
            let (commitment2, opening2) = pedersen::commit(value2);

            // Add commitments
            let commitment_sum = commitment.add(&commitment2);
            let opening_sum = opening.add(&opening2);

            // Verify sum commitment
            assert!(pedersen::verify(&commitment_sum, sum, &opening_sum));
        }
    }
});
