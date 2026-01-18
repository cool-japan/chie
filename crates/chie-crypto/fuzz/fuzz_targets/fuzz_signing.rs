//! Fuzzing harness for Ed25519 signing and verification

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::KeyPair;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for secret key
    if data.len() < 32 {
        return;
    }

    let secret_key: [u8; 32] = data[0..32].try_into().unwrap();
    let message = &data[32..];

    // Create keypair from secret
    if let Ok(keypair) = KeyPair::from_secret_key(&secret_key) {
        // Sign the message
        let signature = keypair.sign(message);

        // Verify signature
        assert!(keypair.verify(message, &signature));

        // Verify signature with wrong message should fail
        let wrong_message = b"different message";
        if message != wrong_message {
            assert!(!keypair.verify(wrong_message, &signature));
        }

        // Test with corrupted signature
        let mut corrupted_sig = signature;
        if !corrupted_sig.is_empty() {
            corrupted_sig[0] ^= 0x01;
            assert!(!keypair.verify(message, &corrupted_sig));
        }
    }
});
