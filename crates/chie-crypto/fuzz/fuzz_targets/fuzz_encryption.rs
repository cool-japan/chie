//! Fuzzing harness for ChaCha20-Poly1305 encryption

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::{decrypt, encrypt};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key and 12 bytes for nonce
    if data.len() < 44 {
        return;
    }

    let key: [u8; 32] = data[0..32].try_into().unwrap();
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let plaintext = &data[44..];

    // Encrypt
    if let Ok(ciphertext) = encrypt(plaintext, &key, &nonce) {
        // Decrypt and verify roundtrip
        if let Ok(decrypted) = decrypt(&ciphertext, &key, &nonce) {
            // Verify decrypted matches original plaintext
            assert_eq!(&decrypted[..], plaintext);
        }
    }

    // Test with corrupted ciphertext (if we got valid ciphertext)
    if let Ok(mut ciphertext) = encrypt(plaintext, &key, &nonce) {
        if !ciphertext.is_empty() {
            // Flip a bit in the ciphertext
            ciphertext[0] ^= 0x01;
            // Decryption should fail with corrupted data
            let _ = decrypt(&ciphertext, &key, &nonce);
        }
    }
});
