//! Fuzzing harness for X25519 key exchange

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::{KeyExchange, KeyExchangeKeypair};

fuzz_target!(|data: &[u8]| {
    // Need at least 64 bytes for two secret keys
    if data.len() < 64 {
        return;
    }

    let secret_a: [u8; 32] = data[0..32].try_into().unwrap();
    let secret_b: [u8; 32] = data[32..64].try_into().unwrap();

    // Create keypairs from secrets
    let keypair_a = KeyExchangeKeypair::from_bytes(secret_a);
    let keypair_b = KeyExchangeKeypair::from_bytes(secret_b);

    // Perform key exchange
    let shared_ab = keypair_a.exchange(keypair_b.public_key());
    let shared_ba = keypair_b.exchange(keypair_a.public_key());

    // Shared secrets should match (symmetric)
    assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());

    // Shared secret should be 32 bytes
    assert_eq!(shared_ab.as_bytes().len(), 32);

    // Same secret with itself should work
    let shared_aa = keypair_a.exchange(keypair_a.public_key());
    assert_eq!(shared_aa.as_bytes().len(), 32);
});
