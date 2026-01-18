//! Onion encryption for privacy-preserving P2P routing.
//!
//! This module provides layered encryption similar to Tor's onion routing,
//! where data is encrypted in multiple layers. Each intermediate node can
//! decrypt only one layer to learn the next hop, preserving privacy.
//!
//! # Example
//!
//! ```
//! use chie_crypto::onion::{OnionBuilder, OnionLayer};
//! use chie_crypto::KeyPair;
//!
//! // Create routing path with 3 hops
//! let hop1 = KeyPair::generate();
//! let hop2 = KeyPair::generate();
//! let hop3 = KeyPair::generate();
//!
//! let data = b"Secret message to route through network";
//!
//! // Build onion with layers
//! let onion = OnionBuilder::new(data)
//!     .add_layer(hop1.public_key())
//!     .add_layer(hop2.public_key())
//!     .add_layer(hop3.public_key())
//!     .build()
//!     .unwrap();
//!
//! // Each hop peels one layer
//! let (layer1, next_onion) = onion.peel_layer(&hop3).unwrap();
//! let (layer2, next_onion) = next_onion.unwrap().peel_layer(&hop2).unwrap();
//! let (layer3, final_packet) = next_onion.unwrap().peel_layer(&hop1).unwrap();
//!
//! // Final packet contains the data
//! assert_eq!(data, final_packet.unwrap().data());
//! ```

use crate::encryption::{decrypt, encrypt};
use crate::signing::{KeyPair, PublicKey};
use blake3;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error types for onion encryption operations.
#[derive(Debug, Error)]
pub enum OnionError {
    #[error("No layers to build onion")]
    NoLayers,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed - invalid key or corrupted data")]
    DecryptionFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid onion structure")]
    InvalidStructure,
}

pub type OnionResult<T> = Result<T, OnionError>;

/// An onion-encrypted packet with multiple layers.
///
/// Each layer is encrypted with a different public key. Only the holder
/// of the corresponding private key can decrypt their layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    /// The encrypted payload (contains either next layer or final data)
    ciphertext: Vec<u8>,
    /// Nonce for this layer's encryption
    nonce: [u8; 12],
    /// Ephemeral public key hint (for key derivation)
    ephemeral_hint: [u8; 32],
}

impl OnionPacket {
    /// Get the ciphertext (for final layer data extraction).
    pub fn data(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> OnionResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| OnionError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> OnionResult<Self> {
        crate::codec::decode(bytes).map_err(|e| OnionError::SerializationError(e.to_string()))
    }

    /// Peel one layer of the onion using the provided keypair.
    ///
    /// Returns a tuple of (layer_info, next_packet_or_data):
    /// - If there are more layers, next_packet_or_data is Some(OnionPacket)
    /// - If this is the last layer, next_packet_or_data is None and the data is returned
    pub fn peel_layer(&self, keypair: &KeyPair) -> OnionResult<(OnionLayer, Option<OnionPacket>)> {
        // Derive decryption key using public key and ephemeral hint
        // This matches the encryption key derivation in build()
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"CHIE-ONION-V1");
        hasher.update(&keypair.public_key());
        hasher.update(&self.ephemeral_hint);
        let decryption_key = *hasher.finalize().as_bytes();

        // Decrypt this layer
        let decrypted = decrypt(&self.ciphertext, &decryption_key, &self.nonce)
            .map_err(|_| OnionError::DecryptionFailed)?;

        // Try to deserialize as OnionLayerPayload
        let payload: OnionLayerPayload =
            crate::codec::decode(&decrypted).map_err(|_| OnionError::InvalidStructure)?;

        match payload {
            OnionLayerPayload::Intermediate {
                next_hop,
                next_packet,
            } => Ok((OnionLayer::Intermediate { next_hop }, Some(next_packet))),
            OnionLayerPayload::Final { data } => Ok((
                OnionLayer::Final,
                Some(OnionPacket {
                    ciphertext: data,
                    nonce: [0; 12],
                    ephemeral_hint: [0; 32],
                }),
            )),
        }
    }
}

/// Information about a peeled onion layer.
#[derive(Debug, Clone)]
pub enum OnionLayer {
    /// Intermediate layer with next hop information
    Intermediate {
        /// Public key of the next hop
        next_hop: PublicKey,
    },
    /// Final layer (contains the actual data)
    Final,
}

/// Internal payload structure for onion layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum OnionLayerPayload {
    /// Intermediate layer pointing to next hop
    Intermediate {
        next_hop: PublicKey,
        next_packet: OnionPacket,
    },
    /// Final layer containing the actual data
    Final { data: Vec<u8> },
}

/// Builder for creating multi-layer onion packets.
pub struct OnionBuilder {
    data: Vec<u8>,
    layers: Vec<PublicKey>,
}

impl OnionBuilder {
    /// Create a new onion builder with the data to encrypt.
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            layers: Vec::new(),
        }
    }

    /// Add a layer to the onion (layers are added from innermost to outermost).
    ///
    /// The first layer added will be the first to decrypt (innermost).
    /// The last layer added will be the last to decrypt (outermost).
    pub fn add_layer(mut self, pubkey: PublicKey) -> Self {
        self.layers.push(pubkey);
        self
    }

    /// Add multiple layers at once.
    pub fn add_layers(mut self, pubkeys: &[PublicKey]) -> Self {
        self.layers.extend_from_slice(pubkeys);
        self
    }

    /// Build the onion packet with all layers.
    pub fn build(self) -> OnionResult<OnionPacket> {
        if self.layers.is_empty() {
            return Err(OnionError::NoLayers);
        }

        // Start with the final payload (the actual data)
        let mut current_payload = OnionLayerPayload::Final { data: self.data };

        // Wrap in layers from inside out
        // We iterate through layers and create encrypted packets
        for (i, pubkey) in self.layers.iter().enumerate() {
            // Serialize current payload
            let payload_bytes = crate::codec::encode(&current_payload)
                .map_err(|e| OnionError::SerializationError(e.to_string()))?;

            // Generate ephemeral hint for key derivation
            let mut ephemeral_hint = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut ephemeral_hint);

            // Derive encryption key for current layer
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"CHIE-ONION-V1");
            hasher.update(pubkey);
            hasher.update(&ephemeral_hint);
            let encryption_key = *hasher.finalize().as_bytes();

            // Generate nonce
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce);

            // Encrypt the payload
            let ciphertext = encrypt(&payload_bytes, &encryption_key, &nonce)
                .map_err(|_| OnionError::EncryptionFailed)?;

            let packet = OnionPacket {
                ciphertext,
                nonce,
                ephemeral_hint,
            };

            // If this is the last (outermost) layer, return the packet
            if i == self.layers.len() - 1 {
                return Ok(packet);
            }

            // Otherwise, wrap this packet for the next layer
            // The next layer should know to forward to the current layer
            current_payload = OnionLayerPayload::Intermediate {
                next_hop: *pubkey,
                next_packet: packet,
            };
        }

        Err(OnionError::InvalidStructure)
    }
}

/// Multi-hop onion route for P2P communication.
pub struct OnionRoute {
    /// The complete routing path (public keys)
    path: Vec<PublicKey>,
}

impl OnionRoute {
    /// Create a new onion route with the specified path.
    pub fn new(path: Vec<PublicKey>) -> Self {
        Self { path }
    }

    /// Get the route length (number of hops).
    pub fn length(&self) -> usize {
        self.path.len()
    }

    /// Get the path of public keys.
    pub fn path(&self) -> &[PublicKey] {
        &self.path
    }

    /// Encrypt data for this route.
    pub fn encrypt(&self, data: &[u8]) -> OnionResult<OnionPacket> {
        let mut builder = OnionBuilder::new(data);
        for pubkey in &self.path {
            builder = builder.add_layer(*pubkey);
        }
        builder.build()
    }
}

/// Create an onion packet with the given data and routing path.
///
/// This is a convenience function that creates an OnionBuilder and builds the packet.
pub fn create_onion(data: &[u8], path: &[PublicKey]) -> OnionResult<OnionPacket> {
    let mut builder = OnionBuilder::new(data);
    for pubkey in path {
        builder = builder.add_layer(*pubkey);
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyPair;

    #[test]
    fn test_onion_single_layer() {
        let data = b"Single layer test";
        let keypair = KeyPair::generate();

        let onion = OnionBuilder::new(data)
            .add_layer(keypair.public_key())
            .build()
            .unwrap();

        let (layer, next) = onion.peel_layer(&keypair).unwrap();
        assert!(matches!(layer, OnionLayer::Final));

        let final_data = next.unwrap();
        assert_eq!(data, &final_data.ciphertext[..]);
    }

    #[test]
    fn test_onion_two_layers() {
        let data = b"Two layer test";
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let onion = OnionBuilder::new(data)
            .add_layer(keypair1.public_key())
            .add_layer(keypair2.public_key())
            .build()
            .unwrap();

        // Peel outer layer (keypair2)
        let (layer1, next1) = onion.peel_layer(&keypair2).unwrap();
        if let OnionLayer::Intermediate { next_hop } = layer1 {
            assert_eq!(next_hop, keypair1.public_key());
        } else {
            panic!("Expected intermediate layer");
        }

        // Peel inner layer (keypair1)
        let onion2 = next1.unwrap();
        let (layer2, final_data) = onion2.peel_layer(&keypair1).unwrap();
        assert!(matches!(layer2, OnionLayer::Final));

        let data_packet = final_data.unwrap();
        assert_eq!(data, &data_packet.ciphertext[..]);
    }

    #[test]
    fn test_onion_three_layers() {
        let data = b"Three layer test message";
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let onion = OnionBuilder::new(data)
            .add_layer(keypair1.public_key())
            .add_layer(keypair2.public_key())
            .add_layer(keypair3.public_key())
            .build()
            .unwrap();

        // Peel layer 3
        let (layer3, next3) = onion.peel_layer(&keypair3).unwrap();
        if let OnionLayer::Intermediate { next_hop } = layer3 {
            assert_eq!(next_hop, keypair2.public_key());
        } else {
            panic!("Expected intermediate layer");
        }

        // Peel layer 2
        let onion2 = next3.unwrap();
        let (layer2, next2) = onion2.peel_layer(&keypair2).unwrap();
        if let OnionLayer::Intermediate { next_hop } = layer2 {
            assert_eq!(next_hop, keypair1.public_key());
        } else {
            panic!("Expected intermediate layer");
        }

        // Peel layer 1
        let onion1 = next2.unwrap();
        let (layer1, final_data) = onion1.peel_layer(&keypair1).unwrap();
        assert!(matches!(layer1, OnionLayer::Final));

        let data_packet = final_data.unwrap();
        assert_eq!(data, &data_packet.ciphertext[..]);
    }

    #[test]
    fn test_onion_wrong_key() {
        let data = b"Test data";
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let wrong_keypair = KeyPair::generate();

        let onion = OnionBuilder::new(data)
            .add_layer(keypair1.public_key())
            .add_layer(keypair2.public_key())
            .build()
            .unwrap();

        // Try to decrypt with wrong key
        let result = onion.peel_layer(&wrong_keypair);
        assert!(matches!(result, Err(OnionError::DecryptionFailed)));
    }

    #[test]
    fn test_onion_no_layers() {
        let data = b"Test";
        let result = OnionBuilder::new(data).build();
        assert!(matches!(result, Err(OnionError::NoLayers)));
    }

    #[test]
    fn test_onion_serialization() {
        let data = b"Serialization test";
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let onion = OnionBuilder::new(data)
            .add_layer(keypair1.public_key())
            .add_layer(keypair2.public_key())
            .build()
            .unwrap();

        // Serialize and deserialize
        let bytes = onion.to_bytes().unwrap();
        let deserialized = OnionPacket::from_bytes(&bytes).unwrap();

        // Verify deserialized onion works
        let (_, next) = deserialized.peel_layer(&keypair2).unwrap();
        let onion2 = next.unwrap();
        let (_, final_data) = onion2.peel_layer(&keypair1).unwrap();

        assert_eq!(data, &final_data.unwrap().ciphertext[..]);
    }

    #[test]
    fn test_onion_route() {
        let data = b"Route test";
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();
        let keypair3 = KeyPair::generate();

        let path = vec![
            keypair1.public_key(),
            keypair2.public_key(),
            keypair3.public_key(),
        ];

        let route = OnionRoute::new(path.clone());
        assert_eq!(route.length(), 3);
        assert_eq!(route.path(), &path[..]);

        let onion = route.encrypt(data).unwrap();

        // Peel all layers
        let (_, next) = onion.peel_layer(&keypair3).unwrap();
        let (_, next) = next.unwrap().peel_layer(&keypair2).unwrap();
        let (_, final_data) = next.unwrap().peel_layer(&keypair1).unwrap();

        assert_eq!(data, &final_data.unwrap().ciphertext[..]);
    }

    #[test]
    fn test_create_onion_convenience() {
        let data = b"Convenience function test";
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let path = vec![keypair1.public_key(), keypair2.public_key()];

        let onion = create_onion(data, &path).unwrap();

        let (_, next) = onion.peel_layer(&keypair2).unwrap();
        let (_, final_data) = next.unwrap().peel_layer(&keypair1).unwrap();

        assert_eq!(data, &final_data.unwrap().ciphertext[..]);
    }

    #[test]
    fn test_large_data() {
        let data = vec![0x42u8; 10_000]; // 10KB
        let keypair1 = KeyPair::generate();
        let keypair2 = KeyPair::generate();

        let onion = OnionBuilder::new(&data)
            .add_layer(keypair1.public_key())
            .add_layer(keypair2.public_key())
            .build()
            .unwrap();

        let (_, next) = onion.peel_layer(&keypair2).unwrap();
        let (_, final_data) = next.unwrap().peel_layer(&keypair1).unwrap();

        assert_eq!(data, final_data.unwrap().ciphertext);
    }

    #[test]
    fn test_add_layers_batch() {
        let data = b"Batch layers test";
        let keypairs: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate()).collect();
        let pubkeys: Vec<PublicKey> = keypairs.iter().map(|kp| kp.public_key()).collect();

        let onion = OnionBuilder::new(data)
            .add_layers(&pubkeys)
            .build()
            .unwrap();

        // Peel all layers
        let mut current = Some(onion);
        for keypair in keypairs.iter().rev() {
            if let Some(pkt) = current {
                let (_, next) = pkt.peel_layer(keypair).unwrap();
                current = next;
            }
        }

        let final_data = current.unwrap();
        assert_eq!(data, &final_data.ciphertext[..]);
    }
}
