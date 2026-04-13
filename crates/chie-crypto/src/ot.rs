//! Oblivious Transfer for private information retrieval.
//!
//! This module implements a 1-out-of-N oblivious transfer protocol where:
//! - A sender has N items (messages)
//! - A receiver wants to retrieve one of the N items by index
//! - The sender doesn't learn which item was chosen
//! - The receiver doesn't learn anything about the other items
//!
//! # Use Cases for CHIE Protocol
//! - Private P2P content discovery (receiver queries without revealing interest)
//! - Privacy-preserving content catalog browsing
//! - Anonymous chunk retrieval from peers
//! - Private database queries in distributed systems
//!
//! # Protocol Overview
//! 1. Receiver generates keypairs for each possible choice
//! 2. Receiver encrypts the chosen index's public key, randomizes others
//! 3. Sender encrypts each message with corresponding receiver public key
//! 4. Receiver can only decrypt the chosen message
//!
//! # Example
//! ```
//! use chie_crypto::ot::*;
//!
//! // Sender has 3 items
//! let items = vec![
//!     b"Item 0".to_vec(),
//!     b"Item 1".to_vec(),
//!     b"Item 2".to_vec(),
//! ];
//!
//! // Receiver wants item at index 1
//! let receiver = OTReceiver::new(items.len(), 1).unwrap();
//! let request = receiver.create_request();
//!
//! // Sender responds
//! let sender = OTSender::new();
//! let response = sender.respond(&request, &items).unwrap();
//!
//! // Receiver retrieves only the chosen item
//! let retrieved = receiver.retrieve(&response).unwrap();
//! assert_eq!(retrieved, b"Item 1");
//! ```

use blake3::Hasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};

/// Errors that can occur during oblivious transfer operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OTError {
    /// Invalid choice index
    InvalidChoice,
    /// Invalid number of items
    InvalidItemCount,
    /// Invalid request format
    InvalidRequest,
    /// Invalid response format
    InvalidResponse,
    /// Decryption failed
    DecryptionFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Invalid public key
    InvalidPublicKey,
    /// Mismatched item count
    MismatchedItemCount,
}

impl std::fmt::Display for OTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OTError::InvalidChoice => write!(f, "Invalid choice index"),
            OTError::InvalidItemCount => write!(f, "Invalid number of items"),
            OTError::InvalidRequest => write!(f, "Invalid request format"),
            OTError::InvalidResponse => write!(f, "Invalid response format"),
            OTError::DecryptionFailed => write!(f, "Decryption failed"),
            OTError::EncryptionFailed => write!(f, "Encryption failed"),
            OTError::InvalidPublicKey => write!(f, "Invalid public key"),
            OTError::MismatchedItemCount => write!(f, "Mismatched item count"),
        }
    }
}

impl std::error::Error for OTError {}

/// Result type for oblivious transfer operations.
pub type OTResult<T> = Result<T, OTError>;

/// Oblivious transfer request from receiver.
#[derive(Clone, Serialize, Deserialize)]
pub struct OTRequest {
    /// Public keys for each possible choice (one real, others random)
    pub_keys: Vec<CompressedRistretto>,
}

/// Oblivious transfer response from sender.
#[derive(Clone, Serialize, Deserialize)]
pub struct OTResponse {
    /// Encrypted items (one for each public key)
    encrypted_items: Vec<EncryptedItem>,
}

/// Encrypted item in oblivious transfer.
#[derive(Clone, Serialize, Deserialize)]
struct EncryptedItem {
    /// Ephemeral public key for this encryption
    ephemeral_pk: CompressedRistretto,
    /// Encrypted data
    ciphertext: Vec<u8>,
    /// Nonce for encryption
    nonce: [u8; 12],
}

/// Receiver in oblivious transfer protocol.
pub struct OTReceiver {
    /// Number of items to choose from
    n_items: usize,
    /// Index of chosen item
    choice: usize,
    /// Secret key for the chosen item
    chosen_sk: Scalar,
    /// Public keys sent to sender
    pub_keys: Vec<CompressedRistretto>,
}

impl OTReceiver {
    /// Create a new receiver choosing item at given index.
    ///
    /// # Arguments
    /// * `n_items` - Total number of items sender has
    /// * `choice` - Index of item to retrieve (0-based)
    pub fn new(n_items: usize, choice: usize) -> OTResult<Self> {
        if n_items == 0 {
            return Err(OTError::InvalidItemCount);
        }
        if choice >= n_items {
            return Err(OTError::InvalidChoice);
        }

        let mut rng = rand::rng();
        let mut pub_keys = Vec::with_capacity(n_items);

        // Generate secret key for chosen item
        let mut sk_bytes = [0u8; 32];
        rng.fill(&mut sk_bytes);
        let chosen_sk = Scalar::from_bytes_mod_order(sk_bytes);
        let chosen_pk = &chosen_sk * RISTRETTO_BASEPOINT_TABLE;

        // Generate public keys for all items
        for i in 0..n_items {
            if i == choice {
                // Use the real public key for chosen item
                pub_keys.push(chosen_pk.compress());
            } else {
                // Generate random points for other items
                let mut random_bytes = [0u8; 32];
                rng.fill(&mut random_bytes);
                let random_sk = Scalar::from_bytes_mod_order(random_bytes);
                let random_pk = &random_sk * RISTRETTO_BASEPOINT_TABLE;
                pub_keys.push(random_pk.compress());
            }
        }

        Ok(Self {
            n_items,
            choice,
            chosen_sk,
            pub_keys,
        })
    }

    /// Create the oblivious transfer request to send to the sender.
    pub fn create_request(&self) -> OTRequest {
        OTRequest {
            pub_keys: self.pub_keys.clone(),
        }
    }

    /// Retrieve the chosen item from the sender's response.
    pub fn retrieve(&self, response: &OTResponse) -> OTResult<Vec<u8>> {
        if response.encrypted_items.len() != self.n_items {
            return Err(OTError::MismatchedItemCount);
        }

        let item = &response.encrypted_items[self.choice];

        // Decompress ephemeral public key
        let ephemeral_pk = item
            .ephemeral_pk
            .decompress()
            .ok_or(OTError::InvalidPublicKey)?;

        // Compute shared secret: chosen_sk * ephemeral_pk
        let shared_point = ephemeral_pk * self.chosen_sk;

        // Derive symmetric key
        let sym_key = derive_ot_key(&shared_point);

        // Decrypt
        let cipher = ChaCha20Poly1305::new(&sym_key.into());
        let nonce = Nonce::from_slice(&item.nonce);

        cipher
            .decrypt(nonce, item.ciphertext.as_ref())
            .map_err(|_| OTError::DecryptionFailed)
    }

    /// Get the choice index.
    pub fn choice(&self) -> usize {
        self.choice
    }

    /// Get the number of items.
    pub fn n_items(&self) -> usize {
        self.n_items
    }
}

/// Sender in oblivious transfer protocol.
pub struct OTSender;

impl OTSender {
    /// Create a new sender.
    pub fn new() -> Self {
        Self
    }

    /// Respond to a receiver's request by encrypting all items.
    ///
    /// # Arguments
    /// * `request` - The receiver's OT request
    /// * `items` - All items (must match the number of public keys in request)
    pub fn respond(&self, request: &OTRequest, items: &[Vec<u8>]) -> OTResult<OTResponse> {
        if items.len() != request.pub_keys.len() {
            return Err(OTError::MismatchedItemCount);
        }
        if items.is_empty() {
            return Err(OTError::InvalidItemCount);
        }

        let mut rng = rand::rng();
        let mut encrypted_items = Vec::with_capacity(items.len());

        // Encrypt each item with corresponding public key
        for (item, pk_compressed) in items.iter().zip(&request.pub_keys) {
            // Decompress public key
            let pk = pk_compressed
                .decompress()
                .ok_or(OTError::InvalidPublicKey)?;

            // Generate ephemeral keypair
            let mut ephemeral_sk_bytes = [0u8; 32];
            rng.fill(&mut ephemeral_sk_bytes);
            let ephemeral_sk = Scalar::from_bytes_mod_order(ephemeral_sk_bytes);
            let ephemeral_pk = &ephemeral_sk * RISTRETTO_BASEPOINT_TABLE;

            // Compute shared secret: ephemeral_sk * receiver_pk
            let shared_point = pk * ephemeral_sk;

            // Derive symmetric key
            let sym_key = derive_ot_key(&shared_point);

            // Generate nonce
            let mut nonce_bytes = [0u8; 12];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Encrypt item
            let cipher = ChaCha20Poly1305::new(&sym_key.into());
            let ciphertext = cipher
                .encrypt(nonce, item.as_ref())
                .map_err(|_| OTError::EncryptionFailed)?;

            encrypted_items.push(EncryptedItem {
                ephemeral_pk: ephemeral_pk.compress(),
                ciphertext,
                nonce: nonce_bytes,
            });
        }

        Ok(OTResponse { encrypted_items })
    }
}

impl Default for OTSender {
    fn default() -> Self {
        Self::new()
    }
}

/// Derive a symmetric key from a shared point for OT encryption.
fn derive_ot_key(point: &RistrettoPoint) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"chie-ot-v1");
    hasher.update(&point.compress().to_bytes());
    let hash = hasher.finalize();
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ot_1_of_2() {
        let items = vec![b"First item".to_vec(), b"Second item".to_vec()];

        // Receiver chooses index 0
        let receiver = OTReceiver::new(2, 0).unwrap();
        let request = receiver.create_request();

        // Sender responds
        let sender = OTSender::new();
        let response = sender.respond(&request, &items).unwrap();

        // Receiver retrieves
        let retrieved = receiver.retrieve(&response).unwrap();
        assert_eq!(retrieved, items[0]);
    }

    #[test]
    fn test_basic_ot_1_of_3() {
        let items = vec![b"Item 0".to_vec(), b"Item 1".to_vec(), b"Item 2".to_vec()];

        // Receiver chooses index 1
        let receiver = OTReceiver::new(3, 1).unwrap();
        let request = receiver.create_request();

        // Sender responds
        let sender = OTSender::new();
        let response = sender.respond(&request, &items).unwrap();

        // Receiver retrieves
        let retrieved = receiver.retrieve(&response).unwrap();
        assert_eq!(retrieved, items[1]);
    }

    #[test]
    fn test_ot_all_choices() {
        let items = vec![
            b"Alpha".to_vec(),
            b"Beta".to_vec(),
            b"Gamma".to_vec(),
            b"Delta".to_vec(),
        ];

        // Test retrieving each item
        for choice in 0..items.len() {
            let receiver = OTReceiver::new(items.len(), choice).unwrap();
            let request = receiver.create_request();

            let sender = OTSender::new();
            let response = sender.respond(&request, &items).unwrap();

            let retrieved = receiver.retrieve(&response).unwrap();
            assert_eq!(retrieved, items[choice]);
        }
    }

    #[test]
    fn test_invalid_choice() {
        assert!(OTReceiver::new(3, 3).is_err());
        assert!(OTReceiver::new(3, 100).is_err());
    }

    #[test]
    fn test_invalid_item_count() {
        assert!(OTReceiver::new(0, 0).is_err());
    }

    #[test]
    fn test_mismatched_item_count() {
        let items = vec![b"Item 1".to_vec(), b"Item 2".to_vec()];
        let receiver = OTReceiver::new(3, 0).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        assert!(sender.respond(&request, &items).is_err());
    }

    #[test]
    fn test_empty_items() {
        let items: Vec<Vec<u8>> = vec![];
        let receiver = OTReceiver::new(1, 0).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        assert!(sender.respond(&request, &items).is_err());
    }

    #[test]
    fn test_large_items() {
        let items = vec![vec![1u8; 10_000], vec![2u8; 10_000]];

        let receiver = OTReceiver::new(2, 1).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        let response = sender.respond(&request, &items).unwrap();

        let retrieved = receiver.retrieve(&response).unwrap();
        assert_eq!(retrieved, items[1]);
    }

    #[test]
    fn test_empty_item_content() {
        let items = vec![b"".to_vec(), b"Non-empty".to_vec()];

        let receiver = OTReceiver::new(2, 0).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        let response = sender.respond(&request, &items).unwrap();

        let retrieved = receiver.retrieve(&response).unwrap();
        assert_eq!(retrieved, items[0]);
    }

    #[test]
    fn test_request_serialization() {
        let receiver = OTReceiver::new(3, 1).unwrap();
        let request = receiver.create_request();

        let serialized = crate::codec::encode(&request).unwrap();
        let deserialized: OTRequest = crate::codec::decode(&serialized).unwrap();

        assert_eq!(request.pub_keys.len(), deserialized.pub_keys.len());
        for (a, b) in request.pub_keys.iter().zip(&deserialized.pub_keys) {
            assert_eq!(a.to_bytes(), b.to_bytes());
        }
    }

    #[test]
    fn test_response_serialization() {
        let items = vec![b"Item 1".to_vec(), b"Item 2".to_vec()];
        let receiver = OTReceiver::new(2, 0).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        let response = sender.respond(&request, &items).unwrap();

        let serialized = crate::codec::encode(&response).unwrap();
        let deserialized: OTResponse = crate::codec::decode(&serialized).unwrap();

        let retrieved = receiver.retrieve(&deserialized).unwrap();
        assert_eq!(retrieved, items[0]);
    }

    #[test]
    fn test_receiver_properties() {
        let receiver = OTReceiver::new(5, 2).unwrap();
        assert_eq!(receiver.choice(), 2);
        assert_eq!(receiver.n_items(), 5);
    }

    #[test]
    fn test_multiple_receivers_same_items() {
        let items = vec![
            b"Content A".to_vec(),
            b"Content B".to_vec(),
            b"Content C".to_vec(),
        ];

        // Multiple receivers with different choices
        let receiver1 = OTReceiver::new(3, 0).unwrap();
        let receiver2 = OTReceiver::new(3, 2).unwrap();

        let request1 = receiver1.create_request();
        let request2 = receiver2.create_request();

        let sender = OTSender::new();
        let response1 = sender.respond(&request1, &items).unwrap();
        let response2 = sender.respond(&request2, &items).unwrap();

        let retrieved1 = receiver1.retrieve(&response1).unwrap();
        let retrieved2 = receiver2.retrieve(&response2).unwrap();

        assert_eq!(retrieved1, items[0]);
        assert_eq!(retrieved2, items[2]);
    }

    #[test]
    fn test_wrong_response_to_receiver() {
        let items1 = vec![b"Set 1 - Item A".to_vec(), b"Set 1 - Item B".to_vec()];
        let items2 = vec![b"Set 2 - Item X".to_vec(), b"Set 2 - Item Y".to_vec()];

        let receiver = OTReceiver::new(2, 0).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        let response1 = sender.respond(&request, &items1).unwrap();
        let _response2 = sender.respond(&request, &items2).unwrap();

        // Correct response should work
        let retrieved = receiver.retrieve(&response1).unwrap();
        assert_eq!(retrieved, items1[0]);
    }

    #[test]
    fn test_1_of_10() {
        let items: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("Item {}", i).into_bytes())
            .collect();

        let receiver = OTReceiver::new(10, 7).unwrap();
        let request = receiver.create_request();

        let sender = OTSender::new();
        let response = sender.respond(&request, &items).unwrap();

        let retrieved = receiver.retrieve(&response).unwrap();
        assert_eq!(retrieved, items[7]);
    }
}
