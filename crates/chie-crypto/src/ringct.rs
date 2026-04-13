//! Ring Confidential Transactions (Ring CT)
//!
//! Combines ring signatures with confidential transactions to provide:
//! - Sender anonymity (via ring signatures)
//! - Amount confidentiality (via Pedersen commitments)
//! - Balance verification without revealing amounts
//!
//! Perfect for privacy-preserving bandwidth credit transfers in CHIE protocol.
//!
//! ## Important Note on Blinding Factors
//!
//! For Ring CT transactions to verify correctly, the blinding factors must balance:
//! `sum(input_blindings) = sum(output_blindings) + fee_blinding`
//!
//! Since fee uses zero blinding, this simplifies to:
//! `sum(input_blindings) = sum(output_blindings)`
//!
//! In production, transaction builders should calculate the last output's blinding
//! factor to ensure this balance.
//!
//! ## Implementation Notes
//!
//! - **Blinding Factor Balance**: Helper methods (`add_output_auto_balance`, `rebalance_last_output`,
//!   `calculate_last_output_blinding`) are provided to automatically balance blinding factors,
//!   ensuring transactions verify correctly.
//!
//! - **Decoy Support**: Full support for public key decoys via `add_decoys` and `add_decoy` methods.
//!   In production, use real public keys from the blockchain for actual anonymity.
//!
//! - **Range Proofs**: Not currently implemented due to API limitations in the bulletproof module.
//!   They will be added when bulletproofs support custom blinding factors. Without range proofs,
//!   the system cannot prevent negative outputs, which is a security concern for production use.

use crate::pedersen::{PedersenCommitment, PedersenOpening, commit_with_blinding};
use crate::ring::{RingSignature, sign_ring, verify_ring};
use crate::{KeyPair, PublicKey};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

/// Errors that can occur in Ring CT operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingCtError {
    /// Invalid ring signature
    InvalidRingSignature,
    /// Transaction is not balanced (inputs != outputs)
    UnbalancedTransaction,
    /// Invalid commitment
    InvalidCommitment,
    /// Empty inputs or outputs
    EmptyTransaction,
    /// Serialization error
    SerializationError,
}

pub type RingCtResult<T> = Result<T, RingCtError>;

/// A Ring CT transaction with hidden amounts and anonymous sender
///
/// Ring CT provides:
/// - Sender anonymity via ring signatures
/// - Amount confidentiality via Pedersen commitments
/// - Transaction validity via balance checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingCtTransaction {
    /// Commitments to input amounts: C_in = v*H + r*G
    pub input_commitments: Vec<PedersenCommitment>,
    /// Commitments to output amounts: C_out = v*H + r*G
    pub output_commitments: Vec<PedersenCommitment>,
    /// Ring signature proving ownership of one input without revealing which
    pub ring_signature: RingSignature,
    /// The ring of public keys used for the signature
    pub ring: Vec<PublicKey>,
    /// Transaction fee commitment (can be zero)
    pub fee_commitment: PedersenCommitment,
}

/// Transaction input with secret opening
#[derive(Debug, Clone)]
pub struct RingCtInput {
    /// The actual amount being spent
    pub amount: u64,
    /// The blinding factor for the commitment
    pub blinding: Scalar,
    /// The commitment to the amount: C = amount*H + blinding*G
    pub commitment: PedersenCommitment,
}

/// Transaction output with commitment
#[derive(Debug, Clone)]
pub struct RingCtOutput {
    /// The actual amount (known to creator, hidden in transaction)
    pub amount: u64,
    /// The blinding factor for the commitment
    pub blinding: Scalar,
    /// The commitment to the amount: C = amount*H + blinding*G
    pub commitment: PedersenCommitment,
}

/// Builder for creating Ring CT transactions
pub struct RingCtBuilder {
    inputs: Vec<RingCtInput>,
    outputs: Vec<RingCtOutput>,
    fee: u64,
    decoy_public_keys: Vec<PublicKey>,
}

impl RingCtBuilder {
    /// Create a new Ring CT transaction builder
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            decoy_public_keys: Vec::new(),
        }
    }

    /// Add an input to the transaction
    pub fn add_input(mut self, amount: u64, blinding: Scalar) -> Self {
        let opening = PedersenOpening::from_bytes(blinding.to_bytes());
        let commitment = commit_with_blinding(amount, &opening);
        self.inputs.push(RingCtInput {
            amount,
            blinding,
            commitment,
        });
        self
    }

    /// Add an output to the transaction
    pub fn add_output(mut self, amount: u64, blinding: Scalar) -> Self {
        let opening = PedersenOpening::from_bytes(blinding.to_bytes());
        let commitment = commit_with_blinding(amount, &opening);
        self.outputs.push(RingCtOutput {
            amount,
            blinding,
            commitment,
        });
        self
    }

    /// Set transaction fee (in smallest units)
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Add decoy public keys for ring signature (for anonymity)
    ///
    /// Decoy public keys are used to create a ring of possible signers, making it
    /// impossible to determine which key actually signed the transaction.
    ///
    /// In a real Ring CT system, these should be real public keys from the blockchain
    /// to provide actual anonymity. The more decoys, the greater the anonymity set.
    ///
    /// # Example
    /// ```ignore
    /// let decoys = vec![
    ///     some_real_public_key_1,
    ///     some_real_public_key_2,
    ///     some_real_public_key_3,
    /// ];
    /// builder.add_decoys(decoys);
    /// ```
    pub fn add_decoys(mut self, decoys: Vec<PublicKey>) -> Self {
        self.decoy_public_keys = decoys;
        self
    }

    /// Add a single decoy public key for ring signature
    pub fn add_decoy(mut self, decoy: PublicKey) -> Self {
        self.decoy_public_keys.push(decoy);
        self
    }

    /// Calculate the required blinding factor for a new output to balance the transaction
    ///
    /// For Ring CT transactions to verify correctly, the blinding factors must balance:
    /// `sum(input_blindings) = sum(output_blindings) + fee_blinding`
    ///
    /// Since fee uses zero blinding, this simplifies to:
    /// `sum(input_blindings) = sum(output_blindings)`
    ///
    /// This method calculates what the next output's blinding factor should be
    /// to achieve this balance given all current inputs and outputs.
    ///
    /// Returns `None` if there are no inputs.
    pub fn calculate_last_output_blinding(&self) -> Option<Scalar> {
        if self.inputs.is_empty() {
            return None;
        }

        // Calculate total input blinding
        let total_input_blinding: Scalar = self.inputs.iter().map(|i| i.blinding).sum();

        // Calculate blinding from ALL current outputs
        let existing_output_blinding: Scalar = self.outputs.iter().map(|o| o.blinding).sum();

        // Fee blinding is always zero, so we don't need to account for it
        // Next output blinding = total_input_blinding - existing_output_blinding
        Some(total_input_blinding - existing_output_blinding)
    }

    /// Add an output with automatic blinding factor calculation
    ///
    /// This method automatically calculates the blinding factor needed to balance
    /// the transaction. It should only be used for the LAST output in a transaction.
    ///
    /// # Panics
    /// Panics if there are no inputs (cannot calculate balance without inputs)
    pub fn add_output_auto_balance(mut self, amount: u64) -> Self {
        let blinding = self
            .calculate_last_output_blinding()
            .expect("Cannot auto-balance without inputs");

        let opening = PedersenOpening::from_bytes(blinding.to_bytes());
        let commitment = commit_with_blinding(amount, &opening);
        self.outputs.push(RingCtOutput {
            amount,
            blinding,
            commitment,
        });
        self
    }

    /// Rebalance the last output's blinding factor to ensure transaction balance
    ///
    /// This is useful if you've added all inputs and outputs but want to ensure
    /// the transaction is properly balanced. It recalculates the last output's
    /// commitment with a new blinding factor that ensures balance.
    ///
    /// Returns the builder for chaining.
    ///
    /// # Panics
    /// Panics if there are no inputs or no outputs
    pub fn rebalance_last_output(mut self) -> Self {
        assert!(!self.inputs.is_empty(), "Cannot rebalance without inputs");
        assert!(!self.outputs.is_empty(), "Cannot rebalance without outputs");

        // Calculate total input blinding
        let total_input_blinding: Scalar = self.inputs.iter().map(|i| i.blinding).sum();

        // Calculate blinding from all outputs EXCEPT the last one
        let existing_output_blinding: Scalar = self
            .outputs
            .iter()
            .take(self.outputs.len() - 1)
            .map(|o| o.blinding)
            .sum();

        // Calculate what the last output's blinding should be
        let blinding = total_input_blinding - existing_output_blinding;

        // Update the last output's blinding and recalculate commitment
        if let Some(last_output) = self.outputs.last_mut() {
            last_output.blinding = blinding;
            let opening = PedersenOpening::from_bytes(blinding.to_bytes());
            last_output.commitment = commit_with_blinding(last_output.amount, &opening);
        }

        self
    }

    /// Build and sign the transaction with the given keypair
    ///
    /// The keypair is used to create the ring signature proving ownership
    /// of one of the inputs without revealing which one.
    pub fn build(self, signer: &KeyPair) -> RingCtResult<RingCtTransaction> {
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(RingCtError::EmptyTransaction);
        }

        // Calculate total input amount and blinding
        let total_input_amount: u64 = self.inputs.iter().map(|i| i.amount).sum();
        let total_input_blinding: Scalar = self.inputs.iter().map(|i| i.blinding).sum();

        // Calculate total output amount and blinding
        let total_output_amount: u64 = self.outputs.iter().map(|o| o.amount).sum();
        let total_output_blinding: Scalar = self.outputs.iter().map(|o| o.blinding).sum();

        // Check balance: inputs = outputs + fee
        if total_input_amount != total_output_amount + self.fee {
            return Err(RingCtError::UnbalancedTransaction);
        }

        // Create fee commitment with zero blinding
        let zero_opening = PedersenOpening::from_bytes(Scalar::ZERO.to_bytes());
        let fee_commitment = commit_with_blinding(self.fee, &zero_opening);

        // Calculate excess blinding: r_in - r_out - r_fee
        let _excess_blinding = total_input_blinding - total_output_blinding;

        // Create commitments lists
        let input_commitments: Vec<PedersenCommitment> =
            self.inputs.iter().map(|i| i.commitment).collect();
        let output_commitments: Vec<PedersenCommitment> =
            self.outputs.iter().map(|o| o.commitment).collect();

        // Create ring for anonymity (signer's key + decoy keys)
        // Ring signatures require at least 2 keys, so add a dummy decoy if none provided
        let mut ring_keys = vec![signer.public_key()];

        // Add all provided decoy public keys
        ring_keys.extend(self.decoy_public_keys.iter().copied());

        // If no decoys provided, add a dummy one (just for testing - in production, real decoys should be used)
        if ring_keys.len() < 2 {
            ring_keys.push(KeyPair::generate().public_key());
        }

        // Create ring signature over the transaction hash
        let tx_hash =
            compute_transaction_hash(&input_commitments, &output_commitments, &fee_commitment);

        let ring_signature = sign_ring(signer, &ring_keys, &tx_hash)
            .map_err(|_| RingCtError::InvalidRingSignature)?;

        Ok(RingCtTransaction {
            input_commitments,
            output_commitments,
            ring_signature,
            ring: ring_keys,
            fee_commitment,
        })
    }
}

impl Default for RingCtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RingCtTransaction {
    /// Verify the Ring CT transaction
    ///
    /// Checks:
    /// 1. Ring signature is valid (proves sender is in the ring)
    /// 2. Transaction is balanced: sum(inputs) = sum(outputs) + fee
    ///
    /// Note: Range proof verification is not currently implemented.
    /// In production, range proofs should be added to prevent negative outputs.
    pub fn verify(&self) -> RingCtResult<bool> {
        // Check for empty transaction
        if self.input_commitments.is_empty() || self.output_commitments.is_empty() {
            return Err(RingCtError::EmptyTransaction);
        }

        // Verify ring signature using the stored ring
        let tx_hash = compute_transaction_hash(
            &self.input_commitments,
            &self.output_commitments,
            &self.fee_commitment,
        );

        let ring_valid = verify_ring(&self.ring, &tx_hash, &self.ring_signature)
            .map_err(|_| RingCtError::InvalidRingSignature)?;

        if !ring_valid {
            return Ok(false);
        }

        // Verify balance: sum(C_in) = sum(C_out) + C_fee
        // This works because Pedersen commitments are homomorphic
        if !self.verify_balance() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify transaction balance using homomorphic property of commitments
    ///
    /// Checks that: sum(inputs) - sum(outputs) - fee = 0 (as commitments)
    fn verify_balance(&self) -> bool {
        // Sum all input commitments using homomorphic addition
        let mut sum_inputs = self.input_commitments[0];
        for input in &self.input_commitments[1..] {
            sum_inputs = sum_inputs.add(input);
        }

        // Sum all output commitments
        let mut sum_outputs = self.output_commitments[0];
        for output in &self.output_commitments[1..] {
            sum_outputs = sum_outputs.add(output);
        }

        // Add fee commitment
        sum_outputs = sum_outputs.add(&self.fee_commitment);

        // Check if inputs = outputs + fee
        sum_inputs == sum_outputs
    }

    /// Get the total number of inputs
    pub fn input_count(&self) -> usize {
        self.input_commitments.len()
    }

    /// Get the total number of outputs
    pub fn output_count(&self) -> usize {
        self.output_commitments.len()
    }
}

/// Compute a hash of the transaction for signing
fn compute_transaction_hash(
    inputs: &[PedersenCommitment],
    outputs: &[PedersenCommitment],
    fee: &PedersenCommitment,
) -> Vec<u8> {
    use blake3::Hasher;
    let mut hasher = Hasher::new();

    // Hash all input commitments
    for input in inputs {
        hasher.update(input.as_bytes());
    }

    // Hash all output commitments
    for output in outputs {
        hasher.update(output.as_bytes());
    }

    // Hash fee commitment
    hasher.update(fee.as_bytes());

    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    fn random_scalar() -> Scalar {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        Scalar::from_bytes_mod_order(bytes)
    }

    #[test]
    fn test_simple_ringct_transaction() {
        let signer = KeyPair::generate();

        // Create a simple 1-input, 1-output transaction
        // IMPORTANT: Blinding factors must balance: r_in = r_out + r_fee
        let blinding = random_scalar();
        let tx = RingCtBuilder::new()
            .add_input(100, blinding)
            .add_output(100, blinding) // Same blinding since no fee
            .fee(0)
            .build(&signer)
            .unwrap();

        // Verify the transaction
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_transaction_with_fee() {
        let signer = KeyPair::generate();

        // Create transaction with fee
        // IMPORTANT: Blinding factors must balance: sum(r_in) = sum(r_out)
        let blinding = random_scalar();
        let tx = RingCtBuilder::new()
            .add_input(100, blinding)
            .add_output(90, blinding) // Same blinding since fee has zero blinding
            .fee(10)
            .build(&signer)
            .unwrap();

        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_multiple_inputs_outputs() {
        let signer = KeyPair::generate();

        // Create transaction with multiple inputs and outputs
        // IMPORTANT: Blinding factors must balance: sum(r_in) = sum(r_out)
        let r1 = random_scalar();
        let r2 = random_scalar();
        let r3 = random_scalar();
        let r4 = r1 + r2 - r3; // Calculate r4 to balance: r1 + r2 = r3 + r4

        let tx = RingCtBuilder::new()
            .add_input(100, r1)
            .add_input(200, r2)
            .add_output(150, r3)
            .add_output(140, r4) // Calculated to ensure balance
            .fee(10)
            .build(&signer)
            .unwrap();

        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_unbalanced_transaction_rejected() {
        let signer = KeyPair::generate();

        // Try to create unbalanced transaction
        let result = RingCtBuilder::new()
            .add_input(100, random_scalar())
            .add_output(200, random_scalar()) // More output than input!
            .fee(0)
            .build(&signer);

        assert_eq!(result.unwrap_err(), RingCtError::UnbalancedTransaction);
    }

    #[test]
    fn test_empty_transaction_rejected() {
        let signer = KeyPair::generate();

        // No inputs
        let result = RingCtBuilder::new()
            .add_output(100, random_scalar())
            .build(&signer);
        assert_eq!(result.unwrap_err(), RingCtError::EmptyTransaction);

        // No outputs
        let result = RingCtBuilder::new()
            .add_input(100, random_scalar())
            .build(&signer);
        assert_eq!(result.unwrap_err(), RingCtError::EmptyTransaction);
    }

    #[test]
    fn test_homomorphic_balance_check() {
        let signer = KeyPair::generate();

        // Create transaction
        // IMPORTANT: For balance to verify, blinding factors must match
        let blinding = random_scalar();

        let tx = RingCtBuilder::new()
            .add_input(100, blinding)
            .add_output(100, blinding) // Same blinding for balance
            .fee(0)
            .build(&signer)
            .unwrap();

        // Balance should verify correctly
        assert!(tx.verify_balance());
    }

    #[test]
    fn test_transaction_with_decoys() {
        let signer = KeyPair::generate();

        // Create transaction with decoys for ring signature
        // IMPORTANT: Blinding factors must balance
        // Note: The builder automatically generates dummy decoy keys for ring signature
        let blinding = random_scalar();
        let tx = RingCtBuilder::new()
            .add_input(100, blinding)
            .add_output(100, blinding) // Same blinding for balance
            .fee(0)
            .build(&signer)
            .unwrap();

        // Ring includes actual signer + decoy public keys (internally)
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_confidential_amounts() {
        // Commitments hide the actual amounts - only balance is verifiable

        let signer = KeyPair::generate();

        // Create transaction with valid amounts
        // IMPORTANT: Blinding factors must balance: r_in = r_out1 + r_out2
        let r_in = random_scalar();
        let r_out1 = random_scalar();
        let r_out2 = r_in - r_out1; // Calculate r_out2 to balance

        let tx = RingCtBuilder::new()
            .add_input(1000, r_in)
            .add_output(500, r_out1)
            .add_output(500, r_out2) // Calculated to ensure balance
            .fee(0)
            .build(&signer)
            .unwrap();

        // Commitments exist but amounts are hidden
        assert_eq!(tx.output_commitments.len(), 2);
        assert_eq!(tx.input_commitments.len(), 1);

        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_serialization() {
        let signer = KeyPair::generate();

        // IMPORTANT: Blinding factors must balance
        let blinding = random_scalar();
        let tx = RingCtBuilder::new()
            .add_input(100, blinding)
            .add_output(90, blinding) // Same blinding since fee has zero blinding
            .fee(10)
            .build(&signer)
            .unwrap();

        // Serialize
        let serialized = crate::codec::encode(&tx).unwrap();

        // Deserialize
        let deserialized: RingCtTransaction = crate::codec::decode(&serialized).unwrap();

        // Verify deserialized transaction
        assert!(deserialized.verify().unwrap());
    }

    #[test]
    fn test_transaction_counts() {
        let signer = KeyPair::generate();

        let tx = RingCtBuilder::new()
            .add_input(100, random_scalar())
            .add_input(200, random_scalar())
            .add_output(150, random_scalar())
            .add_output(140, random_scalar())
            .fee(10)
            .build(&signer)
            .unwrap();

        assert_eq!(tx.input_count(), 2);
        assert_eq!(tx.output_count(), 2);
    }

    #[test]
    fn test_large_transaction() {
        let signer = KeyPair::generate();

        // Create transaction with many inputs and outputs
        // IMPORTANT: Blinding factors must balance: sum(r_in) = sum(r_out)
        let mut builder = RingCtBuilder::new();

        // Generate random blinding factors for inputs
        let mut input_blindings = Vec::new();
        let mut total_in = 0u64;
        for _ in 0..10 {
            let amount = 100;
            total_in += amount;
            let blinding = random_scalar();
            input_blindings.push(blinding);
            builder = builder.add_input(amount, blinding);
        }

        // Generate random blinding factors for outputs (except the last one)
        let mut output_blindings = Vec::new();
        let mut total_out = 0u64;
        for _ in 0..8 {
            let amount = 100;
            total_out += amount;
            let blinding = random_scalar();
            output_blindings.push(blinding);
            builder = builder.add_output(amount, blinding);
        }

        // Calculate the last output's blinding to ensure balance
        let sum_input_blindings: Scalar = input_blindings.iter().sum();
        let sum_output_blindings: Scalar = output_blindings.iter().sum();
        let last_blinding = sum_input_blindings - sum_output_blindings;

        let amount = 100;
        total_out += amount;
        builder = builder.add_output(amount, last_blinding);

        let fee = total_in - total_out;
        let tx = builder.fee(fee).build(&signer).unwrap();

        assert_eq!(tx.input_count(), 10);
        assert_eq!(tx.output_count(), 9);

        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_commitment_homomorphism() {
        // Test that C(a) + C(b) = C(a+b)
        let a = 100u64;
        let b = 200u64;
        let r1 = random_scalar();
        let r2 = random_scalar();

        let opening1 = PedersenOpening::from_bytes(r1.to_bytes());
        let opening2 = PedersenOpening::from_bytes(r2.to_bytes());
        let opening_sum = PedersenOpening::from_bytes((r1 + r2).to_bytes());

        let c1 = commit_with_blinding(a, &opening1);
        let c2 = commit_with_blinding(b, &opening2);
        let c_sum = commit_with_blinding(a + b, &opening_sum);

        // Homomorphic property: C(a) + C(b) = C(a+b)
        let c_added = c1.add(&c2);
        assert_eq!(c_added, c_sum);
    }

    #[test]
    fn test_calculate_last_output_blinding() {
        let r1 = random_scalar();
        let r2 = random_scalar();
        let r3 = random_scalar();

        let builder = RingCtBuilder::new()
            .add_input(100, r1)
            .add_input(50, r2)
            .add_output(80, r3);

        // Calculate what the last output's blinding should be
        let last_blinding = builder.calculate_last_output_blinding().unwrap();

        // Should be: r1 + r2 - r3 (since we have 2 inputs and 1 output so far)
        let expected = r1 + r2 - r3;
        assert_eq!(last_blinding, expected);
    }

    #[test]
    fn test_add_output_auto_balance() {
        let signer = KeyPair::generate();
        let r1 = random_scalar();
        let r2 = random_scalar();

        // Create a transaction with auto-balanced last output
        let tx = RingCtBuilder::new()
            .add_input(1000, r1)
            .add_output(700, r2)
            .add_output_auto_balance(300) // Should auto-calculate blinding
            .build(&signer)
            .unwrap();

        // Transaction should verify because blinding is balanced
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_rebalance_last_output() {
        let signer = KeyPair::generate();
        let r1 = random_scalar();
        let r2 = random_scalar();
        let r3 = random_scalar();

        // Create a transaction with initially unbalanced outputs
        let tx = RingCtBuilder::new()
            .add_input(1000, r1)
            .add_output(700, r2)
            .add_output(300, r3) // Initially uses r3
            .rebalance_last_output() // This will recalculate the last output's blinding
            .build(&signer)
            .unwrap();

        // Transaction should verify because we rebalanced
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_auto_balance_with_fee() {
        let signer = KeyPair::generate();
        let r1 = random_scalar();
        let r2 = random_scalar();

        // Create a transaction with fee
        let tx = RingCtBuilder::new()
            .add_input(1000, r1)
            .add_output(600, r2)
            .add_output_auto_balance(350) // 1000 - 600 - 50 (fee) = 350
            .fee(50)
            .build(&signer)
            .unwrap();

        // Transaction should verify
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_multiple_inputs_auto_balance() {
        let signer = KeyPair::generate();
        let r1 = random_scalar();
        let r2 = random_scalar();
        let r3 = random_scalar();
        let r4 = random_scalar();

        // Create a transaction with multiple inputs and balanced amounts
        let tx = RingCtBuilder::new()
            .add_input(500, r1)
            .add_input(500, r2)
            .add_output(300, r3)
            .add_output(700, r4) // 500 + 500 = 300 + 700
            .rebalance_last_output() // Ensure blinding balance
            .build(&signer)
            .unwrap();

        // Transaction should verify
        assert!(tx.verify().unwrap());
    }

    #[test]
    fn test_real_decoy_public_keys() {
        let signer = KeyPair::generate();
        let r1 = random_scalar();
        let r2 = random_scalar();

        // Create real decoy public keys (simulating other users' keys)
        let decoy1 = KeyPair::generate().public_key();
        let decoy2 = KeyPair::generate().public_key();
        let decoy3 = KeyPair::generate().public_key();

        // Create a transaction with real decoys
        let tx = RingCtBuilder::new()
            .add_input(1000, r1)
            .add_output(600, r2)
            .add_output_auto_balance(400)
            .add_decoy(decoy1)
            .add_decoy(decoy2)
            .add_decoy(decoy3)
            .build(&signer)
            .unwrap();

        // Transaction should verify
        assert!(tx.verify().unwrap());

        // Ring should contain signer + 3 decoys = 4 keys
        assert_eq!(tx.ring.len(), 4);

        // Ring should contain the signer's public key
        assert!(tx.ring.contains(&signer.public_key()));

        // Ring should contain all decoys
        assert!(tx.ring.contains(&decoy1));
        assert!(tx.ring.contains(&decoy2));
        assert!(tx.ring.contains(&decoy3));
    }

    #[test]
    fn test_bulk_decoys_addition() {
        let signer = KeyPair::generate();
        let r1 = random_scalar();

        // Create a list of decoy public keys
        let decoys: Vec<PublicKey> = (0..5).map(|_| KeyPair::generate().public_key()).collect();

        // Create a transaction with bulk decoys
        let tx = RingCtBuilder::new()
            .add_input(1000, r1)
            .add_output_auto_balance(1000)
            .add_decoys(decoys.clone())
            .build(&signer)
            .unwrap();

        // Transaction should verify
        assert!(tx.verify().unwrap());

        // Ring should contain signer + 5 decoys = 6 keys
        assert_eq!(tx.ring.len(), 6);

        // All decoys should be in the ring
        for decoy in &decoys {
            assert!(tx.ring.contains(decoy));
        }
    }
}
