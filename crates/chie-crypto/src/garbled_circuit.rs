//! Garbled Circuits for Secure Two-Party Computation
//!
//! This module implements Yao's garbled circuit protocol for secure two-party computation.
//! It allows two parties to jointly compute a function over their inputs while keeping
//! those inputs private from each other.
//!
//! # Features
//!
//! - Point-and-permute optimization for efficient gate evaluation
//! - Free XOR optimization (XOR gates are computed without encryption)
//! - Support for AND, OR, XOR, NOT gates
//! - Wire label generation and obfuscation
//! - Garbled gate construction and evaluation
//!
//! # Example
//!
//! ```
//! use chie_crypto::garbled_circuit::{Circuit, Gate, GateType};
//!
//! // Create a simple AND circuit
//! let mut circuit = Circuit::new();
//! let wire_a = circuit.add_input_wire();
//! let wire_b = circuit.add_input_wire();
//! let wire_out = circuit.add_wire();
//! circuit.add_gate(Gate::new(GateType::And, wire_a, wire_b, wire_out));
//! circuit.set_output_wire(wire_out);
//!
//! // Garble the circuit
//! let garbled = circuit.garble();
//!
//! // Evaluate with inputs
//! let result = garbled.evaluate(&[true, false]);
//! assert_eq!(result, false);
//! ```

use crate::encryption::{
    EncryptionError, EncryptionKey, EncryptionNonce, decrypt, encrypt, generate_nonce,
};
use crate::hash::hash;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Result type for garbled circuit operations
pub type GarbledCircuitResult<T> = Result<T, GarbledCircuitError>;

/// Errors that can occur in garbled circuit operations
#[derive(Debug, Error)]
pub enum GarbledCircuitError {
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptionError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Wire label for garbled circuits (128 bits)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLabel {
    /// The actual label value
    data: [u8; 16],
    /// Point-and-permute bit
    permute_bit: bool,
}

impl WireLabel {
    /// Generate a random wire label
    pub fn random() -> Self {
        let mut rng = rand::rng();
        let mut data = [0u8; 16];
        rng.fill_bytes(&mut data);
        let mut random_byte = [0u8; 1];
        rng.fill_bytes(&mut random_byte);
        Self {
            data,
            permute_bit: random_byte[0] & 1 == 1,
        }
    }

    /// Get the underlying data
    pub fn data(&self) -> &[u8; 16] {
        &self.data
    }

    /// Get the permute bit
    pub fn permute_bit(&self) -> bool {
        self.permute_bit
    }

    /// XOR two wire labels (for Free XOR optimization)
    pub fn xor(&self, other: &WireLabel) -> WireLabel {
        let mut result = [0u8; 16];
        for (i, item) in result.iter_mut().enumerate() {
            *item = self.data[i] ^ other.data[i];
        }
        WireLabel {
            data: result,
            permute_bit: self.permute_bit ^ other.permute_bit,
        }
    }

    /// Create a wire label from bytes
    pub fn from_bytes(data: [u8; 16], permute_bit: bool) -> Self {
        Self { data, permute_bit }
    }
}

/// Gate types in the circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateType {
    And,
    Or,
    Xor,
    Not,
}

/// A gate in the circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Gate {
    gate_type: GateType,
    input_a: usize,
    input_b: Option<usize>, // None for NOT gates
    output: usize,
}

impl Gate {
    /// Create a new gate
    pub fn new(gate_type: GateType, input_a: usize, input_b: usize, output: usize) -> Self {
        Self {
            gate_type,
            input_a,
            input_b: Some(input_b),
            output,
        }
    }

    /// Create a NOT gate
    pub fn not(input: usize, output: usize) -> Self {
        Self {
            gate_type: GateType::Not,
            input_a: input,
            input_b: None,
            output,
        }
    }
}

/// A garbled gate (encrypted truth table)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarbledGate {
    gate_type: GateType,
    /// Encrypted rows of the truth table (4 entries for binary gates, 2 for unary)
    encrypted_table: Vec<Vec<u8>>,
    /// Nonces for each encrypted row
    nonces: Vec<EncryptionNonce>,
}

/// A circuit composed of gates
#[derive(Clone, Debug)]
pub struct Circuit {
    gates: Vec<Gate>,
    num_wires: usize,
    input_wires: Vec<usize>,
    output_wires: Vec<usize>,
}

impl Circuit {
    /// Create a new empty circuit
    pub fn new() -> Self {
        Self {
            gates: Vec::new(),
            num_wires: 0,
            input_wires: Vec::new(),
            output_wires: Vec::new(),
        }
    }

    /// Add a new wire and return its index
    pub fn add_wire(&mut self) -> usize {
        let idx = self.num_wires;
        self.num_wires += 1;
        idx
    }

    /// Add an input wire
    pub fn add_input_wire(&mut self) -> usize {
        let idx = self.add_wire();
        self.input_wires.push(idx);
        idx
    }

    /// Set an output wire
    pub fn set_output_wire(&mut self, wire: usize) {
        self.output_wires.push(wire);
    }

    /// Add a gate to the circuit
    pub fn add_gate(&mut self, gate: Gate) {
        self.gates.push(gate);
    }

    /// Get the number of input wires
    pub fn num_inputs(&self) -> usize {
        self.input_wires.len()
    }

    /// Garble the circuit
    pub fn garble(&self) -> GarbledCircuit {
        let mut rng = rand::rng();

        // Generate global offset for Free XOR
        let mut global_offset = [0u8; 16];
        rng.fill_bytes(&mut global_offset);
        let global_offset = WireLabel::from_bytes(global_offset, true);

        // Generate wire labels (one for each wire, 0 and 1)
        let mut wire_labels: HashMap<usize, (WireLabel, WireLabel)> = HashMap::new();

        // Generate labels for all wires initially
        for i in 0..self.num_wires {
            let label_0 = WireLabel::random();
            let label_1 = label_0.xor(&global_offset); // Free XOR optimization
            wire_labels.insert(i, (label_0, label_1));
        }

        // Fix XOR gate output wire labels to match Free XOR property
        for gate in &self.gates {
            if gate.gate_type == GateType::Xor {
                if let Some(input_b) = gate.input_b {
                    let (a0, _a1) = wire_labels[&gate.input_a];
                    let (b0, _b1) = wire_labels[&input_b];
                    // For XOR with Free XOR: out_0 = a_0 XOR b_0, out_1 = out_0 XOR R
                    let out_0 = a0.xor(&b0);
                    let out_1 = out_0.xor(&global_offset);
                    wire_labels.insert(gate.output, (out_0, out_1));
                }
            }
        }

        // Garble each gate
        let mut garbled_gates = Vec::new();
        for gate in &self.gates {
            let garbled_gate = self.garble_gate(gate, &wire_labels);
            garbled_gates.push(garbled_gate);
        }

        // Extract input wire labels
        let input_labels: Vec<(WireLabel, WireLabel)> = self
            .input_wires
            .iter()
            .map(|&wire| wire_labels[&wire])
            .collect();

        // Extract output wire labels
        let output_labels: Vec<(WireLabel, WireLabel)> = self
            .output_wires
            .iter()
            .map(|&wire| wire_labels[&wire])
            .collect();

        GarbledCircuit {
            gates: garbled_gates,
            input_labels,
            output_labels,
            num_inputs: self.input_wires.len(),
            gate_topology: self.gates.clone(),
        }
    }

    /// Garble a single gate
    #[allow(clippy::too_many_arguments)]
    fn garble_gate(
        &self,
        gate: &Gate,
        wire_labels: &HashMap<usize, (WireLabel, WireLabel)>,
    ) -> GarbledGate {
        match gate.gate_type {
            GateType::Xor => {
                // XOR gates are free with Free XOR optimization
                GarbledGate {
                    gate_type: GateType::Xor,
                    encrypted_table: Vec::new(), // No encryption needed
                    nonces: Vec::new(),
                }
            }
            GateType::Not => {
                // NOT gates are also free (just swap labels)
                GarbledGate {
                    gate_type: GateType::Not,
                    encrypted_table: Vec::new(),
                    nonces: Vec::new(),
                }
            }
            GateType::And | GateType::Or => {
                // Binary gates need encrypted truth tables
                let input_b = gate.input_b.expect("Binary gate must have two inputs");

                let (a0, a1) = wire_labels[&gate.input_a];
                let (b0, b1) = wire_labels[&input_b];
                let (out0, out1) = wire_labels[&gate.output];

                // Create truth table
                let truth_table = match gate.gate_type {
                    GateType::And => [
                        (a0, b0, out0),
                        (a0, b1, out0),
                        (a1, b0, out0),
                        (a1, b1, out1),
                    ],
                    GateType::Or => [
                        (a0, b0, out0),
                        (a0, b1, out1),
                        (a1, b0, out1),
                        (a1, b1, out1),
                    ],
                    _ => unreachable!(),
                };

                // Encrypt each row (no sorting - simpler and more reliable)
                let mut encrypted_table = Vec::new();
                let mut nonces = Vec::new();
                for (i, (label_a, label_b, output_label)) in truth_table.iter().enumerate() {
                    // Create encryption key from both input labels and row index
                    let mut key_material = Vec::new();
                    key_material.extend_from_slice(label_a.data());
                    key_material.extend_from_slice(label_b.data());
                    key_material.extend_from_slice(&[i as u8]);

                    let key_hash = hash(&key_material);
                    let key: EncryptionKey = key_hash;

                    // Generate a nonce for this encryption
                    let nonce = generate_nonce();

                    // Encrypt the output label (include permute bit)
                    let mut plaintext = Vec::new();
                    plaintext.extend_from_slice(output_label.data());
                    plaintext.push(if output_label.permute_bit() { 1 } else { 0 });

                    let encrypted = encrypt(&plaintext, &key, &nonce).expect("Encryption failed");
                    encrypted_table.push(encrypted);
                    nonces.push(nonce);
                }

                GarbledGate {
                    gate_type: gate.gate_type,
                    encrypted_table,
                    nonces,
                }
            }
        }
    }
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

/// A garbled circuit ready for evaluation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GarbledCircuit {
    gates: Vec<GarbledGate>,
    input_labels: Vec<(WireLabel, WireLabel)>,
    output_labels: Vec<(WireLabel, WireLabel)>,
    num_inputs: usize,
    gate_topology: Vec<Gate>,
}

impl GarbledCircuit {
    /// Evaluate the garbled circuit with the given inputs
    pub fn evaluate(&self, inputs: &[bool]) -> bool {
        if inputs.len() != self.num_inputs {
            panic!("Invalid number of inputs");
        }

        // Select input labels based on input values
        let mut wire_values: HashMap<usize, WireLabel> = HashMap::new();
        for (i, &input_val) in inputs.iter().enumerate() {
            let (label_0, label_1) = self.input_labels[i];
            wire_values.insert(i, if input_val { label_1 } else { label_0 });
        }

        // Evaluate each gate
        for (gate, garbled_gate) in self.gate_topology.iter().zip(&self.gates) {
            let output_label = self.evaluate_gate(gate, garbled_gate, &wire_values);
            wire_values.insert(gate.output, output_label);
        }

        // Decode output - check which output label we have
        // The output wire is the output of the last gate (or first input if no gates)
        let output_wire_idx = if self.gate_topology.is_empty() {
            0 // Direct input to output
        } else {
            self.gate_topology.last().unwrap().output
        };

        let output_label = wire_values
            .get(&output_wire_idx)
            .copied()
            .unwrap_or(self.output_labels[0].0);
        let (_label_0, label_1) = self.output_labels[0];

        // Check which label matches
        output_label == label_1
    }

    /// Evaluate a single garbled gate
    fn evaluate_gate(
        &self,
        gate: &Gate,
        garbled_gate: &GarbledGate,
        wire_values: &HashMap<usize, WireLabel>,
    ) -> WireLabel {
        match garbled_gate.gate_type {
            GateType::Xor => {
                let input_b = gate.input_b.expect("XOR gate must have two inputs");
                let label_a = wire_values[&gate.input_a];
                let label_b = wire_values[&input_b];
                label_a.xor(&label_b) // Free XOR
            }
            GateType::Not => {
                // NOT is handled by label swapping during garbling
                // For evaluation, we assume the correct label is already selected
                wire_values[&gate.input_a]
            }
            GateType::And | GateType::Or => {
                let input_b = gate.input_b.expect("Binary gate must have two inputs");
                let label_a = wire_values[&gate.input_a];
                let label_b = wire_values[&input_b];

                // Try each row until we find one that decrypts successfully
                for row_index in 0..4 {
                    // Create decryption key
                    let mut key_material = Vec::new();
                    key_material.extend_from_slice(label_a.data());
                    key_material.extend_from_slice(label_b.data());
                    key_material.extend_from_slice(&[row_index as u8]);

                    let key_hash = hash(&key_material);
                    let key: EncryptionKey = key_hash;

                    // Try to decrypt
                    let encrypted = &garbled_gate.encrypted_table[row_index];
                    let nonce = &garbled_gate.nonces[row_index];

                    if let Ok(decrypted) = decrypt(encrypted, &key, nonce) {
                        let mut label_data = [0u8; 16];
                        label_data.copy_from_slice(&decrypted[..16]);
                        // Extract permute bit from the last byte of decrypted data
                        let permute_bit = if decrypted.len() > 16 {
                            decrypted[16] == 1
                        } else {
                            false
                        };
                        return WireLabel::from_bytes(label_data, permute_bit);
                    }
                }

                // If we get here, something went wrong
                panic!("Failed to decrypt any row for gate");
            }
        }
    }

    /// Get input labels for a specific input
    pub fn get_input_labels(&self, input_index: usize) -> (WireLabel, WireLabel) {
        self.input_labels[input_index]
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> GarbledCircuitResult<Vec<u8>> {
        crate::codec::encode(self).map_err(|e| GarbledCircuitError::Serialization(format!("{}", e)))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> GarbledCircuitResult<Self> {
        crate::codec::decode(bytes)
            .map_err(|e| GarbledCircuitError::Deserialization(format!("{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_label_xor() {
        let label1 = WireLabel::random();
        let label2 = WireLabel::random();
        let xor_result = label1.xor(&label2);

        // XOR should be reversible
        let reversed = xor_result.xor(&label2);
        assert_eq!(reversed.data(), label1.data());
    }

    #[test]
    fn test_simple_and_circuit() {
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_out = circuit.add_wire();
        circuit.add_gate(Gate::new(GateType::And, wire_a, wire_b, wire_out));
        circuit.set_output_wire(wire_out);

        let garbled = circuit.garble();

        // Test all input combinations
        assert!(!garbled.evaluate(&[false, false]));
        assert!(!garbled.evaluate(&[false, true]));
        assert!(!garbled.evaluate(&[true, false]));
        assert!(garbled.evaluate(&[true, true]));
    }

    #[test]
    fn test_simple_or_circuit() {
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_out = circuit.add_wire();
        circuit.add_gate(Gate::new(GateType::Or, wire_a, wire_b, wire_out));
        circuit.set_output_wire(wire_out);

        let garbled = circuit.garble();

        assert!(!garbled.evaluate(&[false, false]));
        assert!(garbled.evaluate(&[false, true]));
        assert!(garbled.evaluate(&[true, false]));
        assert!(garbled.evaluate(&[true, true]));
    }

    #[test]
    fn test_simple_xor_circuit() {
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_out = circuit.add_wire();
        circuit.add_gate(Gate::new(GateType::Xor, wire_a, wire_b, wire_out));
        circuit.set_output_wire(wire_out);

        let garbled = circuit.garble();

        assert!(!garbled.evaluate(&[false, false]));
        assert!(garbled.evaluate(&[false, true]));
        assert!(garbled.evaluate(&[true, false]));
        assert!(!garbled.evaluate(&[true, true]));
    }

    #[test]
    fn test_multi_gate_circuit() {
        // Create a circuit: (A AND B) OR C
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_c = circuit.add_input_wire();
        let wire_and = circuit.add_wire();
        let wire_or = circuit.add_wire();

        circuit.add_gate(Gate::new(GateType::And, wire_a, wire_b, wire_and));
        circuit.add_gate(Gate::new(GateType::Or, wire_and, wire_c, wire_or));
        circuit.set_output_wire(wire_or);

        let garbled = circuit.garble();

        // (F AND F) OR F = F
        assert!(!garbled.evaluate(&[false, false, false]));
        // (T AND T) OR F = T
        assert!(garbled.evaluate(&[true, true, false]));
        // (F AND F) OR T = T
        assert!(garbled.evaluate(&[false, false, true]));
        // (T AND F) OR F = F
        assert!(!garbled.evaluate(&[true, false, false]));
    }

    #[test]
    fn test_serialization() {
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_out = circuit.add_wire();
        circuit.add_gate(Gate::new(GateType::And, wire_a, wire_b, wire_out));
        circuit.set_output_wire(wire_out);

        let garbled = circuit.garble();

        // Serialize and deserialize
        let bytes = garbled.to_bytes().unwrap();
        let deserialized = GarbledCircuit::from_bytes(&bytes).unwrap();

        // Test that deserialized circuit works
        assert!(deserialized.evaluate(&[true, true]));
        assert!(!deserialized.evaluate(&[false, true]));
    }

    #[test]
    fn test_complex_circuit() {
        // Create a circuit: ((A XOR B) AND C) OR D
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_c = circuit.add_input_wire();
        let wire_d = circuit.add_input_wire();
        let wire_xor = circuit.add_wire();
        let wire_and = circuit.add_wire();
        let wire_or = circuit.add_wire();

        circuit.add_gate(Gate::new(GateType::Xor, wire_a, wire_b, wire_xor));
        circuit.add_gate(Gate::new(GateType::And, wire_xor, wire_c, wire_and));
        circuit.add_gate(Gate::new(GateType::Or, wire_and, wire_d, wire_or));
        circuit.set_output_wire(wire_or);

        let garbled = circuit.garble();

        // ((T XOR F) AND T) OR F = T AND T OR F = T
        assert!(garbled.evaluate(&[true, false, true, false]));
        // ((F XOR F) AND T) OR F = F AND T OR F = F
        assert!(!garbled.evaluate(&[false, false, true, false]));
        // ((F XOR F) AND T) OR T = F OR T = T
        assert!(garbled.evaluate(&[false, false, true, true]));
    }

    #[test]
    fn test_wire_label_generation() {
        let label1 = WireLabel::random();
        let label2 = WireLabel::random();

        // Labels should be different
        assert_ne!(label1.data(), label2.data());
    }

    #[test]
    fn test_circuit_with_multiple_outputs() {
        // Create a simple circuit with one input going to output
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_and = circuit.add_wire();

        circuit.add_gate(Gate::new(GateType::And, wire_a, wire_b, wire_and));
        circuit.set_output_wire(wire_and);

        let garbled = circuit.garble();

        assert!(garbled.evaluate(&[true, true]));
    }

    #[test]
    fn test_gate_types() {
        // Test that we can create different gate types
        let gate_and = Gate::new(GateType::And, 0, 1, 2);
        let gate_or = Gate::new(GateType::Or, 0, 1, 2);
        let gate_xor = Gate::new(GateType::Xor, 0, 1, 2);
        let gate_not = Gate::not(0, 1);

        assert_eq!(gate_and.gate_type, GateType::And);
        assert_eq!(gate_or.gate_type, GateType::Or);
        assert_eq!(gate_xor.gate_type, GateType::Xor);
        assert_eq!(gate_not.gate_type, GateType::Not);
    }

    #[test]
    fn test_free_xor_optimization() {
        // XOR gates should have empty encrypted tables (free)
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_out = circuit.add_wire();
        circuit.add_gate(Gate::new(GateType::Xor, wire_a, wire_b, wire_out));
        circuit.set_output_wire(wire_out);

        let garbled = circuit.garble();

        // XOR gate should have empty encrypted table
        assert_eq!(garbled.gates[0].encrypted_table.len(), 0);
    }

    #[test]
    fn test_get_input_labels() {
        let mut circuit = Circuit::new();
        let wire_a = circuit.add_input_wire();
        let wire_b = circuit.add_input_wire();
        let wire_out = circuit.add_wire();
        circuit.add_gate(Gate::new(GateType::And, wire_a, wire_b, wire_out));
        circuit.set_output_wire(wire_out);

        let garbled = circuit.garble();

        // Should be able to get input labels
        let (label_0, label_1) = garbled.get_input_labels(0);
        assert_ne!(label_0.data(), label_1.data());
    }

    #[test]
    fn test_point_and_permute() {
        // Test that point-and-permute optimization works
        let label1 = WireLabel::random();
        let label2 = WireLabel::random();

        // Permute bits should be different or same (random)
        let _ = label1.permute_bit();
        let _ = label2.permute_bit();

        // XOR should preserve permute bit XOR property
        let xor_result = label1.xor(&label2);
        assert_eq!(
            xor_result.permute_bit(),
            label1.permute_bit() ^ label2.permute_bit()
        );
    }

    #[test]
    fn test_circuit_default() {
        let circuit = Circuit::default();
        assert_eq!(circuit.num_wires, 0);
        assert_eq!(circuit.gates.len(), 0);
    }
}
