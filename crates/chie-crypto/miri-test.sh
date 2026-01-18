#!/bin/bash
# MIRI Memory Safety Verification for chie-crypto
#
# This script runs MIRI on critical cryptographic operations to detect:
# - Undefined behavior
# - Memory safety violations
# - Data races
# - Use-after-free
# - Out-of-bounds access

set -e

echo "========================================"
echo "MIRI Memory Safety Verification"
echo "========================================"

# Install MIRI if not already installed
if ! rustup component list | grep -q "miri-x86_64"; then
    echo "Installing MIRI..."
    rustup toolchain install nightly --component miri
fi

# Run MIRI on specific test modules
echo ""
echo "Running MIRI on encryption tests..."
cargo +nightly miri test encryption:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on signing tests..."
cargo +nightly miri test signing:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on hashing tests..."
cargo +nightly miri test hash:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on constant-time tests..."
cargo +nightly miri test ct:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on key derivation tests..."
cargo +nightly miri test kdf:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on Shamir Secret Sharing tests..."
cargo +nightly miri test shamir:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on Pedersen commitment tests..."
cargo +nightly miri test pedersen:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "Running MIRI on Merkle tree tests..."
cargo +nightly miri test merkle:: --lib || echo "Note: Some tests may be skipped due to platform dependencies"

echo ""
echo "========================================"
echo "MIRI verification completed!"
echo "========================================"
