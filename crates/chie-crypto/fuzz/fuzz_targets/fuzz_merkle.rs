//! Fuzzing harness for Merkle trees

#![no_main]

use libfuzzer_sys::fuzz_target;
use chie_crypto::merkle::MerkleTree;

fuzz_target!(|data: &[u8]| {
    // Split data into chunks
    if data.is_empty() {
        return;
    }

    let chunk_size = (data.len() / 10).max(1);
    let mut leaves = Vec::new();

    for chunk in data.chunks(chunk_size) {
        if !chunk.is_empty() {
            leaves.push(chunk.to_vec());
        }
    }

    if leaves.is_empty() {
        return;
    }

    // Build Merkle tree
    if let Ok(tree) = MerkleTree::from_leaves(&leaves) {
        let root = tree.root();

        // Verify each leaf
        for (index, leaf) in leaves.iter().enumerate() {
            if let Some(proof) = tree.generate_proof(index) {
                // Verify proof
                assert!(proof.verify(root, index, leaf));

                // Wrong leaf should fail verification
                let wrong_leaf = b"wrong data";
                if leaf.as_slice() != wrong_leaf {
                    assert!(!proof.verify(root, index, wrong_leaf));
                }

                // Wrong index should fail
                if index + 1 < leaves.len() {
                    assert!(!proof.verify(root, index + 1, leaf));
                }
            }
        }

        // Multi-proof verification if we have multiple leaves
        if leaves.len() >= 2 {
            let indices: Vec<usize> = (0..leaves.len().min(5)).collect();
            if let Some(multi_proof) = tree.generate_multi_proof(&indices) {
                let leaves_subset: Vec<&[u8]> = indices
                    .iter()
                    .map(|&i| leaves[i].as_slice())
                    .collect();
                assert!(multi_proof.verify(root, &indices, &leaves_subset));
            }
        }
    }
});
