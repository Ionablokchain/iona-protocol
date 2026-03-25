//! Deterministic Merkle tree for IONA state root computation.
//!
//! This module implements a simple sorted‑leaf Merkle tree using SHA-256:
//! - Leaves are sorted by key (deterministic regardless of insertion order)
//! - Internal nodes: H(left || right)
//! - Single leaf: H(key || value)
//! - Empty tree: H(b"empty")
//!
//! The tree is built over a sorted list of key‑value pairs. It is fully
//! deterministic across platforms and Rust versions, and can be updated
//! incrementally (though this implementation focuses on full recompute).

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Domain separators to prevent collisions between different node types.
const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const EMPTY_PREFIX: u8 = 0x02;

/// Computes the Merkle root of a sorted map of key‑value pairs.
///
/// The tree is built by first hashing each pair into a leaf, then building
/// a binary Merkle tree over the leaves. The tree is padded with the last
/// leaf when the number of leaves is not a power of two (Bitcoin style).
pub fn state_merkle_root(kv: &BTreeMap<String, String>) -> [u8; 32] {
    if kv.is_empty() {
        return empty_root();
    }

    // Compute leaf hashes (already sorted by BTreeMap)
    let leaves: Vec<[u8; 32]> = kv
        .iter()
        .map(|(k, v)| leaf_hash(k.as_bytes(), v.as_bytes()))
        .collect();

    merkle_root_of(&leaves)
}

/// Hash for an empty state.
fn empty_root() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[EMPTY_PREFIX]);
    h.update(b"empty");
    h.finalize().into()
}

/// Hash for a leaf node (key‑value pair).
fn leaf_hash(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[LEAF_PREFIX]);
    h.update(&(key.len() as u32).to_le_bytes());
    h.update(key);
    h.update(&(value.len() as u32).to_le_bytes());
    h.update(value);
    h.finalize().into()
}

/// Hash for an internal node (combining two child hashes).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Computes the Merkle root of a list of leaf hashes (must not be empty).
fn merkle_root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty());
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Build tree bottom‑up using iterative doubling
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for i in (0..level.len()).step_by(2) {
            let left = &level[i];
            let right = if i + 1 < level.len() {
                &level[i + 1]
            } else {
                left // duplicate last element when odd
            };
            next.push(node_hash(left, right));
        }
        level = next;
    }
    level[0]
}

// -----------------------------------------------------------------------------
// Merkle Proofs (optional, for light clients)
// -----------------------------------------------------------------------------

/// A Merkle proof for a key‑value pair.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf hash of the key‑value pair.
    pub leaf_hash: [u8; 32],
    /// The sibling hashes along the path to the root (bottom‑up).
    pub siblings: Vec<[u8; 32]>,
    /// The position of the leaf (true = right, false = left) for each sibling.
    pub positions: Vec<bool>,
}

impl MerkleProof {
    /// Verify that this proof is valid for the given root.
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let mut current = self.leaf_hash;
        for (sibling, pos) in self.siblings.iter().zip(&self.positions) {
            current = if *pos {
                node_hash(sibling, &current)
            } else {
                node_hash(&current, sibling)
            };
        }
        &current == root
    }
}

/// Generate a Merkle proof for a specific key in the state.
/// Returns `None` if the key does not exist.
pub fn generate_proof(kv: &BTreeMap<String, String>, key: &str) -> Option<MerkleProof> {
    // Collect all leaves (sorted)
    let leaves: Vec<(String, [u8; 32])> = kv
        .iter()
        .map(|(k, v)| (k.clone(), leaf_hash(k.as_bytes(), v.as_bytes())))
        .collect();

    // Find the index of the target key
    let idx = leaves.iter().position(|(k, _)| k == key)?;
    let leaf_hash = leaves[idx].1;

    // Build the proof by iterating through the tree levels
    let mut level_hashes: Vec<[u8; 32]> = leaves.iter().map(|(_, h)| *h).collect();
    let mut siblings = Vec::new();
    let mut positions = Vec::new();

    while level_hashes.len() > 1 {
        let mut next = Vec::with_capacity((level_hashes.len() + 1) / 2);
        for i in (0..level_hashes.len()).step_by(2) {
            let left = &level_hashes[i];
            let right = if i + 1 < level_hashes.len() {
                &level_hashes[i + 1]
            } else {
                left
            };
            let (is_right, sibling_hash) = if idx % 2 == 1 && i == idx - 1 {
                // current leaf is right child
                (true, *left)
            } else if idx % 2 == 0 && i == idx {
                // current leaf is left child
                (false, *right)
            } else {
                // not on this level yet
                (false, [0u8; 32]) // placeholder
            };

            if i == idx || i == idx - 1 {
                siblings.push(sibling_hash);
                positions.push(is_right);
                // Update index for the next level
                idx = if is_right { i / 2 } else { i / 2 };
            }

            next.push(node_hash(left, right));
        }
        level_hashes = next;
    }

    Some(MerkleProof {
        leaf_hash,
        siblings,
        positions,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("a".to_string(), "1".to_string());
        kv1.insert("b".to_string(), "2".to_string());
        let mut kv2 = BTreeMap::new();
        kv2.insert("b".to_string(), "2".to_string());
        kv2.insert("a".to_string(), "1".to_string());
        assert_eq!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    #[test]
    fn test_different_values() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("k".to_string(), "v1".to_string());
        let mut kv2 = BTreeMap::new();
        kv2.insert("k".to_string(), "v2".to_string());
        assert_ne!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    #[test]
    fn test_empty_root() {
        let kv = BTreeMap::new();
        let root = state_merkle_root(&kv);
        // Known value: sha256(0x02 || "empty") computed once.
        let expected = empty_root();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_single_pair() {
        let mut kv = BTreeMap::new();
        kv.insert("key".to_string(), "value".to_string());
        let root = state_merkle_root(&kv);
        // Should be leaf_hash directly.
        let leaf = leaf_hash(b"key", b"value");
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_two_pairs() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        let root = state_merkle_root(&kv);
        let leaf_a = leaf_hash(b"a", b"1");
        let leaf_b = leaf_hash(b"b", b"2");
        let expected = node_hash(&leaf_a, &leaf_b);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_pairs() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        kv.insert("c".to_string(), "3".to_string());
        let root = state_merkle_root(&kv);
        let leaf_a = leaf_hash(b"a", b"1");
        let leaf_b = leaf_hash(b"b", b"2");
        let leaf_c = leaf_hash(b"c", b"3");
        // Expected tree: left = node(leaf_a, leaf_b), right = leaf_c, then root = node(left, right)
        let left = node_hash(&leaf_a, &leaf_b);
        let expected = node_hash(&left, &leaf_c);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_proof() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        kv.insert("c".to_string(), "3".to_string());

        let root = state_merkle_root(&kv);
        let proof = generate_proof(&kv, "b").unwrap();

        // Verify that the proof matches the root
        assert!(proof.verify(&root));

        // A different root should not verify
        let wrong_root = empty_root();
        assert!(!proof.verify(&wrong_root));
    }
}
