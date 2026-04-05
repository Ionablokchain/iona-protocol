//! Computation of Ethereum state root and storage root.
//!
//! This module implements the Merkle Patricia Trie (MPT) for state and storage
//! as defined by Ethereum. It uses the `trie_db` crate and the `state_trie`
//! feature flag to toggle between a real MPT and a deterministic placeholder
//! (used for testing and development without the full trie implementation).

use crate::evm::db::MemDb;
use revm::primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Compute Keccak-256 hash of data.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Format a byte slice as a hex string with `0x` prefix.
fn keccak_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

/// Ethereum empty trie root (hash of RLP‑encoded empty list).
/// Value: keccak256(0xc0) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// Empty trie root as a hex string.
pub const EMPTY_TRIE_ROOT_HEX: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// Return the empty trie root (as bytes).
pub fn empty_trie_root() -> [u8; 32] {
    EMPTY_TRIE_ROOT
}

// -----------------------------------------------------------------------------
// RLP account encoding
// -----------------------------------------------------------------------------

/// RLP‑encode an Ethereum account: [nonce, balance, storage_root, code_hash].
///
/// The encoding follows the Ethereum specification:
/// - `nonce` as RLP integer
/// - `balance` as RLP integer (big‑endian, minimal byte length)
/// - `storage_root` as 32‑byte array
/// - `code_hash` as 32‑byte array
fn rlp_account(nonce: u64, balance: U256, storage_root: [u8; 32], code_hash: [u8; 32]) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(4);
    stream.append(&nonce);

    // Balance as minimal big‑endian bytes
    let mut bal_bytes = [0u8; 32];
    let bal_bytes_tmp = balance.to_be_bytes::<32>(); bal_bytes.copy_from_slice(&bal_bytes_tmp);
    let trimmed = bal_bytes.iter().skip_while(|&&b| b == 0).cloned().collect::<Vec<u8>>();
    if trimmed.is_empty() {
        stream.append(&0u8);
    } else {
        stream.append(&trimmed.as_slice());
    }

    stream.append(&storage_root.as_slice());
    stream.append(&code_hash.as_slice());
    stream.out().to_vec()
}

// -----------------------------------------------------------------------------
// Storage root computation (real MPT under feature flag)
// -----------------------------------------------------------------------------

#[cfg(feature = "state_trie")]
fn compute_storage_root(addr: &Address, db: &MemDb) -> [u8; 32] {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{HashKey, MemoryDB};
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root = <KeccakHasher as Hasher>::Out::default();

    // Collect all slots for this account (sorted for determinism)
    let mut slots: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
    for ((a, slot), value) in &db.storage {
        if a == addr {
            let mut key = [0u8; 32];
            let key_tmp = slot.to_be_bytes::<32>(); key.copy_from_slice(&key_tmp);
            let mut val = [0u8; 32];
            let val_tmp = value.to_be_bytes::<32>(); val.copy_from_slice(&val_tmp);
            slots.insert(key, val);
        }
    }

    if slots.is_empty() {
        return EMPTY_TRIE_ROOT;
    }

    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);
        for (slot_bytes, value_bytes) in slots {
            // Secure trie key = keccak(slot)
            let key = keccak256(&slot_bytes);

            // Value = RLP of trimmed big‑endian bytes
            let trimmed = value_bytes.iter().skip_while(|&&b| b == 0).cloned().collect::<Vec<u8>>();
            let mut rlp_stream = rlp::RlpStream::new();
            if trimmed.is_empty() {
                rlp_stream.append(&0u8);
            } else {
                rlp_stream.append(&trimmed.as_slice());
            }
            let value = rlp_stream.out().to_vec();

            trie.insert(&key, &value)
                .expect("failed to insert storage slot");
        }
    }

    root.0
}

// -----------------------------------------------------------------------------
// State root computation (real MPT under feature flag)
// -----------------------------------------------------------------------------

#[cfg(feature = "state_trie")]
fn compute_state_root_mpt(db: &MemDb) -> [u8; 32] {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{HashKey, MemoryDB};
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root = <KeccakHasher as Hasher>::Out::default();

    if db.accounts.is_empty() {
        return EMPTY_TRIE_ROOT;
    }

    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);
        for (addr, info) in &db.accounts {
            let nonce = info.nonce;
            let balance = info.balance;
            let storage_root = compute_storage_root(addr, db);
            let code_hash = info.code_hash.0;

            let value = rlp_account(nonce, balance, storage_root, code_hash);
            let key = keccak256(addr.as_slice()); // secure trie key

            trie.insert(&key, &value)
                .expect("failed to insert account");
        }
    }

    root.0
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Compute the state root (hex string) from a `MemDb`.
///
/// When the `state_trie` feature is enabled, it uses a real Merkle Patricia Trie.
/// Otherwise, it returns a deterministic placeholder (hash of sorted account encodings).
pub fn compute_state_root_hex(db: &MemDb) -> String {
    #[cfg(feature = "state_trie")]
    {
        let root = compute_state_root_mpt(db);
        format!("0x{}", hex::encode(root))
    }
    #[cfg(not(feature = "state_trie"))]
    {
        // Placeholder: deterministic but NOT Ethereum‑compatible.
        if db.accounts.is_empty() {
            return EMPTY_TRIE_ROOT_HEX.to_string();
        }

        let mut items: Vec<Vec<u8>> = Vec::with_capacity(db.accounts.len());
        for (addr, info) in &db.accounts {
            let nonce = info.nonce;
            let balance = info.balance;
            let storage_root = compute_storage_root_hex_placeholder(addr, db);
            let code_hash = info.code_hash.0;
            let sr_bytes = hex::decode(&storage_root).unwrap_or_else(|_| vec![0u8; 32]);
            let mut storage_root_arr = [0u8; 32];
            if sr_bytes.len() == 32 { storage_root_arr.copy_from_slice(&sr_bytes); }
            let encoded = rlp_account(nonce, balance, storage_root_arr, code_hash);
            items.push(encoded);
        }
        items.sort(); // ensure determinism

        let mut hasher = Keccak256::new();
        for item in &items {
            hasher.update(item);
        }
        format!("0x{}", hex::encode(hasher.finalize()))
    }
}

/// Compute the storage root (hex string) for a given address.
///
/// When the `state_trie` feature is enabled, it uses a real MPT; otherwise, a placeholder.
pub fn compute_storage_root_hex(addr: &Address, db: &MemDb) -> String {
    #[cfg(feature = "state_trie")]
    {
        let root = compute_storage_root(addr, db);
        format!("0x{}", hex::encode(root))
    }
    #[cfg(not(feature = "state_trie"))]
    {
        compute_storage_root_hex_placeholder(addr, db)
    }
}

/// Placeholder storage root (deterministic but not MPT).
#[cfg(not(feature = "state_trie"))]
fn compute_storage_root_hex_placeholder(addr: &Address, db: &MemDb) -> String {
    let mut pairs: Vec<([u8; 32], [u8; 32])> = db.storage
        .iter()
        .filter(|((a, _), _)| a == addr)
        .map(|((_, slot), value)| {
            let mut key = [0u8; 32];
            let mut val = [0u8; 32];
            let key_tmp = slot.to_be_bytes::<32>(); key.copy_from_slice(&key_tmp);
            let val_tmp = value.to_be_bytes::<32>(); val.copy_from_slice(&val_tmp);
            (key, val)
        })
        .collect();

    if pairs.is_empty() {
        return EMPTY_TRIE_ROOT_HEX.to_string();
    }

    pairs.sort_by_key(|(k, _)| *k);
    let mut hasher = Keccak256::new();
    for (k, v) in pairs {
        hasher.update(k);
        hasher.update(v);
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::{AccountInfo, B256};

    fn test_db() -> MemDb {
        let mut db = MemDb::default();

        // Account A: balance 1000, nonce 5
        let addr_a = Address::from([0xaa; 20]);
        let info_a = AccountInfo {
            balance: U256::from(1000),
            nonce: 5,
            code_hash: B256::ZERO,
            code: None,
        };
        db.accounts.insert(addr_a, info_a);

        // Storage for account A: slot 0 = 0x1234
        let slot = U256::from(1);
        db.storage.insert((addr_a, slot), U256::from(0x1234));

        // Account B: zero balance, nonce 0
        let addr_b = Address::from([0xbb; 20]);
        let info_b = AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: B256::ZERO,
            code: None,
        };
        db.accounts.insert(addr_b, info_b);

        db
    }

    #[test]
    fn test_empty_state_root() {
        let db = MemDb::default();
        let root_hex = compute_state_root_hex(&db);
        assert_eq!(root_hex, EMPTY_TRIE_ROOT_HEX);
    }

    #[test]
    fn test_empty_storage_root() {
        let db = test_db();
        let addr = Address::from([0xbb; 20]);
        let root_hex = compute_storage_root_hex(&addr, &db);
        assert_eq!(root_hex, EMPTY_TRIE_ROOT_HEX);
    }

    #[test]
    fn test_state_root_deterministic() {
        let db = test_db();
        let root1 = compute_state_root_hex(&db);
        let root2 = compute_state_root_hex(&db);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_storage_root_non_empty() {
        let db = test_db();
        let addr = Address::from([0xaa; 20]);
        let root_hex = compute_storage_root_hex(&addr, &db);
        // Should not be empty trie root
        assert_ne!(root_hex, EMPTY_TRIE_ROOT_HEX);
        // Should be a valid hex string
        assert!(root_hex.starts_with("0x"));
        assert_eq!(root_hex.len(), 66);
    }
}
