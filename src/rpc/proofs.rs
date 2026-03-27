//! Ethereum Merkle Patricia Trie proofs for accounts and storage.
//!
//! This module provides functions to generate proofs for account state and storage slots,
//! used by the `eth_getProof` RPC method. The proofs are built from an in‑memory database
//! (`MemDb`) by reconstructing the state and storage tries on the fly.
//!
//! **Limitation**: In production, this should be replaced with a persistent state backend
//! that maintains the trie structures directly, avoiding the O(N) reconstruction cost.

use crate::evm::db::MemDb;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Proof structures (compatible with Ethereum JSON‑RPC)
// -----------------------------------------------------------------------------

/// Proof for a single storage slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    /// Slot key as a hex string (without `0x` prefix).
    pub key: String,
    /// Slot value as a hex string (without `0x` prefix). `0x0` if empty.
    pub value: String,
    /// List of RLP‑encoded trie nodes forming the proof.
    pub proof: Vec<String>,
}

/// Full account proof as returned by `eth_getProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProof {
    /// Account address as a hex string with `0x` prefix.
    pub address: String,
    /// Account balance as a hex string with `0x` prefix.
    pub balance: String,
    /// Account nonce as a hex string with `0x` prefix.
    pub nonce: String,
    /// Hash of the account's code (or empty hash).
    pub code_hash: String,
    /// Hash of the account's storage trie root.
    pub storage_hash: String,
    /// List of RLP‑encoded trie nodes forming the account proof.
    pub account_proof: Vec<String>,
    /// Proofs for each requested storage slot.
    pub storage_proofs: Vec<StorageProof>,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Keccak‑256 hash of the given data.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Format bytes as a hex string with `0x` prefix.
fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Convert a `U256` to its trimmed big‑endian representation (as used in RLP).
/// Returns `vec![0]` for zero.
fn u256_to_trimmed_be(v: U256) -> Vec<u8> {
    let mut bytes = [0u8; 32];
    v.to_big_endian(&mut bytes);
    let trimmed = bytes.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<_>>();
    if trimmed.is_empty() {
        vec![0u8]
    } else {
        trimmed
    }
}

/// RLP‑encode a `U256` value as a byte slice.
fn rlp_encode_u256(v: U256) -> Vec<u8> {
    let trimmed = u256_to_trimmed_be(v);
    rlp::encode(&trimmed.as_slice()).to_vec()
}

/// RLP‑encode an account for insertion into the state trie.
/// Format: [nonce, balance, storage_root, code_hash]
fn rlp_encode_account(nonce: u64, balance: U256, storage_root: [u8; 32], code_hash: [u8; 32]) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(4);
    stream.append(&nonce);
    // balance as trimmed bytes slice
    let balance_trimmed = u256_to_trimmed_be(balance);
    stream.append(&balance_trimmed.as_slice());
    stream.append(&storage_root.as_slice());
    stream.append(&code_hash.as_slice());
    stream.out().to_vec()
}

/// Compute the empty trie root (Keccak‑256 of RLP(empty list)).
const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

// -----------------------------------------------------------------------------
// Proof generation (rebuilds tries from MemDb)
// -----------------------------------------------------------------------------

/// Build a complete account proof for the given address and storage keys.
///
/// This function reconstructs the entire state and storage tries from the
/// in‑memory database. For production use, a persistent state backend with
/// pre‑computed tries is recommended.
pub fn build_proof(db: &MemDb, addr: Address, storage_keys: Vec<[u8; 32]>) -> Result<AccountProof, String> {
    // Build storage trie for the target account
    let (storage_memdb, storage_root) = build_storage_trie(db, addr)?;

    // Build the full state trie and obtain account proof
    let (state_memdb, state_root) = build_state_trie(db, &storage_memdb, storage_root, addr)?;

    // Extract account data from the database
    let account_info = db
        .basic(addr)
        .map_err(|e| format!("failed to read account info: {e}"))?
        .ok_or_else(|| format!("account {:?} not found", addr))?;

    let balance = account_info.balance;
    let nonce = account_info.nonce;
    let code_hash = account_info.code_hash;

    // Account proof
    let trie_state = trie_db::TrieDBBuilder::<keccak_hasher::KeccakHasher>::new(&state_memdb, &state_root).build();
    let addr_key = keccak256(addr.as_slice());
    let nodes = trie_state
        .get_proof(&addr_key)
        .map_err(|e| format!("failed to get account proof: {e}"))?;
    let account_proof = nodes.into_iter().map(|n| hex0x(&n)).collect();

    // Storage proofs for each requested slot
    let trie_storage = trie_db::TrieDBBuilder::<keccak_hasher::KeccakHasher>::new(&storage_memdb, &storage_root).build();
    let mut storage_proofs = Vec::with_capacity(storage_keys.len());

    for slot in storage_keys {
        let slot_u256 = U256::from_be_bytes(slot);
        // In Ethereum, the storage key is the hash of the slot (secure trie)
        let slot_hash = keccak256(&slot);
        let nodes = trie_storage
            .get_proof(&slot_hash)
            .map_err(|e| format!("failed to get storage proof for slot {:?}: {e}", hex0x(&slot)))?;
        let proof_nodes = nodes.into_iter().map(|n| hex0x(&n)).collect();

        // Value from database
        let value = db.storage.get(&(addr, slot_u256)).copied().unwrap_or(U256::ZERO);
        let value_hex = format!("0x{:x}", value);

        storage_proofs.push(StorageProof {
            key: hex::encode(slot),
            value: value_hex,
            proof: proof_nodes,
        });
    }

    Ok(AccountProof {
        address: hex0x(addr.as_slice()),
        balance: format!("0x{:x}", balance),
        nonce: format!("0x{:x}", nonce),
        code_hash: hex0x(&code_hash.0),
        storage_hash: hex0x(&storage_root.0),
        account_proof,
        storage_proofs,
    })
}

/// Build the storage trie for a single account.
/// Returns (in‑memory database, root hash).
fn build_storage_trie(db: &MemDb, addr: Address) -> Result<(trie_db::MemoryDB<keccak_hasher::KeccakHasher, trie_db::HashKey<_>, Vec<u8>>, [u8; 32]), String> {
    use hash_db::Hasher;
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: trie_db::MemoryDB<keccak_hasher::KeccakHasher, trie_db::HashKey<_>, Vec<u8>> = trie_db::MemoryDB::default();
    let mut root = <keccak_hasher::KeccakHasher as Hasher>::Out::default();

    {
        let mut trie = TrieDBMut::<keccak_hasher::KeccakHasher>::new(&mut memdb, &mut root);

        for ((a, slot), value) in &db.storage {
            if *a != addr {
                continue;
            }
            // Slot as big‑endian 32‑byte array
            let mut slot_bytes = [0u8; 32];
            slot.to_big_endian(&mut slot_bytes);
            let key = keccak256(&slot_bytes); // secure trie key

            // Value as RLP‑encoded trimmed bytes
            let encoded_value = rlp_encode_u256(*value);
            trie.insert(&key, &encoded_value)
                .map_err(|e| format!("failed to insert storage entry: {e}"))?;
        }
    }

    Ok((memdb, root.0))
}

/// Build the full state trie from the account database, using the pre‑computed storage trie
/// for the target account (other accounts use the empty storage root).
/// Returns (in‑memory database, root hash).
fn build_state_trie(
    db: &MemDb,
    storage_memdb: &trie_db::MemoryDB<keccak_hasher::KeccakHasher, trie_db::HashKey<_>, Vec<u8>>,
    storage_root: [u8; 32],
    target_addr: Address,
) -> Result<(trie_db::MemoryDB<keccak_hasher::KeccakHasher, trie_db::HashKey<_>, Vec<u8>>, [u8; 32]), String> {
    use hash_db::Hasher;
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: trie_db::MemoryDB<keccak_hasher::KeccakHasher, trie_db::HashKey<_>, Vec<u8>> = trie_db::MemoryDB::default();
    let mut root = <keccak_hasher::KeccakHasher as Hasher>::Out::default();

    {
        let mut trie = TrieDBMut::<keccak_hasher::KeccakHasher>::new(&mut memdb, &mut root);

        for (addr, info) in &db.accounts {
            // Determine storage root for this account
            let storage_root_for_account = if *addr == target_addr {
                storage_root
            } else {
                EMPTY_TRIE_ROOT
            };

            let nonce = info.nonce.unwrap_or(0);
            let balance = info.balance;
            let code_hash = info.code_hash;

            // RLP‑encode the account
            let encoded_account = rlp_encode_account(nonce, balance, storage_root_for_account, code_hash.0);
            let key = keccak256(addr.as_slice()); // secure trie key

            trie.insert(&key, &encoded_account)
                .map_err(|e| format!("failed to insert account: {e}"))?;
        }
    }

    Ok((memdb, root.0))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::{AccountInfo, Bytecode, B256};

    fn setup_test_db() -> MemDb {
        let mut db = MemDb::default();

        // Account A: with storage slot 0x01 = 0x1234
        let addr_a = Address::from([0xaa; 20]);
        let mut acc_a = AccountInfo {
            balance: U256::from(1000u64),
            nonce: 5,
            code_hash: B256::ZERO,
            code: None,
        };
        db.accounts.insert(addr_a, acc_a.clone());

        let slot1 = U256::from(1);
        let val1 = U256::from(0x1234);
        db.storage.insert((addr_a, slot1), val1);

        // Account B: no storage
        let addr_b = Address::from([0xbb; 20]);
        let acc_b = AccountInfo {
            balance: U256::from(2000u64),
            nonce: 0,
            code_hash: B256::ZERO,
            code: None,
        };
        db.accounts.insert(addr_b, acc_b);

        db
    }

    #[test]
    fn test_build_proof_existing_account() {
        let db = setup_test_db();
        let addr = Address::from([0xaa; 20]);
        let storage_keys = vec![[0u8; 32]]; // slot 0x00...00
        let mut slot1_bytes = [0u8; 32];
        U256::from(1).to_big_endian(&mut slot1_bytes);
        let storage_keys = vec![slot1_bytes];

        let proof = build_proof(&db, addr, storage_keys).unwrap();

        // Check account fields
        assert_eq!(proof.address, hex0x(addr.as_slice()));
        assert_eq!(proof.balance, "0x3e8"); // 1000 in hex
        assert_eq!(proof.nonce, "0x5");
        assert_eq!(proof.code_hash, hex0x(&B256::ZERO.0));
        assert_ne!(proof.storage_hash, hex0x(&EMPTY_TRIE_ROOT));

        // Account proof should have at least one node
        assert!(!proof.account_proof.is_empty());

        // Storage proof should exist
        assert_eq!(proof.storage_proofs.len(), 1);
        let sp = &proof.storage_proofs[0];
        assert_eq!(sp.key, hex::encode(slot1_bytes));
        assert_eq!(sp.value, "0x1234");
        assert!(!sp.proof.is_empty());
    }

    #[test]
    fn test_build_proof_nonexistent_account() {
        let db = setup_test_db();
        let addr = Address::from([0xcc; 20]);
        let result = build_proof(&db, addr, vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_build_proof_empty_storage() {
        let db = setup_test_db();
        let addr = Address::from([0xbb; 20]); // account with no storage
        let result = build_proof(&db, addr, vec![]).unwrap();

        assert_eq!(result.storage_hash, hex0x(&EMPTY_TRIE_ROOT));
        assert!(result.storage_proofs.is_empty());
    }
}
