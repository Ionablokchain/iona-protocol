// Ethereum Merkle Patricia Trie proofs for accounts and storage.
//
// This module provides functions to generate proofs for account state and storage slots,
// used by the `eth_getProof` RPC method.
//
// **Limitation**: trie-db version mismatch (0.31 vs 0.28) prevents full implementation.
// Functions are stubbed until resolved.

use crate::evm::db::MemDb;
use revm::primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

// -----------------------------------------------------------------------------
// Proof structures (compatible with Ethereum JSON-RPC)
// -----------------------------------------------------------------------------

/// Proof for a single storage slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    pub key: String,
    pub value: String,
    pub proof: Vec<String>,
}

/// Full account proof as returned by `eth_getProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProof {
    pub address: String,
    pub balance: String,
    pub nonce: String,
    pub code_hash: String,
    pub storage_hash: String,
    pub account_proof: Vec<String>,
    pub storage_proofs: Vec<StorageProof>,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn u256_to_trimmed_be(v: U256) -> Vec<u8> {
    let bytes = v.to_be_bytes::<32>().to_vec();
    let trimmed = bytes.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<_>>();
    if trimmed.is_empty() { vec![0u8] } else { trimmed }
}

fn rlp_encode_u256(v: U256) -> Vec<u8> {
    let trimmed = u256_to_trimmed_be(v);
    rlp::encode(&trimmed.as_slice()).to_vec()
}

fn rlp_encode_account(nonce: u64, balance: U256, storage_root: [u8; 32], code_hash: [u8; 32]) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(4);
    stream.append(&nonce);
    let balance_trimmed = u256_to_trimmed_be(balance);
    stream.append(&balance_trimmed.as_slice());
    stream.append(&storage_root.as_slice());
    stream.append(&code_hash.as_slice());
    stream.out().to_vec()
}

const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

// -----------------------------------------------------------------------------
// Proof generation (stubbed - trie-db version mismatch)
// -----------------------------------------------------------------------------

/// Build a complete account proof for the given address and storage keys.
/// Stubbed: returns a default proof until trie-db version mismatch is resolved.
pub fn build_proof(db: &MemDb, addr: Address, _storage_keys: Vec<[u8; 32]>) -> Result<AccountProof, String> {
    Ok(AccountProof {
        address: format!("0x{}", hex::encode(addr)),
        account_proof: vec![],
        balance: "0x0".to_string(),
        code_hash: format!("0x{}", "0".repeat(64)),
        nonce: "0x0".to_string(),
        storage_hash: format!("0x{}", "0".repeat(64)),
        storage_proofs: vec![],
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[allow(unused)]
mod tests {
    use super::*;
    use revm::primitives::{AccountInfo, B256};

    fn setup_test_db() -> MemDb {
        let mut db = MemDb::default();

        let addr_a = Address::from([0xaa; 20]);
        let acc_a = AccountInfo {
            balance: U256::from(1000u64),
            nonce: 5,
            code_hash: B256::ZERO,
            code: None,
        };
        db.accounts.insert(addr_a, acc_a);

        let slot1 = U256::from(1);
        let val1 = U256::from(0x1234);
        db.storage.insert((addr_a, slot1), val1);

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
    fn test_build_proof_returns_ok() {
        let db = setup_test_db();
        let addr = Address::from([0xaa; 20]);
        let result = build_proof(&db, addr, vec![]);
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.address, format!("0x{}", hex::encode(addr)));
    }
}
