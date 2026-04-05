//! Withdrawals (EIP‑4895 / Shanghai) support.
//!
//! This module provides types and utilities for handling withdrawals in Ethereum‑compatible
//! block headers and RPC responses. Withdrawals were introduced in the Shanghai hard fork
//! (EIP‑4895) and allow validators to withdraw staked ETH from the beacon chain.

use rlp::RlpStream;
use serde::{Deserialize, Serialize};

/// 20‑byte Ethereum address.
pub type H160 = [u8; 20];

/// A withdrawal from the beacon chain to an execution layer account.
///
/// Withdrawals are included in the execution block header via the `withdrawals_root` field,
/// which is the root of an ordered Merkle‑Patricia Trie over RLP‑encoded withdrawals.
fn deserialize_hex_address<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
where D: serde::Deserializer<'de> {
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    let hex_str = s.trim_start_matches("0x");
    let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
    if bytes.len() != 20 {
        return Err(serde::de::Error::custom("address must be 20 bytes"));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn serialize_hex_address<S>(addr: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    serializer.serialize_str(&format!("0x{}", hex::encode(addr)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    /// Unique index of the withdrawal.
    pub index: u64,
    /// Index of the validator making the withdrawal.
    pub validator_index: u64,
    /// Execution layer address receiving the funds.
    #[serde(serialize_with = "serialize_hex_address", deserialize_with = "deserialize_hex_address")]
    pub address: H160,
    /// Amount in Gwei (1 Gwei = 10^9 wei).
    pub amount_gwei: u64,
}

impl Withdrawal {
    /// Creates a new withdrawal.
    pub fn new(index: u64, validator_index: u64, address: H160, amount_gwei: u64) -> Self {
        Self {
            index,
            validator_index,
            address,
            amount_gwei,
        }
    }

    /// RLP‑encodes the withdrawal according to the Ethereum specification.
    ///
    /// The encoding is: `RLP([index, validator_index, address, amount])`.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut s = RlpStream::new_list(4);
        s.append(&self.index);
        s.append(&self.validator_index);
        s.append(&self.address.as_slice());
        s.append(&self.amount_gwei);
        s.out().to_vec()
    }
}

/// Computes the `withdrawalsRoot` field of an Ethereum block header.
///
/// The root is the hash of an ordered Merkle‑Patricia Trie over RLP‑encoded withdrawals,
/// where each withdrawal is stored at the key `RLP(index)`.
///
/// # Returns
/// A hex string with `0x` prefix.
pub fn withdrawals_root_hex(withdrawals: &[Withdrawal]) -> String {
    let items: Vec<Vec<u8>> = withdrawals
        .iter()
        .map(|w| w.rlp_encode())
        .collect();
    // `eth_ordered_trie_root_hex` is assumed to be defined in `crate::rpc::mpt`.
    // It computes the root of an ordered trie from RLP‑encoded items.
    crate::rpc::mpt::eth_ordered_trie_root_hex(&items)
}

/// Convenience function to compute the root as bytes (if needed).
pub fn withdrawals_root_bytes(withdrawals: &[Withdrawal]) -> Vec<u8> {
    // The hex string has `0x` prefix; we strip it and decode.
    let hex = withdrawals_root_hex(withdrawals);
    hex::decode(hex.trim_start_matches("0x")).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_withdrawal_rlp_encode() {
        let w = Withdrawal::new(1, 2, [0xaa; 20], 1000);
        let encoded = w.rlp_encode();
        // RLP of [1, 2, 0xaa...20, 1000] – we can check a known length.
        // This is a basic test; in production you may want to compare with known vectors.
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_withdrawals_root_hex() {
        let withdrawals = vec![
            Withdrawal::new(0, 0, [0xaa; 20], 10_000_000_000),
        ];
        let root = withdrawals_root_hex(&withdrawals);
        // The root is a hex string of length 66 (including 0x)
        assert_eq!(root.len(), 66);
        assert!(root.starts_with("0x"));
    }

    #[test]
    fn test_serialization() {
        let w = Withdrawal::new(42, 7, [0xbb; 20], 5_000_000_000);
        let json = serde_json::to_string(&w).unwrap();
        // Minimal check: it contains the fields.
        assert!(json.contains("\"index\":42"));
        assert!(json.contains("\"amount_gwei\":5000000000"));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "index": 1,
            "validator_index": 2,
            "address": "0x1111111111111111111111111111111111111111",
            "amount_gwei": 1000
        }"#;
        let w: Withdrawal = serde_json::from_str(json).unwrap();
        assert_eq!(w.index, 1);
        assert_eq!(w.validator_index, 2);
        assert_eq!(w.address, [0x11; 20]);
        assert_eq!(w.amount_gwei, 1000);
    }
}
