//! Cryptographic utilities for transaction handling.
//!
//! This module provides functions for deriving addresses from public keys
//! and constructing the byte string that is signed by transactions.

use crate::types::Tx;
use serde_json;
use thiserror::Error;

/// Error type for transaction signing preparation.
#[derive(Debug, Error)]
pub enum TxSignError {
    #[error("failed to serialize transaction for signing: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Derive a human‑readable address from a public key.
///
/// The address is the first 20 bytes of the BLAKE3 hash of the public key,
/// encoded in hex. This matches the `from` field in the transaction.
///
/// # Example
/// ```
/// let pk = vec![1u8; 32];
/// let addr = derive_address(&pk);
/// assert_eq!(addr.len(), 40); // 20 bytes hex
/// ```
pub fn derive_address(pubkey: &[u8]) -> String {
    let h = blake3::hash(pubkey);
    hex::encode(&h.as_bytes()[..20])
}

/// Compute the bytes that should be signed for a transaction.
///
/// The format is a JSON array with the following fields (in order):
/// - `"iona-tx-v1"` – protocol version marker
/// - `chain_id`
/// - `pubkey` (as bytes)
/// - `nonce`
/// - `max_fee_per_gas`
/// - `max_priority_fee_per_gas`
/// - `gas_limit`
/// - `payload`
///
/// This representation is stable across different implementations because
/// the field order is fixed and JSON serialization of arrays preserves order.
///
/// # Errors
/// Returns `TxSignError` if serialization fails (unlikely with these types).
pub fn tx_sign_bytes(tx: &Tx) -> Result<Vec<u8>, TxSignError> {
    let serialized = serde_json::to_vec(&(
        "iona-tx-v1",
        tx.chain_id,
        &tx.pubkey,
        tx.nonce,
        tx.max_fee_per_gas,
        tx.max_priority_fee_per_gas,
        tx.gas_limit,
        &tx.payload,
    ))?;
    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx() -> Tx {
        Tx {
            pubkey: vec![1u8; 32],
            from: "from".into(),
            nonce: 42,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 21_000,
            payload: "test".into(),
            signature: vec![],
            chain_id: 1,
        }
    }

    #[test]
    fn test_derive_address() {
        let pk = vec![0xaa; 32];
        let addr = derive_address(&pk);
        assert_eq!(addr.len(), 40); // 20 bytes in hex
        // Known value from BLAKE3 of 0xaa repeated 32 times.
        // Not asserting exact value, just that it's deterministic.
        let addr2 = derive_address(&pk);
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_tx_sign_bytes_deterministic() {
        let tx = dummy_tx();
        let bytes1 = tx_sign_bytes(&tx).unwrap();
        let bytes2 = tx_sign_bytes(&tx).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_tx_sign_bytes_contains_fields() {
        let tx = dummy_tx();
        let bytes = tx_sign_bytes(&tx).unwrap();
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("iona-tx-v1"));
        assert!(s.contains(&tx.chain_id.to_string()));
        assert!(s.contains(&tx.nonce.to_string()));
    }
}
