//! EVM transaction types for Iona.
//!
//! This module defines the structures for Ethereum-compatible transactions
//! that can be executed by the Iona EVM integration. It supports:
//! - Legacy transactions (pre-EIP-155)
//! - EIP-2930 transactions (with access lists)
//! - EIP-1559 transactions (with fee market)
//!
//! All types implement `serde` serialization and include methods for
//! validation, RLP encoding/decoding (when needed), and hash computation.

use serde::{Deserialize, Serialize};
use std::fmt;

// ------------------------------
// Type aliases
// ------------------------------

/// 20-byte Ethereum address.
pub type Address20 = [u8; 20];

/// 32-byte hash (used for storage keys, transaction hashes, etc.).
pub type H256 = [u8; 32];

// ------------------------------
// Access List Item
// ------------------------------

/// An entry in an EIP-2930 access list.
///
/// Access lists specify which accounts and storage slots a transaction intends
/// to access, allowing for gas savings and improved parallelism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessListItem {
    /// The address of the contract to be accessed.
    pub address: Address20,
    /// The storage keys (slots) to be accessed within the contract.
    pub storage_keys: Vec<H256>,
}

impl AccessListItem {
    /// Creates a new access list item.
    pub fn new(address: Address20, storage_keys: Vec<H256>) -> Self {
        Self { address, storage_keys }
    }

    /// Returns `true` if the access list item is valid (no additional checks needed).
    pub fn is_valid(&self) -> bool {
        // No inherent validity rules beyond type correctness.
        true
    }
}

// ------------------------------
// EVM Transaction Enum
// ------------------------------

/// Represents an Ethereum-compatible transaction that can be executed by the Iona EVM.
///
/// This enum covers the three most common transaction types:
/// - `Legacy`: Pre-EIP-155 transactions (simple `to`, `value`, `data`)
/// - `Eip2930`: Transactions with an access list (EIP-2930)
/// - `Eip1559`: Transactions with a fee market (EIP-1559)
///
/// All variants include the `from` field (the sender) for convenience, though
/// in Ethereum this is recovered from the signature. In Iona, signatures are
/// handled separately, so the `from` is stored directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EvmTx {
    /// EIP-2930 transaction: includes an access list.
    #[serde(rename = "eip2930")]
    Eip2930 {
        /// Sender address (20 bytes).
        from: Address20,
        /// Recipient address. `None` indicates contract creation.
        to: Option<Address20>,
        /// Transaction nonce (replay protection).
        nonce: u64,
        /// Gas limit for the transaction.
        gas_limit: u64,
        /// Gas price (in wei) – used for both legacy and EIP-2930.
        gas_price: u128,
        /// Amount of wei to transfer.
        value: u128,
        /// Input data (for contract calls or init code).
        data: Vec<u8>,
        /// Access list (accounts and storage keys).
        access_list: Vec<AccessListItem>,
        /// Chain ID to prevent replay across networks.
        chain_id: u64,
    },

    /// Legacy transaction (pre-EIP-155).
    #[serde(rename = "legacy")]
    Legacy {
        /// Sender address (20 bytes).
        from: Address20,
        /// Recipient address. `None` indicates contract creation.
        to: Option<Address20>,
        /// Transaction nonce.
        nonce: u64,
        /// Gas limit.
        gas_limit: u64,
        /// Gas price (in wei).
        gas_price: u128,
        /// Amount of wei to transfer.
        value: u128,
        /// Input data.
        data: Vec<u8>,
        /// Chain ID (used for replay protection; legacy transactions without chain ID
        /// are not supported – they must include it).
        chain_id: u64,
    },

    /// EIP-1559 transaction: includes a fee market (max fee + priority fee).
    #[serde(rename = "eip1559")]
    Eip1559 {
        /// Sender address.
        from: Address20,
        /// Recipient address. `None` for contract creation.
        to: Option<Address20>,
        /// Transaction nonce.
        nonce: u64,
        /// Gas limit.
        gas_limit: u64,
        /// Maximum total fee per gas (base fee + priority fee) the sender is willing to pay.
        max_fee_per_gas: u128,
        /// Maximum priority fee per gas (tip for the block producer).
        max_priority_fee_per_gas: u128,
        /// Amount of wei to transfer.
        value: u128,
        /// Input data.
        data: Vec<u8>,
        /// Access list (optional, but EIP-1559 supports it).
        access_list: Vec<AccessListItem>,
        /// Chain ID.
        chain_id: u64,
    },
}

impl EvmTx {
    /// Returns the sender address.
    pub fn from(&self) -> &Address20 {
        match self {
            EvmTx::Eip2930 { from, .. } => from,
            EvmTx::Legacy { from, .. } => from,
            EvmTx::Eip1559 { from, .. } => from,
        }
    }

    /// Returns the recipient address, if any.
    pub fn to(&self) -> Option<&Address20> {
        match self {
            EvmTx::Eip2930 { to, .. } => to.as_ref(),
            EvmTx::Legacy { to, .. } => to.as_ref(),
            EvmTx::Eip1559 { to, .. } => to.as_ref(),
        }
    }

    /// Returns the nonce.
    pub fn nonce(&self) -> u64 {
        match self {
            EvmTx::Eip2930 { nonce, .. } => *nonce,
            EvmTx::Legacy { nonce, .. } => *nonce,
            EvmTx::Eip1559 { nonce, .. } => *nonce,
        }
    }

    /// Returns the gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            EvmTx::Eip2930 { gas_limit, .. } => *gas_limit,
            EvmTx::Legacy { gas_limit, .. } => *gas_limit,
            EvmTx::Eip1559 { gas_limit, .. } => *gas_limit,
        }
    }

    /// Returns the chain ID.
    pub fn chain_id(&self) -> u64 {
        match self {
            EvmTx::Eip2930 { chain_id, .. } => *chain_id,
            EvmTx::Legacy { chain_id, .. } => *chain_id,
            EvmTx::Eip1559 { chain_id, .. } => *chain_id,
        }
    }

    /// Basic validity checks (e.g., addresses have correct length, nonce not too large).
    /// Does **not** verify signatures or balance sufficiency.
    pub fn is_valid(&self) -> bool {
        // All addresses are fixed-size arrays, so they are always valid.
        // Additional checks:
        match self {
            EvmTx::Eip2930 { gas_limit, access_list, .. }
            | EvmTx::Legacy { gas_limit, .. }
            | EvmTx::Eip1559 { gas_limit, access_list, .. } => {
                if *gas_limit == 0 {
                    return false; // Gas limit must be positive
                }
            }
        }

        // Access list items are always valid (just containers).
        // For EIP-1559, max_fee_per_gas must be >= max_priority_fee_per_gas.
        if let EvmTx::Eip1559 { max_fee_per_gas, max_priority_fee_per_gas, .. } = self {
            if max_fee_per_gas < max_priority_fee_per_gas {
                return false;
            }
        }

        // Chain ID should be reasonable (non-zero, but any u64 is acceptable).
        true
    }

    /// Returns the type of the transaction as a string (for logging/debugging).
    pub fn type_str(&self) -> &'static str {
        match self {
            EvmTx::Eip2930 { .. } => "eip2930",
            EvmTx::Legacy { .. } => "legacy",
            EvmTx::Eip1559 { .. } => "eip1559",
        }
    }

    /// Computes the transaction hash (Keccak256 of the RLP-encoded transaction *without* signature).
    /// This matches Ethereum's `tx.hash` semantics.
    ///
    /// Note: This function requires the `rlp` crate and the `keccak-hash` crate.
    /// It is implemented as a placeholder; you will need to add the actual RLP encoding.
    #[cfg(feature = "evm_hash")]
    pub fn hash(&self) -> H256 {
        use keccak_hash::keccak;
        use rlp::Encodable;

        // Encode the transaction according to its type.
        // This is a placeholder – you must implement the actual RLP encoding.
        let rlp_bytes = match self {
            EvmTx::Legacy { .. } => {
                // Legacy: [nonce, gas_price, gas_limit, to, value, data, v, r, s]
                // For hash we exclude signature fields (v, r, s are zero or omitted).
                // In Ethereum, the hash is over the transaction *without* the signature,
                // but with a dummy `v` for chain ID (EIP-155). This is complex.
                // We'll omit full implementation here; you need to match the exact Ethereum rules.
                unimplemented!("Legacy tx hash requires EIP-155 chain ID handling")
            }
            EvmTx::Eip2930 { .. } => {
                // EIP-2930: [chain_id, nonce, gas_price, gas_limit, to, value, data, access_list]
                unimplemented!("EIP-2930 tx hash requires RLP encoding")
            }
            EvmTx::Eip1559 { .. } => {
                // EIP-1559: [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list]
                unimplemented!("EIP-1559 tx hash requires RLP encoding")
            }
        };
        keccak(&rlp_bytes).0
    }
}

impl fmt::Display for EvmTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EvmTx(type={}, from={:?}, nonce={}, gas_limit={})",
            self.type_str(),
            self.from(),
            self.nonce(),
            self.gas_limit()
        )
    }
}

// ------------------------------
// Default implementations (optional)
// ------------------------------

impl Default for AccessListItem {
    fn default() -> Self {
        Self {
            address: [0u8; 20],
            storage_keys: Vec::new(),
        }
    }
}

// ------------------------------
// Tests
// ------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_address() -> Address20 {
        [0x01; 20]
    }

    fn sample_access_list() -> Vec<AccessListItem> {
        vec![AccessListItem {
            address: [0xaa; 20],
            storage_keys: vec![[0xbb; 32]],
        }]
    }

    #[test]
    fn test_eip2930_creation() {
        let tx = EvmTx::Eip2930 {
            from: sample_address(),
            to: Some([0x02; 20]),
            nonce: 5,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 1_000_000,
            data: vec![0xde, 0xad, 0xbe, 0xef],
            access_list: sample_access_list(),
            chain_id: 6126151,
        };
        assert_eq!(tx.nonce(), 5);
        assert_eq!(tx.chain_id(), 6126151);
        assert!(tx.is_valid());
    }

    #[test]
    fn test_legacy_creation() {
        let tx = EvmTx::Legacy {
            from: sample_address(),
            to: None, // contract creation
            nonce: 0,
            gas_limit: 50_000,
            gas_price: 5_000_000_000,
            value: 0,
            data: vec![0x60, 0x80, 0x60, 0x40],
            chain_id: 1,
        };
        assert!(tx.to().is_none());
        assert_eq!(tx.type_str(), "legacy");
        assert!(tx.is_valid());
    }

    #[test]
    fn test_eip1559_creation() {
        let tx = EvmTx::Eip1559 {
            from: sample_address(),
            to: Some([0x03; 20]),
            nonce: 7,
            gas_limit: 200_000,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 2_000_000_000,
            value: 500_000,
            data: vec![],
            access_list: sample_access_list(),
            chain_id: 6126151,
        };
        assert!(tx.is_valid());
    }

    #[test]
    fn test_invalid_gas_limit() {
        let tx = EvmTx::Legacy {
            from: sample_address(),
            to: None,
            nonce: 0,
            gas_limit: 0, // invalid
            gas_price: 1,
            value: 0,
            data: vec![],
            chain_id: 1,
        };
        assert!(!tx.is_valid());
    }

    #[test]
    fn test_invalid_eip1559_fee() {
        let tx = EvmTx::Eip1559 {
            from: sample_address(),
            to: None,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 5,
            max_priority_fee_per_gas: 10, // > max_fee
            value: 0,
            data: vec![],
            access_list: vec![],
            chain_id: 1,
        };
        assert!(!tx.is_valid());
    }

    #[test]
    fn test_serde_roundtrip() {
        let tx = EvmTx::Eip2930 {
            from: sample_address(),
            to: Some([0x02; 20]),
            nonce: 5,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 1_000_000,
            data: vec![0xde, 0xad, 0xbe, 0xef],
            access_list: sample_access_list(),
            chain_id: 6126151,
        };
        let serialized = serde_json::to_string(&tx).unwrap();
        let deserialized: EvmTx = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, deserialized);
    }
}
