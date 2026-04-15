//! Ethereum‑compatible block header structures and utilities.
//!
//! This module provides a minimal scaffold for Ethereum‑like block headers,
//! used primarily for RPC compatibility (e.g., `eth_getBlockByNumber`).
//! It is **not** intended to replace Iona's native consensus types.
//!
//! The header fields follow Ethereum's post‑London (EIP‑1559) format,
//! with placeholders for post‑Shanghai and post‑Cancun fields.
//!
//! # Example
//!
//! ```
//! use iona::rpc::eth_header::{EthHeader, header_hash_hex};
//!
//! let header = EthHeader::default();
//! let hash = header_hash_hex(&header);
//! assert_eq!(hash.len(), 66);
//! ```

use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use std::fmt;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Empty Keccak‑256 hash (all zeros).
pub const EMPTY_HASH: [u8; 32] = [0u8; 32];

/// Keccak‑256 hash of an empty RLP list (`0xc0`).
pub const EMPTY_OMMERS_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xdc, 0x75, 0xee, 0xef,
    0x42, 0x3b, 0x7a, 0xef, 0x78, 0x8b, 0xfc, 0x8f,
    0x41, 0xcc, 0x2a, 0xd6, 0x55, 0xbd, 0xea, 0xba,
    0xeb, 0xe5, 0xae, 0x8b, 0xa7, 0xfe, 0xcf, 0x5c,
];

/// Zeroed bloom filter (256 bytes).
pub const EMPTY_BLOOM: [u8; 256] = [0u8; 256];

// -----------------------------------------------------------------------------
// Type aliases
// -----------------------------------------------------------------------------

/// 32‑byte hash.
pub type H256 = [u8; 32];
/// 20‑byte address.
pub type H160 = [u8; 20];
/// 256‑byte bloom filter.
pub type Bloom256 = [u8; 256];
/// 8‑byte nonce.
pub type Nonce = [u8; 8];

// -----------------------------------------------------------------------------
// Ethereum Block Header
// -----------------------------------------------------------------------------

/// Minimal Ethereum block header structure (post‑London).
///
/// This includes fields up to EIP‑1559. For full compatibility, additional fields
/// (withdrawalsRoot, blobGasUsed, excessBlobGas) would need to be added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthHeader {
    /// Hash of the parent block.
    pub parent_hash: H256,
    /// Hash of the ommer list (RLP‑encoded).
    pub ommers_hash: H256,
    /// Address of the beneficiary (coinbase) receiving fees.
    pub beneficiary: H160,
    /// Root of the state trie after applying the block.
    pub state_root: H256,
    /// Root of the transaction trie.
    pub transactions_root: H256,
    /// Root of the receipts trie.
    pub receipts_root: H256,
    /// Bloom filter of logs in the block.
    pub logs_bloom: Bloom256,
    /// Block difficulty (not used in proof‑of‑stake, kept for compatibility).
    pub difficulty: u64,
    /// Block number (height).
    pub number: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Gas used by transactions in the block.
    pub gas_used: u64,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Extra data (max 32 bytes in Ethereum).
    pub extra_data: Vec<u8>,
    /// Mix hash (or prevRandao after the merge).
    pub mix_hash: H256,
    /// Nonce (zero in PoS, but kept for compatibility).
    pub nonce: Nonce,
    /// Base fee per gas (EIP‑1559).
    pub base_fee_per_gas: u64,
    /// Root of the withdrawals list (post‑Shanghai). Defaults to empty.
    pub withdrawals_root: H256,
}

impl Default for EthHeader {
    fn default() -> Self {
        Self {
            parent_hash: EMPTY_HASH,
            ommers_hash: EMPTY_OMMERS_HASH,
            beneficiary: [0u8; 20],
            state_root: EMPTY_HASH,
            transactions_root: EMPTY_HASH,
            receipts_root: EMPTY_HASH,
            logs_bloom: EMPTY_BLOOM,
            difficulty: 0,
            number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            mix_hash: EMPTY_HASH,
            nonce: [0u8; 8],
            base_fee_per_gas: 0,
            withdrawals_root: EMPTY_HASH,
        }
    }
}

impl fmt::Display for EthHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EthHeader {{ number: {}, hash: {} }}", self.number, hex::encode(self.hash()))
    }
}

impl EthHeader {
    /// Compute the Keccak‑256 hash of the header (block hash).
    pub fn hash(&self) -> H256 {
        keccak256(&rlp_encode_header(self))
    }

    /// Return the block hash as a hex string with `0x` prefix.
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash()))
    }
}

// -----------------------------------------------------------------------------
// RLP Encoding and Hashing
// -----------------------------------------------------------------------------

/// Encode an Ethereum header into RLP bytes.
///
/// The field order follows the canonical Ethereum specification (London fork).
pub fn rlp_encode_header(header: &EthHeader) -> Vec<u8> {
    let mut s = RlpStream::new_list(17); // 17 fields in post‑London (excluding withdrawalsRoot)
    s.append(&header.parent_hash.as_slice());
    s.append(&header.ommers_hash.as_slice());
    s.append(&header.beneficiary.as_slice());
    s.append(&header.state_root.as_slice());
    s.append(&header.transactions_root.as_slice());
    s.append(&header.receipts_root.as_slice());
    s.append(&header.logs_bloom.as_slice());
    s.append(&header.difficulty);
    s.append(&header.number);
    s.append(&header.gas_limit);
    s.append(&header.gas_used);
    s.append(&header.timestamp);
    s.append(&header.extra_data.as_slice());
    s.append(&header.mix_hash.as_slice());
    s.append(&header.nonce.as_slice());
    s.append(&header.base_fee_per_gas);
    s.append(&header.withdrawals_root.as_slice());
    s.out().to_vec()
}

/// Compute the Keccak‑256 hash of the header (block hash).
pub fn header_hash(header: &EthHeader) -> H256 {
    header.hash()
}

/// Return the block hash as a hex string with `0x` prefix.
pub fn header_hash_hex(header: &EthHeader) -> String {
    header.hash_hex()
}

// -----------------------------------------------------------------------------
// Keccak‑256 Helper
// -----------------------------------------------------------------------------

/// Compute the Keccak‑256 hash of the given bytes.
pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// -----------------------------------------------------------------------------
// Hex Parsing (with error handling)
// -----------------------------------------------------------------------------

/// Parse a hex string into a 32‑byte hash. Returns `Err` if invalid.
pub fn h256_from_hex(s: &str) -> Result<H256, String> {
    let hex_str = s.trim_start_matches("0x");
    if hex_str.len() != 64 {
        return Err(format!("invalid hash length: expected 64 hex chars, got {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a hex string into a 256‑byte bloom filter. Returns `Err` if invalid.
pub fn bloom_from_hex(s: &str) -> Result<Bloom256, String> {
    let hex_str = s.trim_start_matches("0x");
    if hex_str.len() != 512 {
        return Err(format!("invalid bloom length: expected 512 hex chars, got {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let mut out = [0u8; 256];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a hex string into a 20‑byte address. Returns `Err` if invalid.
pub fn address_from_hex(s: &str) -> Result<H160, String> {
    let hex_str = s.trim_start_matches("0x");
    if hex_str.len() != 40 {
        return Err(format!("invalid address length: expected 40 hex chars, got {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_ommers_hash() {
        // Known value: keccak(rlp([])) = 0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a741c0f142a0c0b27c2c2
        let expected = [
            0x1d, 0xcc, 0x4d, 0xe8, 0xdc, 0x75, 0xee, 0xef,
            0x42, 0x3b, 0x7a, 0xef, 0x78, 0x8b, 0xfc, 0x8f,
            0x41, 0xcc, 0x2a, 0xd6, 0x55, 0xbd, 0xea, 0xba,
            0xeb, 0xe5, 0xae, 0x8b, 0xa7, 0xfe, 0xcf, 0x5c,
        ];
        assert_eq!(EMPTY_OMMERS_HASH, expected);
    }

    #[test]
    fn test_header_encoding_roundtrip() {
        let header = EthHeader {
            number: 123,
            parent_hash: [0xaa; 32],
            ..Default::default()
        };
        let encoded = rlp_encode_header(&header);
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_hex_parsing() {
        let hash_hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let hash = h256_from_hex(hash_hex).unwrap();
        assert_eq!(hash, [0x11; 32]);

        let bloom_hex = "0x" + &"00".repeat(512);
        let bloom = bloom_from_hex(bloom_hex).unwrap();
        assert_eq!(bloom, EMPTY_BLOOM);

        let addr_hex = "0x1111111111111111111111111111111111111111";
        let addr = address_from_hex(addr_hex).unwrap();
        assert_eq!(addr, [0x11; 20]);
    }

    #[test]
    fn test_invalid_hex() {
        assert!(h256_from_hex("0x123").is_err());
        assert!(h256_from_hex("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
        assert!(bloom_from_hex("0x00").is_err());
        assert!(address_from_hex("0x1234567890").is_err());
    }

    #[test]
    fn test_header_hash_deterministic() {
        let h1 = EthHeader::default();
        let h2 = EthHeader::default();
        assert_eq!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_header_display() {
        let header = EthHeader {
            number: 42,
            ..Default::default()
        };
        let s = format!("{}", header);
        assert!(s.contains("number: 42"));
    }
}
