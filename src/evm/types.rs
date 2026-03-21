//! EVM primitive type aliases and conversion utilities.
//!
//! This module re‑exports common REVM types and provides helpers to convert
//! between Iona's native types (32‑byte addresses, hash arrays) and EVM types
//! (20‑byte addresses, `U256`, `B256`).

pub use revm::primitives::{Address, Bytes, B256, U256};

/// Alias for EVM address (20 bytes).
pub type EvmAddress = Address;

/// Alias for EVM 256‑bit hash.
pub type EvmHash = B256;

/// Alias for EVM 256‑bit integer.
pub type EvmU256 = U256;

// ── Address conversions (32‑byte ↔ 20‑byte) ───────────────────────────────────

/// Convert a 32‑byte Iona address to a 20‑byte EVM address (last 20 bytes).
pub fn iona_to_evm_addr(iona: &[u8; 32]) -> Address {
    Address::from_slice(&iona[12..])
}

/// Convert a 20‑byte EVM address to a 32‑byte Iona address (zero‑padded).
pub fn evm_to_iona_addr(evm: Address) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(evm.as_slice());
    out
}

// ── Byte array ↔ U256 ─────────────────────────────────────────────────────────

/// Convert a `U256` to a `[u8; 32]` big‑endian representation.
pub fn u256_to_be_bytes(v: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    v.to_big_endian(&mut bytes);
    bytes
}

/// Convert a `[u8; 32]` big‑endian representation to a `U256`.
pub fn be_bytes_to_u256(bytes: [u8; 32]) -> U256 {
    U256::from_be_bytes(bytes)
}

// ── Byte array ↔ B256 ────────────────────────────────────────────────────────

/// Convert a `B256` to a `[u8; 32]`.
pub fn b256_to_bytes(h: B256) -> [u8; 32] {
    h.0
}

/// Convert a `[u8; 32]` to a `B256`.
pub fn bytes_to_b256(bytes: [u8; 32]) -> B256 {
    B256::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_roundtrip() {
        let mut iona = [0u8; 32];
        iona[31] = 0xaa;
        let evm = iona_to_evm_addr(&iona);
        let back = evm_to_iona_addr(evm);
        assert_eq!(iona, back);
    }

    #[test]
    fn test_u256_conversion() {
        let v = U256::from(0xdeadbeefu64);
        let bytes = u256_to_be_bytes(v);
        let back = be_bytes_to_u256(bytes);
        assert_eq!(v, back);
    }

    #[test]
    fn test_b256_conversion() {
        let bytes = [0xaa; 32];
        let b = bytes_to_b256(bytes);
        let back = b256_to_bytes(b);
        assert_eq!(bytes, back);
    }
}
