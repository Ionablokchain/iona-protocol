//! Ethereum logs bloom filter — 256 bytes (2048 bits).
//!
//! Implements the Ethereum bloom filter algorithm (EIP-234):
//! for each inserted item, 3 bit positions are set using consecutive
//! 2‑byte windows of the keccak256 hash.
//!
//! # Example
//!
//! ```
//! use iona::rpc::bloom::Bloom;
//!
//! let mut bloom = Bloom::zero();
//! bloom.insert(b"hello");
//! assert!(bloom.contains(b"hello"));
//! assert!(!bloom.contains(b"world"));
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Number of bytes in a bloom filter (256 bytes = 2048 bits).
pub const BLOOM_BYTES: usize = 256;
/// Number of bits in a bloom filter.
pub const BLOOM_BITS: usize = BLOOM_BYTES * 8;

/// Ethereum logs bloom filter — 256 bytes (2048 bits).
///
/// `Default` is manually derived because `[u8; 256]` does not automatically
/// derive `Default` in all contexts (but it does in Rust 2021, we keep explicit
/// for clarity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bloom(pub [u8; BLOOM_BYTES]);

impl Default for Bloom {
    fn default() -> Self {
        Bloom([0u8; BLOOM_BYTES])
    }
}

impl Bloom {
    /// Create an empty bloom filter (all zeros).
    pub fn zero() -> Self {
        Self::default()
    }

    /// Insert an item into the bloom filter.
    ///
    /// Sets three bits based on the Keccak‑256 hash of `data`.
    /// The bits are determined by the first 6 bytes of the hash,
    /// each 16‑bit value masked with `BLOOM_BITS - 1`.
    pub fn insert(&mut self, data: &[u8]) {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2 * i] as u16) << 8 | hash[2 * i + 1] as u16) & (BLOOM_BITS - 1) as u16;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            self.0[byte_index] |= 1u8 << bit_in_byte;
        }
    }

    /// Test whether an item *might* be in the set (false positives possible).
    ///
    /// Returns `true` if all three bits that would be set by `insert(data)`
    /// are already set in this bloom filter.
    pub fn contains(&self, data: &[u8]) -> bool {
        let hash = keccak256(data);
        for i in 0..3 {
            let bitpos = ((hash[2 * i] as u16) << 8 | hash[2 * i + 1] as u16) & (BLOOM_BITS - 1) as u16;
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            if self.0[byte_index] & (1u8 << bit_in_byte) == 0 {
                return false;
            }
        }
        true
    }

    /// Check if the bloom filter is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Bitwise OR: combine another bloom filter into this one (in‑place).
    pub fn accrue(&mut self, other: &Bloom) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a |= b;
        }
    }

    /// Return a new bloom filter that is the bitwise OR of `self` and `other`.
    pub fn or(&self, other: &Bloom) -> Bloom {
        let mut result = self.clone();
        result.accrue(other);
        result
    }

    /// Create a bloom filter from an iterator of byte slices.
    pub fn from_iter<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut bloom = Bloom::zero();
        for data in iter {
            bloom.insert(data);
        }
        bloom
    }

    /// Encode to a hex string with `0x` prefix (512 hex characters).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Decode from a hex string (with or without `0x` prefix).
    /// Returns `None` if the string is invalid or length is not 512 hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        let hex_str = s.trim_start_matches("0x");
        if hex_str.len() != BLOOM_BYTES * 2 {
            return None;
        }
        let bytes = hex::decode(hex_str).ok()?;
        let mut arr = [0u8; BLOOM_BYTES];
        arr.copy_from_slice(&bytes);
        Some(Bloom(arr))
    }
}

/// Compute the Keccak‑256 hash of the input data.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_insert_contains() {
        let mut bloom = Bloom::zero();
        bloom.insert(b"hello");
        assert!(bloom.contains(b"hello"));
        assert!(!bloom.contains(b"world"));
    }

    #[test]
    fn test_bloom_is_zero() {
        let bloom = Bloom::zero();
        assert!(bloom.is_zero());

        let mut non_zero = Bloom::zero();
        non_zero.insert(b"something");
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_bloom_accrue() {
        let mut b1 = Bloom::zero();
        let mut b2 = Bloom::zero();
        b1.insert(b"a");
        b2.insert(b"b");

        let mut merged = b1.clone();
        merged.accrue(&b2);
        assert!(merged.contains(b"a"));
        assert!(merged.contains(b"b"));
        assert!(!merged.contains(b"c"));
    }

    #[test]
    fn test_bloom_or() {
        let mut b1 = Bloom::zero();
        let mut b2 = Bloom::zero();
        b1.insert(b"a");
        b2.insert(b"b");

        let merged = b1.or(&b2);
        assert!(merged.contains(b"a"));
        assert!(merged.contains(b"b"));
    }

    #[test]
    fn test_bloom_from_iter() {
        let items = vec![b"a", b"b"];
        let bloom = Bloom::from_iter(items);
        assert!(bloom.contains(b"a"));
        assert!(bloom.contains(b"b"));
        assert!(!bloom.contains(b"c"));
    }

    #[test]
    fn test_bloom_hex_roundtrip() {
        let mut bloom = Bloom::zero();
        bloom.insert(b"test");
        let hex = bloom.to_hex();
        let parsed = Bloom::from_hex(&hex).unwrap();
        assert_eq!(bloom, parsed);
    }

    #[test]
    fn test_bloom_from_hex_invalid() {
        assert!(Bloom::from_hex("0x123").is_none());
        assert!(Bloom::from_hex("0x" + &"00".repeat(300)).is_none());
        assert!(Bloom::from_hex("not hex").is_none());
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"");
        // Known empty hash
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
