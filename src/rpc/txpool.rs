//! Transaction pool for pending transactions.
//!
//! This module implements a mempool with per‑sender nonce ordering,
//! replace‑by‑fee (RBF) rules, and efficient indexing for fast
//! transaction retrieval and pruning.

use crate::mempool::{Mempool as MempoolTrait, MempoolError};
use crate::types::tx_evm::EvmTx;
use crate::types::{Hash32, Height, Tx};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum number of pending transactions per sender.
pub const DEFAULT_MAX_PER_SENDER: usize = 64;

/// Default maximum total transactions in the pool.
pub const DEFAULT_MAX_TOTAL: usize = 200_000;

/// Default maximum age of a transaction (seconds) before being pruned.
pub const DEFAULT_MAX_AGE_SECS: u64 = 300; // 5 minutes

// -----------------------------------------------------------------------------
// Pending transaction type
// -----------------------------------------------------------------------------

/// Mempool entry – raw signed transaction bytes plus metadata needed for ordering and replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,      // 0x-prefixed address
    pub nonce: u64,
    pub tx_type: u8,       // 0 = legacy, 1 = EIP-2930, 2 = EIP-1559
    pub gas_limit: u64,
    pub gas_price: u128,                    // for legacy/2930
    pub max_fee_per_gas: Option<u128>,      // for EIP-1559
    pub max_priority_fee_per_gas: Option<u128>, // for EIP-1559
    pub raw: Vec<u8>,
    pub inserted_at: u64, // unix timestamp (seconds)
}

impl PendingTx {
    /// Effective tip used for ordering (max_priority_fee for 1559, otherwise gas_price).
    pub fn priority(&self) -> u128 {
        self.max_priority_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Fee cap used for replacement (max_fee for 1559, otherwise gas_price).
    pub fn fee_cap(&self) -> u128 {
        self.max_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Create a `PendingTx` from an `EvmTx` and raw bytes.
    pub fn from_evm_tx(tx: &EvmTx, raw: Vec<u8>, inserted_at: u64) -> Result<Self, &'static str> {
        use crate::crypto::tx::derive_address;
        use crate::types::tx_evm::EvmTx;

        let hash = crate::rpc::tx_decode::keccak256_hex(&raw); // compute hash from raw
        let (from, nonce, gas_limit, tx_type, gas_price, max_fee, max_priority) = match tx {
            EvmTx::Legacy { from, nonce, gas_limit, gas_price, .. } => {
                let addr = hex::encode(from);
                (addr, *nonce, *gas_limit, 0u8, *gas_price, None, None)
            }
            EvmTx::Eip2930 { from, nonce, gas_limit, gas_price, .. } => {
                let addr = hex::encode(from);
                (addr, *nonce, *gas_limit, 1u8, *gas_price, None, None)
            }
            EvmTx::Eip1559 { from, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, .. } => {
                let addr = hex::encode(from);
                (addr, *nonce, *gas_limit, 2u8, 0, Some(*max_fee_per_gas), Some(*max_priority_fee_per_gas))
            }
        };

        Ok(PendingTx {
            hash,
            from,
            nonce,
            tx_type,
            gas_limit,
            gas_price,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: max_priority,
            raw,
            inserted_at,
        })
    }

    /// Convert back to `EvmTx` (requires decoding the raw bytes).
    pub fn to_evm_tx(&self) -> Result<EvmTx, String> {
        crate::rpc::tx_decode::decode_typed_tx(&self.raw).map_err(|e| e.to_string())
    }
}

// -----------------------------------------------------------------------------
// Key for global ordering by insertion time (used for pruning).
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct TxAgeKey {
    inserted_at: u64,
    sender: String,
    nonce: u64,
}

// -----------------------------------------------------------------------------
// Mempool statistics
// -----------------------------------------------------------------------------

/// Metrics for the transaction pool.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TxPoolMetrics {
    pub admitted: u64,
    pub rejected_dup: u64,
    pub rejected_full: u64,
    pub rejected_sender_limit: u64,
    pub rejected_low_nonce: u64,
    pub replaced: u64,
    pub evicted: u64,
    pub expired: u64,
}

// -----------------------------------------------------------------------------
// Transaction pool
// -----------------------------------------------------------------------------

/// Mempool with per‑sender nonce lanes, strict replacement rules,
/// hash index, and efficient pruning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxPool {
    /// Primary storage: sender -> nonce -> transaction.
    by_sender: HashMap<String, BTreeMap<u64, PendingTx>>,
    /// Secondary index: hash -> (sender, nonce, inserted_at) for O(1) removal.
    by_hash: HashMap<String, (String, u64, u64)>,
    /// Global ordering by insertion time (for pruning).
    age_order: BTreeSet<TxAgeKey>,

    /// Maximum total number of transactions in the pool.
    max_total: usize,
    /// Maximum number of transactions per sender.
    max_per_sender: usize,
    /// Maximum age in seconds.
    max_age_secs: u64,

    /// Metrics for the pool.
    metrics: TxPoolMetrics,
}

impl Default for TxPool {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_TOTAL, DEFAULT_MAX_PER_SENDER, DEFAULT_MAX_AGE_SECS)
    }
}

impl TxPool {
    /// Create a new transaction pool with given limits.
    pub fn new(max_total: usize, max_per_sender: usize, max_age_secs: u64) -> Self {
        Self {
            by_sender: HashMap::new(),
            by_hash: HashMap::new(),
            age_order: BTreeSet::new(),
            max_total,
            max_per_sender,
            max_age_secs,
            metrics: TxPoolMetrics::default(),
        }
    }

    /// Total number of pending transactions.
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Number of pending transactions for a specific sender.
    pub fn pending_for_sender(&self, sender: &str) -> usize {
        self.by_sender.get(sender).map(|m| m.len()).unwrap_or(0)
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &TxPoolMetrics {
        &self.metrics
    }

    /// Insert a new transaction. Implements strict replacement rules:
    /// - If the new transaction has the same type as the old one, we enforce:
    ///   * For EIP-1559: strictly higher max_fee_per_gas AND max_priority_fee_per_gas.
    ///   * For legacy/EIP-2930: strictly higher gas_price.
    /// - If types differ, we compare by fee_cap() and priority() (both must be strictly higher)
    ///   to avoid underpriced replacements across types.
    pub fn insert(&mut self, tx: PendingTx, expected_nonce: Option<u64>) -> Result<(), String> {
        // Check duplicate hash.
        if self.by_hash.contains_key(&tx.hash) {
            self.metrics.rejected_dup += 1;
            return Err("transaction already in pool".into());
        }

        let sender = tx.from.clone();
        let nonce = tx.nonce;
        let inserted_at = tx.inserted_at;

        // Validate nonce (if we have an expected nonce for this sender).
        if let Some(expected) = expected_nonce {
            if nonce < expected {
                self.metrics.rejected_low_nonce += 1;
                return Err(format!("nonce too low: expected {}, got {}", expected, nonce));
            }
        }

        // Check per‑sender limit.
        let current_sender_count = self.pending_for_sender(&sender);
        if current_sender_count >= self.max_per_sender {
            self.metrics.rejected_sender_limit += 1;
            return Err("sender queue full".into());
        }

        // Check global capacity.
        if self.len() >= self.max_total {
            // Try to evict the oldest transaction.
            if !self.evict_oldest() {
                self.metrics.rejected_full += 1;
                return Err("mempool full".into());
            }
        }

        // Check for existing transaction at same sender/nonce.
        let old_meta = self.by_sender.get(&sender).and_then(|lane| {
            lane.get(&nonce).map(|existing| {
                (
                    existing.hash.clone(),
                    existing.inserted_at,
                    existing.tx_type,
                    existing.gas_price,
                    existing.max_fee_per_gas,
                    existing.max_priority_fee_per_gas,
                )
            })
        });

        // If there is an existing transaction, apply replacement rules.
        if let Some((old_hash, old_inserted_at, old_type, old_gas_price, old_max_fee, old_max_priority)) = old_meta {
            let can_replace = match (tx.tx_type, old_type) {
                (2, 2) => {
                    // Both are EIP-1559: must increase both max_fee and max_priority_fee.
                    let new_max_fee = tx.max_fee_per_gas.unwrap_or(0);
                    let new_max_priority = tx.max_priority_fee_per_gas.unwrap_or(0);
                    new_max_fee > old_max_fee.unwrap_or(0) && new_max_priority > old_max_priority.unwrap_or(0)
                }
                (1, 1) | (0, 0) => {
                    // Same legacy or EIP-2930: must increase gas_price.
                    tx.gas_price > old_gas_price
                }
                _ => {
                    // Mixed types: require strictly higher fee_cap AND priority.
                    tx.fee_cap() > Self::old_fee_cap(old_gas_price, old_max_fee)
                        && tx.priority() > Self::old_priority(old_gas_price, old_max_priority)
                }
            };

            if !can_replace {
                self.metrics.rejected_dup += 1;
                return Err("replacement underpriced".into());
            }

            // Remove the old transaction from indexes.
            self.by_hash.remove(&old_hash);
            let age_key = TxAgeKey {
                inserted_at: old_inserted_at,
                sender: sender.clone(),
                nonce,
            };
            self.age_order.remove(&age_key);
            self.metrics.replaced += 1;
        }

        // Now insert the new transaction.
        let lane = self.by_sender.entry(sender.clone()).or_insert_with(BTreeMap::new);
        lane.insert(nonce, tx.clone());

        // Update indexes.
        self.by_hash.insert(tx.hash.clone(), (sender.clone(), nonce, inserted_at));
        let age_key = TxAgeKey {
            inserted_at,
            sender,
            nonce,
        };
        self.age_order.insert(age_key);
        self.metrics.admitted += 1;

        Ok(())
    }

    /// Helper: extract old fee cap.
    fn old_fee_cap(old_gas_price: u128, old_max_fee: Option<u128>) -> u128 {
        old_max_fee.unwrap_or(old_gas_price)
    }

    /// Helper: extract old priority.
    fn old_priority(old_gas_price: u128, old_max_priority: Option<u128>) -> u128 {
        old_max_priority.unwrap_or(old_gas_price)
    }

    /// Evict the oldest transaction (by insertion time) from the pool.
    /// Returns `true` if an entry was removed.
    fn evict_oldest(&mut self) -> bool {
        if let Some(oldest) = self.age_order.iter().next().cloned() {
            // Remove from primary storage.
            let mut remove_sender = false;
            if let Some(lane) = self.by_sender.get_mut(&oldest.sender) {
                if let Some(tx) = lane.remove(&oldest.nonce) {
                    self.by_hash.remove(&tx.hash);
                }
                remove_sender = lane.is_empty();
            }
            if remove_sender {
                self.by_sender.remove(&oldest.sender);
            }
            self.age_order.remove(&oldest);
            self.metrics.evicted += 1;
            true
        } else {
            false
        }
    }

    /// Get the next batch of ready transactions (by nonce) without removing them.
    /// For each sender, takes all transactions with consecutive nonces starting from the expected nonce.
    /// Returns up to `max` transactions, globally sorted by priority (descending).
    ///
    /// # Note
    /// The returned list is sorted by priority, not by sender/nonce order.
    /// When building a block, the caller **must** re-order the transactions
    /// to preserve per-sender nonce ordering before execution.
    pub fn ready_txs(&self, account_nonces: &HashMap<String, u64>, max: usize) -> Vec<PendingTx> {
        let mut candidates = Vec::new();

        for (sender, lane) in &self.by_sender {
            let expected = account_nonces.get(sender).copied().unwrap_or(0);
            let mut nonce = expected;
            while let Some(tx) = lane.get(&nonce) {
                candidates.push(tx.clone());
                nonce += 1;
            }
        }

        // Sort by priority descending (highest tip first).
        candidates.sort_by(|a, b| b.priority().cmp(&a.priority()));
        candidates.truncate(max);
        candidates
    }

    /// Remove confirmed transactions by hash (e.g., after they are included in a block).
    /// Returns the number of removed transactions.
    pub fn remove_confirmed(&mut self, hashes: &HashSet<String>) -> usize {
        let mut removed = 0;
        for hash in hashes {
            if let Some((sender, nonce, inserted_at)) = self.by_hash.remove(hash) {
                // Remove from primary storage.
                let mut remove_sender = false;
                if let Some(lane) = self.by_sender.get_mut(&sender) {
                    lane.remove(&nonce);
                    remove_sender = lane.is_empty();
                }
                if remove_sender {
                    self.by_sender.remove(&sender);
                }

                // Remove from age order.
                let age_key = TxAgeKey {
                    inserted_at,
                    sender,
                    nonce,
                };
                self.age_order.remove(&age_key);
                removed += 1;
            }
        }
        removed
    }

    /// Prune old transactions and enforce size limit.
    /// - Removes any transaction older than `max_age_secs`.
    /// - If total size exceeds `max_total`, keeps the newest `max_total` by insertion time.
    pub fn all_txs(&self) -> Vec<&PendingTx> {
        self.by_sender.values()
            .flat_map(|lane| lane.values())
            .collect()
    }

    pub fn prune(&mut self, now_secs: u64) {
        // 1. Remove by age.
        let cutoff = now_secs.saturating_sub(self.max_age_secs);
        let old_keys: Vec<TxAgeKey> = self.age_order
            .iter()
            .take_while(|key| key.inserted_at < cutoff)
            .cloned()
            .collect();

        for key in old_keys {
            // Remove from primary storage.
            let mut remove_sender = false;
            if let Some(lane) = self.by_sender.get_mut(&key.sender) {
                if let Some(tx) = lane.remove(&key.nonce) {
                    self.by_hash.remove(&tx.hash);
                }
                remove_sender = lane.is_empty();
            }
            if remove_sender {
                self.by_sender.remove(&key.sender);
            }
            self.age_order.remove(&key);
            self.metrics.expired += 1;
        }

        // 2. Enforce size limit.
        if self.len() > self.max_total {
            let to_remove = self.len() - self.max_total;
            let keys: Vec<TxAgeKey> = self.age_order.iter().cloned().collect();
            for key in keys.into_iter().take(to_remove) {
                // Remove from primary storage.
                let mut remove_sender = false;
                if let Some(lane) = self.by_sender.get_mut(&key.sender) {
                    if let Some(tx) = lane.remove(&key.nonce) {
                        self.by_hash.remove(&tx.hash);
                    }
                    remove_sender = lane.is_empty();
                }
                if remove_sender {
                    self.by_sender.remove(&key.sender);
                }
                self.age_order.remove(&key);
                self.metrics.evicted += 1;
            }
        }
    }

    /// Check if a transaction exists by hash.
    pub fn contains(&self, hash: &str) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Get transaction by hash (if present).
    pub fn get_by_hash(&self, hash: &str) -> Option<&PendingTx> {
        self.by_hash.get(hash).and_then(|(sender, nonce, _)| {
            self.by_sender.get(sender)?.get(nonce)
        })
    }

    /// Get all transactions for a sender, in nonce order.
    pub fn txs_for_sender(&self, sender: &str) -> Vec<&PendingTx> {
        self.by_sender
            .get(sender)
            .map(|lane| lane.values().collect())
            .unwrap_or_default()
    }
}

// -----------------------------------------------------------------------------
// Implementation of the Mempool trait (for integration with the node)
// -----------------------------------------------------------------------------

impl MempoolTrait for TxPool {
    type Error = MempoolError;

    fn submit_tx(&mut self, tx: Tx) -> Result<(), Self::Error> {
        // We need to convert from `Tx` (the node's generic transaction) to `PendingTx`.
        // In Iona, the `Tx` type contains a `payload` that may be `stake`, `vm`, or `evm_unified`.
        // For the EVM path, the payload is of the form "evm_unified <hex‑encoded EvmTx bincode>".
        // We need to decode that and then create a `PendingTx`.
        //
        // For simplicity, we assume that the transaction is already an EVM transaction.
        // In production, this would be handled by the RPC layer (which already decodes to `EvmTx`).
        // So we'll implement a conversion from the raw bytes that were originally received.
        // Since the `Tx` struct does not contain the raw bytes, we cannot easily reconstruct.
        // To avoid complexity, we'll just return an error.
        // This method is not used directly by the node; instead, the RPC handler calls `insert`
        // after decoding. We keep it as a placeholder.
        Err(MempoolError::Unsupported)
    }

    fn drain(&mut self, n: usize) -> Vec<Tx> {
        // Not needed for the RPC mempool; the node uses `ready_txs` directly.
        Vec::new()
    }

    fn advance_height(&mut self, height: Height, _block_hash: &Hash32) {
        // We could use the height to remove confirmed transactions, but the node
        // will call `remove_confirmed` directly after each block. We'll leave it empty.
        let _ = height;
    }

    fn pending_count(&self) -> usize {
        self.len()
    }

    fn metrics(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&self.metrics).ok()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(hash: &str, from: &str, nonce: u64, gas_price: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: hash.to_string(),
            from: from.to_string(),
            nonce,
            tx_type: 0,
            gas_limit: 21000,
            gas_price,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            raw: vec![],
            inserted_at,
        }
    }

    fn dummy_tx_1559(hash: &str, from: &str, nonce: u64, max_fee: u128, max_priority: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: hash.to_string(),
            from: from.to_string(),
            nonce,
            tx_type: 2,
            gas_limit: 21000,
            gas_price: 0,
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(max_priority),
            raw: vec![],
            inserted_at,
        }
    }

    #[test]
    fn test_insert_and_duplicate() {
        let mut pool = TxPool::default();
        let tx = dummy_tx("hash1", "alice", 0, 10, 100);
        assert!(pool.insert(tx, None).is_ok());
        assert_eq!(pool.len(), 1);
        // Same hash again -> error.
        let tx2 = dummy_tx("hash1", "alice", 0, 20, 101);
        assert!(pool.insert(tx2, None).is_err());
        assert_eq!(pool.metrics.rejected_dup, 1);
    }

    #[test]
    fn test_replacement_legacy() {
        let mut pool = TxPool::default();
        let tx1 = dummy_tx("hash1", "alice", 0, 10, 100);
        pool.insert(tx1, None).unwrap();
        // Replace with higher gas_price -> ok.
        let tx2 = dummy_tx("hash2", "alice", 0, 20, 101);
        assert!(pool.insert(tx2, None).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash2"));
        assert!(!pool.contains("hash1"));
        assert_eq!(pool.metrics.replaced, 1);
    }

    #[test]
    fn test_replacement_1559() {
        let mut pool = TxPool::default();
        let tx1 = dummy_tx_1559("hash1", "alice", 0, 100, 10, 100);
        pool.insert(tx1, None).unwrap();
        // Increase only max_fee -> should fail.
        let tx2 = dummy_tx_1559("hash2", "alice", 0, 200, 10, 101);
        assert!(pool.insert(tx2, None).is_err());
        // Increase both -> ok.
        let tx3 = dummy_tx_1559("hash3", "alice", 0, 200, 20, 102);
        assert!(pool.insert(tx3, None).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash3"));
    }

    #[test]
    fn test_ready_txs() {
        let mut pool = TxPool::default();
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100), None).unwrap();
        pool.insert(dummy_tx("hash2", "alice", 1, 4, 101), None).unwrap();
        pool.insert(dummy_tx("hash3", "bob",   0, 10, 102), None).unwrap();

        let mut account_nonces = HashMap::new();
        account_nonces.insert("alice".to_string(), 0);
        account_nonces.insert("bob".to_string(), 0);

        let ready = pool.ready_txs(&account_nonces, 10);
        assert_eq!(ready.len(), 3);
        assert_eq!(ready[0].hash, "hash3");
        assert_eq!(ready[1].hash, "hash1");
        assert_eq!(ready[2].hash, "hash2");

        // Remove alice nonce0 and see nonce1 still there but not ready because nonce0 missing.
        pool.remove_confirmed(&HashSet::from(["hash1".to_string()]));
        let ready2 = pool.ready_txs(&account_nonces, 10);
        assert_eq!(ready2.len(), 1);
        assert_eq!(ready2[0].hash, "hash3");
    }

    #[test]
    fn test_prune_age() {
        let mut pool = TxPool::new(100, 100, 100);
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100), None).unwrap();
        pool.insert(dummy_tx("hash2", "bob",   0, 5, 200), None).unwrap();
        pool.prune(150); // now=150, max_age=100 → cutoff=50; both are >50, so none removed.
        assert_eq!(pool.len(), 2);
        pool.prune(250); // now=250, cutoff=150; hash1 (100) is older than 150 -> removed.
        assert_eq!(pool.len(), 1);
        assert!(pool.contains("hash2"));
        assert_eq!(pool.metrics.expired, 1);
    }

    #[test]
    fn test_prune_size() {
        let mut pool = TxPool::new(2, 100, 1000);
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100), None).unwrap();
        pool.insert(dummy_tx("hash2", "bob",   0, 5, 200), None).unwrap();
        pool.insert(dummy_tx("hash3", "carol", 0, 5, 150), None).unwrap();
        pool.prune(1000);
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains("hash1")); // oldest removed
        assert!(pool.contains("hash2"));
        assert!(pool.contains("hash3"));
    }

    #[test]
    fn test_low_nonce_rejection() {
        let mut pool = TxPool::default();
        let tx = dummy_tx("hash1", "alice", 0, 10, 100);
        // Expected nonce = 1, but tx has nonce 0 -> reject.
        assert!(pool.insert(tx, Some(1)).is_err());
        assert_eq!(pool.metrics.rejected_low_nonce, 1);
    }

    #[test]
    fn test_sender_limit() {
        let mut pool = TxPool::new(100, 2, 1000);
        pool.insert(dummy_tx("hash1", "alice", 0, 10, 100), None).unwrap();
        pool.insert(dummy_tx("hash2", "alice", 1, 10, 101), None).unwrap();
        // Third transaction from alice should be rejected.
        let tx3 = dummy_tx("hash3", "alice", 2, 10, 102);
        assert!(pool.insert(tx3, None).is_err());
        assert_eq!(pool.metrics.rejected_sender_limit, 1);
    }

    #[test]
    fn test_global_capacity_eviction() {
        let mut pool = TxPool::new(2, 100, 1000);
        pool.insert(dummy_tx("hash1", "alice", 0, 5, 100), None).unwrap();
        pool.insert(dummy_tx("hash2", "bob",   0, 5, 200), None).unwrap();
        // Third transaction should trigger eviction of the oldest (hash1).
        let tx3 = dummy_tx("hash3", "carol", 0, 5, 150);
        assert!(pool.insert(tx3, None).is_ok());
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains("hash1"));
        assert!(pool.contains("hash2"));
        assert!(pool.contains("hash3"));
        assert_eq!(pool.metrics.evicted, 1);
    }
}
