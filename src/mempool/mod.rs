//! Mempool module for IONA.
//!
//! This module provides two transaction pool implementations:
//! - `pool::StandardMempool`: a basic FIFO mempool with nonce ordering.
//! - `mev_resistant::MevMempool`: a MEV‑resistant mempool with commit‑reveal,
//!   threshold encryption, fair ordering, and backrun protection.
//!
//! Both pools implement the `Mempool` trait, allowing the node to switch
//! between them seamlessly.

pub mod mev_resistant;
pub mod pool;

// Re‑export core types and traits.
pub use mev_resistant::{
    compute_commit_hash, decrypt_tx_envelope, derive_epoch_secret, encrypt_tx_envelope,
    CommitStatus, EncryptedEnvelope, MevConfig, MevMempool, MevMempoolMetrics, TxCommit, TxReveal,
};
pub use pool::StandardMempool;

// Re‑export common error type.
pub use self::error::MempoolError;

// Re‑export the unified trait.
pub use self::trait_def::Mempool;

// ── Trait definition ──────────────────────────────────────────────────────

pub mod trait_def {
    use crate::types::{Hash32, Height, Tx};

    /// Common interface for all mempool implementations.
    pub trait Mempool {
        type Error;

        /// Submit a transaction to the pool.
        fn submit_tx(&mut self, tx: Tx) -> Result<(), Self::Error>;

        /// Remove up to `n` transactions from the pool (ready for inclusion).
        fn drain(&mut self, n: usize) -> Vec<Tx>;

        /// Notify the pool that the chain has advanced to a new height.
        fn advance_height(&mut self, height: Height, block_hash: &Hash32);

        /// Returns the number of pending transactions (ready for inclusion).
        fn pending_count(&self) -> usize;

        /// Returns current metrics (if any).
        fn metrics(&self) -> Option<serde_json::Value> {
            None
        }
    }
}

// ── Error definitions ──────────────────────────────────────────────────────

pub mod error {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum MempoolError {
        #[error("duplicate transaction")]
        Duplicate,
        #[error("invalid nonce (expected {expected}, got {got})")]
        InvalidNonce { expected: u64, got: u64 },
        #[error("mempool is full")]
        Full,
        #[error("mempool is full")]
        MempoolFull,
        #[error("transaction too large")]
        TooLarge,
        #[error("commit-reveal error: {0}")]
        CommitReveal(&'static str),
        #[error("threshold encryption error")]
        Encryption,
        #[error("fee too low (max_fee={max_fee}, base_fee={base_fee})")]
        FeeTooLow { max_fee: u64, base_fee: u64 },
        #[error("replace-by-fee too low (existing_tip={existing_tip}, required={required})")]
        RbfTooLow { existing_tip: u64, required: u64 },
        #[error("missing sender")]
        MissingSender,
        #[error("sender queue full")]
        SenderQueueFull,
        #[error("unsupported operation")]
        Unsupported,
    }
}
