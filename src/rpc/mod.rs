#![allow(clippy::unwrap_used)]
//! RPC module — core Ethereum‑compatible JSON‑RPC and supporting types.
//!
//! This module provides:
//! - Ethereum‑compatible JSON‑RPC server (`server::serve`)
//! - Types and utilities for RPC responses
//! - Storage backends for blocks, receipts, and state
//! - Middleware for security, logging, and rate limiting

pub mod auth_api_key;
pub mod basefee;
pub mod block_store;
pub mod bloom;
pub mod chain_store;
pub mod eth_header;
pub mod eth_rlp;
pub mod eth_rpc;
pub mod fs_store;
pub mod middleware;
pub mod mpt;
pub mod proofs;
pub mod rlp_encode;
pub mod router;
pub mod state_trie;
pub mod tx_decode;
pub mod txpool;
pub mod withdrawals;

// Re‑export the main server entry point
pub use router::serve;

// Re‑export commonly used types for convenience
pub use eth_rpc::{Block, EthRpcState, Log, Receipt, TxRecord};
pub use txpool::TxPool;
pub use withdrawals::Withdrawal;
