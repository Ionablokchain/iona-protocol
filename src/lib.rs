//! IONA blockchain node library.
//!
//! This crate implements a production‑ready blockchain node with a focus on
//! deterministic execution, upgrade safety, and validator hardening.
//!
//! # Modules
//!
//! - `config` – Node configuration (TOML + env overrides).
//! - `consensus` – Tendermint‑style BFT consensus engine.
//! - `crypto` – Cryptographic primitives (Ed25519, keystore, remote signer).
//! - `evidence` – Slashable offence detection (double‑vote, double‑proposal).
//! - `execution` – State transition and block execution (KV, VM, EVM, staking).
//! - `governance` – On‑chain governance (proposals, voting, parameter changes).
//! - `mempool` – Transaction pool (standard + MEV‑resistant).
//! - `merkle` – Deterministic Merkle tree for state roots.
//! - `metrics` – Prometheus metrics for monitoring.
//! - `net` – P2P networking (libp2p, peer scoring, state sync).
//! - `rpc_limits` – Rate limiting for RPC and P2P.
//! - `slashing` – Validator slashing for misbehaviour.
//! - `storage` – Persistent storage (blocks, state, WAL, snapshots).
//! - `types` – Core data types (Block, Tx, Hash32, etc.).
//! - `wal` – Write‑ahead log for crash recovery.
//! - `vm` – Custom VM interpreter.
//! - `evm` – Ethereum Virtual Machine integration.
//! - `economics` – Staking, rewards, and economic parameters.
//! - `protocol` – Protocol versioning and upgrade management.
//! - `audit` – Security audit logging.
//! - `snapshot` – State snapshots and delta sync.
//! - `replay` – Block replay and divergence detection.
//! - `admin` – Administrative commands (reset, backup, status).
//! - `rpc_health` – Health and status RPC endpoints.
//! - `rpc` – Ethereum‑compatible JSON‑RPC server.
//! - `upgrade` – Protocol and schema upgrade orchestration.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::prelude::*;
//!
//! let config = Config::load().expect("failed to load config");
//! let node = Node::new(config).await?;
//! node.run().await?;
//! ```

pub mod config;
pub mod consensus;
pub mod crypto;
pub mod evidence;
pub mod execution;
pub mod governance;
pub mod mempool;
pub mod merkle;
pub mod metrics;
pub mod net;
pub mod rpc_limits;
pub mod slashing;
pub mod storage;
pub mod types;
pub mod wal;

pub mod vm;
pub mod evm;
pub mod economics;
pub mod protocol;
pub mod audit;
pub mod snapshot;
pub mod replay;
pub mod admin;
pub mod rpc_health;
pub mod rpc;
pub mod upgrade;

// -----------------------------------------------------------------------------
// Re‑exports for a convenient top‑level API
// -----------------------------------------------------------------------------

// Configuration
pub use config::NodeConfig as Config;

// Core types
pub use types::{Block, Hash32, Height, Receipt, Round, Tx};

// Consensus
pub use consensus::engine::Engine;
pub use consensus::validator_set::ValidatorSet;

// Crypto
pub use crypto::{PublicKeyBytes, SignatureBytes, Signer, Verifier};
pub use crypto::ed25519::{Ed25519Keypair, Ed25519Signer, Ed25519Verifier};

// Execution
pub use execution::KvState;

// Mempool
pub use mempool::{Mempool as MempoolTrait, StandardMempool, MevMempool};

// Networking
pub use net::inmem::InMemNet;

// Storage
pub use storage::layout::DataLayout;
pub use storage::block_store::FsBlockStore;

// EVM
pub use evm::kv_state_db::KvStateDb;

// Metrics
pub use metrics::{init_metrics, metrics, Metrics};

// RPC
pub use rpc::eth_rpc::EthRpcState;
pub use rpc::router::serve as serve_rpc;

// -----------------------------------------------------------------------------
// Prelude: import commonly used items
// -----------------------------------------------------------------------------

/// A prelude module that re‑exports the most common types and traits.
///
/// # Example
///
/// ```
/// use iona::prelude::*;
/// ```
pub mod prelude {
    pub use crate::config::NodeConfig as Config;
    pub use crate::types::{Block, Hash32, Height, Receipt, Round, Tx};
    pub use crate::execution::KvState;
    pub use crate::crypto::{PublicKeyBytes, Signer, Verifier};
    pub use crate::crypto::ed25519::Ed25519Verifier;
    pub use crate::mempool::Mempool as MempoolTrait;
    pub use crate::metrics::{init_metrics, metrics};
}
