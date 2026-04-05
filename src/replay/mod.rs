//! Replay and determinism verification subsystem.
//!
//! Provides tools for:
//! - **Replaying historical blocks** to verify state transitions
//! - **Verifying state root reproducibility** across rebuilds
//! - **Detecting divergence** across environments (platforms, compilers)
//! - **Logging nondeterministic inputs** for audit and debugging
//!
//! # Architecture
//!
//! ```text
//!   historical::replay_chain(blocks, state)
//!       │
//!       ├── state_root_verify::verify_roots(blocks, expected_roots)
//!       │
//!       ├── divergence::compare_results(local, remote)
//!       │
//!       └── nondeterminism::NdLogger::log(source, value)
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::replay::{historical, divergence, nondeterminism};
//!
//! let result = historical::replay_chain(&blocks, &state, &config);
//! if !result.success {
//!     eprintln!("{}", result);
//! }
//! ```

pub mod divergence;
pub mod historical;
pub mod nondeterminism;
pub mod replay_tool;
pub mod state_root_verify;

// Re‑export core types and functions from submodules for convenience.
pub use divergence::{
    compare_snapshots, detect_divergence, detect_divergence_range, Divergence, DivergenceDetail,
    DivergenceReport, DivergenceSummary, NodeSnapshot, VmSnapshot,
};
pub use historical::{
    replay_and_verify_roots, replay_block, replay_chain, resume_replay, BlockReplayResult,
    ChainReplayResult, ReplayConfig,
};
pub use nondeterminism::NdLogger; // if implemented
                                  // ReplayTool not yet implemented
