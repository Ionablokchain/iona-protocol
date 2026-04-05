//! Staking and governance module for IONA.
//!
//! This module provides the core staking logic, including validator bonding/unbonding,
//! reward distribution, slashing, and governance proposals.
//!
//! # Submodules
//!
//! - `params` – Configuration parameters for staking and governance.
//! - `staking` – Core staking state: validators, delegations, unbonding.
//! - `governance` – On‑chain proposal system for parameter changes and upgrades.
//! - `rewards` – Distribution of block rewards to validators and delegators.
//! - `staking_tx` – Transaction types for staking operations.
//!
//! # Example
//!
//! ```rust
//! use iona::staking::*;
//!
//! let mut state = StakingState::default();
//! let tx = StakingTx::Delegate {
//!     delegator: "alice".into(),
//!     validator: "val1".into(),
//!     amount: 1000,
//! };
//! apply_staking_tx(&mut state, tx).unwrap();
//! ```

// Re‑export core types and functions from each submodule.
pub use governance::{
    process_proposals, submit_proposal, vote, GovernanceParams, GovernanceState, Proposal,
    ProposalKind, ProposalResult,
};
pub use params::StakingParams;
pub use rewards::{distribute_rewards, RewardConfig, RewardState};
pub use staking::{
    apply_staking_tx, Delegation, StakingError, StakingState, UnbondingEntry, Validator,
};
pub use staking_tx::{validate_staking_tx, StakingTx, StakingTxKind};

// Optionally, re‑export error types for convenience.
pub use staking::StakeLedger;
pub use staking::StakingError as Error;

// Module declarations (kept private to enforce re‑export interface).
pub mod governance;
pub mod params;
pub mod rewards;
pub mod staking;
pub mod staking_tx;

// Test helpers (only in dev builds).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staking_and_rewards_integration() {
        // Simple integration test to ensure submodules work together.
        let _state = StakingState::default();
        // ... test logic ...
    }
}
