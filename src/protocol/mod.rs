//! Protocol versioning, upgrade safety, and backward compatibility.
//!
//! This module handles all aspects of protocol evolution:
//!
//! - **`version`**: Core protocol version constants, activation schedule, and helper functions.
//! - **`wire`**: Wire format compatibility and message versioning.
//! - **`safety`**: Safety checks for upgrades (e.g., no double-signing, equivocation).
//! - **`dual_validate`**: Shadow validation of new protocol rules before activation.
//! - **`transitions`**: State transition rules across protocol versions.
//! - **`rolling`**: Rolling upgrade coordination and peer version negotiation.
//! - **`compat`**: Comprehensive backward compatibility checks (enforced in CI).
//! - **`state_invariants`**: Invariants that must hold across all versions.
//! - **`upgrade_constraints`**: Constraints that upgrades must satisfy (e.g., activation heights).
//! - **`activation_guarantees`**: Formal guarantees about activation behavior (determinism, monotonicity, etc.).

// Re-export commonly used items from submodules.
pub use self::activation_guarantees::{
    check_all_guarantees, ActivationCheck, ActivationReport,
};
pub use self::compat::{
    build_compat_matrix, check_version_compat, generate_upgrade_guide, CompatChecker,
    CompatDomain, CompatLevel, CompatReport,
};
// dual_validate re-exports handled below
pub use self::version::{
    version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};

// Submodules (the actual implementations)
pub mod activation_guarantees;
pub mod compat;
pub mod dual_validate;
pub mod rolling;
pub mod safety;
pub mod state_invariants;
pub mod transitions;
pub mod upgrade_constraints;
pub mod version;
pub mod wire;

pub const MAX_FUTURE_BLOCK_TIME_SECS: u64 = 15;
