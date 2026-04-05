//! Safety invariant checks for protocol upgrades.
//!
//! These functions verify the formal safety properties defined in
//! `spec/upgrade/UPGRADE_SPEC.md` section 7.
//!
//! # Invariants checked
//!
//! - **S1 (No Split Finality)**: At most one finalized block per height.
//! - **S2 (Finality Monotonic)**: `finalized_height` never decreases.
//! - **S3 (Deterministic PV)**: All correct nodes agree on `PV(height)`.
//! - **S4 (State Compatibility)**: Old PV not applied after activation.
//! - **S5 (State Integrity)**: State invariants hold (e.g., non‑negative balances, non‑zero roots).
//! - **M2 (Value Conservation)**: Token supply is conserved across state transitions.
//! - **M3 (Root Equivalence)**: Format‑only migrations preserve the state root.

use crate::execution::KvState;
use crate::protocol::version::{self, ProtocolActivation};
use crate::types::{Hash32, Height};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

#[cfg(feature = "prometheus")]
use lazy_static::lazy_static;
#[cfg(feature = "prometheus")]
use prometheus::{register_int_counter_vec, IntCounterVec, Opts};

// -----------------------------------------------------------------------------
// Prometheus metrics (optional)
// -----------------------------------------------------------------------------

#[cfg(feature = "prometheus")]
lazy_static! {
    static ref SAFETY_VIOLATIONS: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "iona_safety_violations",
            "Number of safety violations by invariant"
        ),
        &["invariant"]
    )
    .expect("failed to register safety violations metric");
}

/// Safety violation counter (simple atomic, always available).
pub static SAFETY_VIOLATION_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn record_safety_violation(_kind: &str) {
    SAFETY_VIOLATION_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
}

// -----------------------------------------------------------------------------
// S1: No split finality
// -----------------------------------------------------------------------------

/// Verify that at most one block has been finalized at the given height.
///
/// `finalized_ids` is the set of distinct block IDs that have been finalized
/// for this height (should be 0 or 1).
pub fn check_no_split_finality(height: Height, finalized_count: usize) -> Result<(), String> {
    if finalized_count > 1 {
        let msg = format!(
            "SAFETY VIOLATION S1: {finalized_count} blocks finalized at height {height}; \
             expected at most 1"
        );
        #[cfg(feature = "prometheus")]
        SAFETY_VIOLATIONS.with_label_values(&["S1"]).inc();
        return Err(msg);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// S2: Finality monotonic
// -----------------------------------------------------------------------------

/// Verify that the new finalized height is >= the previous one.
pub fn check_finality_monotonic(
    prev_finalized: Height,
    new_finalized: Height,
) -> Result<(), String> {
    if new_finalized < prev_finalized {
        let msg = format!(
            "SAFETY VIOLATION S2: finalized_height decreased from {prev_finalized} to {new_finalized}"
        );
        #[cfg(feature = "prometheus")]
        SAFETY_VIOLATIONS.with_label_values(&["S2"]).inc();
        return Err(msg);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// S3: Deterministic PV
// -----------------------------------------------------------------------------

/// Verify that the locally computed PV matches the block's PV.
///
/// This check ensures that all correct nodes agree on which protocol version
/// applies at a given height.
pub fn check_deterministic_pv(
    height: Height,
    block_pv: u32,
    local_pv: u32,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    // The block's PV must be valid for this height (grace window considered).
    version::validate_block_version(block_pv, height, activations)?;

    // Additionally, the block PV should match local computation exactly
    // (outside of grace windows).
    let expected = version::version_for_height(height, activations);
    if block_pv != expected && block_pv != local_pv {
        let msg = format!(
            "SAFETY WARNING S3: block PV={block_pv} differs from local PV={local_pv} \
             at height {height} (expected PV={expected})"
        );
        // For S3 we only warn; it's not a hard violation unless grace window is misapplied.
        #[cfg(feature = "prometheus")]
        SAFETY_VIOLATIONS.with_label_values(&["S3_warn"]).inc();
        return Err(msg); // or just log? We keep as error for strictness.
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// S4: State compatibility (no old PV after activation)
// -----------------------------------------------------------------------------

/// Verify that after activation, we're not applying old-PV execution rules.
pub fn check_state_compat(
    height: Height,
    execution_pv: u32,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    let expected = version::version_for_height(height, activations);
    if execution_pv < expected {
        // Check grace window
        let in_grace = activations.iter().any(|a| {
            a.protocol_version == expected
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });
        if !in_grace {
            let msg = format!(
                "SAFETY VIOLATION S4: executing with PV={execution_pv} at height {height}, \
                 but PV={expected} is mandatory (grace window expired)"
            );
            #[cfg(feature = "prometheus")]
            SAFETY_VIOLATIONS.with_label_values(&["S4"]).inc();
            return Err(msg);
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// S5: State integrity
// -----------------------------------------------------------------------------

/// Verify basic integrity of a state.
///
/// - Balances are non‑negative (they are `u64`, so automatically non‑negative).
/// - State root is not zero (except genesis).
/// - No key with empty string.
/// - Additional checks can be added.
pub fn check_state_integrity(
    state: &KvState,
    height: Height,
    is_genesis: bool,
) -> Result<(), String> {
    // S5‑1: root non‑zero (except genesis)
    let root = state.root();
    if !is_genesis && root.0 == [0u8; 32] {
        let msg = format!(
            "SAFETY VIOLATION S5: state root is zero at height {}",
            height
        );
        #[cfg(feature = "prometheus")]
        SAFETY_VIOLATIONS.with_label_values(&["S5_root"]).inc();
        return Err(msg);
    }

    // S5‑2: no empty keys in KV store
    for (k, _) in &state.kv {
        if k.is_empty() {
            let msg = format!("SAFETY VIOLATION S5: empty key in KV at height {}", height);
            #[cfg(feature = "prometheus")]
            SAFETY_VIOLATIONS.with_label_values(&["S5_empty_key"]).inc();
            return Err(msg);
        }
    }

    // S5‑3: balances (already u64, so non‑negative)
    // Could add more invariants (e.g., total supply not exceeding some limit).

    Ok(())
}

// -----------------------------------------------------------------------------
// M2: Value conservation
// -----------------------------------------------------------------------------

/// Check that total token supply is conserved across a state transition.
///
/// `supply_before` = sum(balances) + sum(staked) before block execution.
/// `supply_after`  = sum(balances) + sum(staked) after block execution.
/// `minted`        = block rewards minted (epoch boundary).
/// `slashed`       = tokens destroyed by slashing.
/// `burned`        = tokens burned via EIP-1559 base fee.
///
/// Invariant: `supply_after == supply_before + minted - slashed - burned`
pub fn check_value_conservation(
    supply_before: u128,
    supply_after: u128,
    minted: u128,
    slashed: u128,
    burned: u128,
) -> Result<(), String> {
    let expected = supply_before
        .saturating_add(minted)
        .saturating_sub(slashed)
        .saturating_sub(burned);
    if supply_after != expected {
        let msg = format!(
            "SAFETY VIOLATION M2: value not conserved. \
             before={supply_before} + minted={minted} - slashed={slashed} - burned={burned} \
             = expected {expected}, got {supply_after} (diff={})",
            (supply_after as i128) - (expected as i128)
        );
        #[cfg(feature = "prometheus")]
        SAFETY_VIOLATIONS.with_label_values(&["M2"]).inc();
        return Err(msg);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// M3: Root equivalence (for format-only migrations)
// -----------------------------------------------------------------------------

/// Verify that a format-only migration preserves the state root.
///
/// `root_before` and `root_after` are the Merkle state roots computed
/// before and after the migration.
pub fn check_root_equivalence(root_before: &Hash32, root_after: &Hash32) -> Result<(), String> {
    if root_before != root_after {
        let msg = format!(
            "SAFETY VIOLATION M3: state root changed after format migration. \
             before={}, after={}",
            hex::encode(root_before.0),
            hex::encode(root_after.0),
        );
        #[cfg(feature = "prometheus")]
        SAFETY_VIOLATIONS.with_label_values(&["M3"]).inc();
        return Err(msg);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// High‑level check
// -----------------------------------------------------------------------------

/// Run all safety checks that can be performed after committing a block.
pub fn check_all_after_commit(
    height: Height,
    prev_finalized: Height,
    new_finalized: Height,
    finalized_count: usize,
    block_pv: u32,
    local_pv: u32,
    execution_pv: u32,
    activations: &[ProtocolActivation],
    state_before: &KvState,
    state_after: &KvState,
    minted: u128,
    slashed: u128,
    burned: u128,
    is_genesis: bool,
) -> Vec<String> {
    let mut violations = Vec::new();

    // S1
    if let Err(e) = check_no_split_finality(height, finalized_count) {
        violations.push(e);
    }

    // S2
    if let Err(e) = check_finality_monotonic(prev_finalized, new_finalized) {
        violations.push(e);
    }

    // S3
    if let Err(e) = check_deterministic_pv(height, block_pv, local_pv, activations) {
        violations.push(e);
    }

    // S4
    if let Err(e) = check_state_compat(height, execution_pv, activations) {
        violations.push(e);
    }

    // S5
    if let Err(e) = check_state_integrity(state_after, height, is_genesis) {
        violations.push(e);
    }

    // M2: value conservation
    let supply_before = total_supply(state_before);
    let supply_after = total_supply(state_after);
    if let Err(e) = check_value_conservation(supply_before, supply_after, minted, slashed, burned) {
        violations.push(e);
    }

    violations
}

/// Compute total supply from a state (balances + staked).
fn total_supply(state: &KvState) -> u128 {
    let balance_sum: u128 = state.balances.values().map(|&v| v as u128).sum();
    let staked_sum: u128 = state.staked.values().map(|&v| v as u128).sum();
    balance_sum + staked_sum
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;
    use crate::protocol::version::default_activations;

    fn sample_state() -> KvState {
        let mut s = KvState::default();
        s.balances.insert("addr1".into(), 1000);
        s.balances.insert("addr2".into(), 2000);
        s.staked.insert("val1".into(), 500);
        s.kv.insert("key".into(), "value".into());
        s
    }

    #[test]
    fn test_no_split_finality_ok() {
        assert!(check_no_split_finality(1, 0).is_ok());
        assert!(check_no_split_finality(1, 1).is_ok());
    }

    #[test]
    fn test_no_split_finality_violation() {
        assert!(check_no_split_finality(1, 2).is_err());
    }

    #[test]
    fn test_finality_monotonic_ok() {
        assert!(check_finality_monotonic(5, 5).is_ok());
        assert!(check_finality_monotonic(5, 6).is_ok());
    }

    #[test]
    fn test_finality_monotonic_violation() {
        assert!(check_finality_monotonic(5, 4).is_err());
    }

    #[test]
    fn test_state_integrity_ok() {
        let s = sample_state();
        assert!(check_state_integrity(&s, 100, false).is_ok());
    }

    #[test]
    fn test_value_conservation_ok() {
        assert!(check_value_conservation(1000, 1005, 10, 0, 5).is_ok());
    }

    #[test]
    fn test_value_conservation_violation() {
        assert!(check_value_conservation(1000, 1020, 10, 0, 0).is_err());
    }

    #[test]
    fn test_root_equivalence_ok() {
        let root = Hash32([42u8; 32]);
        assert!(check_root_equivalence(&root, &root).is_ok());
    }

    #[test]
    fn test_root_equivalence_violation() {
        let a = Hash32([1u8; 32]);
        let b = Hash32([2u8; 32]);
        assert!(check_root_equivalence(&a, &b).is_err());
    }

    #[test]
    fn test_state_compat_ok() {
        let activations = default_activations();
        assert!(check_state_compat(100, 1, &activations).is_ok());
    }

    #[test]
    fn test_total_supply() {
        let s = sample_state();
        assert_eq!(total_supply(&s), 1000 + 2000 + 500);
    }
}

#[derive(Debug, Clone)]
pub struct SafetyCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
