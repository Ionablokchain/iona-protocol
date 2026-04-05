//! ProtocolVersion transition state machine.
//!
//! Manages the lifecycle of protocol version transitions, including:
//!   - Transition scheduling and validation
//!   - Pre-activation readiness checks
//!   - Activation execution
//!   - Post-activation cleanup
//!   - Rollback support (pre-activation only)
//!
//! # State Machine
//!
//! ```text
//!   Idle ──▶ Scheduled ──▶ PreActivation ──▶ Activating ──▶ Active ──▶ Finalized
//!                │                │                                        │
//!                ▼                ▼                                        │
//!            Cancelled       RolledBack ◀─────────────────────────────────┘
//!                                                        (only with snapshot)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let mut mgr = TransitionManager::new(activations, current_height).expect("invalid activations");
//! // Each block:
//! mgr.on_block(height);
//! let state = mgr.state();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::version::{ProtocolActivation, version_for_height, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};

// Number of blocks before activation to enter PreActivation state.
const PRE_ACTIVATION_WINDOW: u64 = 1000;

// -----------------------------------------------------------------------------
// Transition state
// -----------------------------------------------------------------------------

/// State of a protocol version transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionState {
    /// No transition in progress; running at stable PV.
    Idle,
    /// A transition has been scheduled but activation height is far away.
    Scheduled {
        target_pv: u32,
        activation_height: u64,
    },
    /// Within the pre-activation window; shadow validation may be running.
    PreActivation {
        target_pv: u32,
        activation_height: u64,
        /// How many blocks until activation.
        blocks_remaining: u64,
    },
    /// Activation height reached; transitioning now.
    Activating {
        from_pv: u32,
        to_pv: u32,
        activation_height: u64,
    },
    /// New PV is active; grace window still open for old-PV blocks.
    Active {
        pv: u32,
        grace_remaining: u64,
    },
    /// Transition fully finalized; grace window expired.
    Finalized {
        pv: u32,
    },
    /// Transition was cancelled before activation.
    Cancelled {
        target_pv: u32,
        reason: String,
    },
    /// Transition was rolled back (requires snapshot).
    RolledBack {
        from_pv: u32,
        to_pv: u32,
        reason: String,
    },
}

impl std::fmt::Display for TransitionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Scheduled { target_pv, activation_height } =>
                write!(f, "Scheduled(PV={target_pv} at height={activation_height})"),
            Self::PreActivation { target_pv, blocks_remaining, .. } =>
                write!(f, "PreActivation(PV={target_pv}, {blocks_remaining} blocks remaining)"),
            Self::Activating { from_pv, to_pv, .. } =>
                write!(f, "Activating(PV {from_pv} -> {to_pv})"),
            Self::Active { pv, grace_remaining } =>
                write!(f, "Active(PV={pv}, grace={grace_remaining} blocks)"),
            Self::Finalized { pv } =>
                write!(f, "Finalized(PV={pv})"),
            Self::Cancelled { target_pv, reason } =>
                write!(f, "Cancelled(PV={target_pv}: {reason})"),
            Self::RolledBack { from_pv, to_pv, reason } =>
                write!(f, "RolledBack(PV {from_pv} -> {to_pv}: {reason})"),
        }
    }
}

// -----------------------------------------------------------------------------
// Transition events
// -----------------------------------------------------------------------------

/// Events emitted during transition lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionEvent {
    /// Transition scheduled for future activation.
    TransitionScheduled { target_pv: u32, activation_height: u64 },
    /// Entered pre-activation window.
    EnteredPreActivation { target_pv: u32, blocks_remaining: u64 },
    /// Activation height reached.
    ActivationReached { from_pv: u32, to_pv: u32, height: u64 },
    /// New PV is now active (grace window open).
    PvActivated { pv: u32, grace_blocks: u64 },
    /// Grace window expired; old PV blocks rejected.
    GraceExpired { pv: u32 },
    /// Transition fully finalized.
    TransitionFinalized { pv: u32 },
    /// Transition cancelled.
    TransitionCancelled { target_pv: u32, reason: String },
    /// Transition rolled back.
    TransitionRolledBack { from_pv: u32, to_pv: u32 },
}

// -----------------------------------------------------------------------------
// Readiness check
// -----------------------------------------------------------------------------

/// Result of a pre-activation readiness check.
#[derive(Debug, Clone)]
pub struct ReadinessReport {
    /// Whether the node is ready for the transition.
    pub ready: bool,
    /// Individual check results.
    pub checks: Vec<ReadinessCheck>,
}

/// A single readiness check.
#[derive(Debug, Clone)]
pub struct ReadinessCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl ReadinessReport {
    /// Create a report from a list of checks.
    pub fn from_checks(checks: Vec<ReadinessCheck>) -> Self {
        let ready = checks.iter().all(|c| c.passed);
        Self { ready, checks }
    }
}

impl std::fmt::Display for ReadinessReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Readiness: {}", if self.ready { "READY" } else { "NOT READY" })?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {}", c.name, c.detail)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Transition manager
// -----------------------------------------------------------------------------

/// Manages protocol version transitions.
pub struct TransitionManager {
    /// Activation schedule.
    activations: Vec<ProtocolActivation>,
    /// Current transition state.
    state: TransitionState,
    /// History of state transitions.
    history: Vec<(u64, TransitionState)>,
    /// Events emitted (drained by caller).
    events: Vec<TransitionEvent>,
    /// Current chain height.
    current_height: u64,
    /// Current active PV.
    current_pv: u32,
    /// Snapshot heights available for rollback.
    snapshot_heights: Vec<u64>,
}

impl TransitionManager {
    /// Create a new transition manager.
    ///
    /// Validates that the activation schedule is well-formed:
    /// - Protocol versions strictly increasing
    /// - Activation heights strictly increasing (if present)
    /// - First activation has None height (current PV)
    pub fn new(activations: Vec<ProtocolActivation>, current_height: u64) -> Result<Self, String> {
        Self::validate_activations(&activations)?;

        let current_pv = version_for_height(current_height, &activations);
        let state = Self::compute_initial_state(&activations, current_height, current_pv);

        Ok(Self {
            activations,
            state,
            history: Vec::new(),
            events: Vec::new(),
            current_height,
            current_pv,
            snapshot_heights: Vec::new(),
        })
    }

    /// Validate that the activation schedule is consistent.
    fn validate_activations(activations: &[ProtocolActivation]) -> Result<(), String> {
        if activations.is_empty() {
            return Err("activation schedule cannot be empty".into());
        }

        // First activation must have protocol_version = 1 and None height.
        let first = &activations[0];
        if first.protocol_version != 1 {
            return Err(format!(
                "first protocol_version must be 1, got {}",
                first.protocol_version
            ));
        }
        if first.activation_height.is_some() {
            return Err("first activation must have activation_height = None".into());
        }

        // Check strictly increasing PV and heights.
        let mut prev_pv = first.protocol_version;
        let mut prev_height = None;

        for act in activations.iter().skip(1) {
            if act.protocol_version <= prev_pv {
                return Err(format!(
                    "protocol_version must be strictly increasing: {} <= {}",
                    act.protocol_version, prev_pv
                ));
            }
            prev_pv = act.protocol_version;

            let Some(ah) = act.activation_height else {
                return Err(format!(
                    "activation for PV={} must have a height",
                    act.protocol_version
                ));
            };

            if let Some(prev) = prev_height {
                if ah <= prev {
                    return Err(format!(
                        "activation heights must be strictly increasing: {} <= {}",
                        ah, prev
                    ));
                }
            }
            prev_height = Some(ah);
        }

        Ok(())
    }

    /// Compute the initial state based on the activation schedule and current height.
    fn compute_initial_state(
        activations: &[ProtocolActivation],
        height: u64,
        current_pv: u32,
    ) -> TransitionState {
        // Find the first activation with protocol_version > current_pv.
        let next_activation = activations.iter().find(|a| a.protocol_version > current_pv);

        match next_activation {
            Some(act) => {
                let ah = act.activation_height.expect("activation_height validated at registration");
                let target_pv = act.protocol_version;

                if height < ah {
                    let blocks_remaining = ah - height;
                    if blocks_remaining <= PRE_ACTIVATION_WINDOW {
                        TransitionState::PreActivation {
                            target_pv,
                            activation_height: ah,
                            blocks_remaining,
                        }
                    } else {
                        TransitionState::Scheduled {
                            target_pv,
                            activation_height: ah,
                        }
                    }
                } else {
                    // We are past the activation height, check grace window.
                    let grace = act.grace_blocks;
                    if height < ah + grace {
                        TransitionState::Active {
                            pv: target_pv,
                            grace_remaining: ah + grace - height,
                        }
                    } else {
                        TransitionState::Finalized { pv: target_pv }
                    }
                }
            }
            None => {
                // No future activation; we are at the highest PV.
                // Check if we are in the grace window of the last activation.
                if let Some(last) = activations.last() {
                    if let Some(ah) = last.activation_height {
                        let grace = last.grace_blocks;
                        if height < ah + grace {
                            return TransitionState::Active {
                                pv: last.protocol_version,
                                grace_remaining: ah + grace - height,
                            };
                        }
                    }
                }
                TransitionState::Finalized { pv: current_pv }
            }
        }
    }

    /// Get the current transition state.
    pub fn state(&self) -> &TransitionState {
        &self.state
    }

    /// Get the current protocol version.
    pub fn current_pv(&self) -> u32 {
        self.current_pv
    }

    /// Get the transition history.
    pub fn history(&self) -> &[(u64, TransitionState)] {
        &self.history
    }

    /// Drain pending events.
    pub fn drain_events(&mut self) -> Vec<TransitionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Register a snapshot height for potential rollback.
    pub fn register_snapshot(&mut self, height: u64) {
        self.snapshot_heights.push(height);
        self.snapshot_heights.sort_unstable();
    }

    /// Process a new block at the given height.
    /// Updates internal state and emits events as transitions occur.
    pub fn on_block(&mut self, height: u64) {
        self.current_height = height;
        let new_pv = version_for_height(height, &self.activations);
        let old_pv = self.current_pv;

        if new_pv != old_pv {
            self.current_pv = new_pv;
        }

        let new_state = self.compute_next_state(height, old_pv, new_pv);

        if new_state != self.state {
            let old_state_clone = self.state.clone();
            self.emit_transition_events(&old_state_clone, &new_state, height, old_pv, new_pv);
            self.history.push((height, self.state.clone()));
            self.state = new_state;
        }
    }

    /// Compute the next state based on current height and PV.
    fn compute_next_state(&self, height: u64, old_pv: u32, new_pv: u32) -> TransitionState {
        // Find the activation that corresponds to the current new_pv.
        let current_activation = self.activations.iter().find(|a| a.protocol_version == new_pv);
        // Find the next activation after current new_pv.
        let next_activation = self.activations.iter().find(|a| a.protocol_version > new_pv);

        match &self.state {
            // Idle: if there is a next activation, move to Scheduled/PreActivation.
            TransitionState::Idle => {
                if let Some(next) = next_activation {
                    let ah = next.activation_height.expect("activation_height validated at registration");
                    if height < ah {
                        let blocks_remaining = ah - height;
                        if blocks_remaining <= PRE_ACTIVATION_WINDOW {
                            TransitionState::PreActivation {
                                target_pv: next.protocol_version,
                                activation_height: ah,
                                blocks_remaining,
                            }
                        } else {
                            TransitionState::Scheduled {
                                target_pv: next.protocol_version,
                                activation_height: ah,
                            }
                        }
                    } else {
                        // We should not be Idle if past activation; this case should be handled elsewhere.
                        self.state.clone()
                    }
                } else {
                    self.state.clone()
                }
            }

            // Scheduled: check if we've entered pre-activation window or reached activation.
            TransitionState::Scheduled { target_pv, activation_height } => {
                let ah = *activation_height;
                if height < ah {
                    let blocks_remaining = ah - height;
                    if blocks_remaining <= PRE_ACTIVATION_WINDOW {
                        TransitionState::PreActivation {
                            target_pv: *target_pv,
                            activation_height: ah,
                            blocks_remaining,
                        }
                    } else {
                        self.state.clone()
                    }
                } else {
                    // Activation reached.
                    TransitionState::Activating {
                        from_pv: old_pv,
                        to_pv: *target_pv,
                        activation_height: ah,
                    }
                }
            }

            // PreActivation: check if activation reached.
            TransitionState::PreActivation { target_pv, activation_height, .. } => {
                let ah = *activation_height;
                if height >= ah {
                    TransitionState::Activating {
                        from_pv: old_pv,
                        to_pv: *target_pv,
                        activation_height: ah,
                    }
                } else {
                    self.state.clone()
                }
            }

            // Activating: move to Active after activation.
            TransitionState::Activating { to_pv, activation_height, .. } => {
                let ah = *activation_height;
                if height >= ah {
                    // Find grace blocks for this activation.
                    let grace = self.activations.iter()
                        .find(|a| a.protocol_version == *to_pv)
                        .map(|a| a.grace_blocks)
                        .unwrap_or(0);
                    if grace > 0 && height < ah + grace {
                        TransitionState::Active {
                            pv: *to_pv,
                            grace_remaining: ah + grace - height,
                        }
                    } else {
                        TransitionState::Finalized { pv: *to_pv }
                    }
                } else {
                    self.state.clone()
                }
            }

            // Active: count down grace, then move to Finalized.
            TransitionState::Active { pv, .. } => {
                // Recompute grace_remaining from the activation schedule
                if let Some(act) = current_activation {
                    let ah = act.activation_height.unwrap_or(0);
                    let grace = act.grace_blocks;
                    let end_height = ah + grace;
                    if height > end_height {
                        // Grace expired: check for next activation directly
                        if let Some(next) = next_activation {
                            let next_ah = next.activation_height.expect("validated");
                            if height < next_ah {
                                let blocks_remaining = next_ah - height;
                                if blocks_remaining <= PRE_ACTIVATION_WINDOW {
                                    TransitionState::PreActivation {
                                        target_pv: next.protocol_version,
                                        activation_height: next_ah,
                                        blocks_remaining,
                                    }
                                } else {
                                    TransitionState::Scheduled {
                                        target_pv: next.protocol_version,
                                        activation_height: next_ah,
                                    }
                                }
                            } else {
                                TransitionState::Finalized { pv: *pv }
                            }
                        } else {
                            TransitionState::Finalized { pv: *pv }
                        }
                    } else {
                        let remaining = end_height - height;
                        TransitionState::Active {
                            pv: *pv,
                            grace_remaining: std::cmp::max(remaining, 1),
                        }
                    }
                } else {
                    // No activation found, finalize
                    TransitionState::Finalized { pv: *pv }
                }
            }

            // Finalized: check if there is another activation coming.
            TransitionState::Finalized { pv } => {
                if let Some(next) = next_activation {
                    let ah = next.activation_height.expect("activation_height validated at registration");
                    if height < ah {
                        let blocks_remaining = ah - height;
                        if blocks_remaining <= PRE_ACTIVATION_WINDOW {
                            TransitionState::PreActivation {
                                target_pv: next.protocol_version,
                                activation_height: ah,
                                blocks_remaining,
                            }
                        } else {
                            TransitionState::Scheduled {
                                target_pv: next.protocol_version,
                                activation_height: ah,
                            }
                        }
                    } else {
                        self.state.clone()
                    }
                } else {
                    self.state.clone()
                }
            }

            // Terminal states (Cancelled, RolledBack) stay as is.
            _ => self.state.clone(),
        }
    }

    /// Emit events for a state transition.
    fn emit_transition_events(
        &mut self,
        old: &TransitionState,
        new: &TransitionState,
        height: u64,
        old_pv: u32,
        new_pv: u32,
    ) {
        match new {
            TransitionState::Scheduled { target_pv, activation_height } => {
                self.events.push(TransitionEvent::TransitionScheduled {
                    target_pv: *target_pv,
                    activation_height: *activation_height,
                });
            }
            TransitionState::PreActivation { target_pv, blocks_remaining, .. } => {
                self.events.push(TransitionEvent::EnteredPreActivation {
                    target_pv: *target_pv,
                    blocks_remaining: *blocks_remaining,
                });
            }
            TransitionState::Activating { from_pv, to_pv, activation_height } => {
                self.events.push(TransitionEvent::ActivationReached {
                    from_pv: *from_pv,
                    to_pv: *to_pv,
                    height: *activation_height,
                });
            }
            TransitionState::Active { pv, grace_remaining } => {
                self.events.push(TransitionEvent::PvActivated {
                    pv: *pv,
                    grace_blocks: *grace_remaining,
                });
            }
            TransitionState::Finalized { pv } => {
                self.events.push(TransitionEvent::TransitionFinalized { pv: *pv });
            }
            TransitionState::Cancelled { target_pv, reason } => {
                self.events.push(TransitionEvent::TransitionCancelled {
                    target_pv: *target_pv,
                    reason: reason.clone(),
                });
            }
            TransitionState::RolledBack { from_pv, to_pv, .. } => {
                self.events.push(TransitionEvent::TransitionRolledBack {
                    from_pv: *from_pv,
                    to_pv: *to_pv,
                });
            }
            _ => {}
        }
    }

    /// Cancel a scheduled transition (only valid before activation).
    pub fn cancel(&mut self, reason: &str) -> Result<(), String> {
        match &self.state {
            TransitionState::Scheduled { target_pv, .. }
            | TransitionState::PreActivation { target_pv, .. } => {
                let tpv = *target_pv;
                self.history.push((self.current_height, self.state.clone()));
                self.state = TransitionState::Cancelled {
                    target_pv: tpv,
                    reason: reason.to_string(),
                };
                self.events.push(TransitionEvent::TransitionCancelled {
                    target_pv: tpv,
                    reason: reason.to_string(),
                });
                Ok(())
            }
            _ => Err(format!("cannot cancel transition in state: {}", self.state)),
        }
    }

    /// Attempt rollback to a previous PV (requires snapshot before activation).
    pub fn rollback(&mut self, reason: &str) -> Result<u64, String> {
        // Find the latest snapshot before the activation height.
        let activation_height = match &self.state {
            TransitionState::Active { .. }
            | TransitionState::Activating { .. } => {
                self.activations.iter()
                    .filter(|a| a.protocol_version == self.current_pv)
                    .filter_map(|a| a.activation_height)
                    .max()
                    .ok_or("no activation height found")?
            }
            _ => return Err(format!("cannot rollback in state: {}", self.state)),
        };

        let snapshot = self.snapshot_heights.iter()
            .rev()
            .find(|&&h| h < activation_height)
            .copied()
            .ok_or("no snapshot available before activation height")?;

        let from_pv = self.current_pv;
        let to_pv = version_for_height(snapshot, &self.activations);

        self.history.push((self.current_height, self.state.clone()));
        self.state = TransitionState::RolledBack {
            from_pv,
            to_pv,
            reason: reason.to_string(),
        };
        self.events.push(TransitionEvent::TransitionRolledBack { from_pv, to_pv });
        self.current_pv = to_pv;

        Ok(snapshot)
    }

    /// Run pre-activation readiness checks.
    pub fn check_readiness(&self) -> ReadinessReport {
        let mut checks = Vec::new();

        // Check 1: Binary supports target PV.
        let target_pv = match &self.state {
            TransitionState::Scheduled { target_pv, .. }
            | TransitionState::PreActivation { target_pv, .. } => Some(*target_pv),
            _ => None,
        };

        if let Some(tpv) = target_pv {
            checks.push(ReadinessCheck {
                name: "binary_supports_target_pv".into(),
                passed: SUPPORTED_PROTOCOL_VERSIONS.contains(&tpv),
                detail: format!(
                    "target PV={tpv}, supported={SUPPORTED_PROTOCOL_VERSIONS:?}"
                ),
            });
        }

        // Check 2: Current PV is supported.
        checks.push(ReadinessCheck {
            name: "current_pv_supported".into(),
            passed: SUPPORTED_PROTOCOL_VERSIONS.contains(&self.current_pv),
            detail: format!("current PV={}", self.current_pv),
        });

        // Check 3: Snapshot available for rollback.
        checks.push(ReadinessCheck {
            name: "snapshot_available".into(),
            passed: !self.snapshot_heights.is_empty(),
            detail: format!("{} snapshots registered", self.snapshot_heights.len()),
        });

        // Check 4: Activation schedule is valid (already validated at creation).
        checks.push(ReadinessCheck {
            name: "activation_schedule_valid".into(),
            passed: true,
            detail: format!("{} activations defined", self.activations.len()),
        });

        // Check 5: No pending migration.
        checks.push(ReadinessCheck {
            name: "no_pending_state".into(),
            passed: !matches!(self.state, TransitionState::Cancelled { .. } | TransitionState::RolledBack { .. }),
            detail: format!("current state: {}", self.state),
        });

        ReadinessReport::from_checks(checks)
    }

    /// Validate that a block's PV is correct for the given height.
    pub fn validate_block_pv(&self, block_pv: u32, height: u64) -> Result<(), String> {
        super::version::validate_block_version(block_pv, height, &self.activations)
    }

    /// Get a summary of the transition manager's state.
    pub fn summary(&self) -> TransitionSummary {
        TransitionSummary {
            current_height: self.current_height,
            current_pv: self.current_pv,
            state: format!("{}", self.state),
            history_len: self.history.len(),
            snapshots: self.snapshot_heights.len(),
            pending_events: self.events.len(),
        }
    }
}

/// Summary of the transition manager state (for RPC / metrics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionSummary {
    pub current_height: u64,
    pub current_pv: u32,
    pub state: String,
    pub history_len: usize,
    pub snapshots: usize,
    pub pending_events: usize,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
        ]
    }

    fn upgrade_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 10,
            },
        ]
    }

    fn multi_upgrade_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 10,
            },
            ProtocolActivation {
                protocol_version: 3,
                activation_height: Some(200),
                grace_blocks: 20,
            },
        ]
    }

    #[test]
    fn test_validate_activations_ok() {
        let acts = upgrade_activations();
        assert!(TransitionManager::validate_activations(&acts).is_ok());
    }

    #[test]
    fn test_validate_activations_invalid_first() {
        let acts = vec![
            ProtocolActivation {
                protocol_version: 2,
                activation_height: None,
                grace_blocks: 0,
            },
        ];
        assert!(TransitionManager::validate_activations(&acts).is_err());
    }

    #[test]
    fn test_validate_activations_non_increasing() {
        let acts = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 10,
            },
            ProtocolActivation {
                protocol_version: 2, // duplicate
                activation_height: Some(200),
                grace_blocks: 20,
            },
        ];
        assert!(TransitionManager::validate_activations(&acts).is_err());
    }

    #[test]
    fn test_initial_state_idle() {
        let mgr = TransitionManager::new(basic_activations(), 50).unwrap();
        assert!(matches!(mgr.state(), TransitionState::Finalized { pv: 1 }));
        assert_eq!(mgr.current_pv(), 1);
    }

    #[test]
    fn test_initial_state_scheduled() {
        // With PRE_ACTIVATION_WINDOW = 1000, activation at 2000, height=1 -> Scheduled
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mgr = TransitionManager::new(activations, 1).unwrap();
        assert!(matches!(mgr.state(), TransitionState::Scheduled { target_pv: 2, activation_height: 2000 }));
    }

    #[test]
    fn test_initial_state_pre_activation() {
        // Activation at 500, height=1, PRE_ACTIVATION_WINDOW=1000 -> PreActivation
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(500),
                grace_blocks: 10,
            },
        ];
        let mgr = TransitionManager::new(activations, 1).unwrap();
        assert!(matches!(mgr.state(), TransitionState::PreActivation { target_pv: 2, activation_height: 500, .. }));
    }

    #[test]
    fn test_initial_state_active() {
        // Height 150, activation at 100 with grace 10 -> still in grace (150 < 110? no) -> active?
        // Wait: activation 100, grace 10 => grace up to 110. Height 150 > 110 => should be Finalized.
        // Let's use height 105.
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 10,
            },
        ];
        let mgr = TransitionManager::new(activations, 105).unwrap();
        assert!(matches!(mgr.state(), TransitionState::Active { pv: 2, grace_remaining: 5 }));
    }

    #[test]
    fn test_initial_state_finalized() {
        let activations = upgrade_activations();
        let mgr = TransitionManager::new(activations, 200).unwrap(); // past grace
        assert!(matches!(mgr.state(), TransitionState::Finalized { pv: 2 }));
    }

    #[test]
    fn test_transition_to_pre_activation() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mut mgr = TransitionManager::new(activations, 1).unwrap();
        // At height 1, activation at 2000: Scheduled (1999 > 1000)
        assert!(matches!(mgr.state(), TransitionState::Scheduled { .. }));

        // Advance to pre-activation window (height 1001)
        mgr.on_block(1001);
        assert!(matches!(mgr.state(), TransitionState::PreActivation { target_pv: 2, activation_height: 2000, blocks_remaining: 999 }));
    }

    #[test]
    fn test_transition_to_activating() {
        let activations = upgrade_activations();
        let mut mgr = TransitionManager::new(activations, 50).unwrap();
        mgr.on_block(99);
        assert!(matches!(mgr.state(), TransitionState::PreActivation { .. }));
        mgr.on_block(100);
        assert!(matches!(mgr.state(), TransitionState::Activating { from_pv: 1, to_pv: 2, .. }));
    }

    #[test]
    fn test_transition_to_active() {
        let activations = upgrade_activations();
        let mut mgr = TransitionManager::new(activations, 100).unwrap();
        // At height 100, activation reached, but not yet applied? Our state machine should move to Activating.
        // But we need to simulate a block at height 100: on_block(100) will compute new state.
        mgr.on_block(100);
        // After processing block at height 100, we should be in Activating? Let's see: compute_next_state at height 100 with Scheduled? Actually initial state at height 100? We start at height 100? The constructor sets current_height=100, state = compute_initial_state at height 100. That should be Activating.
        // Let's check: compute_initial_state at height 100: next_activation PV=2, ah=100, height=100, so we go to Active? No, in compute_initial_state we handle height < ah? height=100, ah=100, so not less, then check grace: grace 10, height=100 < 110 => Active. So initial state is Active. That's fine.
        // Then on_block(101) should keep Active with decreasing grace.
        mgr.on_block(101);
        assert!(matches!(mgr.state(), TransitionState::Active { pv: 2, grace_remaining: 9 }));
    }

    #[test]
    fn test_grace_countdown() {
        let activations = upgrade_activations();
        let mut mgr = TransitionManager::new(activations, 101).unwrap();
        assert!(matches!(mgr.state(), TransitionState::Active { grace_remaining: 9, .. }));

        mgr.on_block(102);
        assert!(matches!(mgr.state(), TransitionState::Active { grace_remaining: 8, .. }));

        // ... down to 0
        for i in 0..8 {
            mgr.on_block(103 + i);
        }
        // After 9 more blocks, we should reach height 111 -> grace_remaining 0? Let's calculate: start at 101 with 9, after 1 block at 102 ->8, ... at 110 ->1, at 111 ->0, should transition to Finalized.
        mgr.on_block(110);
        assert!(matches!(mgr.state(), TransitionState::Active { grace_remaining: 1, .. }));
        mgr.on_block(111);
        assert!(matches!(mgr.state(), TransitionState::Finalized { pv: 2 }));
    }

    #[test]
    fn test_cancel_scheduled() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mut mgr = TransitionManager::new(activations, 1).unwrap();
        assert!(matches!(mgr.state(), TransitionState::Scheduled { .. }));

        let result = mgr.cancel("critical bug found");
        assert!(result.is_ok());
        assert!(matches!(mgr.state(), TransitionState::Cancelled { target_pv: 2, .. }));

        let events = mgr.drain_events();
        assert!(events.iter().any(|e| matches!(e, TransitionEvent::TransitionCancelled { .. })));
    }

    #[test]
    fn test_cancel_invalid_state() {
        let mgr_activations = basic_activations();
        let mut mgr = TransitionManager::new(mgr_activations, 50).unwrap();
        assert!(mgr.cancel("test").is_err());
    }

    #[test]
    fn test_readiness_check() {
        let mut mgr = TransitionManager::new(upgrade_activations(), 50).unwrap();
        mgr.register_snapshot(40);

        let report = mgr.check_readiness();
        // current_pv_supported should pass
        assert!(report.checks.iter().any(|c| c.name == "current_pv_supported" && c.passed));
        // snapshot_available should pass
        assert!(report.checks.iter().any(|c| c.name == "snapshot_available" && c.passed));
        // target PV check should be present because state is PreActivation? Actually at height 50, activation at 100, we are in PreActivation. So yes.
        assert!(report.checks.iter().any(|c| c.name == "binary_supports_target_pv" && c.passed));
    }

    #[test]
    fn test_summary() {
        let mgr = TransitionManager::new(basic_activations(), 50).unwrap();
        let summary = mgr.summary();
        assert_eq!(summary.current_height, 50);
        assert_eq!(summary.current_pv, 1);
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", TransitionState::Idle), "Idle");
        assert_eq!(
            format!("{}", TransitionState::Finalized { pv: 2 }),
            "Finalized(PV=2)"
        );
    }

    #[test]
    fn test_history_tracking() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mut mgr = TransitionManager::new(activations, 1).unwrap();
        assert!(mgr.history().is_empty());

        // Advance to pre-activation
        mgr.on_block(1001);
        assert_eq!(mgr.history().len(), 1);
    }

    #[test]
    fn test_multi_upgrade() {
        let activations = multi_upgrade_activations();
        let mut mgr = TransitionManager::new(activations, 1).unwrap();
        // Height 1: activation at 100 (PV2) and 200 (PV3). At 1, PV2 is Scheduled? 100-1=99 <1000, so PreActivation for PV2.
        assert!(matches!(mgr.state(), TransitionState::PreActivation { target_pv: 2, activation_height: 100, .. }));

        mgr.on_block(100);
        // At 100, should become Activating for PV2.
        assert!(matches!(mgr.state(), TransitionState::Activating { from_pv: 1, to_pv: 2, .. }));

        mgr.on_block(101);
        // At 101, grace for PV2: 10 blocks, so Active with grace 9.
        assert!(matches!(mgr.state(), TransitionState::Active { pv: 2, grace_remaining: 9 }));

        // Fast forward to after grace (111)
        for h in 102..=111 {
            mgr.on_block(h);
        }
        // At 111, PV2 should be Finalized, and next activation PV3 should be Scheduled/PreActivation? At 111, next activation PV3 at 200, distance 89 < 1000 -> PreActivation.
        assert!(matches!(mgr.state(), TransitionState::PreActivation { target_pv: 3, activation_height: 200, .. }));

        mgr.on_block(200);
        // At 200, should become Activating for PV3.
        assert!(matches!(mgr.state(), TransitionState::Activating { from_pv: 2, to_pv: 3, .. }));

        mgr.on_block(201);
        // At 201, grace 20 -> Active.
        assert!(matches!(mgr.state(), TransitionState::Active { pv: 3, grace_remaining: 19 }));
    }
}
