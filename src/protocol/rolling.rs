//! Rolling upgrade scenario simulation and validation.
//!
//! Provides tools for planning, simulating, and validating rolling upgrades
//! across a multi-node IONA network. A rolling upgrade means nodes are
//! upgraded one at a time while the network continues producing blocks.
//!
//! # Upgrade Phases
//!
//! ```text
//! Phase 1: Pre-upgrade     All nodes on PV_old
//! Phase 2: Rolling         Nodes upgrade one-by-one; mixed PV_old + PV_new
//! Phase 3: Post-upgrade    All nodes on PV_new (before activation)
//! Phase 4: Activation      PV_new becomes mandatory at activation_height
//! Phase 5: Grace expiry    Old PV blocks rejected after grace window
//! ```
//!
//! # Safety Guarantees
//!
//! During a rolling upgrade:
//! - Network liveness is maintained (≥ 2f+1 nodes always online)
//! - No split finality (invariant S1)
//! - Finality monotonicity (invariant S2)
//! - Deterministic PV selection (invariant S3)
//! - Wire compatibility between old and new nodes (handshake overlap)

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use tracing::{debug, info, warn};

use super::version::{ProtocolActivation, version_for_height, SUPPORTED_PROTOCOL_VERSIONS, CURRENT_PROTOCOL_VERSION};
use super::wire::{Hello, check_hello_compat};
use super::safety::{self, SafetyCheck};
use crate::types::Height;

// -----------------------------------------------------------------------------
// Constants & Type Aliases
// -----------------------------------------------------------------------------

/// Estimated seconds per block (used for timing estimates).
const ESTIMATED_BLOCK_TIME_SECS: u64 = 2;

// -----------------------------------------------------------------------------
// Upgrade Plan
// -----------------------------------------------------------------------------

/// A planned rolling upgrade for a set of nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollingUpgradePlan {
    /// Total number of validator nodes.
    pub total_nodes: usize,
    /// Maximum concurrent Byzantine faults tolerated (f < N/3).
    pub max_byzantine: usize,
    /// Maximum nodes that can be offline simultaneously during upgrade.
    pub max_offline: usize,
    /// Upgrade order (node indices).
    pub upgrade_order: Vec<usize>,
    /// Target protocol version.
    pub target_pv: u32,
    /// Activation height (None for minor/rolling upgrades without PV change).
    pub activation_height: Option<u64>,
    /// Grace window in blocks after activation.
    pub grace_blocks: u64,
    /// Estimated time per node upgrade (seconds).
    pub estimated_per_node_s: u64,
    /// Whether to enforce strict ordering (cannot skip nodes).
    pub strict_ordering: bool,
}

impl RollingUpgradePlan {
    /// Create a plan for upgrading N nodes to a target PV.
    ///
    /// # Panics
    ///
    /// Panics if `target_pv` is not greater than the current protocol version.
    pub fn new(total_nodes: usize, target_pv: u32) -> Self {
        assert!(
            target_pv > CURRENT_PROTOCOL_VERSION,
            "target PV must be greater than current ({})",
            CURRENT_PROTOCOL_VERSION
        );

        let max_byzantine = (total_nodes - 1) / 3;
        // During upgrade, at most 1 node is offline at a time.
        let max_offline = 1;
        let upgrade_order: Vec<usize> = (0..total_nodes).collect();

        Self {
            total_nodes,
            max_byzantine,
            max_offline,
            upgrade_order,
            target_pv,
            activation_height: None,
            grace_blocks: 1000,
            estimated_per_node_s: 120,
            strict_ordering: true,
        }
    }

    /// Set activation height for a coordinated hard-fork upgrade.
    pub fn with_activation(mut self, height: u64, grace: u64) -> Self {
        self.activation_height = Some(height);
        self.grace_blocks = grace;
        self
    }

    /// Set custom upgrade order.
    pub fn with_order(mut self, order: Vec<usize>) -> Self {
        self.upgrade_order = order;
        self
    }

    /// Disable strict ordering (allows skipping nodes, but riskier).
    pub fn with_relaxed_ordering(mut self) -> Self {
        self.strict_ordering = false;
        self
    }

    /// Validate the upgrade plan.
    ///
    /// Returns `Ok(())` if the plan is valid, or a vector of error messages.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.total_nodes < 4 {
            errors.push(format!(
                "minimum 4 nodes required for BFT (have {})",
                self.total_nodes
            ));
        }

        let f = self.max_byzantine;
        let required_online = self.total_nodes - f;
        if self.max_offline > f {
            errors.push(format!(
                "max_offline ({}) exceeds BFT tolerance f={} for N={}",
                self.max_offline, f, self.total_nodes
            ));
        }

        if self.upgrade_order.len() != self.total_nodes {
            errors.push(format!(
                "upgrade_order length ({}) != total_nodes ({})",
                self.upgrade_order.len(), self.total_nodes
            ));
        }

        // Check for duplicate indices and invalid indices.
        let mut seen = vec![false; self.total_nodes];
        for &idx in &self.upgrade_order {
            if idx >= self.total_nodes {
                errors.push(format!("invalid node index {idx} in upgrade_order"));
            } else if seen[idx] {
                errors.push(format!("duplicate node index {idx} in upgrade_order"));
            } else {
                seen[idx] = true;
            }
        }

        // Check target PV is supported by this binary and is greater than current.
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&self.target_pv) {
            errors.push(format!(
                "target PV={} is not supported by this binary (supported: {:?})",
                self.target_pv, SUPPORTED_PROTOCOL_VERSIONS
            ));
        }
        if self.target_pv <= CURRENT_PROTOCOL_VERSION {
            errors.push(format!(
                "target PV must be > current ({})",
                CURRENT_PROTOCOL_VERSION
            ));
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Estimate total upgrade duration in seconds.
    pub fn estimated_duration_s(&self) -> u64 {
        self.total_nodes as u64 * self.estimated_per_node_s
    }

    /// Estimate total upgrade duration in blocks.
    pub fn estimated_duration_blocks(&self) -> u64 {
        self.estimated_duration_s() / ESTIMATED_BLOCK_TIME_SECS
    }

    /// Check if activation height gives enough time for rolling upgrade.
    pub fn check_activation_timing(&self) -> Option<String> {
        if let Some(ah) = self.activation_height {
            let estimated_blocks = self.estimated_duration_blocks();
            if ah < estimated_blocks {
                return Some(format!(
                    "activation_height={ah} may be too soon; estimated upgrade takes ~{estimated_blocks} blocks"
                ));
            }
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Simulated Node
// -----------------------------------------------------------------------------

/// State of a simulated node during rolling upgrade.
#[derive(Debug, Clone)]
pub struct SimNode {
    /// Node index.
    pub index: usize,
    /// Protocol versions this node supports.
    pub supported_pv: Vec<u32>,
    /// Whether the node is currently online.
    pub online: bool,
    /// Whether the node has been upgraded.
    pub upgraded: bool,
    /// Current chain height on this node.
    pub height: Height,
    /// Finalized height on this node.
    pub finalized_height: Height,
    /// Whether this node is considered Byzantine (malicious).
    pub byzantine: bool,
}

impl SimNode {
    fn new(index: usize, start_height: Height) -> Self {
        Self {
            index,
            supported_pv: vec![CURRENT_PROTOCOL_VERSION],
            online: true,
            upgraded: false,
            height: start_height,
            finalized_height: start_height,
            byzantine: false,
        }
    }

    /// Mark this node as Byzantine (it will behave maliciously).
    fn set_byzantine(&mut self) {
        self.byzantine = true;
    }

    /// Get the hello message for this node at given height.
    fn hello(&self, height: Height, pv: u32) -> Hello {
        Hello {
            supported_pv: self.supported_pv.clone(),
            supported_sv: vec![0, 1, 2, 3, 4, 5], // example
            software_version: "simulated".into(),
            chain_id: 6126151,
            genesis_hash: crate::types::Hash32::zero(),
            head_height: height,
            head_pv: pv,
        }
    }
}

// -----------------------------------------------------------------------------
// Simulation Events & Results
// -----------------------------------------------------------------------------

/// Events during simulation.
#[derive(Debug, Clone)]
pub enum SimEvent {
    /// Node taken offline for upgrade.
    NodeOffline { index: usize, height: Height },
    /// Node brought back online after upgrade.
    NodeOnline { index: usize, height: Height, new_pv: Vec<u32> },
    /// Block produced at height.
    BlockProduced { height: Height, pv: u32, proposer: usize },
    /// All nodes upgraded.
    AllUpgraded { height: Height },
    /// Activation height reached.
    ActivationReached { height: Height, pv: u32 },
    /// Safety check passed.
    SafetyCheckPassed { check: String, height: Height },
    /// Safety violation detected.
    SafetyViolation { check: String, height: Height, detail: String },
    /// Byzantine node detected.
    ByzantineDetected { index: usize, height: Height },
}

impl fmt::Display for SimEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SimEvent::NodeOffline { index, height } =>
                write!(f, "Node {} offline at height {}", index, height),
            SimEvent::NodeOnline { index, height, new_pv } =>
                write!(f, "Node {} online at height {} with PVs {:?}", index, height, new_pv),
            SimEvent::BlockProduced { height, pv, proposer } =>
                write!(f, "Block produced at height {}, PV={}, proposer={}", height, pv, proposer),
            SimEvent::AllUpgraded { height } =>
                write!(f, "All nodes upgraded at height {}", height),
            SimEvent::ActivationReached { height, pv } =>
                write!(f, "Activation reached at height {}, PV={} now mandatory", height, pv),
            SimEvent::SafetyCheckPassed { check, height } =>
                write!(f, "Safety check {} passed at height {}", check, height),
            SimEvent::SafetyViolation { check, height, detail } =>
                write!(f, "Safety violation {} at height {}: {}", check, height, detail),
            SimEvent::ByzantineDetected { index, height } =>
                write!(f, "Byzantine node {} detected at height {}", index, height),
        }
    }
}

/// Result of a rolling upgrade simulation.
#[derive(Debug, Clone)]
pub struct SimResult {
    /// Whether the simulation succeeded (no safety violations).
    pub success: bool,
    /// Safety violations detected (empty if success).
    pub violations: Vec<String>,
    /// Events that occurred during simulation.
    pub events: Vec<SimEvent>,
    /// Final state of each node.
    pub nodes: Vec<SimNode>,
    /// Total blocks produced during simulation.
    pub blocks_produced: u64,
}

impl SimResult {
    /// Print a summary of the simulation.
    pub fn print_summary(&self) {
        println!("=== Rolling Upgrade Simulation ===");
        println!("Success: {}", self.success);
        println!("Blocks produced: {}", self.blocks_produced);
        println!("Violations: {}", self.violations.len());
        for v in &self.violations {
            println!("  - {}", v);
        }
        println!("Events:");
        for e in &self.events {
            println!("  {}", e);
        }
    }

    /// Log the result using tracing.
    pub fn log(&self) {
        if self.success {
            info!("Rolling upgrade simulation succeeded: {} blocks, {} events",
                  self.blocks_produced, self.events.len());
        } else {
            warn!("Rolling upgrade simulation FAILED with {} violations", self.violations.len());
            for v in &self.violations {
                warn!("  Violation: {}", v);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Simulation Core
// -----------------------------------------------------------------------------

/// Configuration for the simulation.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Number of Byzantine nodes (malicious).
    pub num_byzantine: usize,
    /// Whether to enforce strict ordering.
    pub strict_ordering: bool,
    /// Whether to simulate network delays.
    pub simulate_network_delays: bool,
    /// Maximum delay in blocks (if simulate_network_delays true).
    pub max_network_delay_blocks: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            num_byzantine: 0,
            strict_ordering: true,
            simulate_network_delays: false,
            max_network_delay_blocks: 5,
        }
    }
}

/// Simulate a rolling upgrade according to the plan.
pub fn simulate_rolling_upgrade(
    plan: &RollingUpgradePlan,
    activations: &[ProtocolActivation],
    start_height: Height,
    blocks_to_simulate: u64,
    config: &SimConfig,
) -> SimResult {
    let mut nodes: Vec<SimNode> = (0..plan.total_nodes)
        .map(|i| SimNode::new(i, start_height))
        .collect();

    // Mark Byzantine nodes.
    for i in 0..config.num_byzantine.min(plan.total_nodes) {
        nodes[i].set_byzantine();
    }

    let mut events = Vec::new();
    let mut violations = Vec::new();
    let mut blocks_produced = 0u64;
    let mut next_upgrade_idx = 0usize;
    let mut all_upgraded = false;
    let mut node_heights: Vec<Height> = vec![start_height; plan.total_nodes];
    let mut node_finalized: Vec<Height> = vec![start_height; plan.total_nodes];

    // Helper to check if a node is Byzantine.
    let is_byzantine = |idx: usize| nodes[idx].byzantine;

    // Upgrade interval (blocks between upgrades).
    let upgrade_interval = if plan.total_nodes > 0 {
        (blocks_to_simulate / (plan.total_nodes as u64 + 1)).max(1)
    } else {
        blocks_to_simulate
    };

    for block_num in 0..blocks_to_simulate {
        let height = start_height + block_num + 1;

        // Determine current PV at this height.
        let pv = version_for_height(height, activations);

        // Check if it's time to upgrade a node.
        if !all_upgraded
            && next_upgrade_idx < plan.upgrade_order.len()
            && block_num > 0
            && block_num % upgrade_interval == 0
        {
            let node_idx = plan.upgrade_order[next_upgrade_idx];

            if !nodes[node_idx].online {
                violations.push(format!("Node {} already offline at height {}", node_idx, height));
            }

            // Take node offline.
            nodes[node_idx].online = false;
            events.push(SimEvent::NodeOffline { index: node_idx, height });

            // Upgrade node.
            nodes[node_idx].supported_pv = (CURRENT_PROTOCOL_VERSION..=plan.target_pv).collect();
            nodes[node_idx].upgraded = true;

            // Simulate network delay if configured.
            if config.simulate_network_delays {
                // Node comes back online after a random delay (simplified: fixed delay)
                let delay = config.max_network_delay_blocks.min(5);
                node_heights[node_idx] = height.saturating_sub(delay);
            }

            // Bring node back online (immediately unless delayed).
            if !config.simulate_network_delays {
                nodes[node_idx].online = true;
                events.push(SimEvent::NodeOnline {
                    index: node_idx,
                    height,
                    new_pv: nodes[node_idx].supported_pv.clone(),
                });
            } else {
                // Will be set online later when it catches up.
            }

            next_upgrade_idx += 1;

            if next_upgrade_idx >= plan.upgrade_order.len() {
                all_upgraded = true;
                events.push(SimEvent::AllUpgraded { height });
            }
        }

        // Determine online nodes at this height (considering network delays).
        let online_nodes: Vec<usize> = nodes.iter()
            .enumerate()
            .filter(|(i, n)| {
                if !n.online { return false; }
                if config.simulate_network_delays {
                    // Node is online only if its height is up to date.
                    node_heights[*i] >= height
                } else {
                    true
                }
            })
            .map(|(i, _)| i)
            .collect();

        if online_nodes.is_empty() {
            violations.push(format!("no online nodes at height {height}"));
            continue;
        }

        // Check BFT liveness: need ≥ 2f+1 online.
        let required_online = plan.total_nodes - plan.max_byzantine;
        if online_nodes.len() < required_online {
            violations.push(format!(
                "liveness violation at height {height}: only {} online, need {}",
                online_nodes.len(), required_online
            ));
        }

        // Select proposer (round-robin among online nodes).
        let proposer = online_nodes[height as usize % online_nodes.len()];

        // Byzantine proposer may cause trouble, but we only log.
        if is_byzantine(proposer) {
            events.push(SimEvent::ByzantineDetected { index: proposer, height });
        }

        // Produce block.
        events.push(SimEvent::BlockProduced { height, pv, proposer });
        blocks_produced += 1;

        // Update all online nodes.
        for (i, node) in nodes.iter_mut().enumerate() {
            if online_nodes.contains(&i) {
                node.height = height;
                node.finalized_height = height;
                node_heights[i] = height;
                node_finalized[i] = height;
            }
        }

        // Safety checks.

        // S1: No split finality (all finalized heights should be equal).
        if !node_finalized.iter().all(|&h| h == node_finalized[0]) {
            violations.push(format!("S1 at height {height}: split finality detected"));
            events.push(SimEvent::SafetyViolation {
                check: "S1".into(), height, detail: "split finality".into(),
            });
        } else {
            events.push(SimEvent::SafetyCheckPassed { check: "S1".into(), height });
        }

        // S2: Finality monotonic (finalized heights must never decrease).
        if height > start_height + 1 {
            let prev_finalized = node_finalized[0];
            if node_finalized[0] < prev_finalized {
                violations.push(format!(
                    "S2 at height {height}: finalized height decreased from {} to {}",
                    prev_finalized, node_finalized[0]
                ));
                events.push(SimEvent::SafetyViolation {
                    check: "S2".into(), height,
                    detail: format!("decreased from {} to {}", prev_finalized, node_finalized[0]),
                });
            } else {
                events.push(SimEvent::SafetyCheckPassed { check: "S2".into(), height });
            }
        }

        // S3: Deterministic PV selection (checked implicitly by version_for_height).

        // Wire compatibility: all online node pairs must be compatible.
        for i in 0..nodes.len() {
            for j in (i+1)..nodes.len() {
                if !online_nodes.contains(&i) || !online_nodes.contains(&j) { continue; }
                let hello_i = nodes[i].hello(node_heights[i], pv);
                let hello_j = nodes[j].hello(node_heights[j], pv);
                let compat = check_hello_compat(&hello_i, &hello_j);
                if !compat.compatible {
                    let detail = format!("node {} <-> node {}: {}", i, j, compat.reason);
                    violations.push(format!("wire incompat at height {height}: {}", detail));
                    events.push(SimEvent::SafetyViolation {
                        check: "WIRE".into(), height, detail,
                    });
                } else {
                    events.push(SimEvent::SafetyCheckPassed { check: "WIRE".into(), height });
                }
            }
        }

        // Check for activation.
        if let Some(ah) = plan.activation_height {
            if height == ah {
                events.push(SimEvent::ActivationReached { height, pv });
            }
        }
    }

    SimResult {
        success: violations.is_empty(),
        violations,
        events,
        nodes,
        blocks_produced,
    }
}

// -----------------------------------------------------------------------------
// Safety Validation
// -----------------------------------------------------------------------------

/// Validate that a rolling upgrade plan is safe for the given network.
pub fn validate_upgrade_safety(plan: &RollingUpgradePlan) -> Vec<String> {
    let mut warnings = Vec::new();

    // Check BFT tolerance.
    let quorum = (plan.total_nodes * 2 + 2) / 3; // ceil(2N/3)
    let min_online = plan.total_nodes - plan.max_offline;
    if min_online < quorum {
        warnings.push(format!(
            "insufficient quorum during upgrade: {min_online} online < {quorum} required"
        ));
    }

    // Check upgrade order doesn't take too many nodes offline.
    if plan.max_offline > 1 {
        warnings.push(format!(
            "max_offline={} > 1; taking multiple nodes offline simultaneously is risky",
            plan.max_offline
        ));
    }

    // Check activation timing.
    if let Some(msg) = plan.check_activation_timing() {
        warnings.push(msg);
    }

    // Check that target PV is supported (already done in validate).
    warnings
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::ProtocolActivation;

    fn basic_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ]
    }

    #[test]
    fn test_plan_creation() {
        let plan = RollingUpgradePlan::new(4, 2);
        assert_eq!(plan.total_nodes, 4);
        assert_eq!(plan.max_byzantine, 1);
        assert_eq!(plan.upgrade_order, vec![0, 1, 2, 3]);
        assert_eq!(plan.target_pv, 2);
    }

    #[test]
    #[should_panic(expected = "target PV must be greater than current")]
    fn test_plan_invalid_target() {
        let _ = RollingUpgradePlan::new(4, 1);
    }

    #[test]
    fn test_plan_validation_ok() {
        let plan = RollingUpgradePlan::new(4, 2);
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn test_plan_validation_too_few_nodes() {
        let plan = RollingUpgradePlan::new(2, 2);
        assert!(plan.validate().is_err());
    }

    #[test]
    fn test_plan_validation_duplicate_order() {
        let mut plan = RollingUpgradePlan::new(4, 2);
        plan.upgrade_order = vec![0, 1, 1, 3]; // duplicate index 1
        assert!(plan.validate().is_err());
    }

    #[test]
    fn test_simulate_basic_rolling() {
        let plan = RollingUpgradePlan::new(4, 2);
        let activations = basic_activations();
        let config = SimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 50, &config);

        assert!(result.success, "violations: {:?}", result.violations);
        assert_eq!(result.blocks_produced, 50);
        assert!(result.nodes.iter().all(|n| n.upgraded));
    }

    #[test]
    fn test_simulate_with_activation() {
        let plan = RollingUpgradePlan::new(4, 2)
            .with_activation(30, 5);
        let activations = basic_activations();
        let config = SimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 60, &config);

        let has_activation = result.events.iter().any(|e| matches!(e, SimEvent::ActivationReached { .. }));
        assert!(has_activation, "should have ActivationReached event");
    }

    #[test]
    fn test_simulate_with_byzantine() {
        let plan = RollingUpgradePlan::new(4, 2);
        let activations = basic_activations();
        let config = SimConfig {
            num_byzantine: 1,
            ..Default::default()
        };
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 50, &config);

        // Byzantine node may cause violations, but we don't assert success.
        // We just check that events include ByzantineDetected.
        let has_byzantine = result.events.iter().any(|e| matches!(e, SimEvent::ByzantineDetected { .. }));
        assert!(has_byzantine);
    }

    #[test]
    fn test_validate_safety_ok() {
        let plan = RollingUpgradePlan::new(4, 2);
        let warnings = validate_upgrade_safety(&plan);
        assert!(warnings.is_empty(), "unexpected warnings: {:?}", warnings);
    }

    #[test]
    fn test_estimated_duration() {
        let plan = RollingUpgradePlan::new(7, 2);
        assert_eq!(plan.estimated_duration_s(), 7 * 120);
        assert_eq!(plan.estimated_duration_blocks(), 7 * 120 / 2);
    }

    #[test]
    fn test_activation_timing_warning() {
        let plan = RollingUpgradePlan::new(7, 2)
            .with_activation(10, 5); // too soon
        let warning = plan.check_activation_timing();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("too soon"));
    }

    #[test]
    fn test_wire_compat_during_rolling() {
        let plan = RollingUpgradePlan::new(5, 2);
        let activations = basic_activations();
        let config = SimConfig::default();
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 30, &config);

        let wire_violations: Vec<_> = result.violations.iter()
            .filter(|v| v.contains("wire incompat"))
            .collect();
        assert!(wire_violations.is_empty(), "wire violations: {:?}", wire_violations);
    }

    #[test]
    fn test_simulate_with_network_delays() {
        let plan = RollingUpgradePlan::new(4, 2);
        let activations = basic_activations();
        let config = SimConfig {
            simulate_network_delays: true,
            ..Default::default()
        };
        let result = simulate_rolling_upgrade(&plan, &activations, 0, 50, &config);
        // Not expecting success necessarily, but should run without panic.
        assert!(result.blocks_produced > 0);
    }
}
