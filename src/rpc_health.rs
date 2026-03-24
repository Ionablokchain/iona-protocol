//! Health, status, and metrics RPC endpoints for IONA v28.
//!
//! GET /health  → ok/fail + reason
//! GET /status  → height, round, peers, validator set, commit info
//! GET /metrics → prometheus-format metrics (optional)

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// -----------------------------------------------------------------------------
// Health Response
// -----------------------------------------------------------------------------

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// "ok" or "degraded" or "error".
    pub status: String,
    /// Reason if not ok (e.g. "no_quorum", "syncing", "no_peers").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Current block height.
    pub height: u64,
    /// Number of connected peers.
    pub peers: usize,
    /// Whether this node is producing blocks.
    pub producing: bool,
    /// Node version string.
    pub version: String,
    /// Whether the node is catching up (syncing).
    pub catching_up: bool,
}

impl HealthResponse {
    pub fn ok(height: u64, peers: usize, producing: bool, catching_up: bool) -> Self {
        Self {
            status: "ok".into(),
            reason: None,
            height,
            peers,
            producing,
            version: env!("CARGO_PKG_VERSION").into(),
            catching_up,
        }
    }

    pub fn degraded(reason: &str, height: u64, peers: usize, producing: bool, catching_up: bool) -> Self {
        Self {
            status: "degraded".into(),
            reason: Some(reason.into()),
            height,
            peers,
            producing,
            version: env!("CARGO_PKG_VERSION").into(),
            catching_up,
        }
    }

    pub fn error(reason: &str) -> Self {
        Self {
            status: "error".into(),
            reason: Some(reason.into()),
            height: 0,
            peers: 0,
            producing: false,
            version: env!("CARGO_PKG_VERSION").into(),
            catching_up: false,
        }
    }

    /// Generate a health response from the current node state.
    pub fn from_node(
        height: u64,
        peers: usize,
        is_producing: bool,
        catching_up: bool,
        quorum_ok: bool,
        sync_ok: bool,
    ) -> Self {
        if !sync_ok {
            Self::degraded("syncing", height, peers, is_producing, catching_up)
        } else if !quorum_ok {
            Self::degraded("no_quorum", height, peers, is_producing, catching_up)
        } else {
            Self::ok(height, peers, is_producing, catching_up)
        }
    }
}

// -----------------------------------------------------------------------------
// Status Response
// -----------------------------------------------------------------------------

/// Validator set summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetInfo {
    pub total: usize,
    pub total_power: u64,
    pub quorum_threshold: u64,
    /// Short hex of each validator's public key.
    pub validators: Vec<ValidatorInfo>,
}

/// Single validator info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub pubkey_short: String,
    pub power: u64,
    pub connected: bool,
}

/// Commit information about the latest block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitInfo {
    pub block_hash: String,
    pub proposer: String,
    pub commit_time: u64,      // Unix seconds
    pub num_txs: usize,
}

/// Sync information (for nodes that are catching up).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncInfo {
    pub catching_up: bool,
    pub latest_block_height: u64,
    pub latest_block_time: u64,
    pub earliest_block_height: u64,
    pub earliest_block_time: u64,
    /// Estimated remaining time in seconds (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_seconds: Option<u64>,
}

/// Status response (detailed node info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node software version.
    pub node_version: String,
    /// Current protocol version.
    pub protocol_version: u32,
    /// Chain ID.
    pub chain_id: u64,
    /// Current block height.
    pub height: u64,
    /// Current consensus round.
    pub round: u32,
    /// Current consensus step (Propose/Prevote/Precommit/Commit).
    pub step: String,
    /// Number of connected peers.
    pub peers: usize,
    /// Connected peer IDs (truncated).
    pub peer_ids: Vec<String>,
    /// Validator set info.
    pub validators: ValidatorSetInfo,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Whether this node is producing blocks.
    pub is_producing: bool,
    /// Last commit timestamp (unix seconds).
    pub last_commit_time: u64,
    /// Blocks per minute (rolling average).
    pub blocks_per_minute: f64,
    /// Mempool size.
    pub mempool_size: usize,
    /// Consensus diagnostic summary (one-line "why no commit" if stalled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    /// Latest block hash.
    pub latest_block_hash: String,
    /// Node's peer ID.
    pub node_id: String,
    /// If validator, the validator address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_address: Option<String>,
    /// Current timestamp (Unix seconds).
    pub current_time: u64,
    /// Sync information.
    pub sync_info: SyncInfo,
    /// Commit info for the latest block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_commit: Option<CommitInfo>,
    /// MEV mempool statistics (if enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mev_stats: Option<MevStats>,
}

/// MEV‑related mempool statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevStats {
    pub pending_commits: usize,
    pub pending_reveals: usize,
    pub encrypted_envelopes: usize,
    pub backrun_attempts_blocked: u64,
    pub fair_order_shuffles: u64,
}

/// Builder for constructing a StatusResponse from node state.
#[derive(Debug, Default)]
pub struct StatusBuilder {
    pub protocol_version: u32,
    pub chain_id: u64,
    pub height: u64,
    pub round: u32,
    pub step: String,
    pub peers: usize,
    pub peer_ids: Vec<String>,
    pub is_validator: bool,
    pub is_producing: bool,
    pub last_commit_time: u64,
    pub blocks_per_minute: f64,
    pub mempool_size: usize,
    pub diagnostic: Option<String>,
    pub validator_infos: Vec<ValidatorInfo>,
    pub total_power: u64,
    pub quorum_threshold: u64,
    pub latest_block_hash: String,
    pub node_id: String,
    pub validator_address: Option<String>,
    pub sync_info: SyncInfo,
    pub last_commit: Option<CommitInfo>,
    pub mev_stats: Option<MevStats>,
}

impl StatusBuilder {
    pub fn build(self) -> StatusResponse {
        StatusResponse {
            node_version: env!("CARGO_PKG_VERSION").into(),
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            height: self.height,
            round: self.round,
            step: self.step,
            peers: self.peers,
            peer_ids: self.peer_ids,
            validators: ValidatorSetInfo {
                total: self.validator_infos.len(),
                total_power: self.total_power,
                quorum_threshold: self.quorum_threshold,
                validators: self.validator_infos,
            },
            is_validator: self.is_validator,
            is_producing: self.is_producing,
            last_commit_time: self.last_commit_time,
            blocks_per_minute: self.blocks_per_minute,
            mempool_size: self.mempool_size,
            diagnostic: self.diagnostic,
            latest_block_hash: self.latest_block_hash,
            node_id: self.node_id,
            validator_address: self.validator_address,
            current_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            sync_info: self.sync_info,
            last_commit: self.last_commit,
            mev_stats: self.mev_stats,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_ok() {
        let h = HealthResponse::ok(100, 5, true, false);
        assert_eq!(h.status, "ok");
        assert!(h.reason.is_none());
        assert_eq!(h.height, 100);
    }

    #[test]
    fn test_health_degraded() {
        let h = HealthResponse::degraded("no_quorum", 50, 2, false, true);
        assert_eq!(h.status, "degraded");
        assert_eq!(h.reason.as_deref(), Some("no_quorum"));
    }

    #[test]
    fn test_health_error() {
        let h = HealthResponse::error("startup_failed");
        assert_eq!(h.status, "error");
        assert_eq!(h.height, 0);
    }

    #[test]
    fn test_status_builder() {
        let status = StatusBuilder {
            protocol_version: 1,
            chain_id: 6126151,
            height: 42,
            round: 0,
            step: "Propose".into(),
            peers: 3,
            peer_ids: vec!["12D3K..1".into(), "12D3K..2".into(), "12D3K..3".into()],
            is_validator: true,
            is_producing: true,
            last_commit_time: 1234567890,
            blocks_per_minute: 120.0,
            mempool_size: 50,
            diagnostic: None,
            validator_infos: vec![
                ValidatorInfo { pubkey_short: "aabb..".into(), power: 1, connected: true },
                ValidatorInfo { pubkey_short: "ccdd..".into(), power: 1, connected: true },
                ValidatorInfo { pubkey_short: "eeff..".into(), power: 1, connected: false },
            ],
            total_power: 3,
            quorum_threshold: 3,
            latest_block_hash: "0xabc123".into(),
            node_id: "12D3KooW...".into(),
            validator_address: Some("iona1...".into()),
            sync_info: SyncInfo {
                catching_up: false,
                latest_block_height: 42,
                latest_block_time: 1234567890,
                earliest_block_height: 1,
                earliest_block_time: 1234567000,
                eta_seconds: None,
            },
            last_commit: Some(CommitInfo {
                block_hash: "0xabc123".into(),
                proposer: "val1".into(),
                commit_time: 1234567890,
                num_txs: 5,
            }),
            mev_stats: None,
        }.build();

        assert_eq!(status.node_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.height, 42);
        assert_eq!(status.validators.total, 3);
        assert_eq!(status.validators.quorum_threshold, 3);
        assert_eq!(status.latest_block_hash, "0xabc123");
        assert!(!status.sync_info.catching_up);
    }

    #[test]
    fn test_health_serialization() {
        let h = HealthResponse::ok(100, 5, true, false);
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(!json.contains("reason")); // None fields skipped
    }
}
