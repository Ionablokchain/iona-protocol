//! Persistent snapshot of the RPC state.
//!
//! Allows the node to resume RPC state (blocks, receipts, transactions, etc.)
//! after restart without re‑indexing the entire chain.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::rpc::eth_rpc::{Block, Receipt, TxRecord, EthRpcState};
use crate::rpc::txpool::TxPool;
use crate::rpc::withdrawals::Withdrawal;

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Full node snapshot (persistent state).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    /// Snapshot format version.
    pub version: u32,
    pub chain_id: u64,
    pub block_number: u64,
    pub base_fee: u64,
    pub blocks: Vec<Block>,
    pub receipts: Vec<Receipt>,
    pub txs: std::collections::HashMap<String, TxRecord>,
    pub receipts_by_block: std::collections::HashMap<u64, Vec<Receipt>>,
    pub pending_withdrawals: Vec<Withdrawal>,
    pub txpool: TxPool,
}

impl StateSnapshot {
    /// Create a new snapshot with the current version.
    pub fn new(
        chain_id: u64,
        block_number: u64,
        base_fee: u64,
        blocks: Vec<Block>,
        receipts: Vec<Receipt>,
        txs: std::collections::HashMap<String, TxRecord>,
        receipts_by_block: std::collections::HashMap<u64, Vec<Receipt>>,
        pending_withdrawals: Vec<Withdrawal>,
        txpool: TxPool,
    ) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            chain_id,
            block_number,
            base_fee,
            blocks,
            receipts,
            txs,
            receipts_by_block,
            pending_withdrawals,
            txpool,
        }
    }
}

/// Path to the snapshot file inside a directory.
fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join("state_snapshot.json")
}

/// Load a snapshot from the given directory.
///
/// Returns `Ok(Some(snapshot))` if the file exists and is valid,
/// `Ok(None)` if the file does not exist, and an error otherwise.
pub fn load_snapshot(dir: impl AsRef<Path>) -> io::Result<Option<StateSnapshot>> {
    let dir = dir.as_ref();
    let path = snapshot_path(dir);
    if !path.exists() {
        return Ok(None);
    }

    let data = fs::read_to_string(&path)?;

    // Check version first before full deserialization
    #[derive(serde::Deserialize)]
    struct VersionCheck { version: u32 }
    if let Ok(vc) = serde_json::from_str::<VersionCheck>(&data) {
        if vc.version != SNAPSHOT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "incompatible snapshot version: expected {}, got {}",
                    SNAPSHOT_VERSION, vc.version
                ),
            ));
        }
    }

    let snap: StateSnapshot = serde_json::from_str(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    Ok(Some(snap))
}

/// Save a snapshot to the given directory using an atomic write.
pub fn save_snapshot(dir: impl AsRef<Path>, snap: &StateSnapshot) -> io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let target = snapshot_path(dir);
    let tmp = target.with_extension("tmp");

    let data = serde_json::to_string_pretty(snap)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    fs::write(&tmp, data)?;
    fs::rename(&tmp, &target)?; // atomic on most filesystems

    info!(
        block_number = snap.block_number,
        path = %target.display(),
        "RPC state snapshot saved"
    );
    Ok(())
}

/// Create a snapshot from the current state of an `EthRpcState`.
pub fn snapshot_from_state(st: &EthRpcState) -> StateSnapshot {
    // To ensure consistency, we need to lock all mutable parts simultaneously.
    // Here we assume the state's internal locks are ordered to avoid deadlocks.
    // We take each lock in a fixed order.
    let block_number = *st.block_number.lock().expect("mutex lock poisoned");
    let base_fee = *st.base_fee.lock().expect("mutex lock poisoned");
    let blocks = st.blocks.lock().expect("mutex lock poisoned").clone();
    let receipts = st.receipts.lock().expect("mutex lock poisoned").clone();
    let txs = st.txs.lock().expect("mutex lock poisoned").clone();
    let receipts_by_block = st.receipts_by_block.lock().expect("mutex lock poisoned").clone();
    let pending_withdrawals = st.pending_withdrawals.lock().expect("mutex lock poisoned").clone();
    let txpool = st.txpool.lock().expect("mutex lock poisoned").clone();

    StateSnapshot::new(
        st.chain_id,
        block_number,
        base_fee,
        blocks,
        receipts,
        txs,
        receipts_by_block,
        pending_withdrawals,
        txpool,
    )
}

/// Apply a snapshot to an existing `EthRpcState`, overwriting its current state.
pub fn apply_snapshot_to_state(st: &mut EthRpcState, snap: StateSnapshot) {
    st.chain_id = snap.chain_id;
    *st.block_number.lock().expect("mutex lock poisoned") = snap.block_number;
    *st.base_fee.lock().expect("mutex lock poisoned") = snap.base_fee;
    *st.blocks.lock().expect("mutex lock poisoned") = snap.blocks;
    *st.receipts.lock().expect("mutex lock poisoned") = snap.receipts;
    *st.txs.lock().expect("mutex lock poisoned") = snap.txs;
    *st.receipts_by_block.lock().expect("mutex lock poisoned") = snap.receipts_by_block;
    *st.pending_withdrawals.lock().expect("mutex lock poisoned") = snap.pending_withdrawals;
    *st.txpool.lock().expect("mutex lock poisoned") = snap.txpool;

    info!(
        block_number = snap.block_number,
        "RPC state restored from snapshot"
    );
}

/// Best‑effort throttled persistence.
///
/// Persists the current state only if the configured interval has elapsed since
/// the last persistence. On failure, logs an error and increments a metric.
pub fn maybe_persist(st: &EthRpcState) {
    let Some(dir) = st.persist_dir.as_ref() else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut last = st.last_persist_secs.lock().expect("mutex lock poisoned");
    if now.saturating_sub(*last) < st.persist_interval_secs {
        return;
    }
    *last = now;
    drop(last);

    let snap = snapshot_from_state(st);
    if let Err(e) = save_snapshot(dir, &snap) {
        error!("Failed to persist RPC state snapshot: {}", e);
        // Optionally increment a metric: metrics::rpc_persist_errors.inc();
    }
}

/// Force immediate persistence (e.g., on graceful shutdown).
pub fn persist_now(st: &EthRpcState) {
    let Some(dir) = st.persist_dir.as_ref() else {
        return;
    };
    let snap = snapshot_from_state(st);
    if let Err(e) = save_snapshot(dir, &snap) {
        error!("Failed to persist RPC state snapshot on shutdown: {}", e);
    } else {
        info!("RPC state snapshot saved on shutdown");
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_snapshot_roundtrip() {
        let dir = tempdir().unwrap();
        let snap = StateSnapshot::new(
            6126151,
            1234,
            10,
            vec![],
            vec![],
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            vec![],
            TxPool::default(),
        );

        save_snapshot(dir.path(), &snap).unwrap();
        let loaded = load_snapshot(dir.path()).unwrap().unwrap();

        assert_eq!(loaded.version, SNAPSHOT_VERSION);
        assert_eq!(loaded.chain_id, snap.chain_id);
        assert_eq!(loaded.block_number, snap.block_number);
    }

    #[test]
    fn test_load_nonexistent() {
        let dir = tempdir().unwrap();
        let loaded = load_snapshot(dir.path()).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_version_mismatch() {
        let dir = tempdir().unwrap();
        // Manually write an old version snapshot
        let old_snap = serde_json::json!({
            "version": 999,
            "chain_id": 1,
            "block_number": 0,
            "base_fee": 1,
            "blocks": [],
            "receipts": [],
            "txs": {},
            "receipts_by_block": {},
            "pending_withdrawals": [],
            "txpool": {}
        });
        let path = snapshot_path(dir.path());
        fs::write(&path, old_snap.to_string()).unwrap();
        let err = load_snapshot(dir.path()).unwrap_err();
        assert!(err.to_string().contains("incompatible snapshot version"));
    }

    #[test]
    fn test_atomic_write() {
        let dir = tempdir().unwrap();
        let snap = StateSnapshot::new(1, 0, 0, vec![], vec![], Default::default(), Default::default(), vec![], TxPool::default());
        save_snapshot(dir.path(), &snap).unwrap();
        // Ensure the temporary file is gone
        let tmp_path = snapshot_path(dir.path()).with_extension("tmp");
        assert!(!tmp_path.exists());
    }
}
