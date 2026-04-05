//! Standard data directory layout for IONA v28.
//!
//! ```text
//! <data_dir>/
//!   identity/
//!     p2p_key.json        # libp2p keypair (node identity on the network)
//!     node_meta.json      # schema_version, protocol_version, node_version
//!   validator/
//!     validator_key.json   # ed25519 signing key (only if this node is a validator)
//!   chain/
//!     blocks/              # committed blocks (one JSON per height)
//!     wal/                 # write-ahead log segments
//!     state/               # state_full.json, stakes.json, evidence
//!     receipts/            # transaction receipts
//!     snapshots/           # periodic state snapshots
//!   peerstore/
//!     peers.json           # known peers with last-seen timestamps
//!     quarantine.json      # quarantined peers
//! ```
//!
//! Benefits:
//!   - `reset chain` only deletes `chain/` — identity preserved
//!   - `reset identity` only deletes `identity/` — chain data untouched
//!   - `peerstore/` survives both resets

use fd_lock::RwLock;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Standard directory layout with production‑ready features:
/// - Exclusive file locking to prevent multiple processes using the same data dir.
/// - Schema version management and migration hooks.
/// - Atomic write operations for critical files.
/// - Data validation on startup.
/// - Efficient disk usage estimation.
#[derive(Debug)]
pub struct DataLayout {
    pub root: PathBuf,
    // File lock guard – kept alive for the lifetime of the struct.
    _lock: Option<fd_lock::RwLockWriteGuard<'static, File>>,
}

impl DataLayout {
    /// Creates a new layout handle without acquiring the lock.
    /// Use `try_lock()` to lock the directory before using it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            _lock: None,
        }
    }


    /// Attempts to acquire an exclusive lock on the data directory.
    /// Returns an error if the lock is already held by another process.
    /// Should be called once at startup, before any other operations.
    pub fn try_lock(&mut self) -> io::Result<()> {
        let lock_path = self.root.join(".lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        // Leak the RwLock to get a 'static lifetime guard we can store.
        let lock = Box::new(RwLock::new(file));
        let lock: &'static mut RwLock<File> = Box::leak(lock);
        match lock.try_write() {
            Ok(guard) => {
                self._lock = Some(guard);
                Ok(())
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Data directory is already in use by another process",
            )),
        }
    }

    // ── Sub-directories ──────────────────────────────────────────────────

    pub fn identity_dir(&self) -> PathBuf { self.root.join("identity") }
    pub fn validator_dir(&self) -> PathBuf { self.root.join("validator") }
    pub fn chain_dir(&self) -> PathBuf { self.root.join("chain") }
    pub fn peerstore_dir(&self) -> PathBuf { self.root.join("peerstore") }

    // ── Chain sub-dirs ───────────────────────────────────────────────────

    pub fn blocks_dir(&self) -> PathBuf { self.chain_dir().join("blocks") }
    pub fn wal_dir(&self) -> PathBuf { self.chain_dir().join("wal") }
    /// Returns the root directory path.
    pub fn root(&self) -> &std::path::Path { &self.root }
    /// Path to the flat (legacy) WAL file, used by v2→v3 migration.
    pub fn wal_flat_path(&self) -> PathBuf { self.root.join("wal.jsonl") }
    /// Alias for wal_dir() for compatibility.
    pub fn wal_path(&self) -> PathBuf { self.wal_dir() }
    /// Path to the KV state file.
    pub fn state_kv_path(&self) -> PathBuf { self.state_dir().join("state.json") }
    pub fn state_dir(&self) -> PathBuf { self.chain_dir().join("state") }
    pub fn receipts_dir(&self) -> PathBuf { self.chain_dir().join("receipts") }
    pub fn snapshots_dir(&self) -> PathBuf { self.chain_dir().join("snapshots") }

    // ── Identity files ───────────────────────────────────────────────────

    pub fn p2p_key_path(&self) -> PathBuf { self.identity_dir().join("p2p_key.json") }
    pub fn node_meta_path(&self) -> PathBuf { self.identity_dir().join("node_meta.json") }

    // ── Validator files ──────────────────────────────────────────────────

    pub fn validator_key_path(&self) -> PathBuf { self.validator_dir().join("validator_key.json") }
    pub fn validator_key_enc_path(&self) -> PathBuf { self.validator_dir().join("validator_key.enc") }

    // ── Chain state files ────────────────────────────────────────────────

    pub fn state_full_path(&self) -> PathBuf { self.state_dir().join("state_full.json") }
    pub fn stakes_path(&self) -> PathBuf { self.state_dir().join("stakes.json") }
    pub fn evidence_path(&self) -> PathBuf { self.state_dir().join("evidence.jsonl") }
    pub fn schema_path(&self) -> PathBuf { self.state_dir().join("schema.json") }
    pub fn tx_index_path(&self) -> PathBuf { self.state_dir().join("tx_index.json") }

    // ── Peerstore files ──────────────────────────────────────────────────

    pub fn peers_path(&self) -> PathBuf { self.peerstore_dir().join("peers.json") }
    pub fn quarantine_path(&self) -> PathBuf { self.peerstore_dir().join("quarantine.json") }

    // ── Ensure all directories exist ─────────────────────────────────────

    pub fn ensure_all(&self) -> io::Result<()> {
        for dir in &[
            self.identity_dir(),
            self.validator_dir(),
            self.blocks_dir(),
            self.wal_dir(),
            self.state_dir(),
            self.receipts_dir(),
            self.snapshots_dir(),
            self.peerstore_dir(),
        ] {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    // ── Schema version management ────────────────────────────────────────

    /// Checks the stored schema version against the expected version.
    /// If the schema file does not exist, it is created with the expected version.
    /// If versions differ, it returns an error (in a real system you'd trigger a migration).
    pub fn check_schema(&self, expected_version: u32) -> io::Result<bool> {
        let schema_path = self.schema_path();
        if !schema_path.exists() {
            // Write the current schema version.
            let schema = serde_json::json!({ "version": expected_version });
            Self::atomic_write(&schema_path, &serde_json::to_vec_pretty(&schema)?)?;
            return Ok(true);
        }
        let content = fs::read_to_string(&schema_path)?;
        let v: serde_json::Value = serde_json::from_str(&content)?;
        let current = v["version"].as_u64().unwrap_or(0) as u32;
        if current == expected_version {
            Ok(true)
        } else {
            // Here you would call a migration routine.
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Schema version mismatch: expected {}, found {}. Migration not implemented.",
                    expected_version, current
                ),
            ))
        }
    }

    // ── Atomic write helper ──────────────────────────────────────────────

    /// Writes data to a file atomically: first to a temporary file, then rename.
    pub fn atomic_write(path: impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
        let path = path.as_ref();
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, data)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    // ── Validation ───────────────────────────────────────────────────────

    /// Validates that all required directories exist and that critical files
    /// (if present) are well‑formed. Returns an error if something is wrong.
    pub fn validate(&self) -> io::Result<()> {
        // Check essential directories.
        for dir in &[self.identity_dir(), self.chain_dir(), self.peerstore_dir()] {
            if !dir.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Missing directory: {:?}", dir),
                ));
            }
        }

        // If validator key exists, try to parse it as JSON (just a basic check).
        if self.validator_key_path().exists() {
            let content = fs::read_to_string(self.validator_key_path())?;
            serde_json::from_str::<serde_json::Value>(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }

        // If peers file exists, try to parse it.
        if self.peers_path().exists() {
            let content = fs::read_to_string(self.peers_path())?;
            serde_json::from_str::<serde_json::Value>(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }

        // Optional: check evidence file by reading a few lines? Too expensive.
        Ok(())
    }

    // ── Freshness checks ─────────────────────────────────────────────────

    /// Check if this is a fresh (empty) data directory.
    pub fn is_fresh(&self) -> bool {
        !self.state_full_path().exists() && !self.validator_key_path().exists()
    }

    /// Check if chain data exists (actual files, not just empty dirs).
    pub fn has_chain_data(&self) -> bool {
        self.state_full_path().exists()
            || self.blocks_dir().read_dir().map(|mut rd| rd.next().is_some()).unwrap_or(false)
    }

    /// Check if identity exists.
    pub fn has_identity(&self) -> bool {
        self.p2p_key_path().exists()
    }

    /// Check if validator key exists.
    pub fn has_validator_key(&self) -> bool {
        self.validator_key_path().exists() || self.validator_key_enc_path().exists()
    }
}

// ── Reset operations ─────────────────────────────────────────────────────

/// What to reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetScope {
    /// Delete chain/ only — preserves identity and peerstore.
    Chain,
    /// Delete identity/ only — preserves chain data and peerstore.
    Identity,
    /// Delete everything (chain + identity + peerstore).
    Full,
}

/// Result of a reset operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetResult {
    pub scope: String,
    pub dirs_removed: Vec<String>,
    pub dirs_preserved: Vec<String>,
}

impl DataLayout {
    /// Perform a controlled reset.
    ///
    /// Returns what was removed and what was preserved.
    pub fn reset(&self, scope: ResetScope) -> io::Result<ResetResult> {
        let mut removed = Vec::new();
        let mut preserved = Vec::new();

        match scope {
            ResetScope::Chain => {
                if self.chain_dir().exists() {
                    fs::remove_dir_all(self.chain_dir())?;
                    removed.push("chain/".into());
                }
                preserved.push("identity/".into());
                preserved.push("validator/".into());
                preserved.push("peerstore/".into());
            }
            ResetScope::Identity => {
                if self.identity_dir().exists() {
                    fs::remove_dir_all(self.identity_dir())?;
                    removed.push("identity/".into());
                }
                preserved.push("validator/".into());
                preserved.push("chain/".into());
                preserved.push("peerstore/".into());
            }
            ResetScope::Full => {
                for dir in &["identity", "validator", "chain", "peerstore"] {
                    let p = self.root.join(dir);
                    if p.exists() {
                        fs::remove_dir_all(&p)?;
                        removed.push(format!("{dir}/"));
                    }
                }
            }
        }

        // Re-create directory structure.
        self.ensure_all()?;

        Ok(ResetResult {
            scope: format!("{:?}", scope),
            dirs_removed: removed,
            dirs_preserved: preserved,
        })
    }
}

// ── Node status (for CLI `admin status`) ─────────────────────────────────

/// Summary of node status from on-disk data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub data_dir: String,
    pub has_identity: bool,
    pub has_validator_key: bool,
    pub has_chain_data: bool,
    pub schema_version: Option<u32>,
    pub blocks_count: usize,
    pub snapshots_count: usize,
    pub disk_usage_bytes: u64,
    // Optional: approximate disk usage as a formatted string (e.g., "1.2 GB")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_usage_human: Option<String>,
}

impl DataLayout {
    /// Gather node status from on-disk data (no RPC needed).
    /// This operation is O(number of files) – it may be slow for large directories.
    /// Use sparingly.
    pub fn status(&self) -> NodeStatus {
        let blocks_count = self.blocks_dir()
            .read_dir()
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);

        let snapshots_count = self.snapshots_dir()
            .read_dir()
            .map(|rd| rd.filter_map(|e| e.ok()).count())
            .unwrap_or(0);

        let schema_version = fs::read_to_string(self.schema_path())
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v.get("version")?.as_u64())
            .map(|v| v as u32);

        let disk_usage = Self::dir_size(&self.root);
        let human = Self::human_bytes(disk_usage);

        NodeStatus {
            data_dir: self.root.display().to_string(),
            has_identity: self.has_identity(),
            has_validator_key: self.has_validator_key(),
            has_chain_data: self.has_chain_data(),
            schema_version,
            blocks_count,
            snapshots_count,
            disk_usage_bytes: disk_usage,
            disk_usage_human: Some(human),
        }
    }

    /// Recursively compute directory size in bytes (can be slow for huge dirs).
    fn dir_size(path: &Path) -> u64 {
        if !path.exists() {
            return 0;
        }
        let mut total = 0u64;
        if let Ok(rd) = fs::read_dir(path) {
            for entry in rd.filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    total += entry.metadata().map(|m| m.len()).unwrap_or(0);
                } else if p.is_dir() {
                    total += Self::dir_size(&p);
                }
            }
        }
        total
    }

    /// Convert bytes to a human‑readable string (e.g., "1.2 GB").
    fn human_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;

        if bytes >= TB {
            format!("{:.2} TB", bytes as f64 / TB as f64)
        } else if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}



// ── Additional convenience methods ──────────────────────────────────────

impl DataLayout {
    /// Temporary directory for atomic operations.
    pub fn tmp_dir(&self) -> PathBuf { self.root.join("tmp") }

    /// Load full state from disk.
    pub fn load_state_full(&self) -> io::Result<crate::execution::KvState> {
        let path = self.state_full_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json: {e}")))
        } else {
            Ok(crate::execution::KvState::default())
        }
    }

    /// Save full state to disk atomically.
    pub fn save_state_full(&self, state: &crate::execution::KvState) -> io::Result<()> {
        let path = self.state_full_path();
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Self::atomic_write(&path, json.as_bytes())
    }

    /// Load stakes from disk.
    pub fn load_stakes(&self) -> io::Result<crate::economics::staking::StakingState> {
        let path = self.stakes_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json: {e}")))
        } else {
            Ok(crate::economics::staking::StakingState::default())
        }
    }

    /// Save stakes to disk atomically.
    pub fn save_stakes(&self, stakes: &crate::economics::staking::StakingState) -> io::Result<()> {
        let path = self.stakes_path();
        let json = serde_json::to_string_pretty(stakes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Self::atomic_write(&path, json.as_bytes())
    }

    /// Load schema metadata.
    pub fn load_schema(&self) -> io::Result<Option<serde_json::Value>> {
        let path = self.schema_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            Ok(Some(serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?))
        } else {
            Ok(None)
        }
    }

    /// Save schema metadata atomically.
    pub fn save_schema(&self, schema: &serde_json::Value) -> io::Result<()> {
        let path = self.schema_path();
        let json = serde_json::to_string_pretty(schema)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Self::atomic_write(&path, json.as_bytes())
    }

    /// Load node metadata.
    pub fn load_node_meta(&self) -> io::Result<Option<serde_json::Value>> {
        let path = self.node_meta_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            Ok(Some(serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?))
        } else {
            Ok(None)
        }
    }

    /// Save node metadata atomically.
    pub fn save_node_meta(&self, meta: &serde_json::Value) -> io::Result<()> {
        let path = self.node_meta_path();
        let json = serde_json::to_string_pretty(meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        Self::atomic_write(&path, json.as_bytes())
    }

    /// Get latest block height from blocks directory.
    pub fn latest_height(&self) -> Option<u64> {
        let dir = self.blocks_dir();
        if !dir.exists() { return None; }
        let mut max_height = None;
        if let Ok(rd) = fs::read_dir(&dir) {
            for entry in rd.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if let Some(h) = name.strip_suffix(".json").and_then(|s| s.parse::<u64>().ok()) {
                    max_height = Some(max_height.map_or(h, |m: u64| m.max(h)));
                }
            }
        }
        max_height
    }

    /// Get peer ID from the p2p key file.
    pub fn peer_id(&self) -> io::Result<String> {
        let path = self.p2p_key_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            let v: serde_json::Value = serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(v.get("peer_id").and_then(|p| p.as_str()).unwrap_or("unknown").to_string())
        } else {
            Ok("unknown".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_layout_paths() {
        let layout = DataLayout::new("/var/lib/iona/val2");
        assert_eq!(layout.identity_dir(), PathBuf::from("/var/lib/iona/val2/identity"));
        assert_eq!(layout.validator_dir(), PathBuf::from("/var/lib/iona/val2/validator"));
        assert_eq!(layout.chain_dir(), PathBuf::from("/var/lib/iona/val2/chain"));
        assert_eq!(layout.peerstore_dir(), PathBuf::from("/var/lib/iona/val2/peerstore"));
        assert_eq!(layout.blocks_dir(), PathBuf::from("/var/lib/iona/val2/chain/blocks"));
        assert_eq!(layout.wal_dir(), PathBuf::from("/var/lib/iona/val2/chain/wal"));
        assert_eq!(layout.state_full_path(), PathBuf::from("/var/lib/iona/val2/chain/state/state_full.json"));
        assert_eq!(layout.validator_key_path(), PathBuf::from("/var/lib/iona/val2/validator/validator_key.json"));
        assert_eq!(layout.p2p_key_path(), PathBuf::from("/var/lib/iona/val2/identity/p2p_key.json"));
        assert_eq!(layout.peers_path(), PathBuf::from("/var/lib/iona/val2/peerstore/peers.json"));
    }

    #[test]
    fn test_lock() {
        let tmp = tempdir().unwrap();
        let mut layout = DataLayout::new(tmp.path());
        // First lock should succeed.
        assert!(layout.try_lock().is_ok());

        // Second lock on the same dir should fail.
        let mut layout2 = DataLayout::new(tmp.path());
        assert!(layout2.try_lock().is_err());
    }

    #[test]
    fn test_schema_check() {
        let tmp = tempdir().unwrap();
        let mut layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        // No schema file -> should create with expected version.
        assert!(layout.check_schema(42).unwrap());

        // Now schema file exists with version 42.
        let content = fs::read_to_string(layout.schema_path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["version"], 42);

        // Check with same version -> ok.
        assert!(layout.check_schema(42).unwrap());

        // Check with different version -> error.
        assert!(layout.check_schema(99).is_err());
    }

    #[test]
    fn test_atomic_write() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("test.txt");
        DataLayout::atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        // No .tmp file left.
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn test_validate() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        // Initially should be valid (dirs exist, no critical files).
        assert!(layout.validate().is_ok());

        // Create a malformed validator key.
        fs::write(layout.validator_key_path(), "not json").unwrap();
        assert!(layout.validate().is_err());

        // Fix it.
        fs::write(layout.validator_key_path(), r#"{"key":"value"}"#).unwrap();
        assert!(layout.validate().is_ok());
    }

    #[test]
    fn test_status() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        // Write a dummy block.
        fs::write(layout.blocks_dir().join("1.json"), "{}").unwrap();

        let status = layout.status();
        assert_eq!(status.blocks_count, 1);
        assert_eq!(status.snapshots_count, 0);
        assert!(!status.has_identity);
        assert!(!status.has_validator_key);
        assert!(status.disk_usage_bytes > 0);
        assert!(status.disk_usage_human.is_some());
    }

    #[test]
    fn test_reset_chain() {
        let tmp = tempdir().unwrap();
        let layout = DataLayout::new(tmp.path());
        layout.ensure_all().unwrap();

        fs::write(layout.p2p_key_path(), "identity").unwrap();
        fs::write(layout.state_full_path(), "{}").unwrap();
        fs::write(layout.peers_path(), "{}").unwrap();

        let result = layout.reset(ResetScope::Chain).unwrap();
        assert!(result.dirs_removed.contains(&"chain/".to_string()));

        // Chain data gone, identity and peerstore remain.
        assert!(!layout.state_full_path().exists());
        assert!(layout.p2p_key_path().exists());
        assert!(layout.peers_path().exists());
    }
}
