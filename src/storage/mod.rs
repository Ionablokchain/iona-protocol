//! Persistent storage for IONA.
//!
//! This module handles all on‑disk data:
//! - Schema versioning and migrations
//! - State (KV store, balances, nonces, VM)
//! - Staking ledger
//! - Keys (plain or encrypted)
//! - WAL (write‑ahead log) and blocks
//! - Evidence, receipts, etc.
//!
//! # Directory layout
//!
//! The data directory contains:
//! - `schema.json` – current schema version and migration log
//! - `node_meta.json` – node metadata (protocol version, etc.)
//! - `keys.json` / `keys.enc` – validator signing keys
//! - `state_full.json` – full node state
//! - `stakes.json` – staking ledger
//! - `wal.jsonl` (legacy) or `wal/` – write‑ahead log
//! - `blocks/` – committed blocks
//! - `receipts/` – transaction receipts
//! - `evidence.jsonl` – slashable evidence
//! - `snapshots/` – state snapshots
//!
//! # Migrations
//!
//! On startup, `ensure_schema_and_migrate()` upgrades the on‑disk schema
//! to the current version. Migrations are atomic and idempotent.
//!
//! # Example
//!
//! ```
//! use iona::storage::DataDir;
//!
//! let data_dir = DataDir::new("./data/node");
//! data_dir.ensure_schema_and_migrate().unwrap();
//! let state = data_dir.load_state_full().unwrap();
//! ```

use crate::crypto::ed25519::Ed25519Keypair;
use crate::execution::KvState;
use crate::slashing::StakeLedger;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Re‑exports of submodules
// -----------------------------------------------------------------------------

pub mod block_store;
pub mod evidence_store;
pub mod layout;
pub mod meta;
pub mod migrations;
pub mod peer_store;
pub mod receipts_store;
pub mod schema_monotonicity;
pub mod snapshots;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Current on‑disk schema version. Bump this every time a breaking change is
/// made to any persistent format. Add a migration arm in `DataDir::run_migration`.
pub const CURRENT_SCHEMA_VERSION: u32 = 5;

// -----------------------------------------------------------------------------
// SchemaMeta
// -----------------------------------------------------------------------------

/// Metadata stored in `<data_dir>/schema.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SchemaMeta {
    pub version: u32,
    /// ISO‑8601 timestamp of the last migration (informational, not load‑bearing).
    #[serde(default)]
    pub migrated_at: Option<String>,
    /// Human‑readable history of applied migrations.
    #[serde(default)]
    pub migration_log: Vec<String>,
}

impl SchemaMeta {
    fn new(version: u32) -> Self {
        Self {
            version,
            migrated_at: None,
            migration_log: Vec::new(),
        }
    }
}

// -----------------------------------------------------------------------------
// DataDir
// -----------------------------------------------------------------------------

/// Handle to a node's data directory.
#[derive(Clone)]
pub struct DataDir {
    pub root: String,
}

impl DataDir {
    /// Create a new `DataDir` instance.
    pub fn new(root: impl Into<String>) -> Self {
        Self { root: root.into() }
    }

    /// Helper: join a path component.
    fn p(&self, file: &str) -> String {
        format!("{}/{}", self.root, file)
    }

    /// Ensure the root directory exists.
    pub fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)?;
        debug!(path = %self.root, "data directory ensured");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Schema management
    // -------------------------------------------------------------------------

    fn schema_path(&self) -> String {
        self.p("schema.json")
    }

    /// Read the current on‑disk schema version (0 = pre‑schema, i.e. very old node).
    pub fn read_schema_version(&self) -> io::Result<u32> {
        let path = self.schema_path();
        if !Path::new(&path).exists() {
            return Ok(0);
        }
        let s = fs::read_to_string(&path)?;
        let meta: SchemaMeta = serde_json::from_str(&s).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("schema.json parse: {e}"))
        })?;
        debug!(version = meta.version, "read schema version");
        Ok(meta.version)
    }

    /// Persist the schema metadata atomically (write to `.tmp` then rename).
    fn write_schema(&self, meta: &SchemaMeta) -> io::Result<()> {
        let path = self.schema_path();
        let tmp = format!("{path}.tmp");
        let out = serde_json::to_string_pretty(meta).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("schema.json encode: {e}"))
        })?;
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &path)?;
        debug!(path, "schema persisted");
        Ok(())
    }

    /// Run a single migration step from `from_version` to `from_version + 1`.
    ///
    /// Design principles:
    ///   - **Never delete user data** — rename or backup instead.
    ///   - **Atomic where possible** — write to `.tmp` then rename.
    ///   - **Idempotent** — safe to run twice if a previous run was interrupted.
    ///   - **Logged** — every step appends to `SchemaMeta.migration_log`.
    fn run_migration(&self, from_version: u32, meta: &mut SchemaMeta) -> io::Result<()> {
        let timestamp = {
            use std::time::{SystemTime, UNIX_EPOCH};
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };

        match from_version {
            // ── v0 → v1 ──────────────────────────────────────────────────────────
            // Introduce schema.json marker. No structural changes to data files.
            0 => {
                meta.migration_log
                    .push(format!("[{timestamp}] v0 → v1: schema.json marker created"));
                info!("migration v0→v1: schema.json marker created");
            }

            // ── v1 → v2 ──────────────────────────────────────────────────────────
            // KvState gained the `vm: VmStorage` field (v26).
            1 => {
                let state_path = self.p("state_full.json");
                if Path::new(&state_path).exists() {
                    let backup = format!("{state_path}.v1.bak");
                    if !Path::new(&backup).exists() {
                        fs::copy(&state_path, &backup)?;
                        debug!(path = %backup, "created backup");
                    }
                    let raw = fs::read_to_string(&state_path)?;
                    let mut val: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("vm").or_insert_with(|| {
                            serde_json::json!({
                                "storage": {}, "code": {}, "nonces": {}, "logs": []
                            })
                        });
                        obj.entry("burned").or_insert(serde_json::Value::from(0u64));
                    }
                    let normalised = serde_json::to_string_pretty(&val)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    fs::write(&state_path, normalised)?;
                }
                // stakes.json: add missing `epoch_snapshots` field if absent.
                let stakes_path = self.p("stakes.json");
                if Path::new(&stakes_path).exists() {
                    let backup = format!("{stakes_path}.v1.bak");
                    if !Path::new(&backup).exists() {
                        fs::copy(&stakes_path, &backup)?;
                        debug!(path = %backup, "created backup");
                    }
                    let raw = fs::read_to_string(&stakes_path)?;
                    let mut val: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("epoch_snapshots")
                            .or_insert_with(|| serde_json::json!([]));
                        obj.entry("params").or_insert_with(|| serde_json::json!({}));
                    }
                    let normalised = serde_json::to_string_pretty(&val)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    fs::write(&stakes_path, normalised)?;
                }
                meta.migration_log.push(format!(
                    "[{timestamp}] v1 → v2: state_full.json + stakes.json normalised; backups created"
                ));
                info!("migration v1→v2: state and stakes normalised");
            }

            // ── v2 → v3 ──────────────────────────────────────────────────────────
            // WAL format: segment files moved from `wal.jsonl` (flat) to
            // `wal/wal_00000000.jsonl` (segmented).
            2 => {
                let old_wal = self.p("wal.jsonl");
                let wal_dir = format!("{}/wal", self.root);
                if Path::new(&old_wal).exists() && !Path::new(&wal_dir).exists() {
                    fs::create_dir_all(&wal_dir)?;
                    let new_seg = format!("{wal_dir}/wal_00000000.jsonl");
                    fs::rename(&old_wal, &new_seg)?;
                    meta.migration_log.push(format!(
                        "[{timestamp}] v2 → v3: wal.jsonl migrated to wal/wal_00000000.jsonl"
                    ));
                    info!("migration v2→v3: WAL migrated to segmented format");
                } else {
                    meta.migration_log.push(format!(
                        "[{timestamp}] v2 → v3: WAL already in segmented format, nothing to do"
                    ));
                    debug!("WAL already segmented");
                }
            }

            // ── v3 → v4 ──────────────────────────────────────────────────────────
            // Introduce node_meta.json with protocol version tracking.
            3 => {
                migrations::m0004_protocol_version::migrate(&self.root, meta)?;
            }

            // ── v4 → v5 ──────────────────────────────────────────────────────────
            // Add tx_index.json for fast transaction lookup by hash.
            4 => {
                migrations::m0005_add_tx_index::migrate(&self.root, meta)?;
            }

            v => {
                error!(from = v, "unsupported migration version");
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported schema migration from v{v} — upgrade the node binary"),
                ));
            }
        }

        Ok(())
    }

    /// Ensures on‑disk schema is at `CURRENT_SCHEMA_VERSION`, running automatic
    /// migrations if needed. Call this once at node startup before opening any
    /// other data files.
    pub fn ensure_schema_and_migrate(&self) -> io::Result<()> {
        self.ensure()?;

        let cur = self.read_schema_version()?;

        if cur > CURRENT_SCHEMA_VERSION {
            error!(
                on_disk = cur,
                binary = CURRENT_SCHEMA_VERSION,
                "on‑disk schema is newer than binary"
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "on-disk schema v{cur} is newer than this binary (v{CURRENT_SCHEMA_VERSION}); \
                     please upgrade the node"
                ),
            ));
        }

        if cur == CURRENT_SCHEMA_VERSION {
            debug!("schema already up to date (v{CURRENT_SCHEMA_VERSION})");
            return Ok(());
        }

        // Load or initialise metadata.
        let mut meta = if cur == 0 {
            SchemaMeta::new(0)
        } else {
            let s = fs::read_to_string(self.schema_path())?;
            serde_json::from_str::<SchemaMeta>(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        };

        info!(from = cur, to = CURRENT_SCHEMA_VERSION, "running schema migrations");

        // Step through each migration one version at a time.
        let mut v = cur;
        while v < CURRENT_SCHEMA_VERSION {
            self.run_migration(v, &mut meta)?;
            v += 1;
            meta.version = v;
            self.write_schema(&meta)?;
            info!(version = v, "schema migration step complete");
        }

        // Final timestamp.
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        meta.migrated_at = Some(ts);
        self.write_schema(&meta)?;

        info!(version = CURRENT_SCHEMA_VERSION, "schema fully migrated");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Key management
    // -------------------------------------------------------------------------

    /// Load or create keys (plain or encrypted) with password from env.
    pub fn load_or_create_keys(
        &self,
        seed: u64,
        keystore: &str,
        password_env: &str,
    ) -> io::Result<Ed25519Keypair> {
        self.load_or_create_keys_with_fallback(seed, keystore, password_env, "")
    }

    /// Load or create keys with an optional fallback password from config.
    pub fn load_or_create_keys_with_fallback(
        &self,
        seed: u64,
        keystore: &str,
        password_env: &str,
        config_password: &str,
    ) -> io::Result<Ed25519Keypair> {
        self.ensure()?;
        let plain_path = self.p("keys.json");
        let enc_path = self.p("keys.enc");

        #[derive(Serialize, Deserialize)]
        struct K {
            seed32: [u8; 32],
        }

        let mode = keystore.trim().to_lowercase();
        if mode == "encrypted" {
            let pass = std::env::var(password_env)
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    if !config_password.is_empty() {
                        Some(config_password.to_string())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "keystore=encrypted but no password provided. \
                             Set env {password_env} or keystore_password in config."
                        ),
                    )
                })?;

            if crate::crypto::keystore::keystore_exists(&enc_path) {
                let seed32 = crate::crypto::keystore::decrypt_seed32_from_file(&enc_path, &pass)?;
                debug!("loaded encrypted keystore");
                Ok(Ed25519Keypair::from_seed(seed32))
            } else {
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let kp = Ed25519Keypair::from_seed(seed32);
                crate::crypto::keystore::encrypt_seed32_to_file(&enc_path, seed32, &pass)?;
                info!("generated new encrypted keystore");
                Ok(kp)
            }
        } else {
            let path = plain_path;
            if Path::new(&path).exists() {
                let s = fs::read_to_string(&path)?;
                let k: K = serde_json::from_str(&s)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keys.json parse: {e}")))?;
                debug!("loaded plain keystore");
                Ok(Ed25519Keypair::from_seed(k.seed32))
            } else {
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let kp = Ed25519Keypair::from_seed(seed32);
                let out = serde_json::to_string_pretty(&K { seed32 })
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keys.json encode: {e}")))?;
                fs::write(&path, out)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }
                info!("generated new plain keystore");
                Ok(kp)
            }
        }
    }

    // -------------------------------------------------------------------------
    // State (KV)
    // -------------------------------------------------------------------------

    /// Load legacy state.json (KV only). Prefer `load_state_full`.
    pub fn load_state_kv(&self) -> io::Result<BTreeMap<String, String>> {
        self.ensure()?;
        let path = self.p("state.json");
        if Path::new(&path).exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("state.json parse: {e}"))
            })
        } else {
            Ok(BTreeMap::new())
        }
    }

    /// Save legacy state.json.
    pub fn save_state_kv(&self, state: &BTreeMap<String, String>) -> io::Result<()> {
        self.ensure()?;
        let path = self.p("state.json");
        let out = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state.json encode: {e}")))?;
        fs::write(path, out)
    }

    // -------------------------------------------------------------------------
    // Full state (KvState)
    // -------------------------------------------------------------------------

    /// Load the full node state (`KvState`).
    pub fn load_state_full(&self) -> io::Result<KvState> {
        self.ensure()?;
        let path = self.p("state_full.json");
        if Path::new(&path).exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json parse: {e}"))
            })
        } else {
            debug!("state_full.json not found, returning default");
            Ok(KvState::default())
        }
    }

    /// Save the full node state.
    pub fn save_state_full(&self, state: &KvState) -> io::Result<()> {
        self.ensure()?;
        let path = self.p("state_full.json");
        let out = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json encode: {e}")))?;
        fs::write(path, out)?;
        debug!(path, "saved state_full");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Staking
    // -------------------------------------------------------------------------

    /// Load the stake ledger.
    pub fn load_stakes(&self) -> io::Result<StakeLedger> {
        self.ensure()?;
        let path = self.p("stakes.json");
        if Path::new(&path).exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json parse: {e}"))
            })
        } else {
            debug!("stakes.json not found, returning default demo ledger");
            Ok(StakeLedger::default_demo())
        }
    }

    /// Save the stake ledger.
    pub fn save_stakes(&self, stakes: &StakeLedger) -> io::Result<()> {
        self.ensure()?;
        let path = self.p("stakes.json");
        let out = serde_json::to_string_pretty(stakes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json encode: {e}")))?;
        fs::write(path, out)?;
        debug!(path, "saved stakes");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Path helpers (for other modules)
    // -------------------------------------------------------------------------

    /// Path to the legacy WAL file (pre‑v3).
    pub fn wal_path(&self) -> String {
        self.p("wal.jsonl")
    }

    /// Path to the blocks directory.
    pub fn blocks_dir(&self) -> String {
        format!("{}/blocks", self.root)
    }

    /// Path to the evidence file.
    pub fn evidence_path(&self) -> String {
        self.p("evidence.jsonl")
    }

    /// Path to the receipts directory.
    pub fn receipts_dir(&self) -> String {
        format!("{}/receipts", self.root)
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
    fn test_data_dir_ensure() {
        let dir = tempdir().unwrap();
        let data_dir = DataDir::new(dir.path().to_str().unwrap());
        data_dir.ensure().unwrap();
        assert!(dir.path().exists());
    }

    #[test]
    fn test_schema_version_new() {
        let dir = tempdir().unwrap();
        let data_dir = DataDir::new(dir.path().to_str().unwrap());
        data_dir.ensure().unwrap();
        let v = data_dir.read_schema_version().unwrap();
        assert_eq!(v, 0);
    }

    #[test]
    fn test_state_full_roundtrip() {
        let dir = tempdir().unwrap();
        let data_dir = DataDir::new(dir.path().to_str().unwrap());
        data_dir.ensure().unwrap();
        let state = KvState::default();
        data_dir.save_state_full(&state).unwrap();
        let loaded = data_dir.load_state_full().unwrap();
        assert_eq!(state.root(), loaded.root());
    }

    #[test]
    fn test_keys_plain() {
        let dir = tempdir().unwrap();
        let data_dir = DataDir::new(dir.path().to_str().unwrap());
        data_dir.ensure().unwrap();
        let kp = data_dir.load_or_create_keys(42, "plain", "").unwrap();
        let kp2 = data_dir.load_or_create_keys(42, "plain", "").unwrap();
        assert_eq!(kp.to_seed(), kp2.to_seed());
    }

    #[test]
    fn test_keys_encrypted_with_env() {
        let dir = tempdir().unwrap();
        let data_dir = DataDir::new(dir.path().to_str().unwrap());
        data_dir.ensure().unwrap();
        std::env::set_var("TEST_PW", "secret");
        let kp = data_dir.load_or_create_keys(42, "encrypted", "TEST_PW").unwrap();
        let kp2 = data_dir.load_or_create_keys(42, "encrypted", "TEST_PW").unwrap();
        assert_eq!(kp.to_seed(), kp2.to_seed());
        std::env::remove_var("TEST_PW");
    }
}
