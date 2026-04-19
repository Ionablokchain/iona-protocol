//! Persistent storage for evidence of consensus violations.
//!
//! This module provides a thread‑safe evidence store that:
//! - Prevents duplicate evidence (by stable hash)
//! - Rate‑limits evidence per peer (30 per minute)
//! - Caps evidence per height (200 per height)
//! - Persists evidence to an append‑only JSONL file
//! - Supports loading all stored evidence at startup
//!
//! # Example
//!
//! ```
//! use iona::evidence::Evidence;
//! use iona::storage::evidence_store::EvidenceStore;
//!
//! let mut store = EvidenceStore::open("./data/evidence.jsonl").unwrap();
//! let ev = Evidence::DoubleVote { /* ... */ };
//! if store.allow("peer1", 100) && store.insert(&ev).unwrap() {
//!     println!("Evidence accepted");
//! }
//! ```

use crate::evidence::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Rate limit: maximum number of evidence messages per peer per minute.
const EVIDENCE_PER_PEER_LIMIT: usize = 30;

/// Rate limit window in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Global cap on evidence per height.
const EVIDENCE_PER_HEIGHT_LIMIT: u32 = 200;

// -----------------------------------------------------------------------------
// EvidenceStore
// -----------------------------------------------------------------------------

/// Persistent store for consensus evidence.
///
/// Internally uses a BTreeSet to detect duplicates, rate‑limiting per peer,
/// per‑height caps, and an append‑only JSONL file for persistence.
#[derive(Clone, Debug)]
pub struct EvidenceStore {
    /// Path to the JSONL file.
    path: PathBuf,
    /// Set of stable evidence IDs (blake3 hash).
    seen: BTreeSet<String>,
    /// Rate limiting: peer → timestamps (seconds) of recent evidence.
    rl: HashMap<String, VecDeque<u64>>,
    /// Per‑height counter for evidence.
    per_height: HashMap<u64, u32>,
}

impl EvidenceStore {
    /// Open (or create) an evidence store at the given path.
    ///
    /// If the file does not exist, it is created.
    /// Existing evidence is **not** loaded automatically; call `load_all()` if needed.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            fs::File::create(&path)?;
            debug!(path = %path.display(), "created new evidence store");
        } else {
            debug!(path = %path.display(), "opening existing evidence store");
        }
        Ok(Self {
            path,
            seen: BTreeSet::new(),
            rl: HashMap::new(),
            per_height: HashMap::new(),
        })
    }

    /// Load all evidence from the file into memory (for duplicate detection at startup).
    ///
    /// This is called automatically by `open_and_load()` or can be called manually.
    pub fn load_all(&mut self) -> std::io::Result<usize> {
        let file = fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Evidence>(&line) {
                Ok(ev) => {
                    let id = Self::id(&ev);
                    if self.seen.insert(id) {
                        count += 1;
                    }
                }
                Err(e) => {
                    warn!(path = %self.path.display(), error = %e, "skipping corrupt line");
                }
            }
        }
        info!(loaded = count, "loaded evidence from store");
        Ok(count)
    }

    /// Open the store and load all existing evidence in one call.
    pub fn open_and_load(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let mut store = Self::open(path)?;
        store.load_all()?;
        Ok(store)
    }

    /// Compute a stable, deterministic ID for an evidence item.
    ///
    /// The ID is the Blake3 hash of the canonical JSON representation.
    /// This ensures that the same evidence is always mapped to the same ID.
    pub fn id(ev: &Evidence) -> String {
        let bytes = serde_json::to_vec(ev).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Check if a given evidence item is already in the store.
    pub fn contains(&self, ev: &Evidence) -> bool {
        let id = Self::id(ev);
        self.seen.contains(&id)
    }

    /// Check whether a new evidence from a given peer and height should be allowed.
    ///
    /// Returns `true` if the evidence passes rate limits and per‑height caps.
    pub fn allow(&mut self, peer: &str, height: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Rate limiting per peer
        let queue = self.rl.entry(peer.to_string()).or_default();
        while let Some(&front) = queue.front() {
            if now.saturating_sub(front) > RATE_LIMIT_WINDOW_SECS {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.len() >= EVIDENCE_PER_PEER_LIMIT {
            debug!(peer, limit = EVIDENCE_PER_PEER_LIMIT, "rate limit exceeded");
            return false;
        }

        // Per‑height cap
        let count = self.per_height.entry(height).or_insert(0);
        if *count >= EVIDENCE_PER_HEIGHT_LIMIT {
            debug!(height, limit = EVIDENCE_PER_HEIGHT_LIMIT, "per‑height cap reached");
            return false;
        }

        queue.push_back(now);
        *count += 1;
        true
    }

    /// Insert a new evidence item into the store.
    ///
    /// Returns `Ok(true)` if the evidence was new and persisted,
    /// `Ok(false)` if it was a duplicate (already seen).
    /// Returns an error if writing to the file fails.
    pub fn insert(&mut self, ev: &Evidence) -> std::io::Result<bool> {
        let id = Self::id(ev);
        if self.seen.contains(&id) {
            debug!(id = %id, "duplicate evidence rejected");
            return Ok(false);
        }

        // Append to file
        let line = serde_json::to_string(ev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{}", line)?;
        file.sync_all()?; // ensure durability

        self.seen.insert(id);
        debug!("evidence persisted");
        Ok(true)
    }

    /// Insert an evidence item only if it passes rate‑limiting checks.
    ///
    /// This is a convenience method that combines `allow()` and `insert()`.
    pub fn allow_and_insert(&mut self, peer: &str, height: u64, ev: &Evidence) -> std::io::Result<bool> {
        if !self.allow(peer, height) {
            return Ok(false);
        }
        self.insert(ev)
    }

    /// Number of distinct evidence items in the store.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear all in‑memory state (does **not** delete the file).
    pub fn clear(&mut self) {
        self.seen.clear();
        self.rl.clear();
        self.per_height.clear();
        debug!("evidence store cleared (memory only)");
    }

    /// Get all evidence IDs currently in memory.
    pub fn ids(&self) -> Vec<String> {
        self.seen.iter().cloned().collect()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::PublicKeyBytes;
    use crate::consensus::messages::{Proposal, Vote, VoteType};
    use crate::types::Hash32;
    use tempfile::tempdir;

    fn dummy_vote() -> Vote {
        Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![1u8; 32]),
            block_id: Some(Hash32([0xAA; 32])),
            signature: crate::crypto::SignatureBytes(vec![0u8; 64]),
        }
    }

    fn dummy_evidence() -> Evidence {
        Evidence::DoubleVote {
            voter: PublicKeyBytes(vec![1u8; 32]),
            height: 1,
            round: 0,
            vote_type: VoteType::Prevote,
            a: Some(Hash32([0xAA; 32])),
            b: Some(Hash32([0xBB; 32])),
            vote_a: dummy_vote(),
            vote_b: dummy_vote(),
        }
    }

    #[test]
    fn test_evidence_id_deterministic() {
        let ev1 = dummy_evidence();
        let ev2 = dummy_evidence();
        assert_eq!(EvidenceStore::id(&ev1), EvidenceStore::id(&ev2));
    }

    #[test]
    fn test_insert_and_contains() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let mut store = EvidenceStore::open(&path).unwrap();
        let ev = dummy_evidence();
        assert!(!store.contains(&ev));
        store.insert(&ev).unwrap();
        assert!(store.contains(&ev));
        // Duplicate should be rejected
        let duplicate = store.insert(&ev).unwrap();
        assert!(!duplicate);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_load_all() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        {
            let mut store = EvidenceStore::open(&path).unwrap();
            store.insert(&dummy_evidence()).unwrap();
        }
        let mut store = EvidenceStore::open(&path).unwrap();
        assert_eq!(store.len(), 0);
        store.load_all().unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_rate_limiting() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let mut store = EvidenceStore::open(&path).unwrap();
        let ev = dummy_evidence();

        // Allow up to 30 per minute
        for _ in 0..30 {
            assert!(store.allow("peer1", 1));
        }
        assert!(!store.allow("peer1", 1));
    }

    #[test]
    fn test_per_height_cap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let mut store = EvidenceStore::open(&path).unwrap();
        let ev = dummy_evidence();

        for _ in 0..200 {
            assert!(store.allow("peer1", 100));
        }
        assert!(!store.allow("peer1", 100));
    }

    #[test]
    fn test_clear() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let mut store = EvidenceStore::open(&path).unwrap();
        store.insert(&dummy_evidence()).unwrap();
        assert_eq!(store.len(), 1);
        store.clear();
        assert_eq!(store.len(), 0);
        // File should still exist
        assert!(path.exists());
    }

    #[test]
    fn test_open_and_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        {
            let mut store = EvidenceStore::open(&path).unwrap();
            store.insert(&dummy_evidence()).unwrap();
        }
        let store = EvidenceStore::open_and_load(&path).unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_allow_and_insert() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evidence.jsonl");
        let mut store = EvidenceStore::open(&path).unwrap();
        let ev = dummy_evidence();
        let inserted = store.allow_and_insert("peer1", 1, &ev).unwrap();
        assert!(inserted);
        assert!(store.contains(&ev));
        // Second attempt should be rate‑limited? Actually duplicate detection will reject.
        let inserted2 = store.allow_and_insert("peer1", 1, &ev).unwrap();
        assert!(!inserted2);
    }
}
