//! Persistent storage for known peer multiaddresses.
//!
//! The data is stored as a JSON file containing a list of addresses.
//! Writes are atomic (write to temp file then rename) to prevent corruption.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::net::peer_store::PeerStore;
//! use iona::data_layout::DataLayout;
//!
//! let layout = DataLayout::new("./data");
//! let store = PeerStore::open(&layout)?;
//! store.add("/ip4/1.2.3.4/tcp/9000/p2p/Qm...".to_string())?;
//! let addrs = store.addrs();
//! ```

use crate::data_layout::DataLayout;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Internal file representation
// -----------------------------------------------------------------------------

/// Internal representation of the peer store file.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PeerStoreFile {
    /// List of peer multiaddresses (e.g., "/ip4/127.0.0.1/tcp/9000/p2p/Qm...").
    addrs: Vec<String>,
}

// -----------------------------------------------------------------------------
// PeerStore
// -----------------------------------------------------------------------------

/// Thread‑safe handle to the peer store.
///
/// All operations that modify the store acquire an internal mutex,
/// so it is safe to share across threads.
#[derive(Clone)]
pub struct PeerStore {
    inner: Arc<Mutex<PeerStoreInner>>,
}

struct PeerStoreInner {
    path: PathBuf,
    data: PeerStoreFile,
}

impl PeerStore {
    /// Opens the peer store at the path provided by `DataLayout::peers_path()`.
    pub fn open(layout: &DataLayout) -> io::Result<Self> {
        let path = layout.peers_path();
        debug!(path = %path.display(), "opening peer store");
        Self::open_path(path)
    }

    /// Opens the peer store at an explicit path (useful for testing or custom locations).
    pub fn open_path(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        debug!(path = %path.display(), "opening peer store from explicit path");

        let data = if path.exists() {
            let s = fs::read_to_string(&path).map_err(|e| {
                error!(path = %path.display(), error = %e, "failed to read peer store file");
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to read peer store: {}", e),
                )
            })?;

            serde_json::from_str(&s).map_err(|e| {
                error!(path = %path.display(), error = %e, "failed to parse peer store JSON");
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse peer store JSON: {}", e),
                )
            })?
        } else {
            debug!(path = %path.display(), "peer store file does not exist, creating new");
            PeerStoreFile::default()
        };

        Ok(Self {
            inner: Arc::new(Mutex::new(PeerStoreInner { path, data })),
        })
    }

    /// Returns a copy of all known peer addresses.
    pub fn addrs(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner.data.addrs.clone()
    }

    /// Number of known peer addresses.
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.data.addrs.len()
    }

    /// Returns `true` if the store contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Adds a new peer address if it is not already present.
    /// Persists the change atomically.
    pub fn add(&self, addr: String) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.data.addrs.contains(&addr) {
            debug!(addr = %addr, "adding new peer address");
            inner.data.addrs.push(addr);
            inner.persist()?;
        } else {
            debug!(addr = %addr, "peer address already present, skipping");
        }
        Ok(())
    }

    /// Removes a peer address if present.
    /// Persists the change atomically.
    pub fn remove(&self, addr: &str) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(pos) = inner.data.addrs.iter().position(|x| x == addr) {
            debug!(addr = %addr, "removing peer address");
            inner.data.addrs.remove(pos);
            inner.persist()?;
        } else {
            debug!(addr = %addr, "peer address not found, skipping removal");
        }
        Ok(())
    }

    /// Replaces the entire list of addresses.
    /// Persists atomically.
    pub fn set_addrs(&self, new_addrs: Vec<String>) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        debug!(count = new_addrs.len(), "replacing all peer addresses");
        inner.data.addrs = new_addrs;
        inner.persist()
    }

    /// Clears all peer addresses.
    pub fn clear(&self) -> io::Result<()> {
        self.set_addrs(Vec::new())
    }
}

impl PeerStoreInner {
    /// Writes the current data to disk atomically.
    fn persist(&self) -> io::Result<()> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize to JSON.
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode error: {}", e)))?;

        // Write atomically: temp file then rename.
        let tmp_path = self.path.with_extension("tmp");
        match fs::write(&tmp_path, &json) {
            Ok(_) => {}
            Err(e) => {
                error!(path = %tmp_path.display(), error = %e, "failed to write temporary peer store file");
                return Err(e);
            }
        }
        match fs::rename(&tmp_path, &self.path) {
            Ok(_) => {
                debug!(path = %self.path.display(), "peer store persisted");
                Ok(())
            }
            Err(e) => {
                error!(from = %tmp_path.display(), to = %self.path.display(), error = %e, "failed to rename peer store file");
                Err(e)
            }
        }
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
    fn test_add_and_get() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.add("/ip4/1.2.3.4/tcp/9000".to_string()).unwrap();
        let addrs = store.addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "/ip4/1.2.3.4/tcp/9000");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        // Adding duplicate does nothing.
        store.add("/ip4/1.2.3.4/tcp/9000".to_string()).unwrap();
        assert_eq!(store.addrs().len(), 1);
    }

    #[test]
    fn test_remove() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        store.add("addr1".to_string()).unwrap();
        store.add("addr2".to_string()).unwrap();
        assert_eq!(store.len(), 2);

        store.remove("addr1").unwrap();
        assert_eq!(store.addrs(), vec!["addr2"]);
        assert_eq!(store.len(), 1);

        store.remove("nonexistent").unwrap(); // no-op
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_set_addrs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        store.set_addrs(vec!["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(store.addrs(), vec!["a", "b"]);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_clear() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        store.add("a".to_string()).unwrap();
        store.add("b".to_string()).unwrap();
        assert_eq!(store.len(), 2);

        store.clear().unwrap();
        assert!(store.is_empty());
        assert_eq!(store.addrs(), Vec::<String>::new());
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        {
            let store = PeerStore::open_path(&path).unwrap();
            store.add("persist-me".to_string()).unwrap();
        } // store dropped

        // Reopen and verify data is still there.
        let store = PeerStore::open_path(&path).unwrap();
        assert_eq!(store.addrs(), vec!["persist-me"]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_corrupted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        fs::write(&path, "this is not json").unwrap();

        let err = PeerStore::open_path(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn test_empty_file_creates_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        // File does not exist -> should create empty store.
        let store = PeerStore::open_path(&path).unwrap();
        assert!(store.is_empty());
        // After adding, file is created.
        store.add("test".to_string()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_concurrent_access() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        let store_clone = store.clone();
        let handle = std::thread::spawn(move || {
            store_clone.add("from_thread".to_string()).unwrap();
        });
        store.add("from_main".to_string()).unwrap();
        handle.join().unwrap();

        let addrs = store.addrs();
        assert!(addrs.contains(&"from_thread".to_string()));
        assert!(addrs.contains(&"from_main".to_string()));
        assert_eq!(addrs.len(), 2);
    }
}
