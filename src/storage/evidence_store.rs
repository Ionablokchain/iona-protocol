use crate::evidence::Evidence;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Internal state of the evidence store, protected by a RwLock.
struct EvidenceStoreInner {
    /// Path to the main evidence file (one JSON per line).
    data_path: PathBuf,
    /// Buffered writer for the evidence file.
    writer: BufWriter<File>,
    /// Set of already seen evidence IDs (for deduplication).
    seen: HashSet<String>,
    /// Rate limiting: for each peer, we store timestamps (seconds) of recent evidence.
    rl: HashMap<String, VecDeque<u64>>,
    /// Per‑height cap: number of evidence already accepted for each height.
    per_height: HashMap<u64, u32>,
    /// Optional path to an index file that stores only the IDs (for faster startup).
    index_path: Option<PathBuf>,
}

/// Thread‑safe evidence store with deduplication, rate limiting and per‑height cap.
#[derive(Clone)]
pub struct EvidenceStore {
    inner: Arc<RwLock<EvidenceStoreInner>>,
}

impl EvidenceStore {
    /// Opens (or creates) the evidence store at the given data path.
    ///
    /// If `index_path` is provided, it is used to store only the IDs of seen evidence.
    /// This speeds up startup because we don't have to deserialize the whole evidence file.
    /// The index file is maintained automatically alongside the data file.
    pub fn open(data_path: impl AsRef<Path>, index_path: Option<impl AsRef<Path>>) -> io::Result<Self> {
        let data_path = data_path.as_ref().to_path_buf();
        let index_path = index_path.map(|p| p.as_ref().to_path_buf());

        // Open (or create) the data file in append mode, also readable for initial loading.
        let data_file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&data_path)?;

        // Prepare the seen set.
        let seen = if let Some(ref idx_path) = index_path {
            // Load from index file if it exists.
            Self::load_index(idx_path)?
        } else {
            // Otherwise load by reading and deserializing the whole data file.
            Self::load_seen_from_data(&data_file)?
        };

        // Reopen the data file for writing (append mode, no read needed now).
        let data_file = OpenOptions::new().append(true).open(&data_path)?;
        let writer = BufWriter::new(data_file);

        let inner = EvidenceStoreInner {
            data_path,
            writer,
            seen,
            rl: HashMap::new(),
            per_height: HashMap::new(),
            index_path,
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    /// Loads seen IDs by reading and deserialising every line of the data file.
    fn load_seen_from_data(data_file: &File) -> io::Result<HashSet<String>> {
        let mut seen = HashSet::new();
        let reader = BufReader::new(data_file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(ev) = serde_json::from_str::<Evidence>(&line) {
                seen.insert(Self::id(&ev));
            } else {
                eprintln!("Warning: corrupted line in evidence file: {}", line);
            }
        }
        Ok(seen)
    }

    /// Loads seen IDs from a dedicated index file (one ID per line).
    fn load_index(index_path: &Path) -> io::Result<HashSet<String>> {
        let mut seen = HashSet::new();
        if index_path.exists() {
            let file = File::open(index_path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if !line.is_empty() {
                    seen.insert(line);
                }
            }
        }
        Ok(seen)
    }

    /// Appends an ID to the index file.
    fn append_to_index(index_path: &Path, id: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(index_path)?;
        writeln!(file, "{}", id)?;
        file.flush()?;
        Ok(())
    }

    /// Generates a stable ID for an evidence, based on a hash of its canonical JSON.
    /// (Assumes that `Evidence` serialises deterministically.)
    pub fn id(ev: &Evidence) -> String {
        let bytes = serde_json::to_vec(ev).expect("serialisation of evidence must succeed");
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Checks whether an evidence would be accepted *at this moment* according to the
    /// rate‑limiting and per‑height caps.
    ///
    /// This method does **not** modify any state (it is read‑only) and can be used for
    /// pre‑validation. However, because the actual insertion may race with other threads,
    /// a subsequent call to `insert` may still fail (e.g., if the per‑height cap is reached
    /// by another thread in the meantime). Always use `insert` for the final decision.
    pub fn allow(&self, peer: &str, height: u64) -> bool {
        let inner = self.inner.read().unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check rate limit: we need to consider only timestamps not older than 60 seconds.
        // Since we don't modify the queue here, we just count how many are still valid.
        if let Some(q) = inner.rl.get(peer) {
            let valid_count = q.iter().filter(|&&ts| now.saturating_sub(ts) <= 60).count();
            if valid_count >= 30 {
                return false;
            }
        }

        // Check per‑height cap.
        if let Some(&count) = inner.per_height.get(&height) {
            if count >= 200 {
                return false;
            }
        }

        true
    }

    /// Inserts an evidence into the store.
    ///
    /// Returns `Ok(true)` if the evidence was new and successfully written,
    /// `Ok(false)` if it was a duplicate, and `Err` if an I/O error occurred.
    ///
    /// This method is thread‑safe; concurrent calls are serialised by a write lock.
    pub fn insert(&self, ev: &Evidence, peer: &str, height: u64) -> io::Result<bool> {
        // Acquire write lock – we will modify state.
        let mut inner = self.inner.write().unwrap();

        // 1. Check for duplicate.
        let id = Self::id(ev);
        if inner.seen.contains(&id) {
            return Ok(false);
        }

        // 2. Clean old entries from the peer's rate‑limit queue.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let q = inner.rl.entry(peer.to_string()).or_default();
        while let Some(&front) = q.front() {
            if now.saturating_sub(front) > 60 {
                q.pop_front();
            } else {
                break;
            }
        }

        // 3. Check rate limit.
        if q.len() >= 30 {
            return Ok(false);
        }

        // 4. Check per‑height cap.
        let count = inner.per_height.entry(height).or_insert(0);
        if *count >= 200 {
            return Ok(false);
        }

        // 5. Serialise the evidence (assumed infallible).
        let line = serde_json::to_vec(ev).expect("serialisation of evidence must succeed");
        let mut data = line;
        data.push(b'\n');

        // 6. Write to the main data file.
        inner.writer.write_all(&data)?;
        inner.writer.flush()?; // ensure durability (can be made optional for performance)

        // 7. Update in‑memory state.
        inner.seen.insert(id.clone());
        *count += 1;
        q.push_back(now);

        // 8. If an index file is used, append the ID.
        if let Some(ref idx_path) = inner.index_path {
            Self::append_to_index(idx_path, &id)?;
        }

        Ok(true)
    }

    /// Flushes the buffered writer to disk.
    pub fn flush(&self) -> io::Result<()> {
        let mut inner = self.inner.write().unwrap();
        inner.writer.flush()
    }

    /// Prunes old entries from the per‑height map to prevent unbounded growth.
    /// Keeps only the `keep_last` highest heights.
    pub fn prune_heights(&self, keep_last: usize) {
        let mut inner = self.inner.write().unwrap();
        if inner.per_height.len() <= keep_last {
            return;
        }
        let mut heights: Vec<u64> = inner.per_height.keys().copied().collect();
        heights.sort_unstable_by(|a, b| b.cmp(a)); // descending
        for h in heights.into_iter().skip(keep_last) {
            inner.per_height.remove(&h);
        }
    }

    /// Cleans up old entries from the rate‑limit maps for all peers.
    /// Can be called periodically to free memory.
    pub fn prune_rl(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut inner = self.inner.write().unwrap();
        inner.rl.retain(|_, q| {
            while let Some(&front) = q.front() {
                if now.saturating_sub(front) > 60 {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty() // remove peers with empty queues
        });
    }
}

// The Drop impl is not needed because BufWriter is flushed when the Arc and RwLock are dropped,
// but we keep it for completeness (the inner writer is dropped when the lock is released).
impl Drop for EvidenceStoreInner {
    fn drop(&mut self) {
        let _ = self.writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // Dummy Evidence type for testing.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestEvidence {
        height: u64,
        hash: String,
    }

    type Evidence = TestEvidence;

    #[test]
    fn test_insert_duplicate() -> io::Result<()> {
        let dir = tempdir()?;
        let data_path = dir.path().join("evidence.log");
        let store = EvidenceStore::open(&data_path, None::<&Path>)?;

        let ev = Evidence { height: 10, hash: "abc".to_string() };
        let peer = "peer1";
        let height = 10;

        assert!(store.insert(&ev, peer, height)?);
        assert!(!store.insert(&ev, peer, height)?); // duplicate

        Ok(())
    }

    #[test]
    fn test_rate_limit() -> io::Result<()> {
        let dir = tempdir()?;
        let data_path = dir.path().join("evidence.log");
        let store = EvidenceStore::open(&data_path, None::<&Path>)?;

        let peer = "peer2";
        let height = 20;

        for i in 0..30 {
            let ev = Evidence { height, hash: format!("hash{}", i) };
            assert!(store.insert(&ev, peer, height)?);
        }

        let ev = Evidence { height, hash: "hash30".to_string() };
        assert!(!store.insert(&ev, peer, height)?); // rate limited

        Ok(())
    }

    #[test]
    fn test_per_height_cap() -> io::Result<()> {
        let dir = tempdir()?;
        let data_path = dir.path().join("evidence.log");
        let store = EvidenceStore::open(&data_path, None::<&Path>)?;

        let peer = "peer3";
        let height = 30;

        for i in 0..200 {
            let ev = Evidence { height, hash: format!("hash{}", i) };
            assert!(store.insert(&ev, peer, height)?);
        }

        let ev = Evidence { height, hash: "hash200".to_string() };
        assert!(!store.insert(&ev, peer, height)?); // cap reached

        Ok(())
    }

    #[test]
    fn test_index_file() -> io::Result<()> {
        let dir = tempdir()?;
        let data_path = dir.path().join("evidence.log");
        let index_path = dir.path().join("index.txt");

        // Create store with index.
        let store = EvidenceStore::open(&data_path, Some(&index_path))?;

        let ev1 = Evidence { height: 1, hash: "a".to_string() };
        let ev2 = Evidence { height: 1, hash: "b".to_string() };

        assert!(store.insert(&ev1, "peer", 1)?);
        assert!(store.insert(&ev2, "peer", 1)?);

        // Drop and reopen – should load from index.
        drop(store);
        let store2 = EvidenceStore::open(&data_path, Some(&index_path))?;

        // Duplicates should still be detected.
        assert!(!store2.insert(&ev1, "peer", 1)?);
        assert!(!store2.insert(&ev2, "peer", 1)?);

        Ok(())
    }

    #[test]
    fn test_concurrent_allow() {
        use std::thread;

        let dir = tempdir().unwrap();
        let data_path = dir.path().join("evidence.log");
        let store = EvidenceStore::open(&data_path, None::<&Path>).unwrap();

        let store_clone = store.clone();
        let handle = thread::spawn(move || {
            // This is a read‑only check, no race.
            assert!(store_clone.allow("peer", 100));
        });

        handle.join().unwrap();
    }
}
