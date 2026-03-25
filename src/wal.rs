//! Production Write-Ahead Log for IONA.
//!
//! Features:
//! - fsync after every write (guarantees durability)
//! - Segment rotation when size exceeds MAX_SEGMENT_BYTES
//! - Corrupt-line tolerance (bad JSON lines are skipped)
//! - Atomic snapshot via rename (not shown here, but used by storage)
//! - Persistent metadata to recover active segment after crash
//! - Truncation after a snapshot (remove events before the snapshot point)

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{error, warn};

const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB per segment
const KEEP_SEGMENTS: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WalEvent {
    Inbound  { bytes: Vec<u8> },
    Outbound { bytes: Vec<u8> },
    Step     { height: u64, round: u32, step: String },
    Snapshot { bytes: Vec<u8> },
    Note     { msg: String },
}

/// Metadata persisted across restarts.
#[derive(Debug, Serialize, Deserialize, Default)]
struct WalMeta {
    /// The current active segment number.
    current_segment: u32,
    /// Last snapshot segment (0 = no snapshot taken yet).
    snapshot_segment: u32,
    /// Offset (in bytes) within the snapshot segment where the snapshot was written.
    snapshot_offset: u64,
}

impl WalMeta {
    fn path(dir: &Path) -> PathBuf {
        dir.join("wal_meta.json")
    }

    fn load(dir: &Path) -> std::io::Result<Self> {
        let path = Self::path(dir);
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(&path)?;
        serde_json::from_str(&content).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }

    fn save(&self, dir: &Path) -> std::io::Result<()> {
        let path = Self::path(dir);
        let tmp = path.with_extension("tmp");
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp, content)?;
        fs::rename(tmp, path)?;
        Ok(())
    }
}

/// Thread‑safe WAL handle.
#[derive(Clone)]
pub struct Wal(Arc<Mutex<WalInner>>);

struct WalInner {
    dir: PathBuf,
    meta: WalMeta,
    current_file: File,
    written: u64,
}

impl Wal {
    /// Open (or create) a WAL in `dir`.
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;

        let meta = WalMeta::load(&dir)?;
        let current_segment = meta.current_segment;
        let path = Self::segment_path(&dir, current_segment);
        let written = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let current_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let inner = WalInner {
            dir,
            meta,
            current_file,
            written,
        };
        Ok(Wal(Arc::new(Mutex::new(inner))))
    }

    fn segment_path(dir: &Path, seg: u32) -> PathBuf {
        dir.join(format!("wal_{:08}.jsonl", seg))
    }

    /// Append an event. Rotates if needed.
    pub fn append(&self, ev: &WalEvent) -> std::io::Result<()> {
        let mut inner = self.0.lock().unwrap();
        if inner.written >= MAX_SEGMENT_BYTES {
            inner.rotate()?;
        }

        let line = serde_json::to_vec(ev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        inner.current_file.write_all(&line)?;
        inner.current_file.write_all(b"\n")?;
        inner.current_file.sync_data()?;
        inner.written += (line.len() + 1) as u64;
        Ok(())
    }

    /// Mark a snapshot point. After this, WAL entries before this snapshot can be pruned.
    /// `segment` and `offset` indicate the exact position in the WAL where the snapshot was taken.
    pub fn mark_snapshot(&self, segment: u32, offset: u64) -> std::io::Result<()> {
        let mut inner = self.0.lock().unwrap();
        inner.meta.snapshot_segment = segment;
        inner.meta.snapshot_offset = offset;
        inner.meta.save(&inner.dir)?;
        inner.prune_old_segments();
        Ok(())
    }

    /// Replay all events from the beginning of the WAL.
    pub fn replay(&self) -> std::io::Result<Vec<WalEvent>> {
        let inner = self.0.lock().unwrap();
        Self::replay_from(&inner.dir, 0, 0)
    }

    /// Replay events starting from a specific segment and offset.
    /// This is used after loading a snapshot: we only need events after the snapshot point.
    pub fn replay_from(start_segment: u32, start_offset: u64, dir: &Path) -> std::io::Result<Vec<WalEvent>> {
        let mut segments = Self::collect_segments(dir)?;
        // Keep only segments >= start_segment
        segments.retain(|&s| s >= start_segment);

        let mut out = Vec::new();
        let mut corrupt = 0;

        for seg in segments {
            let path = Self::segment_path(dir, seg);
            let f = File::open(&path)?;
            let br = BufReader::new(f);
            let mut line_num = 0;
            let mut current_offset = 0;

            for line in br.lines() {
                let line = match line {
                    Ok(l) if l.trim().is_empty() => { current_offset += l.len() as u64 + 1; continue; },
                    Ok(l) => l,
                    Err(e) => {
                        warn!("WAL read error seg={seg} line={line_num}: {e}");
                        corrupt += 1;
                        current_offset += 1; // approximate
                        continue;
                    }
                };
                let len = line.len() as u64 + 1;
                // Skip lines before the snapshot point in the starting segment
                if seg == start_segment && current_offset < start_offset {
                    current_offset += len;
                    line_num += 1;
                    continue;
                }
                match serde_json::from_str::<WalEvent>(&line) {
                    Ok(ev) => out.push(ev),
                    Err(e) => {
                        warn!("WAL corrupt line seg={seg} line={line_num}: {e}");
                        corrupt += 1;
                    }
                }
                current_offset += len;
                line_num += 1;
            }
        }

        if corrupt > 0 {
            error!("WAL replay: {corrupt} corrupt lines skipped");
        }
        Ok(out)
    }

    /// Collect all segment numbers in the WAL directory.
    fn collect_segments(dir: &Path) -> std::io::Result<Vec<u32>> {
        let mut segments = Vec::new();
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if s.starts_with("wal_") && s.ends_with(".jsonl") {
                    if let Ok(seg) = s[4..12].parse::<u32>() {
                        segments.push(seg);
                    }
                }
            }
        }
        segments.sort_unstable();
        Ok(segments)
    }
}

impl WalInner {
    fn rotate(&mut self) -> std::io::Result<()> {
        self.meta.current_segment += 1;
        self.meta.save(&self.dir)?;
        let path = Wal::segment_path(&self.dir, self.meta.current_segment);
        self.current_file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.written = 0;
        self.prune_old_segments();
        Ok(())
    }

    fn prune_old_segments(&self) {
        // Keep at least KEEP_SEGMENTS, and also keep all segments >= snapshot_segment.
        let min_keep = self.meta.snapshot_segment.saturating_sub(KEEP_SEGMENTS as u32);
        // We cannot delete segments that are before the snapshot if they are still referenced by `snapshot_segment`.
        // Actually we should keep at least the snapshot segment and maybe a few before for safety.
        // We'll keep all segments with seg >= snapshot_segment.saturating_sub(KEEP_SEGMENTS as u32).
        let cutoff = self.meta.snapshot_segment.saturating_sub(KEEP_SEGMENTS as u32);
        for seg in 0..cutoff {
            let path = Wal::segment_path(&self.dir, seg);
            if path.exists() {
                if let Err(e) = fs::remove_file(&path) {
                    warn!("WAL prune failed for seg {}: {e}", seg);
                }
            }
        }
    }
}
