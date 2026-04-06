# Runbook: Disk / WAL Growth

**Alerts**: `IonaWalSizeGrowthRapid`, `IonaDiskFreeBelow20Pct`, `IonaDiskFreeBelow10Pct`, `IonaSnapshotStaleness`
**Severity**: Page (< 10% free or < 20% free) / Warning (rapid WAL growth or stale snapshot)

---

## Impact

Running out of disk space causes an immediate node crash. The WAL (Write-Ahead Log) is the primary disk consumer; without periodic compaction via snapshots, it grows unboundedly. A node with < 5% free disk will crash-stop and require manual intervention to recover.

---

## Disk Layout

| Path | Contents | Typical size |
|------|----------|--------------|
| `/data/node/wal/` | Write-Ahead Log (unbounded without compaction) | 1–50 GiB |
| `/data/node/state_full.json` | Serialized full state | 100 MiB – 2 GiB |
| `/data/node/snapshots/` | Periodic compressed state snapshots | N × (state size × zstd-ratio) |
| `/data/audit.log` | Append-only audit log | grows ~1 MiB/day typically |

---

## Diagnosis

### 1. Current disk usage

```bash
df -h /data
du -sh /data/node/* | sort -rh | head -10
```

### 2. WAL growth rate

```bash
# Prometheus
rate(iona_wal_bytes_total[10m]) * 3600  # bytes per hour
```

Expected: < 50 MiB/hour at normal transaction rates. > 500 MiB/hour indicates a transaction flood or compaction failure.

### 3. Snapshot status

```bash
ls -lh /data/node/snapshots/ | tail -5
curl -s http://localhost:9001/metrics | grep last_snapshot
```

Expected: a snapshot every 500 blocks (configurable via `storage.snapshot_every_n_blocks`).

### 4. Is the snapshot worker running?

```bash
journalctl -u iona-node -n 100 | grep -i "snapshot\|compaction"
```

Look for errors like "snapshot failed" or "compaction error". If snapshots are failing, the WAL will grow without bound.

### 5. Snapshot compression check

```bash
# zstd compression ratio
stat -c %s /data/node/snapshots/latest.snap.zst
stat -c %s /data/node/state_full.json
# ratio = compressed / uncompressed
```

Level-3 zstd typically achieves 3–6x compression on state data.

---

## Remediation

### A. Immediate: free disk space

If disk is > 90% full, take emergency action immediately.

**Step 1**: Remove old snapshots beyond the keep count:

```bash
ls -t /data/node/snapshots/ | tail -n +6 | xargs -I{} rm /data/node/snapshots/{}
```

**Step 2**: If WAL is the culprit, force a snapshot now:

```bash
curl -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/snapshot
```

A successful snapshot truncates the WAL up to the snapshot height.

**Step 3**: Verify recovery:

```bash
df -h /data
```

### B. Snapshot worker not running

If snapshots have been failing:

1. Check for disk I/O errors in `dmesg` or `/var/log/syslog`.
2. Ensure the snapshot config is correct:
   ```toml
   [storage]
   enable_snapshots        = true
   snapshot_every_n_blocks = 500
   snapshot_keep           = 10
   snapshot_zstd_level     = 3
   ```
3. Reload config without restart:
   ```bash
   curl -X POST --cert client.crt.pem --key client.key.pem \
     https://localhost:9002/admin/config-reload
   ```
4. If still failing, restart the node: `systemctl restart iona-node`.

### C. Rapid WAL growth — transaction flood

If the WAL is growing > 500 MiB/hour:

1. Check the mempool size (see `mempool_pressure` runbook).
2. If a transaction spam attack is ongoing, flush the mempool after getting sign-off:
   ```bash
   curl -X POST --cert client.crt.pem --key client.key.pem \
     https://localhost:9002/admin/mempool-flush
   ```
3. Monitor WAL growth rate post-flush.

### D. Increase disk capacity (permanent fix)

If the node is at capacity due to legitimate growth:

1. Provision additional disk storage (EBS volume resize, etc.).
2. After expanding, update the filesystem:
   ```bash
   # Example: resize ext4 on AWS EBS
   sudo resize2fs /dev/nvme1n1
   df -h /data  # should show new capacity
   ```
3. Consider reducing `snapshot_every_n_blocks` to compact the WAL more frequently.

### E. Archive old data

If you need to retain history but free space:

```bash
# Move old snapshots to cold storage
aws s3 cp /data/node/snapshots/snapshot-1000.snap.zst \
  s3://your-bucket/iona-snapshots/ --storage-class GLACIER
```

---

## Escalation

- Disk < 5% free → page the on-call engineer immediately; do NOT wait for auto-recovery.
- WAL corruption suspected → escalate to lead engineer before any destructive operations.

---

## Capacity Planning

Rule of thumb for IONA disk sizing:

| Traffic level | WAL growth/day | Recommended disk |
|--------------|---------------|-----------------|
| Testnet (< 100 TPS) | ~ 1 GiB/day | 100 GiB minimum |
| Mainnet light (< 500 TPS) | ~ 5 GiB/day | 500 GiB, expandable |
| Mainnet heavy (> 1000 TPS) | > 10 GiB/day | 2 TiB+, auto-expand |

With snapshots at every 500 blocks and `snapshot_keep = 10`, the WAL is effectively bounded to approximately the size of 500 blocks × average block size. At 500 TPS and 4,096 txs/block, expect ~1 GiB/day WAL before compaction, reduced to ~200 MiB/day after.

---

## Post-incident

1. Capture pre-and-post `df -h` and `du -sh` output.
2. If snapshot worker was silently failing, add a test to the monitoring pipeline to alert faster.
3. Review and adjust `snapshot_every_n_blocks` and `snapshot_keep` based on observed growth rates.
