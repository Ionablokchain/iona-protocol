# Runbook: Finality Lag / Chain Halt

**Alerts**: `IonaFinalityLagCritical`, `IonaFinalityLagWarning`, `IonaNoBlocksProduced`, `IonaEquivocationDetected`
**Severity**: Page (> 20 block lag or no blocks) / Warning (> 5 block lag)

---

## Impact

Consensus stalls mean no new blocks are being finalized. Transactions accumulate in mempools and are never confirmed. For a validator this can result in slashing. An equivocation event is a critical security incident requiring immediate investigation.

---

## Diagnosis

### 1. Verify the node's current height and peers

```bash
# Local node height
curl -s http://localhost:9001/status | jq '.result.sync_info'

# Compare against a known-good external node or explorer
curl -s https://explorer.yournet.example/api/latest-block | jq '.height'
```

If the local height is advancing but slower than the network → catching-up mode (expected after restart). Wait for it to sync.

If the height is completely frozen → consensus has stalled.

### 2. Check consensus state

```bash
curl -s http://localhost:9001/status | jq '.result.consensus_state'
```

Key fields:
- `height` — current consensus round height
- `round` — current round within that height (non-zero for an extended time = stall)
- `step` — propose/prevote/precommit

If `round` is incrementing continuously → validators are timing out, possibly because a quorum can't be reached.

### 3. Check validator set and connectivity

```bash
curl -s http://localhost:9001/validators | jq '.result.validators[].address'
```

Compare the list of active validators against the expected set in your deployment. A missing validator may have gone offline.

```bash
# Check if our own node is a validator and signing correctly
curl -s http://localhost:9001/admin/status | jq '.signing'
```

### 4. Check for equivocation (double-sign)

If `IonaEquivocationDetected` fired:

```bash
# Find equivocation events in audit log
tail -500 /data/audit.log | jq 'select(.action=="equivocation_detected")'
```

This is a critical security event — stop here and escalate immediately (see below).

### 5. Check for network partition

```bash
# Check peer count
curl -s http://localhost:9001/net_peerCount | jq

# Look for partition indicators in logs
journalctl -u iona-node -n 200 | grep -i "partition\|split\|timeout\|quorum"
```

If peer count dropped to < 1/3 of the validator set, a network partition may have split the quorum.

---

## Remediation

### A. Catching-up after restart (not a true stall)

Do nothing. The node will sync via P2P state sync or block replay. Monitor:

```bash
watch -n 2 'curl -s http://localhost:9001/status | jq .result.sync_info.catching_up'
```

Expected: `true` while syncing, then `false` when caught up.

### B. Single validator down (non-quorum loss)

If one validator is offline and there are still 2/3+1 validators active, consensus continues. The offline validator just misses rounds and doesn't get rewards.

- Restart the offline validator node.
- If it won't restart, trigger a config-reload or snapshot on a replica.

### C. Quorum loss (≥ 1/3 validators offline)

Consensus halts. Recovery requires:

1. Get ≥ 1/3 of the offline validators back online.
2. If validators are online but can't connect to each other, fix the network partition first (see peer_drop runbook).
3. Restart all affected validators simultaneously after connectivity is restored.

### D. Persistent height freeze (bug / chain halt)

If the chain appears stuck at the same height for > 10 minutes with all validators online:

1. Check all validator logs for the same error.
2. A protocol bug may require an emergency upgrade. Contact the lead engineer.
3. To perform an emergency upgrade trigger:
   ```bash
   curl -X POST --cert maintainer.crt.pem --key maintainer.key.pem \
     https://localhost:9002/admin/upgrade-trigger \
     -d '{"version": "28.2.1", "height": <current_height+100>}'
   ```

### E. Equivocation response

1. **Immediately isolate the offending validator**: remove it from the network or stop its node.
2. Investigate how the double-sign occurred (key compromise, duplicate deployment, etc.).
3. If keys were compromised:
   ```bash
   # Rotate keys (maintainer role required)
   curl -X POST --cert maintainer.crt.pem --key maintainer.key.pem \
     https://localhost:9002/admin/key-rotate
   ```
4. File a security incident report within 1 hour.

---

## Escalation

- Chain halted > 5 minutes → page the protocol lead.
- Equivocation detected → page both on-call and security lead immediately.
- If an emergency chain reset is needed:
  ```bash
  # DESTRUCTIVE — requires maintainer cert, explicit confirmation
  curl -X POST --cert maintainer.crt.pem --key maintainer.key.pem \
    https://localhost:9002/admin/reset-chain -d '{"confirm": "RESET"}'
  ```

---

## Post-incident

1. Capture full validator logs from the stall window.
2. Replay the consensus state machine in test to reproduce.
3. If a fork occurred, investigate the fork-choice rule and ensure all nodes converged.
4. Update chaos tests to cover the failure mode.
