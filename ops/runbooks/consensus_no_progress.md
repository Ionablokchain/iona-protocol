# Runbook: Consensus No Progress (Chain Halt)

**Alert**: `IonaConsensusNoProgress`  
**Severity**: Critical — chain halted  
**Impact**: No blocks; all transactions stalled; validator rewards missed

---

## Immediate Triage (< 5 minutes)

```bash
# Is height advancing?
H1=$(curl -sf http://127.0.0.1:9001/status | jq '.sync_info.latest_block_height')
sleep 10
H2=$(curl -sf http://127.0.0.1:9001/status | jq '.sync_info.latest_block_height')
echo "Delta: $((H2 - H1))"   # Must be > 0

# Peer count
curl -sf http://127.0.0.1:9001/net_info | jq '.n_peers'

# Consensus round info
curl -sf http://127.0.0.1:9001/consensus_state | jq '.round_state'
```

---

## Root Cause Paths

### A. Network partition (peers = 0)
```bash
ss -tlnp | grep 7001
iona-cli admin peer add /dns4/seed1.iona.network/tcp/7001/p2p/12D3KooW...
```

### B. < 2/3 validators online
Coordinate with other validators to bring nodes back online.

### C. Proposer stuck
```bash
iona-cli admin consensus nil-vote   # advance to next proposer
```

### D. Remote signer down
```bash
systemctl restart iona-remote-signer
iona-cli cert status
```

### E. OOM / memory pressure
```bash
dmesg | grep -i "oom\|killed" | tail -10
systemctl restart iona-node
```

---

## Escalation Timeline
- T+0: Alert fires
- T+5: Page on-call maintainer
- T+15: Open war room; notify validators@example.invalid
- T+30: Emergency governance if needed
