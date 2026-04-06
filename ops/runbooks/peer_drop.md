# Runbook: Peer Drop / Low Peer Count

**Alerts**: `IonaPeerCountLow`, `IonaPeerCountWarning`, `IonaPeerBanRateHigh`
**Severity**: Page (< 3 peers) / Warning (< 5 peers)

---

## Impact

A validator node with fewer than 3 peers risks missing block proposals and precommits from the rest of the network, which can stall consensus and halt block production on the entire chain if multiple validators are affected.

---

## Diagnosis

### 1. Check current peer status

```bash
# Via admin API (requires operator cert)
curl -s --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/status | jq '.peers'

# Via RPC
curl -s http://localhost:9001/net_peerCount | jq
```

Expected: at least 5–10 connected peers for a healthy production node.

### 2. Check recent peer bans

```bash
# Tail the audit log for NETWORK events
tail -100 /data/audit.log | jq 'select(.category=="NETWORK")'
```

High ban rate → someone may be probing/flooding the node.

### 3. Check P2P listen address and port

```bash
ss -tlnp | grep 7001        # should be LISTEN
curl -s http://localhost:9001/admin/status | jq '.network.listen'
```

Port `7001` must be reachable from peers. Check firewall rules:

```bash
# AWS
aws ec2 describe-security-groups --group-ids <sg-id> --query \
  'SecurityGroups[0].IpPermissions[?FromPort==`7001`]'

# iptables
iptables -L INPUT -n | grep 7001
```

### 4. Check DNS / bootstrap nodes

```bash
grep bootnodes config.toml
# Verify each bootnode is reachable:
nc -zvw3 <bootnode-ip> 7001
```

### 5. Check mDNS / Kademlia state

```bash
# Enable debug logging temporarily
IONA_LOG=debug iona-node --config config.toml 2>&1 | grep -i "kademlia\|mdns\|peer"
```

---

## Remediation

### A. Restart the libp2p transport

```bash
curl -s -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/peer-kick \
  -d '{"reason": "reconnect-all"}'
```

This closes all existing connections; the reconnect loop will re-dial within `reconnect_s` seconds.

### B. Add static peers

Edit `config.toml` and add known-good peer addresses:

```toml
[network]
peers = [
  "/ip4/1.2.3.4/tcp/7001",
  "/ip4/5.6.7.8/tcp/7001",
]
```

Then reload config:

```bash
curl -s -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/config-reload
```

### C. If ban rate is high (suspected DoS)

Increase `rr_strikes_before_ban` is NOT the right move — banning faster is correct.
Instead, ensure the node is not publicly indexable:

- Set `rpc.listen = "127.0.0.1:9001"` and never expose without `--unsafe-rpc-public`.
- Rate limit inbound TCP at the firewall level.
- Consider moving to a private VPC / VPN overlay.

### D. Eclipse attack suspicion

If all connected peers resolve to the same /16 subnet:

```bash
curl -s http://localhost:9001/admin/status | jq '.peers[].addr' | \
  awk -F'/' '{print $3}' | cut -d'.' -f1,2 | sort | uniq -c | sort -rn
```

A single subnet dominating → possible eclipse. Trigger a peer reseed:

```bash
curl -s -X POST --cert client.crt.pem --key client.key.pem \
  https://localhost:9002/admin/peer-kick -d '{"reason": "reseed"}'
```

---

## Escalation

- 5 minutes with < 3 peers and no recovery → page the on-call network engineer.
- If the chain has halted (see `finality_lag` runbook), escalate to the lead engineer.

---

## Post-incident

1. File a post-mortem within 48 hours.
2. Add newly identified reliable peers to the bootstrap list.
3. Review `diversity.max_inbound_per_bucket` if eclipse was suspected.
