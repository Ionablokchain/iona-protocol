# IONA Incident Response Playbook — v28.8.0

**Owner**: On-Call Engineering  
**Classification**: Operator Confidential  
**Version**: 2.0 (2026-03-05)

---

## Severity Definitions

| Level | Definition | Response Time | Example |
|-------|-----------|--------------|---------|
| **SEV-1** | Chain halted / total outage | 15 min | Consensus no progress |
| **SEV-2** | Critical degradation | 30 min | Double-sign, cert expired, RPC down |
| **SEV-3** | Significant impact | 2 hours | High latency, peer loss > 50% |
| **SEV-4** | Minor / cosmetic | Next business day | Warning alerts, metric anomalies |

---

## On-Call Contacts

```
Primary on-call:    +1-XXX-XXX-XXXX  (PagerDuty rotation)
Security issues:    security@example.invalid  (GPG: https://iona.network/security.gpg)
Validator hotline:  validators@example.invalid
Escalation:        engineering@example.invalid
```

---

## Phase 1 — Detection (T+0 to T+5 min)

```bash
# Step 1.1: Confirm the alert
iona-cli status
iona-cli doctor

# Step 1.2: Check Grafana
# https://metrics.testnet.iona.network
# Dashboard: "IONA Consensus Overview"

# Step 1.3: Assess impact scope
curl -sf http://127.0.0.1:9001/net_info | jq '{peers: .n_peers}'
curl -sf http://127.0.0.1:9001/status | jq '{height: .sync_info.latest_block_height, catching_up: .sync_info.catching_up}'

# Step 1.4: Open incident channel
# Slack: #incidents  /incident open "SEV-X: <brief description>"
```

---

## Phase 2 — Triage (T+5 to T+15 min)

Run through this checklist in order:

```
□ Is the local node process running?         ps aux | grep iona-node
□ Is RPC responding?                         curl -sf http://127.0.0.1:9001/status
□ Is block height advancing?                 compare two height readings 10s apart
□ Are peers connected?                       jq '.n_peers' from net_info
□ Is remote signer healthy?                  systemctl status iona-remote-signer
□ Is disk space OK?                          df -h /var/lib/iona
□ Is memory OK?                              free -h
□ Any OOM in dmesg?                          dmesg | grep -i oom | tail -5
□ Any storage errors?                        dmesg | grep -i "error\|corrupt" | tail -5
□ NTP synced?                                chronyc tracking | grep "System time"
```

---

## Phase 3 — Containment (T+15 to T+30 min)

### SEV-1: Chain Halt
```bash
# Option A: Restart node (if local issue)
systemctl restart iona-node
sleep 10 && iona-cli status

# Option B: Force nil-vote (if stuck proposer)
iona-cli admin consensus nil-vote

# Option C: Add bootstrap peers (if partition)
iona-cli admin peer add /dns4/seed1.iona.network/tcp/7001/p2p/12D3KooW...
```

### SEV-2: Double-Sign
```bash
# STOP EVERYTHING FIRST
systemctl stop iona-remote-signer iona-node
# Preserve evidence, diagnose before restart
# See ops/runbooks/validator_double_sign.md
```

### SEV-2: Cert Expired
```bash
bash dist/release-artifacts/validator-pack/mtls/renew-cert.sh --server admin
iona-cli cert reload
```

### SEV-3: High Latency / Mempool Pressure
```bash
# Check mempool
iona-cli mempool
# Increase rate limits temporarily
iona-cli admin config set rpc.rate_limit_rps 50
```

---

## Phase 4 — Resolution & Communication

### Internal
```
Status update every 15 min in incident channel:
  T+15: "Investigating high RPC latency on node-3. Height advancing normally."
  T+30: "Root cause: mempool at 95%. Applying rate limit. ETA: 5 min."
  T+45: "RESOLVED. Mempool cleared. All metrics normal."
```

### External (if validator network affected)
```
validators@example.invalid:
  Subject: [IONA INCIDENT] SEV-X: <brief description>
  Body: What happened, who is affected, current status, ETA for resolution.
```

---

## Phase 5 — Post-Incident

Within 48 hours:
1. Fill out `ops/playbooks/postmortem_template.md`
2. File in `ops/postmortems/YYYY-MM-DD-<slug>.md`
3. Create GitHub issues for action items
4. Update relevant runbook if procedure was unclear

---

## Secret Redaction Policy

**CRITICAL**: Support bundles and incident artifacts MUST have secrets redacted before sharing.

```bash
# Always generate support bundles via CLI (auto-redacts)
iona-cli support-bundle --output /tmp/bundle.tar.gz
# Verify no secrets present
tar -tf /tmp/bundle.tar.gz | xargs tar -xOf /tmp/bundle.tar.gz | \
  grep -iE "password|secret|private_key|mnemonic|seed" && \
  echo "WARNING: secrets found" || echo "OK: no secrets detected"
```

**Never share**:
- Validator private keys (any format)
- mTLS private key files (`*.key`)
- RBAC credentials
- Keystore passwords
- Any file from `/etc/iona/tls/*.key`

**Safe to share** (after redaction):
- Logs with `REDACTED` placeholders for sensitive values
- Config with sensitive values replaced by `<REDACTED>`
- Support bundle output (auto-redacted by iona-cli)
- Prometheus metrics (no secrets)

---

## Quick Reference Card

```
Check status:     iona-cli status
Check health:     iona-cli doctor
Reload cert:      iona-cli cert reload   (or: systemctl reload iona-node)
Cert status:      iona-cli cert status
Verify audit:     iona-cli audit verify
Support bundle:   iona-cli support-bundle --output /tmp/iona-$(date +%Y%m%d).tar.gz
Stop signer:      systemctl stop iona-remote-signer
Restart node:     systemctl restart iona-node
View logs:        journalctl -u iona-node -f
Add peer:         iona-cli admin peer add /dns4/<host>/tcp/7001/p2p/<id>
```
