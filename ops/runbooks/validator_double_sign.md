# Runbook: Validator Double-Sign Detection

**Alert**: `IonaValidatorDoubleSigned`  
**Severity**: CRITICAL — slashing risk; immediate action required  
**Impact**: Validator may be slashed (stake loss); reputation damage; consensus safety violation

---

## STOP — Do This First

```bash
# 1. Immediately halt the signing process
systemctl stop iona-remote-signer
systemctl stop iona-node

# 2. Preserve evidence
cp -r /var/lib/iona/wal /tmp/wal-evidence-$(date +%Y%m%d-%H%M%S)/
cp /var/log/iona/audit.log /tmp/audit-evidence-$(date +%Y%m%d-%H%M%S).log
```

**DO NOT restart the node until you understand why the double-sign occurred.**

---

## Diagnosis

```bash
# Check WAL for duplicate height/round
iona-cli audit export --last 200 | grep -i "sign\|double\|wal" | head -30

# Check if another instance is running (most common cause)
ps aux | grep iona-node | grep -v grep

# Check if key is present on multiple machines
# (Manual check required — inspect all servers with this validator key)
```

---

## Root Cause Categories

| Cause | Indicator | Fix |
|-------|-----------|-----|
| Two node instances with same key | Two PIDs; two IPs in consensus | Kill duplicate; implement key-use mutex |
| Migration accident | Recent restore from backup | Never run backup node with same key |
| Remote signer bug | WAL shows conflict at same height | Upgrade iona-remote-signer |
| Clock skew > 1s | System time far off | Fix NTP; `chronyc tracking` |

---

## Recovery

Only restart after identifying and eliminating the root cause:

```bash
# 1. Verify single instance
ps aux | grep iona-node   # must show exactly 1

# 2. Check WAL guard is active
grep "double_sign_guard" /etc/iona/config.toml  # must be true

# 3. Restart
systemctl start iona-remote-signer
sleep 5
systemctl start iona-node

# 4. Monitor for 10 minutes
journalctl -u iona-node -f | grep -E "ERROR|WARN|sign"
```

---

## Escalation
Notify: validators@example.invalid, security@example.invalid  
File postmortem within 48 hours (see `ops/playbooks/postmortem_template.md`)
