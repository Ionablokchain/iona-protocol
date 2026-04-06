# Runbook: Audit Chain Integrity Failure

**Alert**: `IonaAuditChainIntegrityFail`  
**Severity**: Critical — potential tampering  
**Impact**: Compliance failure; audit records may be untrustworthy

---

## Immediate Actions

```bash
# 1. Verify the chain
iona-cli audit verify
# Expected: "Audit chain intact: N entries, hash=<hash>"

# 2. Find first failing entry
iona-cli audit verify --verbose 2>&1 | grep -i "fail\|mismatch" | head -5

# 3. Export segment around failure
iona-cli audit export --from-entry 8280 --count 20 > /tmp/audit-segment.jsonl

# 4. Check storage
dmesg | grep -i "error\|corrupt" | tail -20
smartctl -a /dev/nvme0 | grep -E "FAILED|Reallocated"
```

---

## Recovery

**Storage corruption**: Stop node → restore audit log from backup → verify → restart  
**Software bug**: Open security issue; do NOT discard corrupt log  
**Tampering suspected**: Escalate immediately; snapshot disk; rotate all keys; notify validators

---

## Post-Incident
Audit chain integrity must pass `iona-cli audit verify` before re-enabling compliance reporting.
