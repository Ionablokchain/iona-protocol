# IONA Postmortem Template

> **Instructions**: Copy this file to `ops/postmortems/YYYY-MM-DD-<slug>.md`.  
> Fill in all sections. Review with team within 48 hours of resolution.  
> Focus on systems and processes — not individuals. Blameless culture.

---

## Incident Summary

| Field | Value |
|-------|-------|
| **Date** | YYYY-MM-DD |
| **Duration** | HH:MM (detection to resolution) |
| **Severity** | SEV-1 / SEV-2 / SEV-3 / SEV-4 |
| **Impact** | _e.g. "Chain halted 23 minutes; 3 validators affected"_ |
| **Detection** | _e.g. "Prometheus alert IonaConsensusNoProgress fired at 14:32 UTC"_ |
| **Resolution** | _e.g. "Node restarted; consensus resumed at 14:55 UTC"_ |
| **Author** | @github-handle |
| **Reviewers** | @handle1, @handle2 |

---

## Timeline

All times UTC. Be precise.

| Time | Event |
|------|-------|
| HH:MM | Alert fired: `<AlertName>` |
| HH:MM | On-call notified |
| HH:MM | Initial triage started |
| HH:MM | Root cause identified: _description_ |
| HH:MM | Mitigation applied: _what was done_ |
| HH:MM | Service restored |
| HH:MM | All-clear declared |

---

## Impact

**Users/operators affected**: _N validators, M full nodes, K API consumers_  
**Blocks missed**: _N blocks over M minutes_  
**Transactions delayed**: _Estimated N txs pending during outage_  
**Financial impact**: _Missed block rewards: estimated X IONA_  
**SLA breach**: Yes / No  

---

## Root Cause

_One concise paragraph describing the root cause. What happened technically?_

```
Example: A configuration change on 2026-03-04 set rpc.rate_limit_rps=1, 
causing all RPC requests from the monitoring system to be rejected. 
The monitoring system could no longer report block heights, 
triggering a false-positive IonaConsensusNoProgress alert.
```

---

## Contributing Factors

- _Factor 1: e.g. No staging environment to test config changes_
- _Factor 2: e.g. Alert threshold too sensitive (< 1 block delta in 10s)_
- _Factor 3: e.g. Runbook for this scenario was outdated_

---

## Detection

**How was it detected?** Alert / User report / Monitoring / Routine check

**Time to detection**: _N minutes from root cause to alert_

**Was detection adequate?** Yes / No — _explain if No_

**Could detection be faster?** _Describe improvements_

---

## Response

**Time to acknowledge**: _N minutes from alert to on-call response_  
**Time to mitigate**: _N minutes from detection to mitigation_  
**Time to resolve**: _N minutes from detection to full resolution_

**Was the runbook followed?** Yes / Partially / No — _explain_

**Was the runbook accurate?** Yes / No — _what was wrong?_

**Communication effective?** Yes / No — _what could be improved?_

---

## Resolution

_What was done to resolve the incident?_

```bash
# Commands run to resolve
systemctl restart iona-node
```

---

## Lessons Learned

**What went well?**
- _e.g. "Alert fired within 30 seconds of chain halt"_
- _e.g. "On-call responded in under 2 minutes"_

**What went poorly?**
- _e.g. "Runbook for this alert was missing"_
- _e.g. "No staging test for config changes"_

**Where did we get lucky?**
- _e.g. "Incident happened during business hours"_

---

## Action Items

Each action item must have: owner, due date, tracking issue.

| # | Action | Owner | Due | Issue |
|---|--------|-------|-----|-------|
| 1 | _e.g. Add config validation to reject rate_limit_rps < 10_ | @alice | 2026-03-19 | #123 |
| 2 | _e.g. Update runbook with correct diagnosis steps_ | @bob | 2026-03-12 | #124 |
| 3 | _e.g. Add staging environment for config testing_ | @charlie | 2026-04-01 | #125 |

---

## Secret Redaction Checklist

Before publishing this postmortem:

```
□ No private keys in timeline or commands
□ No passwords or secrets in code blocks
□ Peer IDs/IP addresses obscured if sensitive
□ Log excerpts use REDACTED for sensitive values
□ Support bundle not attached (link to internal storage only)
```

---

## Sign-off

| Role | Name | Date |
|------|------|------|
| Incident Commander | | |
| On-Call Engineer | | |
| Engineering Lead | | |

_Reviewed and approved for publication_
