# Runbook: Node Version Skew

**Alert**: `IonaNodeVersionSkew`  
**Severity**: Warning  
**Impact**: Security patches missed; mixed-version consensus risk

---

## Diagnosis

```bash
iona-node --version
curl -sf https://api.github.com/repos/iona/iona/releases/latest | jq '.tag_name'
iona-cli validators | grep version
```

## Upgrade (Rolling, Zero Downtime)

```bash
VERSION=v28.8.0
curl -LO "https://github.com/iona/iona/releases/download/${VERSION}/iona-node_${VERSION#v}_amd64.deb"
curl -LO "https://github.com/iona/iona/releases/download/${VERSION}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
sudo dpkg -i "iona-node_${VERSION#v}_amd64.deb"
sudo systemctl restart iona-node
iona-cli doctor
```

## SLA
- Critical patches: ≤ 48 hours
- High: ≤ 7 days
- Routine: ≤ 30 days
