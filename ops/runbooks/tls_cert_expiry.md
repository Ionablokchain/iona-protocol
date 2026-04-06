# Runbook: TLS Cert Expiry

**Alerts**: `IonaTLSCertExpiringSoon` (warning: < 30 days), `IonaTLSCertCritical` (critical: < 7 days)  
**Severity**: Warning → Critical  
**Impact**: Admin RPC and remote signer become unreachable when cert expires

---

## Immediate Actions

### 1. Assess time remaining
```bash
iona-cli cert status
openssl x509 -noout -enddate -in /etc/iona/tls/admin-server.crt
```

### 2. Check which service is affected
```bash
openssl s_client -connect 127.0.0.1:9099 -showcerts 2>/dev/null | openssl x509 -noout -enddate
openssl s_client -connect 127.0.0.1:7777 -showcerts 2>/dev/null | openssl x509 -noout -enddate
```

---

## Rotation (Zero-Downtime)

```bash
# Step 1: Generate new cert (on CA machine)
bash dist/release-artifacts/validator-pack/mtls/renew-cert.sh \
  --server admin --ca-dir /secure/ca --tls-dir /etc/iona/tls

# Step 2: Hot-reload (zero downtime — 60s overlap window)
iona-cli cert reload
# or: systemctl reload iona-node

# Step 3: Verify
iona-cli cert status
# Expected: expires_in_s > 31536000
```

---

## Prevention
- Alert fires at 30 days (warning) and 7 days (critical)
- Calendar reminder 45 days before expiry
- Automate: `0 2 1 * * bash /etc/iona/scripts/renew-cert.sh`

---

## Escalation
If hot-reload fails and cert is expired: `systemctl restart iona-node` (< 30s downtime).
