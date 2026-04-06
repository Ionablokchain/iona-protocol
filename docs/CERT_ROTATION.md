# IONA mTLS Certificate Rotation — Zero-Downtime Guide

**Applies to**: Admin RPC server, Remote Signer server  
**Version**: v30.0.0+  
**Feature**: Hot-reload via `SIGHUP` + file-watcher + graceful overlap

---

## Overview

IONA v30.0.0 introduces zero-downtime certificate rotation for mTLS endpoints.
When a `SIGHUP` is received (or a file-change is detected), the node:

1. Loads the new certificate and private key from disk
2. Starts accepting connections with the new cert immediately
3. Continues accepting connections with the old cert for a **60-second overlap window**
4. Drops the old cert after the overlap window expires
5. Logs the rotation event to the audit chain (tamper-evident)

No connections are dropped. No restart required.

---

## Configuration

```toml
# /etc/iona/config.toml

[admin.tls]
# Server certificate and key (rotated via SIGHUP or file-watcher)
cert_file = "/etc/iona/tls/admin-server.crt"
key_file  = "/etc/iona/tls/admin-server.key"
ca_file   = "/etc/iona/tls/ca.crt"

# Cert hot-reload settings
hot_reload = true                  # Enable SIGHUP + file-watcher reload
overlap_seconds = 60               # Accept old+new certs for this many seconds
reload_watcher = true              # Watch cert_file for changes (inotify)
reload_log_level = "info"          # Log level for rotation events

[remote_signer.tls]
cert_file = "/etc/iona/tls/signer-server.crt"
key_file  = "/etc/iona/tls/signer-server.key"
ca_file   = "/etc/iona/tls/ca.crt"
hot_reload = true
overlap_seconds = 60
```

---

## Certificate Hierarchy

```
CA (root, offline)
├── admin-server.crt   (server cert for admin RPC)
├── signer-server.crt  (server cert for remote signer)
├── ops-alice.crt      (client cert, role: operator)
├── on-call.crt        (client cert, role: maintainer)
└── auditor.crt        (client cert, role: auditor)
```

The CA private key should be kept **offline** (air-gapped or HSM). Only the
server and client certs need to be on the validator machine.

---

## Step-by-Step Rotation Procedure

### Step 1 — Generate new server certificate (from your CA machine)

```bash
# On your offline CA machine:
cd /etc/iona/tls/

# Generate new server key
openssl genrsa -out admin-server-new.key 4096

# Generate CSR
openssl req -new \
  -key admin-server-new.key \
  -subj "/CN=iona-admin/O=IONA Validator/OU=Operations" \
  -out admin-server-new.csr

# Sign with CA (valid 1 year)
openssl x509 -req \
  -in admin-server-new.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out admin-server-new.crt \
  -days 365 \
  -extensions v3_req \
  -extfile <(printf "[v3_req]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth")

# Verify new cert
openssl verify -CAfile ca.crt admin-server-new.crt
openssl x509 -in admin-server-new.crt -noout -text | grep -E "Not (Before|After)|Subject:"
```

### Step 2 — Deploy new cert to validator

```bash
# Copy to validator (use scp or secrets management)
scp admin-server-new.crt admin-server-new.key validator:/etc/iona/tls/

# On the validator — move into place atomically
cd /etc/iona/tls/
cp admin-server.crt admin-server.crt.backup-$(date +%Y%m%d)
cp admin-server.key admin-server.key.backup-$(date +%Y%m%d)

# Atomic replace (rename is atomic on Linux)
mv admin-server-new.crt admin-server.crt
mv admin-server-new.key admin-server.key

# Fix permissions
chown iona:iona admin-server.crt admin-server.key
chmod 0640 admin-server.crt
chmod 0600 admin-server.key
```

### Step 3 — Trigger hot-reload (zero-downtime)

```bash
# Method A: SIGHUP (triggers immediate reload)
systemctl reload iona-node
# or: kill -HUP $(pidof iona-node)

# Method B: File-watcher (if reload_watcher = true, automatic on file change)
# No manual action needed — the node detects the file change via inotify.

# Verify reload happened (check audit log)
iona-cli audit tail --last 5
# Expected:
# [2026-03-04T12:00:01Z] cert_reloaded  subject="iona-admin" expires="2027-03-04"
# [2026-03-04T12:00:01Z] cert_overlap_started  old_expires="2026-03-04" overlap_s=60
```

### Step 4 — Verify new cert is active

```bash
# Check the cert being served
openssl s_client \
  -connect 127.0.0.1:9099 \
  -cert /etc/iona/tls/ops-alice.crt \
  -key /etc/iona/tls/ops-alice.key \
  -CAfile /etc/iona/tls/ca.crt \
  -showcerts 2>/dev/null \
  | openssl x509 -noout -text | grep -E "Not (Before|After)|Subject:"

# Or use iona-cli:
iona-cli admin cert info
# Expected: cert=admin-server.crt  subject=iona-admin  expires=2027-03-04  status=active
```

### Step 5 — Rotate client certificates (if needed)

Client certificates (operator, auditor, maintainer) follow the same process.
Update `rbac.toml` with the new fingerprint **before** the old cert expires:

```bash
# Get new client cert fingerprint
openssl x509 -in ops-alice-new.crt -noout -fingerprint -sha256

# Update rbac.toml
# [[identities]]
# cn = "ops-alice"
# fingerprint = "<new fingerprint>"
# roles = ["operator"]

# Reload RBAC config (no restart needed)
systemctl reload iona-node
iona-cli admin rbac reload
```

---

## Graceful Overlap Window

During the 60-second overlap:
- Both old and new server certs are accepted for TLS handshake
- Clients using either cert can connect
- After 60s, the old cert is dropped and only the new cert is valid
- The overlap window is configurable via `overlap_seconds`

```
t=0s    SIGHUP received → new cert loaded
t=0–60s Both old cert (CN=iona-admin exp 2026-03-04)
         and new cert (CN=iona-admin exp 2027-03-04) accepted
t=60s   Old cert dropped. Only new cert accepted.
```

---

## Expiry Monitoring

Prometheus alerts fire 30 days before expiry:

```yaml
# ops/alerts/prometheus_rules.yml (included in release)
- alert: IonaTLSCertExpiringSoon
  expr: iona_tls_cert_expiry_seconds < 86400 * 30
  labels:
    severity: warning
  annotations:
    summary: "Admin TLS cert expires in < 30 days"
    description: "Rotate cert. See docs/CERT_ROTATION.md"

- alert: IonaTLSCertCritical
  expr: iona_tls_cert_expiry_seconds < 86400 * 7
  labels:
    severity: critical
  annotations:
    summary: "Admin TLS cert expires in < 7 days — rotate NOW"
```

---

## Remote Signer Certificate Rotation

The remote signer (`iona-remote-signer`) uses the same mechanism:

```bash
# Rotate signer server cert
mv signer-server-new.crt /etc/iona/tls/signer-server.crt
mv signer-server-new.key /etc/iona/tls/signer-server.key
kill -HUP $(pidof iona-remote-signer)

# Verify
iona-cli admin signer cert info
```

The signer also supports rotating **client allowlist** fingerprints via SIGHUP:
update `rbac.toml` with new fingerprints and reload — no downtime.

---

## Quick Reference

| Action | Command |
|--------|---------|
| Reload certs (SIGHUP) | `systemctl reload iona-node` |
| Check cert expiry | `iona-cli admin cert info` |
| View rotation in audit | `iona-cli audit tail --last 10` |
| Generate new server cert | `bash dist/release-artifacts/validator-pack/mtls/renew-cert.sh` |
| Overlap window | 60 seconds (configurable) |
| Monitoring alert | 30 days before expiry |
