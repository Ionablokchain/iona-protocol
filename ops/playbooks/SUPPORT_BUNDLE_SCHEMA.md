# IONA Support Bundle Schema — v28.8.0

Every support bundle produced by `iona-cli support-bundle` follows this schema.  
Bundles contain **zero secrets** by design — all sensitive values are replaced  
with `<REDACTED>` before inclusion.

---

## Generation

```bash
# Standard bundle (operator)
iona-cli support-bundle --output /tmp/iona-bundle-$(date +%Y%m%d-%H%M%S).tar.gz

# With extended metrics (maintainer)
iona-cli support-bundle --extended --output /tmp/iona-bundle.tar.gz

# Verify no secrets before sharing
iona-cli support-bundle verify /tmp/iona-bundle.tar.gz
```

---

## Bundle Structure

```
iona-support-bundle-YYYYMMDD-HHMMSS/
├── MANIFEST.txt              # File list + SHA-256 of each file
├── BUNDLE_INFO.json          # Bundle metadata (version, timestamp, node ID)
├── config/
│   ├── config.toml.redacted  # Node config, all secrets replaced with <REDACTED>
│   ├── rbac.toml.redacted    # RBAC policy, fingerprints partially redacted
│   └── deny.toml             # Cargo deny config (no secrets)
├── status/
│   ├── node_status.json      # iona-cli status output
│   ├── node_doctor.json      # iona-cli doctor output
│   ├── peers.json            # Connected peers (addresses, not keys)
│   ├── validators.json       # Validator set (public keys only)
│   └── mempool.json          # Mempool stats
├── audit/
│   └── audit_tail_500.jsonl  # Last 500 audit log entries (key material redacted)
├── metrics/
│   └── prometheus_snapshot.txt  # iona_* metrics only (no system secrets)
├── logs/
│   ├── node_tail_1000.log    # Last 1000 log lines (secrets redacted)
│   └── signer_tail_200.log   # Remote signer logs if available
├── system/
│   ├── os_info.txt           # uname -a, /etc/os-release
│   ├── uptime.txt            # uptime output
│   ├── memory.txt            # free -h output
│   ├── disk.txt              # df -h /var/lib/iona output
│   ├── cpu.txt               # nproc, /proc/cpuinfo summary
│   └── network.txt           # ss -tlnp (listening ports only)
└── cert/
    ├── cert_status.json      # iona-cli cert status (public info only)
    └── cert_chain.txt        # openssl x509 -noout -text (no private key)
```

---

## BUNDLE_INFO.json Schema

```json
{
  "schema_version": "1.2",
  "iona_version": "28.8.0",
  "bundle_timestamp": "2026-03-05T12:00:00Z",
  "node_id": "12D3KooW...",
  "chain_id": "iona-mainnet-1",
  "generated_by": "iona-cli 28.8.0",
  "hostname_hash": "sha256:abc123...",
  "redaction_applied": true,
  "redaction_version": "1.1",
  "files": 24
}
```

## MANIFEST.txt Format

```
SHA-256                                                           Size  File
3a4b5c6d7e8f...  1024  config/config.toml.redacted
7f8e9d0c1b2a...   512  status/node_status.json
...
```

---

## Redaction Rules

The following patterns are **always** redacted before bundle creation:

| Pattern | Replacement | Applies To |
|---------|------------|-----------|
| `password = "..."` | `password = "<REDACTED>"` | config files |
| `keystore_password*` | `keystore_password = "<REDACTED>"` | config |
| `private_key = "..."` | `private_key = "<REDACTED>"` | any file |
| `mnemonic = "..."` | `mnemonic = "<REDACTED>"` | any file |
| `seed = "..."` (if > 6 chars) | `seed = "<REDACTED>"` | config |
| Any file matching `*.key` | **Excluded entirely** | file list |
| Any file matching `*.pem` with private key | **Excluded entirely** | file list |
| API keys matching `[A-Za-z0-9]{32,}` | `<REDACTED_APIKEY>` | logs |
| JWT tokens `eyJ...` | `<REDACTED_JWT>` | logs |
| gpg passphrases in logs | `<REDACTED>` | logs |

---

## Verification

```bash
# Check bundle for accidental secret leakage
iona-cli support-bundle verify /tmp/iona-bundle.tar.gz

# Manual check
tar -xOf /tmp/iona-bundle.tar.gz | \
  grep -iE "password|private_key|mnemonic|seed|secret" | \
  grep -v "REDACTED\|<REDACTED" && \
  echo "WARNING: possible secrets" || echo "OK: clean"
```

---

## Sharing Guidelines

**Safe to share with IONA Engineering**:
- Entire bundle (auto-redacted)
- Grafana dashboard links (read-only)
- Prometheus metrics

**Never share externally without legal review**:
- Validator addresses linked to real identities
- IP addresses of other validators
- Governance vote details before public

**Never share with anyone**:
- Unredacted config files
- Private key material
- Keystore files
