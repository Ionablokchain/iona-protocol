# IONA Security Posture — v30.0.0

**Audience**: Validators, operators, auditors, security researchers  
**Classification**: Public  
**Last Review**: 2026-03-04  
**Next Review**: 2026-09-04

---

## Executive Summary

IONA is built with security as a first-class engineering concern. The platform implements role-based access control (RBAC), mutual TLS (mTLS), tamper-evident audit logging with BLAKE3 hashchains, hardened RPC endpoints with DoS mitigations, and consensus safety guards including double-sign protection. All controls are implemented in production code, backed by comprehensive test coverage (33+ admin RBAC tests, 18+ negative security RPC tests, continuous fuzzing, and a formal threat model).

This document covers:
1. [Threat Model](#threat-model)
2. [Control Matrix](#control-matrix)
3. [Non-Goals](#non-goals)
4. [Security Controls Detail](#security-controls-detail)
5. [Open Items & Debt](#open-items--debt)
6. [Incident Response](#incident-response)
7. [Validator Security Checklist](#validator-security-checklist)

---

## Threat Model

### Assets to Protect

| Asset | Classification | Impact of Compromise |
|-------|---------------|----------------------|
| Validator signing key (`keys.enc`) | Critical | Double-sign slash, consensus disruption, fund loss |
| Admin RPC credentials (mTLS certs) | High | Unauthorized node control, key extraction |
| Chain state / block data | High | State corruption, consensus failure |
| Network peering credentials | Medium | Eclipse attack, partition |
| Node configuration | Medium | Misconfiguration-based DoS |
| Audit log | Medium | Tamper evidence lost |

### Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| **External attacker (remote)** | Network access; no code execution | Slash validators; disrupt consensus; extract keys |
| **Malicious peer node** | P2P protocol access | Eclipse attacks; spam; invalid block injection |
| **Compromised operator machine** | SSH/admin access; possibly root | Key theft; silent config changes |
| **Malicious insider** | Code access; infra access | Supply chain attack; backdoor |
| **Regulatory / legal compulsion** | Legal process | Data access; key surrender |
| **Hardware failure** | Physical | Data loss; availability |

### Attack Vectors

| Vector | Mitigations in Place |
|--------|---------------------|
| RPC endpoint abuse (DoS, auth bypass) | mTLS + RBAC, rate limiting, JSON depth limits, bind-address gate |
| Validator key theft | Key-file permission gates (0600), remote signer support, HSM interface |
| Double-sign (slashing) | WAL-based DoubleSignGuard; consensus state machine guards |
| Malicious peer injection | CometBFT P2P auth; block validation at consensus layer |
| Supply chain (dependency) | `cargo deny`, `Cargo.lock`, SBOM (CycloneDX), signed releases |
| Replay attacks | Nonce tracking; ABCI version checks at startup |
| Memory corruption | Rust (memory-safe), `panic=abort`, overflow-checks, `cargo-fuzz` |
| Config injection | Strong typing; TOML validation on load; `iona doctor` checks |
| Eclipse attack | Seed peer diversity; peer scoring; minimum peer count enforcement |

---

## Control Matrix

| Control | Category | Status | Evidence Location |
|---------|----------|--------|-------------------|
| Admin RBAC (Auditor / Operator / Maintainer) | Access Control | ✅ Implemented | `src/rpc/rbac.rs`, `tests/admin_rbac.rs` (33 tests) |
| mTLS client certificate admin auth | Access Control | ✅ Implemented | `src/rpc/admin_auth.rs` |
| Tamper-evident audit hashchain (BLAKE3) | Audit | ✅ Implemented | `src/audit.rs`, `iona audit verify` command |
| RPC bind-address gate (localhost by default) | Secure Defaults | ✅ Implemented | `src/bin/iona-node.rs` — flag `--rpc-public` required for external |
| JSON request depth limit (max 32 levels) | DoS Hardening | ✅ Implemented | `src/rpc/middleware.rs` |
| HTTP header size limit (8 KiB) | DoS Hardening | ✅ Implemented | `src/rpc/middleware.rs` |
| Uniform read rate limiting (per-IP + global) | DoS Hardening | ✅ Implemented | `src/rpc/middleware.rs` |
| CORS disabled by default in production | Secure Defaults | ✅ Implemented | `config.toml` — `cors_allowed_origins = []` |
| Key-file permission gates (0600 keys, 0700 dir) | Key Security | ✅ Implemented | Startup check; override: `--unsafe-skip-key-perms` |
| Double-sign WAL guard | Consensus Safety | ✅ Implemented | `DoubleSignGuard` in `src/consensus/` |
| `panic=abort` in release builds | Memory Safety | ✅ Implemented | `Cargo.toml` `[profile.release]` |
| Integer overflow-checks in release | Memory Safety | ✅ Implemented | `Cargo.toml` `overflow-checks = true` |
| 18+ negative security RPC tests | Test Coverage | ✅ Implemented | `tests/rpc_security_gates.rs` |
| 33+ admin RBAC unit tests | Test Coverage | ✅ Implemented | `tests/admin_rbac.rs` |
| Signed releases (GPG + cosign) | Supply Chain | ✅ Implemented | `.github/workflows/release.yml` |
| SBOM (CycloneDX 1.4) | Supply Chain | ✅ Implemented | Published with each release as `sbom.json` |
| `cargo deny` (license + advisory checks) | Supply Chain | ✅ Implemented | `deny.toml`, CI enforced |
| Prometheus security alert rules (14 rules) | Monitoring | ✅ Implemented | `ops/alerts/prometheus_rules.yml` |
| Remote signer support (separate process) | Key Security | ✅ Implemented | `src/bin/iona-remote-signer.rs` |
| HSM / KMS pluggable trait interface | Key Security | 🔶 Interface ready | `docs/VALIDATOR_KEYS.md` — PKCS#11 driver in Enterprise Pack (v29) |
| Continuous fuzzing (4 targets) | Test Coverage | ✅ Implemented | `fuzz/fuzz_targets/`, runs in CI |
| IBC light-client verification | Cross-chain | 🔶 Planned v29 | See `SUPPORTED_NETWORKS.md` |
| Third-party security audit | Audit | 🔶 Planned v29 | Scheduled Q3 2026 before mainnet |

---

## Non-Goals

The following are **explicitly out of scope** for IONA's security model. Operators must address these independently:

| Non-Goal | Rationale | Operator Responsibility |
|----------|-----------|------------------------|
| Host OS hardening | Out of scope for node software | Operators must harden the host: SELinux/AppArmor, patch management, SSH key auth only, UFW/iptables |
| DDoS protection at network layer | L3/L4 DDoS requires CDN or hardware appliances | Use Cloudflare, AWS Shield, or BGP scrubbing; IONA protects at L7 only |
| Physical security | Hardware is operator-managed | Secure datacenter; locked racks; tamper-evident hardware |
| Validator key custody off-host | PKCS#11/HSM requires hardware; IONA provides the interface | Operators must source and configure HSM (YubiHSM2, Ledger, etc.) |
| Network partition tolerance beyond BFT | BFT consensus requires 2/3+ honest nodes | Operators must ensure sufficient peer diversity; IONA enforces BFT safety bounds |
| Sybil resistance | Sybil resistance is a staking economics concern | Protocol-level; handled by staking module and slashing |
| Application-level smart contract bugs | IONA validates but does not audit user contracts | Operators and users are responsible for contract security |
| Regulatory compliance (SOC 2, GDPR) | Compliance frameworks are operator obligations | IONA provides audit logs and controls; compliance is operator responsibility |

---

## Security Controls Detail

### 1. Access Control (RBAC + mTLS)

**Admin RBAC roles** (`rbac.toml`):

| Role | Permissions | Use Case |
|------|------------|---------|
| `Auditor` | Read-only access to logs, metrics, status | Security audit; compliance monitoring |
| `Operator` | Read + operational commands (restart, peer mgmt) | Day-to-day operations |
| `Maintainer` | Full admin access including key rotation | On-call engineers; break-glass |

All admin endpoints require a valid mTLS client certificate. Certificate rotation is supported without downtime via `iona-cli admin cert rotate`.

### 2. Tamper-Evident Audit Log

Every admin action and security event produces an append-only audit log entry chained with BLAKE3 hashes. The chain is verifiable:

```bash
iona-cli audit verify --config /etc/iona/config.toml
# Output: Audit chain intact: 14,392 entries verified (no tampering detected)
```

If the chain is broken (tampered), the command exits non-zero and prints the first diverging entry.

### 3. DoS Hardening

The RPC middleware enforces (all configurable in `config.toml`):

- `rpc.max_json_depth = 32` — prevents deeply nested JSON attacks
- `rpc.max_header_bytes = 8192` — limits HTTP header abuse
- `rpc.rate_limit_rps = 100` — per-IP rate limit (requests per second)
- `rpc.rate_limit_global_rps = 5000` — global rate limit across all clients
- Automatic 429 response with `Retry-After` header
- IP blocklist support via `rpc.blocked_ips = [...]`

### 4. Key Security

**Validator signing keys** are encrypted at rest (`data/keys.enc`, AES-256-GCM). Key file permissions are enforced at startup:

```
data/keys.enc  → mode 0600 (owner-read only)
data/          → mode 0700 (owner-access only)
```

To bypass for testing: `--unsafe-skip-key-perms` (logs a loud warning; do not use in production).

**Remote signer**: The `iona-remote-signer` binary implements a separate signing process. The main node binary communicates with it over a local UNIX socket, ensuring the signing key is never loaded into the main process memory space. This enables process isolation and facilitates HSM integration.

### 5. Double-Sign Protection

`DoubleSignGuard` uses a Write-Ahead Log (WAL) to record every proposed and pre-committed block height/round before signing. If the node is asked to sign a conflicting proposal for the same height/round, it refuses and logs the incident:

```
SECURITY: Double-sign attempt detected at height=12345 round=0. Refusing to sign.
          Previous signature recorded in WAL. Investigate immediately.
```

### 6. Supply Chain Security

- **`Cargo.lock`**: Pinned; all dependency hashes are committed.
- **`cargo deny`**: Enforces license policy and checks against RustSec advisories on every CI run.
- **SBOM**: CycloneDX 1.4 JSON published with every release; scan with `grype sbom:sbom.json`.
- **Signed releases**: GPG-signed SHA256SUMS and cosign-signed binaries. See `dist/VERIFY.md`.
- **Reproducible builds**: Builds are pinned to a specific Rust toolchain (`rust-toolchain.toml`) and use `--locked` to pin dependencies.

### 7. Fuzzing

Four continuous fuzzing targets run in CI on every commit:

| Target | What it tests |
|--------|--------------|
| `state_transition` | Consensus state machine transitions and signature verification |
| `rpc_parse` | RPC request deserialization and validation |
| `block_decode` | Block and transaction decoding |
| `p2p_message` | P2P message parsing |

Current status: 0 unresolved crashes; 150+ corpus entries.

```bash
# Run locally (requires nightly)
cargo +nightly fuzz run state_transition -- -max_len=4096 -timeout=5
```

---

## Open Items & Debt

| Item | Severity | Target | Status |
|------|---------|--------|--------|
| Independent third-party security audit | High | v29 / Q3 2026 | Vendor selected; scheduled |
| Full PKCS#11 HSM driver | Medium | v29 Enterprise | Interface ready; driver in development |
| BLS threshold signatures for governance | Medium | v29 | On roadmap |
| IBC light-client verification | Medium | v29 | Design phase |
| Formal verification of consensus state machine | Low | v30 | Exploratory (`formal/` directory) |

---

## Incident Response

### Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

| Channel | Address | Use for |
|---------|---------|---------|
| Email (primary) | security@example.invalid | All security reports |
| GPG encryption | https://iona.network/security.gpg | Sensitive / critical reports |
| GitHub Security Advisories | via GitHub Security tab | Alternative channel |

### Response SLA

| Severity | Acknowledgement | Patch Released | Back-ported to LTS |
|---------|----------------|---------------|-------------------|
| Critical (RCE, key extraction) | ≤ 24 hours | ≤ 72 hours | Yes |
| High (DoS, auth bypass) | ≤ 48 hours | ≤ 7 days | Yes |
| Medium (info disclosure, denial) | ≤ 1 week | ≤ 30 days | Yes |
| Low | ≤ 2 weeks | Next minor release | At discretion |

### Coordinated Disclosure

IONA follows responsible disclosure: reporters are given 90 days before public disclosure. We aim to release a patch and a coordinated CVE advisory simultaneously.

---

## Validator Security Checklist

Complete this checklist before running a mainnet validator:

### Pre-Launch
- [ ] Read `docs/VALIDATOR_KEYS.md` in full
- [ ] Run `iona-cli keys check` — verify all outputs pass
- [ ] Run `iona-cli doctor` — validate node configuration
- [ ] Create offline encrypted backup of `data/keys.enc`
- [ ] Verify backup restoration on a separate machine before launch
- [ ] Test key rotation procedure on testnet
- [ ] Configure mTLS admin certificates (`rbac.toml`)
- [ ] Review and adjust `config.toml` rate limits and bind addresses
- [ ] Ensure `rpc.bind_addr` is NOT set to `0.0.0.0` unless behind a firewall

### Operations
- [ ] Set up Prometheus + Grafana monitoring (see `ops/monitoring-quickstart.md`)
- [ ] Enable the 14 Prometheus alert rules in `ops/alerts/prometheus_rules.yml`
- [ ] Subscribe to the validator security mailing list: security.iona.network
- [ ] Configure alerting for `iona_double_sign_attempt_total > 0`
- [ ] Configure alerting for `iona_audit_chain_broken == 1`
- [ ] Document and test your rollback procedure
- [ ] Practice disaster recovery on testnet (key loss scenario)

### Ongoing
- [ ] Apply security patches within 48 hours of announcement
- [ ] Rotate mTLS admin certificates annually
- [ ] Run `iona-cli audit verify` weekly (automate via cron)
- [ ] Review `grype sbom:sbom.json` output after each upgrade

---

**Contact**: security@example.invalid | GPG: https://iona.network/security.gpg  
**Response SLA**: Critical ≤ 24h | High ≤ 48h | Medium ≤ 1 week
