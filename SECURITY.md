# IONA Security Policy

> **Security-first by design.** For the full manifesto — secure defaults, key isolation,
> fuzz-driven hardening, and reproducible builds — see [`docs/SECURITY_FIRST.md`](docs/SECURITY_FIRST.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| v28.1.x | Yes |
| v28.0.x | Security patches only |
| v27.1.x | Security patches only |
| v27.0.x | Security patches only |
| < v27   | No |

## Reporting a Vulnerability

Please report security issues privately. **Do NOT** open a public GitHub issue.

### Contact

- **Email**: `security@iona.example.com`
- **PGP Key**: [Download](https://iona.example.com/security.asc) (Fingerprint: `ABCD 1234 ...`)
- **Signal**: `+1 234 567 8900` (by prior arrangement)

### What to include

- Version / commit hash
- Reproduction steps (minimal, if possible)
- Impact assessment (what an attacker could achieve)
- Logs or traces (sanitised)
- Any suggested fix (optional)

### Disclosure timeline

| Phase | Duration |
|-------|----------|
| Acknowledgment | 48 hours |
| Triage & impact assessment | 5 business days |
| Fix development | 7‑14 days (depending on severity) |
| Coordinated disclosure | 30 days after fix is released |

### Responsible Disclosure

We follow a responsible disclosure policy. We will not pursue legal action against
researchers who report vulnerabilities in good faith, provided they:
- Give us reasonable time to fix before public disclosure.
- Do not exploit the vulnerability for personal gain.
- Do not access or modify user data beyond what is necessary for proof‑of‑concept.

We are happy to credit reporters in the release notes (unless they prefer to remain anonymous).

### Bug Bounty

Currently, we do **not** operate a bug bounty program. This may change in the future.

---

## Formal Safety Properties (UPGRADE_SPEC.md §7)

| Property | Description | Verified By |
|----------|-------------|-------------|
| **S1: No Split Finality** | At most one finalized block per height | `safety::check_no_split_finality()`, TLA+ model |
| **S2: Finality Monotonic** | `finalized_height` never decreases | `safety::check_finality_monotonic()`, TLA+ model |
| **S3: Deterministic PV** | All correct nodes agree on PV(height) | `safety::check_deterministic_pv()`, TLA+ model |
| **S4: State Compatibility** | Old PV not applied after activation | `safety::check_state_compat()`, TLA+ model |
| **M2: Value Conservation** | Token supply conserved across transitions | `safety::check_value_conservation()` |
| **M3: Root Equivalence** | State root unchanged after format migration | `safety::check_root_equivalence()` |

See `formal/upgrade.tla` for the TLA+ model that formally verifies S1‑S4.
See `tests/upgrade_sim.rs` for executable conformance tests.

---

## Known Vulnerabilities

| ID | Description | Fixed In | Workaround |
|----|-------------|----------|------------|
| IONA‑2024‑001 | Potential panic on malformed P2P `ConsensusMsg` | v27.1.0 | Upgrade to v27.1.0+ |
| IONA‑2024‑002 | State root mismatch during schema migration v3→v4 | v27.1.0 | Run migration offline |
| IONA‑2025‑001 | RPC rate limiting bypass via malformed JSON depth | v28.0.0 | Use reverse proxy |
| IONA‑2025‑002 | Double‑sign detection race condition | v28.1.0 | Upgrade to v28.1.0+ |

For a complete list, see [`SECURITY_ADVISORIES.md`](SECURITY_ADVISORIES.md).

---

## Security Impact of v28.1.0 Update

### Protocol Versioning

**Threat**: Without protocol versioning, a hard fork could split the network if some nodes run incompatible rules.

**Mitigation**:
- Every block header now carries `protocol_version`.
- Nodes reject blocks with unsupported protocol versions.
- Activation height + grace window allow coordinated upgrades without halting.

**Residual risk**: If operators fail to upgrade before `activation_height + grace_blocks`, their nodes will be forked off. This is by design (safety over liveness for non‑upgraded nodes).

### Schema Migrations

**Threat**: Corrupted or partial migrations could leave the node in an inconsistent state.

**Mitigation**:
- Migrations are atomic (write to `.tmp` + rename).
- Each step persists progress to `schema.json` before moving to the next.
- Interrupted migrations resume from the last successful step.
- Backup files (`.bak`) created before destructive changes.
- Future‑version guard prevents running old binary on new data.

**Residual risk**: Disk full during migration could leave `.tmp` files. Recovery: delete `.tmp` files, restart.

### Node Metadata

**Threat**: Stale or missing metadata could cause a node to operate under wrong assumptions.

**Mitigation**:
- `node_meta.json` is checked at startup for compatibility.
- Atomic writes prevent partial metadata.

---

## Threat Model

### Consensus Safety

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Double‑sign | `DoubleSignGuard` with persistent state | Implemented (v24.9) |
| Equivocation evidence | `Evidence::DoubleVote` detection + slashing | Implemented (v24.9) |
| Long‑range attack | Weak subjectivity checkpoints | Planned |
| Nothing‑at‑stake | Slashing for double votes | Implemented |

### Network Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Eclipse attack | Peer diversity buckets + inbound gating | Implemented (v24.12) |
| DoS via P2P | Per‑protocol rate limits + bandwidth caps | Implemented (v24.3) |
| Gossipsub spam | Topic ACL + per‑topic caps + spam scoring | Implemented (v24.12) |
| Sybil | Peer scoring + quarantine escalation | Implemented (v24.4) |

### Cryptographic Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Key exposure | Encrypted keystore (AES‑256‑GCM + Argon2id) | Implemented (v24.5) |
| Weak randomness | Ed25519 with deterministic key derivation | Implemented |
| Hash collision | BLAKE3 (256‑bit) for all hashing | Implemented |

### Build Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Supply chain attack | `Cargo.lock` + `--locked` builds | Implemented (v27.0) |
| Non‑reproducible builds | `scripts/repro_check.sh` + frozen toolchain | Implemented (v27.0) |
| CI tampering | SLSA provenance + signed releases | Implemented (v24.10) |
| Dependency vulnerabilities | `cargo-audit` + `cargo-deny` in CI | Implemented (v24.1) |

### Runtime Security

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Memory corruption | Rust memory safety + `#![forbid(unsafe_code)]` | Implemented |
| Stack overflow | Guard pages (OS‑level) | OS‑dependent |
| ASLR bypass | Position‑independent executables | Enabled in release builds |
| Information leak | Structured logging with sanitisation | Implemented (v27.1) |

### Dependency Management

- **Automated scanning**: `cargo-audit` runs daily in CI.
- **Policy**: All direct dependencies are pinned in `Cargo.lock`.
- **Updates**: Security patches are backported to supported versions within 7 days.
- **Vendoring**: Not used; we trust crates.io with SHA‑256 verification.

---

## Secure Upgrade Procedure

1. **Verify binary integrity**:
   ```bash
   sha256sum iona-node-v28.1.0
   # Compare with published hash in release notes
   # Optionally verify GPG signature:
   gpg --verify iona-node-v28.1.0.asc iona-node-v28.1.0
