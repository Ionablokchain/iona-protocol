# Security Policy

> **Security-first by design.**  
> For the broader security engineering approach behind IONA — including secure defaults, key isolation, fuzz-driven hardening, reproducible builds, and operational safeguards — see [`docs/SECURITY_FIRST.md`](docs/SECURITY_FIRST.md).

## Overview

IONA is an open-source infrastructure project focused on deterministic execution, reproducibility, upgrade safety, and operator reliability in distributed systems.

Security is treated as a core engineering concern rather than an afterthought. This repository includes protocol, operational, and build-level controls intended to reduce the risk of unsafe upgrades, inconsistent state transitions, key exposure, and supply-chain compromise.

That said, IONA remains under active development. The repository should be evaluated as a security-conscious research and engineering project, not as a blanket claim of final production readiness.

## Reporting a Vulnerability

Please report suspected vulnerabilities **privately**.

**Do not open a public GitHub issue for unpatched security problems.**

When reporting an issue, please include as much of the following as possible:

- affected version, tag, or commit
- environment details
- clear reproduction steps
- expected versus actual behavior
- impact assessment
- logs, traces, or screenshots where relevant

If the report is valid, the project aims to:

- acknowledge receipt within 48 hours
- assess severity and scope as quickly as possible
- provide a remediation plan or fix timeline for critical issues

## Supported Versions

The following versions currently receive security attention:

| Version | Support Status |
|---------|----------------|
| v28.0.x | Supported |
| v27.1.x | Security patches only |
| v27.0.x | Security patches only |
| < v27   | Not supported |

Older versions may contain known or unknown security issues and should not be relied on for current deployments.

## Security Model

IONA approaches security across four main areas:

- **consensus safety**
- **network resilience**
- **cryptographic key protection**
- **build and release integrity**

The repository also includes upgrade-safety mechanisms intended to reduce the risk of state incompatibility, protocol-version mismatches, and partial migration failures.

## Formal Safety Properties

The project defines and tests a number of upgrade and protocol safety properties.

| Property | Description | Verified By |
|----------|-------------|-------------|
| **S1: No Split Finality** | At most one finalized block exists per height | `safety::check_no_split_finality()`, TLA+ model |
| **S2: Finality Monotonicity** | `finalized_height` never decreases | `safety::check_finality_monotonic()`, TLA+ model |
| **S3: Deterministic Protocol View** | Correct nodes agree on protocol view at a given height | `safety::check_deterministic_pv()`, TLA+ model |
| **S4: State Compatibility** | Outdated protocol rules are not applied after activation | `safety::check_state_compat()`, TLA+ model |
| **M2: Value Conservation** | Token supply remains conserved across transitions | `safety::check_value_conservation()` |
| **M3: Root Equivalence** | State root remains unchanged after format migration | `safety::check_root_equivalence()` |

Where applicable, these properties are backed by both executable tests and formal models.

References:

- `formal/upgrade.tla`
- `tests/upgrade_sim.rs`
- `docs/UPGRADE_SPEC.md`

## Threat Model

### Consensus Safety

| Threat | Mitigation | Status |
|--------|------------|--------|
| Double-signing | `DoubleSignGuard` with persistent state tracking | Implemented |
| Equivocation | `Evidence::DoubleVote` detection and slashing | Implemented |
| Nothing-at-stake behavior | Slashing for conflicting votes | Implemented |
| Long-range attack | Weak subjectivity checkpoints | Planned |

### Network Security

| Threat | Mitigation | Status |
|--------|------------|--------|
| Eclipse attack | Peer diversity buckets and inbound gating | Implemented |
| Denial of service via P2P | Per-protocol rate limits and bandwidth caps | Implemented |
| Gossipsub spam | Topic ACLs, per-topic caps, and spam scoring | Implemented |
| Sybil behavior | Peer scoring and quarantine escalation | Implemented |

### Cryptographic Security

| Threat | Mitigation | Status |
|--------|------------|--------|
| Key exposure | Encrypted keystore with authenticated encryption | Implemented |
| Weak randomness assumptions | Deterministic Ed25519-based key handling | Implemented |
| Hash collision risks | BLAKE3 (256-bit) hashing throughout core flows | Implemented |

### Build and Release Security

| Threat | Mitigation | Status |
|--------|------------|--------|
| Supply-chain drift | `Cargo.lock` and `--locked` builds | Implemented |
| Non-reproducible builds | reproducibility checks and frozen toolchain workflows | Implemented |
| CI or provenance tampering | SLSA provenance and signed release process | Implemented |
| Dependency vulnerabilities | `cargo-audit` and `cargo-deny` in CI | Implemented |

## Upgrade Security

Protocol and schema upgrades are treated as security-sensitive operations.

### Protocol Versioning

Without explicit protocol versioning, incompatible rule changes may create unsafe network divergence.

Current mitigation strategy includes:

- explicit `protocol_version` signaling in block headers
- rejection of unsupported protocol versions
- activation heights and grace windows for coordinated transitions

**Residual risk:** nodes that fail to upgrade before the defined transition window may fall off the canonical network. This is an intentional safety tradeoff.

### Schema Migrations

Storage and schema transitions introduce risks around partial writes, incompatible data layouts, and interrupted upgrade procedures.

Current mitigation strategy includes:

- atomic migration flow using temporary files and rename operations
- persisted migration progress tracking
- resumable migration steps after interruption
- backup creation before destructive steps
- forward-version compatibility guards

**Residual risk:** disk exhaustion or abrupt interruption may leave temporary files behind. Recovery procedures should remove incomplete temporary files and restart the migration process cleanly.

### Node Metadata

Incorrect or stale metadata can cause a node to start under invalid assumptions.

Current mitigation strategy includes:

- startup compatibility checks for node metadata
- atomic metadata writes to prevent partial state

## Secure Upgrade Procedure

Before upgrading a node, operators should follow a conservative process.

### 1. Verify binary integrity

```bash
sha256sum iona-node-v27.1.0
# Compare with the published hash from the release notes
