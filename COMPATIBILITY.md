# IONA Compatibility Matrix — v30.0.0

**Version**: v30.0.0  
**Last Updated**: 2026-03-05  
**Status**: Active development — LTS patch back-ported to v28.6 LTS

---

## LTS Lifecycle Policy

IONA follows a **12-month LTS support window** for designated LTS releases.

| Version | Type | Release Date | End of Security Support | Status |
|---------|------|-------------|------------------------|--------|
| v30.0.0 | Minor | 2026-03-05 | — | ✅ Active |
| v28.7.0 | Minor | 2026-03-04 | — | ✅ Active |
| **v28.6.0** | **LTS** | **2026-01-10** | **2027-01-10 (12 mo)** | ✅ **LTS Active** |
| v28.5.x | Minor | 2025-10-01 | 2026-04-01 | ⚠️ Approaching EOL |
| v27.5.x | LTS | 2025-03-01 | 2026-03-01 | ❌ EOL — upgrade now |
| v27.x   | Minor | — | 2025-12-01 | ❌ EOL |

### LTS Guarantees (12-month window)
- Critical security patches within 48 hours
- High severity patches within 7 days
- No breaking API changes within a minor series
- Database format compatibility across all patches
- `COMPATIBLE_SINCE` field in every release binary

### LTS Compatibility Declaration
```
iona-node --version
# iona-node 30.0.0 (git: abc1234, lts-compat: v28.6.0+)
```

---

## Cosmos SDK / CometBFT Compatibility

### CometBFT
| CometBFT Version | IONA v28.6 | IONA v28.7 | IONA v28.8 | Notes |
|-----------------|-----------|-----------|-----------|-------|
| 0.34.x | ❌ | ❌ | ❌ | ABCI 0.x — incompatible |
| 0.37.x | ✅ | ✅ | ✅ | ABCI 1.0, fully tested |
| 0.38.x | ✅ | ✅ | ✅ | ABCI 2.0, recommended |
| 1.0.0-rc | 🔶 | 🔶 | ✅ | ABCI 3.0 preview |

Detection: IONA checks CometBFT version at startup and refuses to start with incompatible versions:
```
FATAL: CometBFT 0.34.x detected. IONA v30.0.0 requires >= 0.37.0. Upgrade CometBFT first.
```

### Cosmos SDK
| SDK Version | IONA v28.8 | Notes |
|-------------|-----------|-------|
| v0.47.x | ✅ | Fully tested |
| v0.48.x | ✅ | Fully tested |
| v0.49.x | ✅ | Recommended |
| v0.50.x | 🔶 | Community testing |

### Tested IBC Networks (v30.0.0)
| Network | Version | Status | Notes |
|---------|---------|--------|-------|
| Cosmos Hub | v19+ | ✅ | |
| Osmosis | v24+ | ✅ | |
| dYdX | v5 | ✅ | |
| Neutron | v3+ | ✅ | |
| Stride | v16+ | ✅ | |

---

## Operating System Support

| OS | Version | Architecture | Status | Notes |
|----|---------|-------------|--------|-------|
| Ubuntu | 22.04 LTS | x86_64, ARM64 | ✅ Fully Supported | CI baseline |
| Ubuntu | 24.04 LTS | x86_64, ARM64 | ✅ Fully Supported | Recommended |
| Debian | 12 (Bookworm) | x86_64, ARM64 | ✅ Fully Supported | |
| macOS | 14 (Sonoma) | ARM64 (Apple Silicon) | ✅ Fully Supported | |
| macOS | 15 (Sequoia) | ARM64 | ✅ Fully Supported | |
| RHEL | 8, 9 | x86_64 | ✅ Supported | EPEL required |
| Alpine | 3.19+ | x86_64 | ✅ Supported | Docker images |
| Windows | WSL2 | x86_64 | 🔶 Dev only | Not production |

**glibc requirement**: >= 2.35 (Ubuntu 22.04 baseline). Alpine uses musl libc (separate build).

---

## Hardware Requirements

| Profile | CPU | RAM | Storage | Notes |
|---------|-----|-----|---------|-------|
| Testnet / dev | 2 cores | 4 GB | 100 GB SSD | Minimum |
| Mainnet full node | 4 cores | 16 GB | 1 TB NVMe | |
| **Mainnet validator** | **8+ cores** | **32 GB ECC** | **2 TB NVMe** | **Recommended** |
| Archive node | 16+ cores | 64 GB | 10 TB+ NVMe | State history |

---

## Rust Toolchain

| Component | Version | Notes |
|-----------|---------|-------|
| MSRV | 1.75.0 | Minimum supported |
| Pinned (rust-toolchain.toml) | 1.85.0 | CI baseline |
| Clippy + rustfmt | bundled | Required for contributors |

---

## RPC API Versions

| API Version | Status | Supported In | Notes |
|------------|--------|-------------|-------|
| v1 (legacy) | ❌ EOL 2025-12-01 | — | Removed |
| v2 | ✅ Active | v28.x | Stable through v28.x EOL |
| v3 | ✅ Stable | v28.6+ | Replaces v2 in v29.0 |

---

## Database Format Compatibility

| Format | Introduced | Migration | Notes |
|--------|-----------|-----------|-------|
| v2.0 | v28.0–28.2 | Auto on first start | |
| v2.1 | v28.3–28.5 | One-way, no rollback | |
| v2.2 | v28.6+ | Optional (recommended) | |
| v2.3 | v28.8 | Optional, 10% perf gain | New index format |

---

## Rolling Upgrade Paths

| From | To | Type | Downtime | Notes |
|------|----|------|----------|-------|
| v27.5 | v28.8 | Major | 30 min | Coordinated with validator set |
| v28.5 | v28.8 | Minor | < 5 min | Rolling safe |
| v28.6 LTS | v28.8 | Minor | < 5 min | Rolling safe |
| v28.7 | v28.8 | Patch | < 2 min | Rolling safe |
| v30.0.0 | v28.9.1 | Patch | 0 | Hot-reload (no restart) |

**Rolling upgrade**: stop one node → upgrade binary → restart → wait for sync → repeat for next node.  
2 versions coexist for ≤ 1 epoch. Tested in CI via `scripts/testnet/rolling_upgrade_sim.sh`.

---

## Security Patch SLA

| Severity | Acknowledgement | Patch Release | Back-port to LTS |
|----------|----------------|---------------|-----------------|
| Critical | ≤ 4 hours | ≤ 48 hours | ✅ Always |
| High | ≤ 24 hours | ≤ 7 days | ✅ Always |
| Medium | ≤ 72 hours | ≤ 30 days | ✅ Within 60 days |
| Low | ≤ 1 week | ≤ 90 days | 🔶 Best-effort |

---

## Incompatibility Detection

IONA automatically checks compatibility at startup:

```
$ iona-node --config /etc/iona/config.toml
[INFO] iona-node 30.0.0 (lts-compat: v28.6.0+)
[INFO] CometBFT 0.38.1 — compatible ✓
[INFO] Cosmos SDK v0.49.2 — compatible ✓
[INFO] Database format v2.3 — migration optional
[INFO] RPC API v3 — active; v2 deprecated (EOL: when v29.0 releases)
[WARN] Your config.toml admin.tls.listen = 0.0.0.0 — binding publicly without --unsafe-rpc-public
[FATAL] Public admin bind requires --unsafe-rpc-public flag. Refusing to start.
```
