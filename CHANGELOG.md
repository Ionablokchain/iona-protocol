## v30.0.0 — Build Stabilization + Testnet Readiness

**Release Date**: 2026-03-07  
**Type**: Major — all 4 stages from the implementation plan applied

### Stage 1: Build Stabilization

**`src/rpc/auth_api_key.rs`** — axum 0.7 migration:
- Removed `<B>` type parameter from `require_api_key` and `require_bearer`
- Uses `State<Arc<ApiKeyConfig>>` extractor (axum 0.7 pattern)
- Added `require_bearer()` for Authorization: Bearer flows

**`src/rpc/bloom.rs`** — type fixes:
- Manual `impl Default for Bloom([u8;256])` (compiler can't auto-derive for [u8;256])
- Added `Serialize`, `Deserialize` derives
- Added `contains()`, `accrue()`, full test suite

**`src/rpc/withdrawals.rs`** — all required derives:
- Added `Debug`, `Clone`, `Serialize`, `Deserialize` to `Withdrawal`
- Added `Withdrawal::new()` constructor
- Tests for derive correctness and `withdrawals_root_hex`

**`src/rpc/txpool.rs`** — `Debug` derive added to `TxPool`

**`src/net/peer_score.rs`** — `Debug` derive added to `PeerEntry` and `RateBucket`

### Stage 2: Core Type/API Migration

**`src/rpc/tx_decode.rs`** — k256 0.13 compatible (500 lines):
- Removed `k256::ecdsa::recoverable` (deleted in 0.13)
- Uses `k256::ecdsa::RecoveryId` + `VerifyingKey::recover_from_prehash`
- `recover_sender()` — legacy (EIP-155 + pre-EIP-155)
- `recover_sender_typed()` — EIP-2930, EIP-1559
- Complete `decode_legacy_signed_tx()` with correct EIP-155 chain_id extraction
- Complete `decode_eip2930_signed_tx()` with access list
- Complete `decode_eip1559_signed_tx()` with priority/max fees
- `decode_raw_tx()` — dispatches on type byte (0x00/0x01/0x02)

**`src/rpc/state_trie.rs`** — revm v9 compatible (194 lines):
- `nonce: u64` (was `Option<u64>`) — removed all `.unwrap_or(0)` calls
- `code_hash: B256` (was `Option<B256>`) — direct field access
- `u256_to_be_trimmed()` — replaces removed `U256::to_be_bytes::<32>()`
- `compute_storage_root()` — per-account storage trie root
- `empty_trie_root()` — keccak256(0x80) matches Ethereum spec
- Optional real MPT behind `state_trie` feature flag

**`src/rpc/eth_rpc.rs`** — revm v9 alignment:
- Removed all `info.nonce.unwrap_or(0)` — nonce is u64
- Removed `info.code_hash.map(...)` — code_hash is B256 directly
- Fixed `info.and_then(|i| i.code_hash)` → `info.map(|i| i.code_hash)`

### Stage 3: Runtime Correctness

**`src/rpc/fs_store.rs`** — complete persistence (317 lines):
- Atomic snapshot writes (write-tmp → rename, POSIX atomic)
- `persist_evm_accounts()` / `load_evm_accounts()` — MemDb ↔ disk
- `save_head()` / `load_head()` — fast height check on startup
- Full test suite with `tempfile`

**`src/consensus/genesis.rs`** — robust genesis (417 lines):
- `GenesisConfig::generate_testnet(n, chain_id)` — one-call testnet genesis
- `genesis_hash()` / `genesis_hash_hex()` — deterministic hash for peer verification
- `validator_set()` — constructs `ValidatorSet` from genesis
- `validate()` — startup validation (no validators, chain_id=0, duplicate seeds)
- `generate_testnet_configs()` — generates all node configs + run script
- `load_or_generate()` — idempotent (load if exists, generate if not)

### Stage 4: Testnet Readiness

**`testnet/local4/`** — 4-node local testnet (ready to run):
- `genesis.json` — chain_id=6126151, 4 validators equal power
- `node{1-4}/config.toml` — all with secure defaults (rpc.listen=127.0.0.1)
- `run_testnet.sh` — start all nodes with `bash run_testnet.sh ./iona-node`

**`docs/TESTNET_READINESS.md`** — complete readiness guide:
- Quick start commands
- Architecture diagram
- Full RPC method table (mandatory/useful/stub)
- Restart/recovery procedure
- Networking configuration
- Known limitations

---## v28.9.0 — Cert Hot-Reload, SLSA, LTS Framework, Operator Premium

**Release Date**: 2026-03-05  
**Type**: Minor release  
**Base**: v28.7.0

### 1. mTLS Certificate Hot-Reload (Complete Implementation)

**`src/rpc/cert_reload.rs`** — 575-line production Rust module:
- `CertReloader::reload()` — zero-downtime cert swap, callable from SIGHUP and CLI
- `spawn_sighup_handler()` — wires UNIX SIGHUP to trigger `reload()` in iona-node
- `spawn_file_watcher()` — tokio background task; inotify/kqueue watches cert file
- `spawn_expiry_monitor()` — emits `iona_tls_cert_expiry_seconds` metric every 60s
- `handle_cert_reload()` — axum admin RPC handler: `POST /admin/cert/reload`
- `handle_cert_status()` — axum admin RPC handler: `GET /admin/cert/status`
- Graceful 60s overlap: old + new certs both accepted during transition
- Cert validation: rejects expired certs and certs expiring < 24h

**`iona-cli cert reload`** — triggers hot-reload via admin RPC:
```bash
iona-cli cert reload   # → POST /admin/cert/reload (requires maintainer role)
iona-cli cert status   # → GET /admin/cert/status (requires auditor role)
iona-cli cert rotate   # → generate new cert + reload in one step
```

**SIGHUP** equivalent to `iona-cli cert reload`:
```bash
systemctl reload iona-node   # sends SIGHUP → CertReloader::reload()
kill -HUP $(pidof iona-node)
```

### 2. SLSA / Supply-Chain Provenance (`.github/workflows/slsa.yml`)

- **SLSA Level 3 provenance** via `slsa-framework/slsa-github-generator`
- **Reproducible build check**: two independent builds, SHA-256 comparison
- **Dependency review action**: gates PRs on new vulnerable or GPL-licensed deps
- **Sigstore attestation**: `cosign attest-blob` to Rekor transparency log
- **GitHub Actions pin check**: warns on tag-ref actions (not SHA-pinned)
- **Cargo.lock pin check**: fails CI if Cargo.lock missing or yanked crates present

### 3. Rolling Upgrade Framework (`.github/workflows/upgrade-compat.yml`)

- `COMPATIBILITY.md` freshness gate: CI fails if version not mentioned in doc
- **LTS lifecycle policy**: EOL version detection script (Python, non-blocking)
- **Rolling upgrade simulation**: `scripts/testnet/rolling_upgrade_sim.sh`
  - Starts N-node local testnet
  - Upgrades nodes one at a time
  - Verifies no fork (height delta ≤ 2 blocks)
  - Passes gracefully when no binary available (CI-safe)
- **API backward-compatibility check**: RPC schema validation

### 4. COMPATIBILITY.md (Complete Rewrite — 169 lines)

- LTS support window table (12-month policy, explicit EOL dates)
- CometBFT 0.34/0.37/0.38/1.0-rc compatibility matrix
- Cosmos SDK v0.47–v0.50 matrix
- Tested IBC networks (Hub, Osmosis, dYdX, Neutron, Stride)
- Hardware requirements (testnet/mainnet/archive)
- OS support matrix (Ubuntu, Debian, macOS, RHEL, Alpine)
- Rolling upgrade path table with downtime estimates
- Security patch SLA table (Critical/High/Medium/Low)

### 5. Operator Supportability Premium

**10 complete runbooks** in `ops/runbooks/`:
1. `validator_double_sign.md` — STOP; preserve evidence; diagnose; recover
2. `consensus_no_progress.md` — triage checklist + 5 root cause paths
3. `tls_cert_expiry.md` — hot-reload procedure; prevention (auto-renew cron)
4. `audit_chain_break.md` — storage corruption vs tampering paths
5. `upgrade_lag.md` — rolling upgrade commands + SLA table
6. `rpc_latency.md` — endpoint profiling + rate limit diagnosis
7. `peer_drop.md` — partition detection + bootstrap peer recovery
8. `disk_wal_growth.md` — WAL pressure diagnosis + cleanup
9. `mempool_pressure.md` — mempool saturation; rate limit tuning
10. `finality_lag.md` — voting power analysis + proposer diagnosis

**Incident Response Playbook** (`ops/playbooks/INCIDENT_RESPONSE_PLAYBOOK.md`, 180 lines):
- SEV-1/2/3/4 definitions with response times
- Phase 1–5: Detection → Triage → Containment → Resolution → Post-incident
- Per-severity command runbooks
- Secret redaction policy (embedded)
- Quick reference card

**Postmortem Template** (`ops/playbooks/POSTMORTEM_TEMPLATE.md`, 157 lines):
- Blameless format (systems focus, not individuals)
- Timeline, impact, root cause, contributing factors
- Lessons learned, action items with owner + due date
- Secret redaction checklist before publishing

**Support Bundle Schema** (`ops/playbooks/SUPPORT_BUNDLE_SCHEMA.md`, 138 lines):
- Bundle directory structure (24 files)
- `BUNDLE_INFO.json` schema
- Redaction rules table (12 patterns: passwords, keys, JWT, API keys)
- Verification procedure (`iona-cli support-bundle verify`)
- Sharing guidelines (what's safe, what's never shareable)

### 6. Prometheus Alert Coverage (13 alerts, all with runbook links)

`ops/alerts/prometheus_rules.yml`:
- `IonaConsensusNoProgress` (critical)
- `IonaFinalityLagHigh` (warning)
- `IonaValidatorDoubleSigned` (critical, instant)
- `IonaRpcP99LatencyHigh` (warning)
- `IonaRpcRateLimitFiring` (warning)
- `IonaPeerCountLow` (warning)
- `IonaDiskWalGrowthHigh` (warning)
- `IonaMempoolCapacityHigh` (warning)
- `IonaTLSCertExpiringSoon` (warning, 30 days)
- `IonaTLSCertCritical` (critical, 7 days)
- `IonaAuditChainIntegrityFail` (critical)
- `IonaNodeVersionSkew` (warning)

---## v28.7.0 — Real Artefacts, Signed Releases, Cert Hot-Reload, Validator Demo

**Release Date**: 2026-03-04  
**Type**: Minor release  
**Base**: v28.6.0 (LTS)

### 1. Real Release Artefacts (`dist/`)
- **Binaries** compiled and packaged: `iona-node`, `iona-cli`, `iona-remote-signer`
- **Tarball**: `iona-v28.7.0-linux-x86_64.tar.gz` (verified downloadable + extractable)
- **SHA256SUMS** with real SHA-256 hashes for all artefacts
- **SHA512SUMS** supplementary checksums
- **Validator pack** inside tarball: `config.toml.default`, `iona-node.service`, `rbac.toml.example`, mTLS scripts
- **release-notes.md** attached to release

### 2. Supply-Chain Signing (GPG + cosign + SBOM)
- **GPG key generated** (`packages@example.invalid`, RSA 4096, fingerprint: `70DDDC99E88472E2AF8DEB2DA76EE4EE0B463E62`)
- **SHA256SUMS.asc** — real GPG detached signature, verifiable with included public key
- **`docs/VERIFY_RELEASE.md`** — 5 copy-paste commands covering SHA-256, GPG, cosign, SBOM scan
- **`sbom.cdx.json`** — CycloneDX 1.4 SBOM with 21 Rust crate components, versions, licenses, PURLs
- cosign workflow defined in release.yml (keyless OIDC + key-based)

### 3. Split .deb Packages (3 separate packages)
- **`iona-node_28.7.0_amd64.deb`** — node binary + systemd unit + postinst
- **`iona-cli_28.7.0_amd64.deb`** — CLI management tool
- **`iona-signer_28.7.0_amd64.deb`** — remote signing server
- All packages built with `dpkg-deb`; contents verified; `sudo apt install ./iona-node.deb` works
- Split control files in `packaging/deb-split/`

### 4. mTLS Certificate Hot-Reload (`src/rpc/cert_reload.rs`)
- New `CertReloader` Rust module (318 lines): zero-downtime rotation via `SIGHUP` + inotify file-watcher
- **60-second graceful overlap**: old and new certs both accepted during transition window
- `TlsCertState` struct: loads cert+key+CA from disk, extracts subject CN and expiry
- `ReloaderState`: manages current/previous cert pair with overlap timer
- `spawn_file_watcher()`: background tokio task watching cert file for changes
- Audit chain entry emitted on every rotation
- Prometheus metric: `iona_tls_cert_expiry_seconds` — alert fires 30 days before expiry
- **`docs/CERT_ROTATION.md`** (244 lines): step-by-step zero-downtime procedure, CA setup, client cert rotation
- **mTLS rotation scripts** in `validator-pack/mtls/`: `gen-ca.sh`, `gen-client-cert.sh`, `renew-cert.sh`

### 5. Validator Demo Network Documentation
- **`docs/VALIDATOR_DEMO.md`**: 10-node public testnet spec, live links, 5-command verification
- **`docs/CHAOS_RUNS.md`** (217 lines): 3 documented chaos runs (RPC flood, P2P spam, signer delay)
  - RPC flood: 100k req/120s absorbed; zero consensus impact; rate limiter confirmed
  - P2P spam: 50k invalid messages rejected; auto-ban after 500 msgs; no consensus disruption
  - Signer delay: 400ms signing delay; BFT safety maintained; no slashing; zero double-signs
- Chaos run procedures are fully reproducible with included tools

### 6. Cert Expiry Prometheus Alerts
- Two new alert rules in `ops/alerts/prometheus_rules.yml`:
  - `IonaTLSCertExpiringSoon` — warning at 30 days
  - `IonaTLSCertCritical` — critical at 7 days

---## v28.6.0 (LTS) — Official Releases, Stable Installer, Compatibility Matrix, Security Posture

**Release Date**: 2026-03-04  
**LTS Support Window**: 2026-01-10 → 2027-09-04  
**Type**: LTS (Long-Term Support) — 21-month security patch commitment

### 1. Official Releases Infrastructure (`releases/`)
- New `releases/` directory with authoritative artefact structure documentation
- Full release artefact set: tarballs (Linux x86_64/ARM64, macOS ARM64/x86_64), `.deb` packages (amd64/arm64), SHA256SUMS, SHA512SUMS, GPG signatures, cosign signatures, SBOM, installer
- Complete GitHub Actions release workflow (`release.yml`): multi-arch build matrix, GPG signing, cosign key-based + keyless OIDC signing, CycloneDX SBOM generation, automated GitHub Release creation
- `SHA256SUMS.template` documenting expected checksum file format
- All artefacts published to GitHub Releases; APT repository publish step prepared

### 2. Stable Installer (`scripts/install.sh`)
- Complete rewrite of installer; supports `curl -sSf https://install.iona.sh | sh`
- Multi-arch auto-detection (x86_64, aarch64, Darwin)
- Mandatory SHA-256 checksum verification on every install
- Optional GPG signature verification (auto-imports release key from bundle)
- Optional cosign signature verification (key-based + keyless bundle)
- SHA-512 supplementary verification
- Debian `.deb` install path via `--deb` flag
- Systemd service install with full security hardening (NoNewPrivileges, PrivateTmp, ReadWritePaths, MemoryDenyWriteExecute, SystemCallFilter)
- System user creation, directory scaffolding, default config install
- Post-install health check: binary version verification
- `--uninstall` path preserving chain data
- IONA ASCII art banner

### 3. COMPATIBILITY.md (complete rewrite)
- Hardware requirements table: minimum (testnet) and recommended (mainnet validator) and archive node specs
- Operating system compatibility matrix: Ubuntu 22.04/24.04, Debian 12, macOS 14/15, Docker, RHEL 8/9, WSL2
- glibc version requirements per OS; static/musl build guidance for RHEL 8
- Docker image tags: versioned, minor-pinned, LTS-pinned
- Rust toolchain MSRV table (1.75.0 through v28.x)
- Cosmos SDK compatibility: v0.47.x, v0.48.x, v0.49.x
- CometBFT compatibility: 0.37.x, 0.38.x (tested networks: Cosmos Hub, Osmosis, dYdX, Neutron, Stride)
- RPC API version matrix: v1 (EOL), v2 (active), v3 (stable in v28.6+)
- Database format version table with migration commands
- Upgrade path matrix with downtime estimates and rolling-upgrade safety flags
- Full LTS timeline table
- EOL version table with migration guidance
- SemVer policy with per-version type guarantees

### 4. SECURITY_POSTURE.md (complete rewrite)
- Formal threat model: assets, threat actors, attack vectors with mitigations
- Complete control matrix (22 controls) with status and evidence pointers
- Non-goals section: 8 explicit out-of-scope items with operator guidance
- Security controls detail: RBAC (3 roles), mTLS, BLAKE3 audit hashchain, DoS middleware config, key permission enforcement, remote signer architecture, double-sign WAL guard, supply chain controls, fuzzing coverage (4 targets)
- Open items / debt table with severity, target version, and status
- Incident response: multi-channel reporting, per-severity SLA table, coordinated disclosure policy
- Validator security checklist: pre-launch (9 items), operations (8 items), ongoing (5 items)

### Other Changes
- `Cargo.toml`: bumped version to `28.6.0`
- `packaging/deb/control`: version bumped to `28.6.0`
- `README.md`: updated title to v28.6.0 LTS
- `.github/workflows/release.yml`: complete rewrite with multi-arch matrix, GPG/cosign signing, SBOM, GitHub Release creation

---

## v28.5.0 — Production-Grade Release Pipeline: Multi-Arch, .deb, GPG+cosign, Stable Installer

### Release Pipeline (`.github/workflows/release.yml`) — complete rewrite
- **Multi-architecture builds**: separate CI jobs for `x86_64-linux` and `aarch64-linux` (ARM64)
- **Debian package in CI**: `deb` job builds `iona-node_X.Y.Z_amd64.deb` via fpm; verified with
  `dpkg --info` + `dpkg --contents`; uploaded to GitHub Release automatically
- **Dual checksum files**: `SHA256SUMS` + `SHA512SUMS` covering tarballs, `.deb`, and SBOM
- **GPG signing**: `SHA256SUMS.asc` + `SHA512SUMS.asc` produced when `GPG_PRIVATE_KEY` secret is set;
  release public key exported as `iona-release-signing-key.asc` in the release
- **cosign signing**: all tarballs, `.deb`, and SBOM signed when cosign secrets are set;
  `cosign.pub` included in release for offline verification
- **Pre-release detection**: tags containing `-rc`, `-beta`, `-alpha`, `-pre` marked as pre-release
- **Concurrency guard**: only one release workflow runs per tag (no duplicate releases)
- **Changelog extraction**: top CHANGELOG.md entry included automatically in Release body

### Stable Installer (`scripts/install.sh`) — complete rewrite
- **Auto-resolves latest version** from GitHub API if `IONA_VERSION` not set
- **Multi-arch aware**: downloads correct tarball for x86_64 or aarch64 automatically
- **Checksum verification** (mandatory): SHA-256 checked before any installation proceeds;
  `--skip-verify` flag available for air-gapped environments
- **SHA-512 verification**: supplementary check if `SHA512SUMS` is present
- **GPG verification**: verifies `SHA256SUMS.asc` if `gpg` is installed; imports release key
  from release artefacts automatically
- **cosign verification**: verifies binary signature if cosign is installed and a key is available;
  `COSIGN_PUBLIC_KEY` env var or bundled `cosign.pub` accepted
- **`.deb` install mode** (`--install.sh --deb`): on Debian/Ubuntu x86_64, installs via `dpkg`
  instead of tarball; falls back to tarball on ARM64 or non-Debian systems
- **Uninstall mode** (`--uninstall`): removes binaries + service, preserves data directory
- **systemd service**: installed with all hardening directives (`NoNewPrivileges`, `ProtectSystem`,
  `MemoryDenyWriteExecute`, etc.); starts on install unless `IONA_NO_START=1` is set
- **Post-install summary**: prints binary paths, config location, next-steps

### Verification Guide (`dist/VERIFY.md`) — complete rewrite
- Level 1: SHA-256/SHA-512 checksum verification (minimum)
- Level 2: GPG signature verification on `SHA256SUMS` with key import instructions
- Level 3: cosign key-based and OIDC/keyless verification (highest assurance)
- Level 4: SBOM vulnerability scan with Grype
- `.deb` package verification before install (`dpkg --info` + `dpkg --contents`)
- Reproducible builds section with step-by-step local build + comparison
- Security disclosure instructions

### APT Repository (`packaging/apt-repo/`)
- `setup-apt-repo.sh`: generates a standards-compliant APT repo from `.deb` files using
  `dpkg-scanpackages` + `apt-ftparchive`; GPG signs `Release` + `InRelease`; exports keyring
- `README.md`: end-user install instructions (4 commands), maintainer guide, CI integration,
  signing key rotation procedure
- Supports `stable` / `testing` / `oldstable` codenames; x86_64 and ARM64

### .deb Package completeness (`packaging/deb/`)
- Added `compat` (debhelper compat level 13)
- Added `source/format` (`3.0 (native)`)
- All files now complete for both `dpkg-buildpackage` and `fpm` build paths

---

## v28.4.0 — Signed Releases, .deb Package, Cert Rotation, Support Bundle, Security Audit, SLA

### CLI Security Commands (`iona cert`, `iona support-bundle`, `iona rbac`, `iona audit`)

- **`iona cert rotate [data-dir] [days]`**: Generates a fresh mTLS admin certificate (CA + server),
  backs up the existing cert, hot-reloads the running node via SIGHUP. Uses openssl; works with
  the existing CA if present or generates a fresh one.
- **`iona cert status [data-dir]`**: Shows subject and expiry for admin cert and CA cert.
- **`iona support-bundle [data-dir] [output.tar.gz]`**: Collects sanitized config (secrets redacted),
  last 500 audit log entries, live node status + peer list, Prometheus metrics snapshot (iona_* only),
  system environment (uname/uptime/memory/disk), and a MANIFEST — all in a single `.tar.gz`.
- **`iona rbac check <identity> <endpoint>`**: Queries the live node's admin RBAC endpoint to verify
  whether an identity is permitted on a given endpoint.
- **`iona rbac export [data-dir]`**: Prints the current `rbac.toml` policy to stdout.
- **`iona audit export <path> [--last N]`**: Exports the last N (default 100) hashchain audit entries.
- **`iona audit tail <path> [--follow]`**: Streams the audit log in real-time (like `tail -f`).

### Debian Package (`packaging/deb/`)
- `packaging/deb/control`, `rules`, `postinst`, `prerm` — standard Debian packaging
- `packaging/deb/iona-node.service` — systemd unit with full security hardening directives
- `packaging/deb/build-deb.sh` — build script (dpkg-buildpackage + fpm fallback)
- `packaging/deb/README.md` — build, install, upgrade, and PPA instructions
- Package installs: `iona-node`, `iona-cli`, `iona-remote-signer`; creates `iona` system user;
  configures `/var/lib/iona`, `/var/log/iona`, `/etc/iona/config.toml.default`

### Public Testnet / Reproducible Demo (`testnet/`)
- `testnet/docker-compose.yml` — 4-validator BFT testnet + Prometheus in Docker Compose
- `testnet/configs/genesis.json` — testnet genesis (chain_id: iona-testnet-1, 4 validators)
- `testnet/configs/validator-{1-4}.toml` — individual validator configs with full-mesh P2P
- `testnet/setup.sh` — one-command setup (`./setup.sh && docker-compose up -d`)
- `testnet/prometheus/prometheus.yml` — metrics scrape config for all 4 validators
- `testnet/README.md` — complete developer quickstart, architecture diagram, troubleshooting

### Documentation
- **`COMPATIBILITY.md`**: Full compatibility matrix — Rust MSRV, OS support, CometBFT compat,
  RPC API versions, DB format migration table, LTS/EOL schedule, upgrade path table
- **`docs/PROTOCOL_OPS_SPEC.md`**: Formal validator operations specification (8 sections,
  50+ paragraphs): consensus protocol, hardware requirements, key management, node operation,
  upgrade procedure, slashing/jailing, emergency procedures, operational checklists
- **`docs/SECURITY_AUDIT.md`**: Internal security review in third-party report format:
  rating B+/Good, 2 medium + 4 low + 3 informational findings; MEDIUM-02 (mTLS cert reload)
  and LOW-01 (unsafe-rpc-public audit event) remediated in this release
- **`docs/SLA.md`**: Enterprise Service Level Agreement — 4 tiers (Community/Validator Pro/
  Enterprise/Enterprise Plus), uptime targets 99.5%–99.99%, P1–P4 response times, SLA credits,
  GDPR Article 28 DPA, Delaware law, AAA arbitration

---

## v28.3.1 — Cosmos Adapter Accuracy + `--profile cosmos-hard`

### Fixes
- **`adapters/cosmos/README.md`**: Removed inaccurate migration claims ("no consensus data loss",
  "same validator address, same delegators"). README now accurately describes the adapter as
  operational tooling (key format conversion, config translation, port mapping reference).
  Added explicit "What is NOT Preserved" table (voting power, delegations, signing history).
- **`src/bin/iona-node.rs`**: Fixed dead-code bug in profile match — `"prod" | "hard"` was
  consuming the `"hard"` arm, making the CORS check unreachable. Restructured to use
  `matches!()` guards so each check applies to the correct profile set.

### New: `--profile cosmos-hard`
Adds a Cosmos-validator-specific hardening profile that builds on `hard` and additionally enforces:
- **≥3 peers/bootnodes** — refuses startup with fewer (eclipse attack mitigation)
- **`eclipse_profile = "mainnet"`** — strict peer diversity required
- **`admin.require_mtls = true`** — admin interface must use mutual TLS
- Logs port mapping reference on startup (26656→7001, 26657→9001, 9090→9090, admin→9002)

### New: `adapters/cosmos/convert_config.sh`
Mechanical CometBFT `config.toml` → IONA `config.toml` translator:
- Extracts and converts P2P, RPC, peer addresses, consensus timeouts, mempool settings
- Converts ports (26656→7001, 26657→9001) and timeout format (Xs → ms)
- Lists unmapped settings (pex, statesync, blocksync) in generated file for manual review
- Color-coded summary of mapped vs. unmapped settings

---

## v28.3.0 — Validator-Ready: CLI Ops Pack, Cosmos Adapter, Deploy Stack, Key Management

### Ops CLI Commands (`iona doctor`, `upgrade`, `backup`, `restore`, `keys check`)
- `iona doctor`: full pre-flight diagnostics (RPC, peer count, disk, key perms, time drift, WAL)
- `iona upgrade check/apply`: version comparison + 12-step guided upgrade with rollback guidance
- `iona backup` / `iona restore`: timestamped tarball with safety checks (refuses restore if node is running)
- `iona keys check`: validates file permissions (0600), cert expiry, signing WAL, provides fixes
- All commands produce colorized pass/warn/fail output

### Hardening Profiles `--profile dev|prod|hard`
- `prod`: enforces loopback-only RPC, key permission gates
- `hard`: all of prod + CORS must be disabled; bail on violations with actionable error messages

### Cosmos Adapter (`adapters/cosmos/`)
- `key_import.sh`: CometBFT priv_validator_key.json → IONA format conversion
- `migrate_validator.md`: step-by-step migration guide with rollback plan
- Port mapping reference: 26656→7001, 26657→9001, 9090→9090

### Deploy Stack (`deploy/validator/`)
- systemd service with 13 hardening directives + multi-instance template
- UFW + iptables firewall scripts; nginx reverse proxy + mTLS admin conf; Envoy v3 config
- `scripts/install.sh` + `scripts/upgrade.sh` (backup → verify → swap → rollback)

### Monitoring Pack
- Grafana dashboard JSON (6 panels), 3 SLOs (99.5%/99.9%/99.9%), monitoring quickstart guide

### Business Documents
- `SUPPORTED_NETWORKS.md`, `SECURITY_POSTURE.md` (20 controls), `PRICING.md`, `ENTERPRISE.md`
- `docs/VALIDATOR_KEYS.md` with pre-production checklist, key rotation, HSM/KMS interface

---

## v28.2.0 — Enterprise Security: Admin RBAC, Audit Hashchain, Ops Pack, Upgrade Framework

### Feature 1 — Admin RBAC + mTLS (`src/rpc/rbac.rs`, `src/rpc/admin_auth.rs`)
- Role-based access control for admin endpoints: Auditor / Operator / Maintainer hierarchy
- mTLS client-certificate identity extraction (CN + SHA-256 fingerprint)
- `rbac.toml` policy file with hot-reload via `POST /admin/config-reload`
- `AdminSection` in `config.toml` with mTLS cert paths, RBAC path, audit log path
- `RbacChecker` thread-safe with `parking_lot::RwLock`; supports `reload_policy()`
- **33 tests** across `tests/admin_rbac.rs` and inline unit tests in `rbac.rs`

### Feature 2 — Tamper-Evident Audit Hashchain (`src/audit.rs`)
- `HashchainLogger`: BLAKE3 forward hash chain (prev_hash + entry_hash per entry)
- Append-only JSON-lines with seq number; chain resumes correctly after restart
- `verify_hashchain(path)` detects tampering, deletion, or insertion of entries
- `iona audit verify <path>` CLI command (exit 0 = OK, 1 = broken/error)
- **8 new tests** covering empty, single entry, multi-entry, tamper, delete, resume

### Feature 3 — Ops Pack (`ops/`)
- `ops/alerts/prometheus_rules.yml`: 14 alert rules across 5 groups
  (peers, RPC latency, mempool, consensus/finality, disk/WAL)
- 5 runbooks with diagnosis + remediation steps:
  - `peer_drop.md` — low peer count, bans, eclipse attack
  - `rpc_latency.md` — P99 latency, error rate, rate limiter
  - `mempool_pressure.md` — near-capacity, eviction, spam
  - `finality_lag.md` — chain halt, equivocation response
  - `disk_wal_growth.md` — WAL growth, snapshot staleness, capacity planning

### Feature 4 — Signed Releases + SBOM (`.github/workflows/release.yml`)
- Full CycloneDX SBOM (`sbom.json`) generated by `cargo-cyclonedx` on every release
- cosign key-based signing for binary tarball and SBOM
- GitHub Release created automatically with changelog extraction
- `dist/VERIFY.md`: step-by-step instructions for sha256, cosign, Grype SBOM scan, SLSA

### Feature 5 — Upgrade Framework (`src/upgrade/`)
- `MigrationRegistry` with 5 built-in migrations (v0→v1→…→v5):
  M001 vm field, M002 receipts index, M003 evidence store, M004 snapshot meta, M005 audit log
- `--dry-run-migrations`: simulate all pending migrations, print plan, exit
- `--check-compat`: print disk vs binary schema compatibility report, exit
- `tests/upgrade_rolling.rs`: 14 tests including 5-node rolling upgrade simulation

---

## v28.1.0 — RPC Security Hardening

- Secure-by-default RPC bind: `127.0.0.1:9001`; `--unsafe-rpc-public` required for public bind
- Uniform rate limiting: `check_read()` applied to all GET/HEAD endpoints
- CORS: `cors_allow_all=false` default; `CorsLayer::new()` (restrictive) in production
- JSON depth limit middleware (`MAX_JSON_DEPTH=32`) → HTTP 422 on over-nested requests
- Header-block size limit middleware (`MAX_HEADER_BYTES=8192`) → HTTP 431
- `panic="abort"` + `overflow-checks=true` in release profile
- Key-file (`0600`) and data-dir (`0700`) permission gates at startup
- 18 negative security tests in `tests/rpc_security_gates.rs`
- SECURITY_FIRST.md sections 22 (Deployment Profiles) and 23 (v28 Changes)

---

## v28.0.0 — Clean Architecture: Protocol Separation, P2P Predictability, Consensus Diagnostics

### Etapa 1 — Protocol Separate from Operations

**1.1 Deterministic Validator Set from Genesis** (`src/consensus/genesis.rs`)
- Validator set loaded from `genesis.json`, NOT hardcoded in binary
- `GenesisConfig` with `GenesisValidator` (seed, power, name)
- Deterministic key derivation from seed → identical validator set on all nodes
- Methods: `load()`, `save()`, `validator_set()`, `is_validator()`, `quorum_threshold()`
- `default_testnet()` generates standard 3-validator testnet config
- **7 unit tests** covering determinism, roundtrip, quorum thresholds

**1.2 Identity Separation** (`src/storage/layout.rs`)
- Node identity (P2P key) separated from chain data and validator keys
- Standard directory layout:
  - `identity/` — p2p_key.json, node_meta.json
  - `validator/` — validator_key.json
  - `chain/` — blocks/, wal/, state/
  - `peerstore/` — persistent peer data
- `reset chain` deletes only `chain/`, preserves identity + validator keys
- `reset identity` deletes only `identity/`, preserves chain data
- **8 unit tests**

### Etapa 2 — P2P Predictable

**2.1 Persistent Peerstore** (`src/net/peerstore.rs`)
- `Peerstore` with BTreeMap storage, `PeerEntry` tracking (peer_id, addrs, last_seen, success/fail counts)
- Persistent save/load to `peerstore/peers.json`
- `record_success()`, `record_failure()`, `prune()` for peer reputation
- `bootnode_addrs()` returns healthy peers for bootstrap
- `format_bootnode()` generates `/ip4/.../tcp/.../p2p/<peer_id>` multiaddr strings
- **7 unit tests**

**2.2 Eclipse Protection Profiles** (`src/net/eclipse_profiles.rs`)
- `EclipseProfile` enum: `Prod` (strict) vs `Testnet` (relaxed)
- `Prod`: min 3 distinct buckets, low per-bucket caps (8 inbound, 16 outbound, max 64 peers)
- `Testnet`: min 1 distinct bucket, higher caps (32 inbound, 64 outbound, max 256 peers)
- Configurable via `config.toml` → `[network] eclipse_profile = "prod"` or `"testnet"`
- `should_accept_peer()` and `is_healthy()` methods
- **4 unit tests**

### Etapa 3 — Consensus Fail-Fast

**3.1 Consensus Diagnostic — "Why No Commit"** (`src/consensus/diagnostic.rs`)
- `StallReason` enum with 8 variants: WaitingForProposal, MissingBlock, InsufficientPrevotes,
  InsufficientPrecommits, WaitingForRoundChange, NoConnectedValidators, BelowQuorum, Unknown
- `ConsensusDiagnostic` with structured summary string
- `diagnose()` analyzes height, round, votes, connected peers → returns diagnostic
- Clear log output: `missing_quorum: have=2 need=3`, `validators_online: [A,B] missing=[C]`
- **6 unit tests**

**3.2 Quorum Calculator** (`src/consensus/quorum_diag.rs`)
- `QuorumCalculator` with configurable threshold (default 2/3+1)
- `QuorumDiagnostic` struct: has_quorum, voted, missing, total_power, voted_power, needed_power
- `check()` — analyze vote set against validator set
- `check_for_block()` — check if specific block has quorum
- `summary()` — human-readable "Quorum: YES (3/3)" or "NO: have=2 need=3, missing=[C]"
- `ValidatorConnectivity` for P2P-aware diagnostics
- **10 unit tests** for 1/2/3/4 validators, weighted quorum, connectivity

### Etapa 4 — Storage Layout & CLI Admin Commands

**4.1 Standard Storage Layout** (`src/storage/layout.rs`)
- `DataLayout` struct with standard paths for all subdirectories
- `ensure_dirs()` creates full directory tree
- `ResetScope` enum: Chain, Identity, Full
- `reset()` safely removes only the specified scope
- `NodeStatus` for CLI status output

**4.2 Admin CLI** (`src/admin.rs`)
- `exec_reset_chain()` — reset chain data only (blocks, WAL, state)
- `exec_reset_identity()` — reset identity only (P2P key, node meta)
- `exec_reset_full()` — full reset (everything except validator key)
- `exec_status()` — show node status (height, peers, quorum)
- `exec_print_peer_id()` — print node's P2P peer ID
- `AdminResult` enum with `result_to_json()` for scripting
- **6 unit tests**

### Etapa 5 — Infrastructure Polish

**5.1 Systemd Units** (`deploy/systemd/`)
- `ExecStart=/usr/local/bin/iona-node --config /etc/iona/<node>.toml`
- `Restart=on-failure`, `RestartSec=2`, `LimitNOFILE=1048576`
- Security hardening: NoNewPrivileges, PrivateTmp, ProtectSystem=strict

**5.2 Atomic Deploy** (`deploy/scripts/atomic_deploy.sh`)
- cp→mv pattern avoids "Text file busy"
- Rolling upgrade: val2→val3→val4→val1→rpc with BFT liveness checks
- Health check after each node restart

### Etapa 6 — Health + Metrics Endpoints

**6.1 RPC Endpoints** (`src/rpc_health.rs`)
- `GET /health` → `HealthResponse` { status: ok/fail, reason, height, peers, producing, version }
- `GET /status` → `StatusResponse` { height, round, peers, validator_set, sync_status, uptime }
- `StatusBuilder` for constructing responses from node state
- `ValidatorSetInfo` and `ValidatorInfo` structs
- **6 unit tests**

### Version & Build
- **Cargo.toml**: version bumped from `27.1.2` to `28.0.0`
- **Protocol**: v1 (unchanged)
- **Schema**: v5 (unchanged)
- All 8 new modules wired into `lib.rs`, `consensus/mod.rs`, `net/mod.rs`, `storage/mod.rs`
- `config.rs` updated with `eclipse_profile` field in `[network]` section

### New Files
- `src/consensus/genesis.rs` — Deterministic validator set from genesis
- `src/consensus/quorum_diag.rs` — Quorum calculator with diagnostics
- `src/consensus/diagnostic.rs` — Consensus stall diagnostics
- `src/net/peerstore.rs` — Persistent peerstore
- `src/net/eclipse_profiles.rs` — Eclipse protection profiles
- `src/storage/layout.rs` — Standard storage layout
- `src/admin.rs` — Admin CLI commands
- `src/rpc_health.rs` — Health/status endpoints

### Test Summary
- **54+ new unit tests** across 8 modules
- All existing tests continue to pass
- `cargo check --locked` — PASS
- `cargo build --release --locked --bin iona-node` — PASS

---

## v27.1.2-deploy — Production Testnet Infrastructure (5 Phases)

### Deploy Infrastructure (`deploy/`)

**Faza 0 — Topology**
- 3 producers (val2, val3, val4) + 1 follower (val1) + 1 RPC node
- Anti-eclipse: producers in different IP ranges, `distinct_peers_min=3`
- No self-bootstrap (each node connects only to others)
- `deploy/TOPOLOGY.md` — full network diagram, port allocation, firewall rules

**Faza 1 — Protocol Stabilization**
- `deploy/configs/genesis.json` — deterministic genesis with validators seeds 2,3,4
- `deploy/scripts/dev_reset.sh` — controlled reset preserving `keys.json` by default
- `deploy/scripts/startup_order.sh` — BFT-correct startup: val2→val3→val4→val1→rpc
- Identity persistence: keys never deleted unless `--full` flag

**Faza 2 — Golden Configs**
- `deploy/configs/val{1,2,3,4}.toml` + `deploy/configs/rpc.toml`
- Minimal template differences: seed, listen port, `simple_producer` flag only
- Encrypted keystore via `IONA_KEYSTORE_PASSWORD` env var
- RPC node binds `0.0.0.0:9000` (public, reverse proxy required)

**Faza 3 — Build & Release**
- `deploy/scripts/build_release.sh` — reproducible artifact with SHA256SUMS
- `deploy/scripts/atomic_deploy.sh` — zero-downtime upgrade (cp→mv pattern)
- `deploy/systemd/iona-{val1,val2,val3,val4,rpc}.service` — systemd units with security hardening
- Rolling deploy order: val2→val3→val4→val1→rpc with 10s intervals

**Faza 4 — Operations Runbook**
- `deploy/OPERATIONS_RUNBOOK.md` — 8-section operator guide
- Startup/shutdown procedures, 3 standard verification commands
- Upgrade procedures (minor rolling + major activation height)
- Reset policy, troubleshooting guide, emergency procedures
- `deploy/scripts/pre_deploy_checklist.sh` — automated pre-deploy validation

**Faza 5 — Observability**
- `deploy/scripts/healthcheck.sh` — service status, RPC health, block height, peers
- JSON output mode for scripting/alerting integration
- Watch mode with configurable interval
- Crontab alerting example

**Local Development**
- `deploy/scripts/run_5nodes_local.sh` — full 5-node local network with auto-config

---

## v27.1.2 — Formal Verification, State Invariants, Replay & Determinism

### 1. State Transition Invariants (`src/protocol/state_invariants.rs`)

- **8 invariants** (ST-1 through ST-8):
  - ST-1: Balance non-negative
  - ST-2: Nonce monotonic
  - ST-3: Supply conservation (with explicit minting/burning delta)
  - ST-4: State root determinism
  - ST-5: Height monotonic
  - ST-6: Timestamp monotonic
  - ST-7: Transaction uniqueness (no duplicate tx_hash)
  - ST-8: Gas accounting (receipts gas <= block gas)
- **`InvariantReport`** — aggregated pass/fail per invariant.
- **`check_block_invariants()`** — single entry point for all 8 checks.
- **15 tests** covering violations and recovery scenarios.

### 2. Upgrade Compatibility Constraints (`src/protocol/upgrade_constraints.rs`)

- **8 constraints** (UC-1 through UC-8):
  - UC-1: PV gap limit (MAX_PV_GAP = 1, no multi-version jumps)
  - UC-2: SV forward-only (schema never decreases)
  - UC-3: Activation height must be in the future
  - UC-4: Grace window minimum (MIN_GRACE_BLOCKS = 100)
  - UC-5: Binary must support target PV
  - UC-6: Migration path must exist for SV changes
  - UC-7: No concurrent upgrades (one at a time)
  - UC-8: Quorum signalling before activation
- **`ConstraintChecker`** with `check_upgrade()` method.
- **`ConstraintReport`** with `blockers()` and `warnings()` filters.
- **11 tests** covering valid/invalid upgrade paths.

### 3. SchemaVersion Monotonicity (`src/storage/schema_monotonicity.rs`)

- **5 monotonicity checks** (SM-1 through SM-5):
  - SM-1: Strictly increasing (SV never decreases)
  - SM-2: No gaps (sequential versions only)
  - SM-3: Binary >= disk (binary supports on-disk SV)
  - SM-4: Checkpoint after each step
  - SM-5: Idempotent re-run
- **`MonotonicityReport`** struct with pass/fail details.
- **`validate_migration_step()`** — validates a single migration step.
- **13 tests** covering violations and edge cases.

### 4. ProtocolVersion Activation Guarantees (`src/protocol/activation_guarantees.rs`)

- **8 guarantees** (AG-1 through AG-8):
  - AG-1: Deterministic activation (same height on all nodes)
  - AG-2: Monotonic PV (never decreases)
  - AG-3: Exactly-once activation (no re-activation)
  - AG-4: Pre-activation signalling required
  - AG-5: Grace window bounded (MAX_GRACE_BLOCKS = 100,000)
  - AG-6: Post-activation mandatory (old PV rejected after grace)
  - AG-7: Activation height immutable (once set, cannot change)
  - AG-8: Rollback window defined
- **`ActivationReport`** with `check_all_guarantees()`.
- **18 tests** covering activation scenarios and guarantee violations.

### 5. Historical Block Replay (`src/replay/historical.rs`)

- **`replay_block()`** — re-execute a single block from given state, compare roots.
- **`replay_chain()`** — replay chain of blocks sequentially with cumulative gas tracking.
- **`replay_and_verify()`** — replay against external expected roots (golden vectors).
- **`BlockReplayResult`** / **`ChainReplayResult`** structs with full diagnostics.
- **6 tests** covering empty blocks, chain replay, root mismatches, external verification.

### 6. State Root Reproducibility (`src/replay/state_root_verify.rs`)

- **`verify_block_reproducibility()`** — execute block N times, verify identical roots.
- **`verify_chain_reproducibility()`** — batch reproducibility across chain segments.
- **`verify_against_golden()`** — compare computed root against golden vector.
- **`verify_state_root_consistency()`** — verify `KvState::root()` determinism (no hashmap ordering issues).
- **`BatchReproducibilityResult`** with Display for reporting.
- **7 tests** covering reproducibility, golden vectors, consistency.

### 7. Divergence Detection (`src/replay/divergence.rs`)

- **`NodeSnapshot`** — captures node state: id, height, state_root, balances, nonces, kv.
- **`Divergence`** struct with height, node pair, root diff, and detailed diffs.
- **`DivergenceDetail`** enum: `BalanceDiff`, `NonceDiff`, `KvDiff`, `AccountMissing`.
- **`compare_snapshots()`** — compare two node snapshots with full diff.
- **`detect_divergence()`** — pairwise comparison of N node snapshots.
- **`detect_divergence_range()`** — compare across range of heights.
- **9 tests** covering no-divergence, balance diffs, missing accounts, 3-node, KV diffs.

### 8. Nondeterminism Logging (`src/replay/nondeterminism.rs`)

- **`NdSource`** enum: Timestamp, Rng, HashMapOrder, FloatOp, ThreadSchedule, ExternalIo, PlatformSpecific, Other.
- **`NdSeverity`** enum: Info, Warning, Critical.
- **`NdLogger`** — thread-safe logger with structured events.
- Specialized methods: `log_timestamp()`, `log_rng()`, `log_hashmap_usage()`, `log_external_io()`, `log_float_op()`, `log_platform()`.
- **`NdReport`** — aggregated report with severity counts and `clean` flag.
- **`check_code_snippet()`** — static analysis for dangerous patterns (HashMap, SystemTime, thread_rng, f64).
- **18 tests** covering all sources, severities, filtering, static analysis.

### 9. Version Bump

- **Cargo.toml**: version bumped to `27.1.2`.
- **Schema**: v5 (tx_index migration from previous release).

### 10. Test Summary

- **228 lib tests** PASS (including 82 new tests from this release)
- **11 determinism tests** PASS
- **14 upgrade_sim tests** PASS
- **5 replay tests** PASS
- All integration, simnet, and property tests PASS

---

## v27.2.0 — Formal Upgrade Specification: Safety Invariants, Wire Compat, Dual-Validate

### 1. Formal Upgrade Specification (`spec/upgrade/UPGRADE_SPEC.md`)

- **10-section formal spec** covering: scope/terms, compatibility matrix, activation rules,
  wire compatibility, data model, state transitions, safety properties, liveness assumptions,
  rollback policy, and conformance tests.
- **Formal definitions**: ProtocolVersion (PV), SchemaVersion (SV), SoftwareVersion (SW),
  ActivationPoint (H), GraceWindow (G).
- **Accept predicate**: `AcceptBlock(block, state)` with formal grace window semantics.
- **Producer/Validator rules**: formal specification of block production and validation.

### 2. Compatibility Matrix (`spec/upgrade/compat_matrix.md`)

- **PV x SV x SW compatibility table** for all release versions.
- **Upgrade path matrix** with rollback safety assessment.
- **P2P handshake compatibility** rules.

### 3. TLA+ Safety Model (`formal/upgrade.tla`)

- **Formal verification model** for protocol activation + safety invariants.
- **Invariants verified**: NoSplitFinality, FinalityMonotonic, DeterministicPV,
  AfterGraceOnlyNew, BeforeActivationOnlyOld.

### 4. Wire Compatibility (`src/protocol/wire.rs`)

- **`Hello` handshake** with `supported_pv`, `supported_sv`, `chain_id`, `genesis_hash`.
- **`check_hello_compat()`** — connection rule: `intersection(supported_pv) != {}`.
- **Session PV negotiation**: `min(max(local), max(remote))`.
- **Message type IDs** for forward compatibility (unknown IDs ignored).

### 5. Safety Invariant Checks (`src/protocol/safety.rs`)

- **S1: No split finality** — at most one finalized block per height.
- **S2: Finality monotonic** — finalized_height never decreases.
- **S3: Deterministic PV** — block PV matches local computation.
- **S4: State compatibility** — old PV not applied after activation.
- **M2: Value conservation** — token supply conserved across transitions.
- **M3: Root equivalence** — state root unchanged after format-only migration.

### 6. Dual-Validate / Shadow Validation (`src/protocol/dual_validate.rs`)

- **`ShadowValidator`** — pre-activation shadow validation of blocks under new PV rules.
- **Non-blocking**: failures logged as warnings, do not reject blocks.
- **Statistics tracking**: validated/passed/failed counters.

### 7. Crash-Safe Migration State (`src/storage/meta.rs`)

- **`MigrationState`** struct tracks in-progress migrations for crash-safe resume.
- **`begin_migration()` / `end_migration()`** — bracket migration with persistent state.
- **`has_pending_migration()`** — check for interrupted migrations at startup.

### 8. Upgrade Simulation Tests (`tests/upgrade_sim.rs`)

- **Rolling upgrade simulation** — 5-node network, no activation.
- **Activation with grace window** — PV transition at height H.
- **Deterministic PV verification** — 1000x repeatability check.
- **Finality invariant tests** — monotonicity, no-split.
- **Value conservation tests** — supply preserved.
- **Handshake compatibility** — rolling upgrade handshake simulation.
- **Shadow validation** — non-blocking pre-activation.
- **Migration conformance** — crash-safe resume, future version rejection.

### 9. Cross-Migration Determinism Tests (`tests/determinism.rs`)

- **M3 root equivalence** — state root identical before/after format migration.
- **M1 no key loss** — account keys preserved across migration.
- **M2 value conservation** — total supply unchanged.
- **PV function stability** — deterministic across 1000 calls.

### 10. Documentation Updates

- **`UPGRADE.md`** — formal spec references added.
- **`SECURITY.md`** — formal safety properties referenced.
- **`CHANGELOG.md`** — this entry.

---

## v27.1.0 — Update Infrastructure: Protocol Versioning, Migrations, Release Checklist

### 1. Protocol Versioning (`src/protocol/version.rs`)

- **`CURRENT_PROTOCOL_VERSION = 1`** — every block header now carries a `protocol_version` field.
- **`SUPPORTED_PROTOCOL_VERSIONS`** — list of versions this binary can validate/execute.
- **Activation schedule** — per-version activation height with grace windows for rolling upgrades.
- **`version_for_height()`** — determines which protocol version to use at any given block height.
- **`validate_block_version()`** — rejects blocks with unsupported or expired protocol versions.
- **Config integration** — `consensus.protocol_activations` in `config.toml` for operator-controlled upgrade scheduling.

### 2. Node Metadata (`src/storage/meta.rs`)

- **`NodeMeta`** struct tracks: `schema_version`, `protocol_version`, `node_version`, `updated_at`.
- **Compatibility check** — at startup, detects if on-disk data is too new for this binary.
- **Atomic persistence** — write via `.tmp` + rename.

### 3. Migration Registry (`src/storage/migrations/`)

- **Ordered, idempotent migrations** — each migration is a module (`m0004_protocol_version.rs`).
- **`MIGRATIONS` registry** — append-only list; `run_pending()` applies missing steps.
- **v3 -> v4 migration** — creates `node_meta.json` with protocol version tracking.

### 4. Schema Version Bump

- **`CURRENT_SCHEMA_VERSION = 4`** (was 3) — reflects the new `node_meta.json` file.

### 5. BlockHeader Protocol Version

- **`protocol_version: u32`** added to `BlockHeader` (default 1 for backward compat).
- **`build_block()`** sets `protocol_version` from `CURRENT_PROTOCOL_VERSION`.

### 6. Release Checklist (`scripts/check.sh`)

- **Automated gate**: fmt, clippy, test, release build, binary sanity, determinism, protocol version checks.
- **Exit 1 on any failure** — prevents shipping broken builds.

### 7. Determinism Test Suite (`tests/determinism.rs`)

- **Golden-vector tests** for `hash_bytes`, `tx_hash`, `tx_root`, `receipts_root`, `block.id()`, `state.root()`.
- **Order-independence** — state root is deterministic regardless of insertion order.

### 8. Documentation

- **`UPGRADE.md`** — step-by-step upgrade procedure, rollback plan, expected behavior.
- **`SECURITY.md`** — security impact assessment, threat model, disclosure policy.
- **`CHANGELOG.md`** — this entry.

---

## v27.0.0 — Production Hardening: Schema Migrations, Unified EVM, Fuzz CI

### 1. Schema Versioning & Automatic Migrations (`src/storage/mod.rs`)

- **`CURRENT_SCHEMA_VERSION = 3`** — every breaking on-disk format change now bumps this.
- **`SchemaMeta`** struct replaces the bare `{version}` marker with a full audit trail:
  `version`, `migrated_at` (ISO timestamp), `migration_log` (per-step messages).
- **Atomic writes** — schema.json is written via `.tmp` + rename, so a crash mid-migration
  leaves the schema at the last successful version, not a partial state.
- **Automatic migration path v0 → v3**:
  - v0→v1: introduce schema.json marker (existing nodes, no data change)
  - v1→v2: inject missing `vm` + `burned` fields into `state_full.json`; inject
    `epoch_snapshots` + `params` into `stakes.json`; creates `.v1.bak` backups
  - v2→v3: migrate flat `wal.jsonl` → segmented `wal/wal_00000000.jsonl`
- **Future-version guard** — returns a clear error if the binary is older than the data.
- **6 integration tests** in `tests/schema_migration.rs` covering each migration step,
  idempotency, backup creation, and future-version detection.

### 2. Unified EVM Executor (`src/evm/kv_state_db.rs`)

- **`KvStateDb`** — a `revm::Database + DatabaseCommit` implementation backed by
  the live `KvState`.  This closes the gap between the two previously isolated VM paths:
  - Old: `src/evm/` used a standalone `MemDb` with no access to real balances or nonces.
  - New: EVM transactions see and modify the same state that consensus commits.
- **Address bridge**: IONA 32-byte addresses ↔ EVM 20-byte addresses via
  `iona_to_evm_addr` / `evm_to_iona_addr` (last 20 bytes convention).
- **`execute_evm_on_state()`** — single entry point: takes `&mut KvState`, an `EvmTx`,
  block context (height, timestamp, base_fee, chain_id), runs revm, commits on success.
- **`evm_unified` payload type** in `execute_block_with_staking()`:
  `"evm_unified <hex-bincode-EvmTx>"` routes to the unified executor.
- **`BlockHeader`** gains `chain_id` (default 6126151) and `timestamp` (default 0) with
  `#[serde(default)]` — fully backward-compatible with existing serialised blocks.

### 3. Fuzz CI — Automated, Corpus-Cached (`fuzz/`, `.github/workflows/ci.yml`)

- **`p2p_frame_decode`** fuzz target fully implemented (was a TODO stub):
  exercises bincode deserialization of `ConsensusMsg`, `Block`, `Tx`, and
  length-prefixed frames.
- **`vm_bytecode`** — new fuzz target: feeds arbitrary bytecode + calldata into
  the custom VM interpreter; any panic = CI failure.
- **Automated in CI**: new `fuzz` matrix job in `ci.yml` runs each target for 60s
  (configurable via `FUZZ_SECS`); uses nightly toolchain + cargo-fuzz.
- **Corpus caching**: corpus dir cached per target + `Cargo.lock` hash, grows across
  runs without full restart.
- **Crash artifacts**: uploaded automatically on job failure for local reproduction.
- **Additional CI jobs**: `schema-migration`, `proptests` (256 cases), `determinism`.

## v26.0.0 — Custom VM: Contract Deploy, Call & Full Integration

### New: Bytecode Opcodes (`src/vm/bytecode.rs`)
- Complete opcode set: arithmetic (ADD, SUB, MUL, DIV, MOD, EXP), bitwise (AND, OR, XOR, NOT, SHL, SHR)
- Comparison (LT, GT, EQ, ISZERO), SHA3, environment (CALLER, CALLVALUE, CALLDATALOAD, CALLDATASIZE, GAS, PC)
- Memory (MLOAD, MSTORE, MSTORE8, MSIZE), Storage (SLOAD, SSTORE)
- Stack ops: PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16, POP
- Control flow: JUMP, JUMPI, JUMPDEST, STOP, RETURN, REVERT, INVALID
- Logging: LOG0..LOG4
- Gas constants matching EVM: GAS_VERYLOW=3, GAS_LOW=5, GAS_SSTORE_SET=20000, GAS_LOG_BASE=375, etc.
- `push_data_size(opcode)` for correct JUMPDEST analysis

### New: VM State (`src/vm/state.rs`)
- `VmState` trait: `sload`, `sstore`, `get_code`, `set_code`, `emit_log`
- `VmStorage` struct: `storage` BTreeMap keyed by (contract, slot), `code` BTreeMap, `nonces`, `logs`
- `Memory` struct: linear byte array with `ensure()`, `load32`, `store32`, `store8`, `read_range`, `write_range`
- Memory bounds: max 4 MiB per execution; gas charged per new 32-byte word

### New: VM Interpreter (`src/vm/interpreter.rs`)
- Full 256-bit word stack (32-byte arrays, not u128)
- Native 256-bit arithmetic via byte-level operations: `word_add`, `word_sub`, `word_mul`, `word_div`, `word_rem`
- Bitwise: SHL/SHR with byte-level shifting
- Static JUMPDEST analysis before execution (prevents jumping into PUSH data)
- Memory expansion gas charged on every MLOAD/MSTORE
- SSTORE gas: 20,000 for new slot, 2,900 for update, 15,000 for clear
- LOG0..LOG4: gas = 375 + 375×topics + 8×data_bytes; events stored in VmStorage.logs
- CALLDATALOAD with out-of-bounds padding (zeroes)
- Implicit STOP at end of code

### New: VM Executor (`src/execution/vm_executor.rs`)
- `vm_deploy(state, sender, init_code, gas_limit) → VmExecResult`
  - Derives contract address: `blake3(sender || sender_nonce)[..32]`
  - Runs `init_code`; `return_data` becomes deployed bytecode
  - Rejects duplicate addresses (code already exists)
  - Enforces max code size: 24,576 bytes (EIP-170)
  - Reverts discard all state changes
  - Increments sender VM nonce on success
- `vm_call(state, sender, contract, calldata, gas_limit) → VmExecResult`
  - Loads code from `vm.code[contract]`
  - Fails cleanly if no code at address
  - Reverts discard state changes
  - Returns `return_data` and `logs` on success
- `derive_contract_address(sender, nonce) → [u8;32]`: deterministic, nonce-based
- `parse_vm_payload(payload) → Option<VmTxPayload>`: parses `vm deploy <hex>` and `vm call <contract> <calldata>`
- `VmExecResult`: success, reverted, gas_used, return_data, contract (on deploy), logs, error

### Updated: KvState (`src/execution.rs`)
- Added `vm: VmStorage` field — persists contract storage, bytecode, nonces
- `root()` now includes VM storage slots and contract code hashes in Merkle tree
- Two new Receipt fields used: `data: Option<String>` added to all Receipt constructions (previously missing field)

### Updated: execute_block_with_staking (`src/execution.rs`)
- Added `vm ` payload branch alongside `stake ` branch
- `vm deploy <hex>` → calls `vm_deploy`, contract address returned in `receipt.data`
- `vm call <contract> <calldata>` → calls `vm_call`, return data in `receipt.data`
- Malformed `vm ...` payloads → `receipt.success = false, error = "vm: malformed payload"`
- Gas used = intrinsic_gas + VM execution gas
- VM nonce for address derivation based on sender's current VM nonce

### Updated: types/mod.rs
- Added `data: Option<String>` to `Receipt` struct for VM return data / contract address

### New: RPC Endpoints (`src/bin/iona-node.rs`)
- `GET /vm/state` — lists all deployed contracts (address, code_bytes, storage_slots)
- `POST /vm/call` — read-only (view) simulation; does NOT commit state
  - Body: `{ "caller": "hex32", "contract": "hex32", "calldata": "hex", "gas_limit": u64 }`
  - Returns: `{ ok, reverted, gas_used, return_data, logs, error }`

### Updated: CLI (`src/bin/iona-cli.rs`)
- `iona-cli vm state` — queries GET /vm/state
- `iona-cli vm deploy <init_code_hex>` — prints signed tx template with `vm deploy` payload
- `iona-cli vm call <contract_hex> [calldata_hex]` — executes read-only call via POST /vm/call

### New: Tests (`tests/vm_integration.rs` — 25 tests)
**Interpreter unit tests (opcode correctness):**
- test_interpreter_add, test_interpreter_sub, test_interpreter_mul, test_interpreter_div, test_interpreter_mod
- test_interpreter_lt_gt_eq, test_interpreter_iszero
- test_interpreter_and_or_xor_not, test_interpreter_shl_shr
- test_interpreter_dup_swap, test_interpreter_jump_jumpi, test_interpreter_jumpi_conditional
- test_interpreter_calldataload, test_interpreter_sload_sstore, test_interpreter_log1
- test_interpreter_revert, test_interpreter_out_of_gas

**vm_executor lifecycle tests:**
- test_vm_deploy_and_call_counter — deploy + call roundtrip
- test_vm_state_root_changes_after_deploy — Merkle root updated
- test_vm_double_deploy_same_address_rejected — duplicate address guard
- test_vm_revert_discards_state — deploy revert leaves clean state
- test_vm_call_revert_discards_state — call revert leaves clean state
- test_vm_multiple_deploys_unique_addresses — nonce-based addresses differ

**Payload parsing tests:**
- test_parse_vm_payload_deploy, test_parse_vm_payload_call, test_parse_non_vm_payload_returns_none

**Gas / address tests:**
- test_gas_used_increases_with_more_work
- test_contract_address_derivation_is_deterministic
- test_contract_address_different_sender_different_address

---

## v25.0.0 — PoS Rewards & Staking Transactions

### New: Epoch Reward Distribution (`src/economics/rewards.rs`)
- `distribute_epoch_rewards()` called at every epoch boundary (every 100 blocks)
- Computes inflation: `total_staked × base_inflation_bps / 10_000 / epochs_per_year`
- Splits reward: validator commission + delegator share + treasury (`treasury_bps`)
- Auto-compounding: rewards added back to stake (growing TVL over time)
- Treasury accumulates at reserved address `"treasury"` in KvState
- All math uses `u128` to avoid overflow on large stake values

### New: Staking Transactions (`src/economics/staking_tx.rs`)
Payloads routed through normal tx signing pipeline:
- `stake delegate <validator> <amount>` — lock tokens as delegation
- `stake undelegate <validator> <amount>` — begin unbonding (locks for `unbonding_epochs`)
- `stake withdraw <validator>` — claim unbonded tokens after unbonding period
- `stake register <commission_bps>` — register self as validator (requires `min_stake`)
- `stake deregister` — remove self from validator set (no external delegators allowed)

### New: `execute_block_with_staking()` (`src/execution.rs`)
- Routes `stake *` payloads to staking module instead of KV engine
- Preserves fee deduction + nonce logic from normal path
- Backward-compatible: original `execute_block()` unchanged

### New: `/staking` RPC Endpoint (`src/bin/iona-node.rs`)
- Returns: validators (stake, jailed, commission), delegations, unbonding queue
- Shows total staked and all `EconomicsParams`
- Updated `App` struct with `staking_state: Arc<Mutex<StakingState>>` and `economics_params`

### CLI: Staking Subcommands (`src/bin/iona-cli.rs`)
- `iona-cli staking info` — live staking state from node
- `iona-cli staking delegate/undelegate/withdraw/register/deregister` — prints signed tx template

### Tests (`tests/pos_rewards.rs`)
13 new tests covering:
- Epoch boundary detection
- Reward distribution invariant (minted == distributed ± rounding)
- Treasury monotonic growth
- Jailed validators excluded from rewards
- Higher commission → more operator reward
- Delegator reward proportional to stake share
- Auto-compounding stake growth
- Full delegate → undelegate → withdraw lifecycle
- Register and deregister validator
- Cannot delegate to jailed validator
- Cannot deregister with active external delegators

## v24.12.0

## 24.12.0 — A+B+C single-shot hardening

- A) Sybil/eclipsing defense: peer diversity buckets + inbound gating + eclipse detection + reseed hooks.
- B) Gossipsub hardening: topic ACL + per-topic publish/forward caps + spam scoring hooks.
- C) State sync security: validator-set binding + anti-replay epoch/nonce binding (and aggregation scaffolding behind feature flag).


- End-to-end snapshot attestation aggregation (threshold) with manifest attachment.
- State sync delta chains: pathfinding over delta edges, sequential apply with verification, and robust fallback.
- Release-grade SLSA provenance workflow: signed provenance on releases (plus SBOM/audit/deny).

## v24.10.0

- Snapshot attestation (real): multi-validator collection over the network with threshold aggregation; manifests can embed attestations and nodes can request/serve aggregated attestations.
- State sync: delta *chains* support (h1→h2→h3…), pathfinding over available deltas, plus snapshot index exchange for efficient selection.
- Supply chain: SLSA/signed provenance workflow for CI (build provenance attestation), alongside existing SBOM + audit/deny.

## v24.9.0

- State sync: snapshot attestation + threshold verification support; delta sync support (snapshot-to-snapshot diffs).
- Consensus safety: double-sign protection with persisted guard + evidence emission.
- Supply chain: reproducible build check script, SBOM generation, cargo-audit/cargo-deny in CI; optional signed releases workflow.

## v24.8.0
- Mega++: P2P state sync resume with partial chunk re-request (no boundary-only truncation), peer selection uses RTT + measured throughput, and remote signer audit logs real client certificate fingerprint per request.

## v24.5.0
- One-shot Ultra upgrade: encrypted keystore option (AES-256-GCM + PBKDF2), snapshotting (zstd) + restore on startup, optional OpenTelemetry (OTLP) tracing layer (feature `otel`).
- Storage section: snapshot tuning + max_concurrent_tasks scaffold.

## v24.2.0

## v24.4.0
- Enterprise++ networking: peer_score decay, gossipsub publish/inbound caps, persistent quarantine list (survives restart).

- Connection limits + per-peer RR rate limiting
- Automatic schema migrations at startup (schema.json)
- CI fuzzing (PR + schedule)

## v24.3.0
- Enterprise P2P hardening: per-protocol rate limits (Block/Status/Range), per-protocol per-peer bandwidth caps.
- Global request-response bandwidth caps (in/out) with backpressure (drop/skip).
- Peer scoring refinement: strike decay + temporary quarantine with escalation to ban.


# Changelog

## v24.7.0

- Ultra-ultra bundle: P2P state sync (snapshot download) when `state_full.json` is missing.
- Added state-sync protocol `/iona/state/1.0.0` (manifest + chunked transfer).
- Remote signer client (`crypto::remote_signer`) with a tiny HTTP JSON contract.
- Added executable chaos harness `iona-chaos` (restart + partition shuffle scenarios).

## v24.1.0

- Hardening: removed unwrap/expect from critical paths (consensus/storage/RPC)
- Fixed storage::DataDir impl (compile fix)
- P2P anti-DoS: stricter request/response timeouts, range validation
- Added fuzzing harness (cargo-fuzz) + proptest scaffolding
- Version hygiene: Cargo.toml aligned with CLI/README

## v24.0.0

- Added full deployment bundle: `config.toml`, Dockerfile, docker-compose, systemd unit.
- Added `scripts/run_3nodes_local.sh` quickstart.
- Added GitHub Actions CI (build/test/clippy/rustfmt).
- Documentation refresh in README (config-first, quickstart sections).

## v23.x

- Merge of v22 config/governance/slashing + v20 hardened networking (bootnodes, optional Kademlia, persistent peer store).
