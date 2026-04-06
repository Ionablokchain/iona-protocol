# IONA Cosmos Adapter

**Operational tooling and configuration guidance for validators familiar with CometBFT-based chains**

---

> **Scope disclaimer**: This adapter provides *key format conversion tooling*, *config translation*, and *deployment templates* for operators who want to run IONA alongside or after a CometBFT validator. It is **not** a live-chain migration tool — it does not move on-chain state, voting power, delegations, or signing history from one network to another. Those are properties of the source chain, not of the node software.

---

## What This Adapter Provides

### 1. Key Format Converter (`key_import.sh`)

Converts a CometBFT `priv_validator_key.json` to IONA's encrypted key storage format.

**Input**: CometBFT key file (ed25519, base64-encoded)
**Output**: Instructions + hex private key for IONA's `iona keys import` command
**Usage**:
```bash
./key_import.sh priv_validator_key.json
```

The script validates the key type, decodes the base64 private key to hex, and prints the exact command to import it into IONA's encrypted keystore. The underlying ed25519 key material is preserved exactly.

See `key_import.sh` for details on format differences and how to complete the import step.

### 2. Config Converter (`convert_config.sh`)

Mechanically translates a CometBFT `config.toml` to an IONA `config.toml`.

**Input**: CometBFT config.toml
**Output**: IONA config.toml
**Usage**:
```bash
./convert_config.sh ~/.cosmos/config/config.toml [output-file]
```

Mapped settings:
- P2P listen address and port (26656 → 7001)
- RPC listen address (26657 → 9001, defaults to loopback for security)
- Static peers and seeds (address format converted)
- Consensus timeouts (propose / prevote / precommit, converted to ms)
- Mempool capacity

Settings with **no direct equivalent** are listed in the `# UNMAPPED SETTINGS` section of the generated file for manual review (pex, statesync, blocksync, rate limits, etc.).

### 3. Port Mapping Reference

| Service | CometBFT Default | IONA Default | Notes |
|---------|------------------|--------------|-------|
| P2P | 26656 | 7001 | Peer discovery and consensus messages |
| RPC HTTP | 26657 | 9001 | Client API, tx broadcast |
| gRPC / metrics | 9090 | 9090 | Prometheus metrics (same port) |
| Admin (mTLS) | — | 9002 | IONA-only; no CometBFT equivalent |

All ports are configurable in IONA `config.toml` under `[network]` and `[rpc]`.

### 4. Deployment Templates

The `deploy/validator/` directory contains:
- systemd unit files with security hardening directives
- UFW and iptables firewall rules aligned to IONA's default ports
- nginx and Envoy reverse-proxy configurations
- `--profile cosmos-hard` startup profile (enforces mTLS admin, eclipse-resistance, ≥3 peers)

---

## What Is NOT Preserved

| Item | Status | Notes |
|------|--------|-------|
| Validator address on source chain | **Not transferred** | The source chain keeps its own state |
| Voting power / delegations | **Not transferred** | On-chain state; only the source chain controls this |
| Signing history / last-signed height | **Not transferred** | Each chain maintains its own WAL |
| Unbonding / rewards / commission | **Not transferred** | Source chain state |
| Node identity (libp2p peer ID) | Converted | IONA uses the same ed25519 key for peer ID derivation |
| Validator signing key (ed25519) | **Preserved** | The key bytes are identical after format conversion |

Running IONA with the same ed25519 key does not make IONA a validator on the source chain. Validator status is determined by the chain's staking module, not the node binary.

---

## Quick Start

### Step 1: Set Up a Migration Machine

Perform key handling on a secure, air-gapped or isolated machine — not your live validator:

```bash
git clone https://github.com/iona/iona.git
cd iona/adapters/cosmos
```

### Step 2: Copy Your Keys Safely

```bash
# Securely copy key files from your CometBFT validator
scp -i migration.key validator@cosmos-node:~/.cosmos/config/priv_validator_key.json .
scp -i migration.key validator@cosmos-node:~/.cosmos/config/node_key.json .
```

Keep private key files on the migration machine only. Delete them after import.

### Step 3: Convert Key Format

```bash
./key_import.sh priv_validator_key.json
```

The script will:
- Validate the ed25519 key type
- Decode and display the public key in hex
- Print the exact `iona keys import` command to run on the IONA node

**Next**: Follow the script's output to encrypt the key with IONA's binary (`iona keys import --encrypt`).

### Step 4: Convert Configuration

```bash
./convert_config.sh ~/.cosmos/config/config.toml iona_config.toml
```

Review the generated `iona_config.toml`:
- Update `[node].chain_id` to the IONA chain ID
- Verify peer addresses (port 26656 → 7001 is converted automatically)
- Review the `# UNMAPPED SETTINGS` section at the bottom

### Step 5: Follow the Full Migration Guide

See `migrate_validator.md` for the complete procedure, including:
- Testnet dry-run (strongly recommended before mainnet)
- Coordinated cutover timing
- Rollback plan

---

## Key Format Differences

### Private Key Storage

| Field | CometBFT | IONA | Notes |
|-------|----------|------|-------|
| **Encoding** | Base64 ed25519 (plaintext JSON) | AES-256-GCM encrypted binary | IONA never stores the key unencrypted on disk |
| **File format** | `priv_validator_key.json` | `keys.enc` | Binary blob; not human-readable |
| **Passphrase** | None | User-provided at import | Set once; required at node startup |

### Public Key Derivation

Both CometBFT and IONA derive the validator address from the ed25519 public key using `SHA256(pubkey)[0:20]`. The key bytes are identical after conversion. The displayed address string will differ only if the bech32 prefix is different between chains (e.g., `cosmos1...` vs `iona1...`).

---

## Supported CometBFT Versions

This adapter's key and config tooling is tested against:

- **CometBFT v0.37.x** and **v0.38.x** (Cosmos SDK v0.47+ chains)
- Any chain using standard ed25519 `priv_validator_key.json` format

Chains include Cosmos Hub, Osmosis, Juno, Neutron, Stride, Sei, and others using the Cosmos SDK. The only hard requirement is ed25519 signing keys — not secp256k1 or BLS.

### Not in Scope

- Pre-CometBFT Tendermint (≤ v0.36): key format differs; manual conversion may be needed
- Solana, Polkadot, Ethereum validators: different key types (not supported)
- Moving stake/delegations between chains: this requires source-chain governance, not node software

---

## Common Issues

### "jq: command not found"

`key_import.sh` requires `jq` for JSON parsing.

```bash
# macOS
brew install jq
# Ubuntu/Debian
sudo apt-get install jq
```

### "Invalid key type"

The key file uses a key type other than `ed25519` (e.g., `secp256k1`). IONA uses ed25519 only.

Check:
```bash
jq '.priv_key.type' priv_validator_key.json
# Expected: "tendermint/PrivKeyEd25519"
```

### "Address looks different"

The ed25519 key is the same; the bech32 prefix differs between the source chain and IONA. This is expected and correct. The key material has not changed.

---

## Next Steps

1. Read `migrate_validator.md` for the complete setup procedure
2. Test on IONA testnet before mainnet
3. Use `--profile cosmos-hard` for a Cosmos-operator-friendly hardening baseline
4. See `../../docs/VALIDATOR_KEYS.md` for ongoing key management and rotation

---

## Support

- **Community**: GitHub Discussions in the IONA repository
- **Security questions**: security@example.invalid
- **Enterprise support**: enterprise@example.invalid
