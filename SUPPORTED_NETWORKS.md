# IONA Supported Networks

IONA is designed to operate as a standalone Layer-1 BFT consensus engine, with progressive integration into the Cosmos ecosystem through adapters and bridges.

## Currently Supported

| Network | Type | Status | Protocol Version | Notes |
|---------|------|--------|------------------|-------|
| IONA Mainnet | Layer-1 BFT | Live | v1 | Native chain |
| IONA Testnet | Layer-1 BFT | Live | v1 | Free faucet at testnet.iona.network |
| IONA Devnet | Layer-1 BFT | On-demand | v1 | CI environment, resets daily |

## Cosmos / CometBFT Compatibility

IONA implements a Tendermint-style BFT consensus mechanism compatible with CometBFT patterns, enabling seamless validator migration and interoperability.

### Key Format Adapters

IONA provides format converters in `adapters/cosmos/` for:
- **priv_validator_key.json** — CometBFT ed25519 validator signing keys
- **node_key.json** — CometBFT libp2p identity keys

Both formats are automatically detected and converted to IONA's encrypted key storage (keys.enc).

### Port Mapping Reference

CometBFT validators are familiar with standard ports. IONA remaps them as follows:

| Service | CometBFT Default | IONA Default | Notes |
|---------|------------------|--------------|-------|
| P2P (libp2p) | 26656 | 7001 | Peer discovery & consensus |
| RPC HTTP | 26657 | 9001 | Client API |
| gRPC | 9090 | 9090 | Protobuf services (unchanged) |

Configure these in IONA's `config.toml` under `[networking]` and `[rpc]`.

### State Sync & Snapshots

IONA implements state sync compatible with Cosmos SDK tooling:
- Periodic snapshot generation (every 1000 blocks by default)
- Snapshot metadata in Prometheus metrics
- Quick-sync via `iona init --state-sync-rpc https://rpc.iona.network:9001`

## Planned Network Support

| Network | Target Version | ETA | Notes |
|---------|----------------|-----|-------|
| IBC relay integration | v29.0 | Q3 2026 | Light-client verification, hub-to-zone messaging |
| Cosmos Hub adapter | v29.0 | Q3 2026 | Read-only query adapter for Cosmos Hub state |
| Osmosis DEX bridge | v30.0 | Q4 2026 | Token swap routing via IBC |
| EVM-compatible L2 | v30.0 | Q4 2026 | Optimistic rollup, Solidity contract support |
| Ethereum mainnet bridge | v31.0 | 2027 | Trust-minimised bridge with light clients |

## Cosmos Validator Migration

Validators running CometBFT-based chains (Cosmos Hub, Osmosis, Juno, Neutron, Stride, etc.) can migrate to IONA with minimal effort.

See **adapters/cosmos/migrate_validator.md** for a step-by-step migration guide covering:
- Key format conversion (priv_validator_key.json → keys.enc)
- Config translation (CometBFT config.toml → IONA config.toml)
- Port mapping and peer format conversion
- Testnet validation before mainnet cutover
- Rollback procedures

Key differences from CometBFT:
- **Port mapping**: P2P, RPC, and gRPC ports differ (see table above)
- **Key encryption**: IONA encrypts validator keys at rest; CometBFT stores plaintext JSON
- **Config structure**: Simplified TOML with clear sections for networking, consensus, and RPC
- **Peer format**: Multiaddr protocol (libp2p) instead of host:port notation

## Protocol Compatibility Matrix

| IONA Version | CometBFT Compat | Ethereum JSON-RPC | Notes |
|--------------|-----------------|-------------------|-------|
| v28.2+ (current) | Partial (key format, port adapters) | Full EIP-1559 | Validator migration possible via adapters |
| v29.0 (planned) | Full IBC | Full EIP-1559 | IBC module enables cross-chain messaging |
| v30.0+ (planned) | Full IBC + EVM | EVM-compatible L2 | Solidity contracts, token bridging |

### EIP-1559 Support

IONA v28.3 includes experimental EIP-1559 fee market dynamics in its mempool layer. This enables:
- Base fee calculation and burn mechanism
- Priority fee support
- Compatibility with Ethereum wallet tooling and bridges

See `docs/FEE_MARKET.md` for implementation details.
