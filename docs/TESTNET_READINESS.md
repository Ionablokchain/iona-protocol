# IONA v30 — Testnet Readiness Guide

**Version**: v30.0.0  
**Status**: Testnet-ready  
**Last Updated**: 2026-03-07

---

## Quick Start (4-node local testnet)

```bash
# 1. Build
cargo build --release --bin iona-node

# 2. Start testnet
cd testnet/local4
bash run_testnet.sh ./target/release/iona-node

# 3. Verify consensus is running
curl -s http://127.0.0.1:8541/  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
# Expected: {"jsonrpc":"2.0","id":1,"result":"0x1"}  (height advancing)

# 4. Check all 4 nodes
for port in 8541 8542 8543 8544; do
  H=$(curl -sf http://127.0.0.1:$port/ \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "unreachable")
  echo "  :$port height=$H"
done
```

---

## Architecture

```
testnet/local4/
├── genesis.json          ← shared genesis (all nodes must use same file)
├── run_testnet.sh        ← start all 4 nodes
├── node1/
│   ├── config.toml       ← node config (rpc: 8541, p2p: 7010)
│   └── data/             ← state persistence (auto-created)
├── node2/  (rpc: 8542, p2p: 7020)
├── node3/  (rpc: 8543, p2p: 7030)
└── node4/  (rpc: 8544, p2p: 7040)
```

---

## What Works in v30

### ✅ Build stabilization (Stage 1 — complete)

| File | Fix |
|------|-----|
| `auth_api_key.rs` | axum 0.7: removed `<B>` generics, uses `State<Arc<ApiKeyConfig>>` |
| `bloom.rs` | Manual `Default` for `[u8;256]`, added `Serialize`/`Deserialize` |
| `withdrawals.rs` | Added `Debug`, `Clone`, `Serialize`, `Deserialize` to `Withdrawal` |
| `txpool.rs` | Added `Debug` to `TxPool` |
| `peer_score.rs` | Added `Debug` to `PeerEntry` and `RateBucket` |
| `chain_store.rs` | `offset: Option<u64>` field present and used correctly |

### ✅ Core type/API migration (Stage 2 — complete)

| File | Fix |
|------|-----|
| `tx_decode.rs` | k256 0.13: replaced `recoverable` module with `RecoveryId` + `recover_from_prehash` |
| `state_trie.rs` | revm v9: `nonce: u64` (not Option), `code_hash: B256` (not Option), `U256::to_be_bytes()` |
| `eth_rpc.rs` | Removed all `info.nonce.unwrap_or(0)` — nonce is u64 in revm v9 |

### ✅ Runtime correctness (Stage 3 — complete)

| Component | Status |
|-----------|--------|
| `tx_decode.rs` | Legacy + EIP-2930 + EIP-1559 decode with correct sender recovery |
| `state_trie.rs` | Correct `rlp_account()`, `compute_storage_root()`, `empty_trie_root()` |
| `fs_store.rs` | Atomic snapshot (write-tmp-then-rename), EVM account persistence, head record |
| `genesis.rs` | Deterministic genesis hash, validator set construction, testnet config generator |

### ✅ Testnet readiness (Stage 4 — complete)

| Component | Status |
|-----------|--------|
| Genesis | `testnet/local4/genesis.json` — 4 validators, chain_id=6126151 |
| Per-node configs | `testnet/local4/node{1-4}/config.toml` — all with secure defaults |
| Run script | `testnet/local4/run_testnet.sh` |
| RPC endpoints | `eth_blockNumber`, `eth_getBalance`, `eth_sendRawTransaction`, etc. |
| Persistence | State snapshot per node in `data/state_snapshot.json` |
| Restart safety | Load snapshot on start, resume from last height |

---

## Supported RPC Methods (v30)

### Mandatory (all implemented)
| Method | Notes |
|--------|-------|
| `web3_clientVersion` | Returns `iona/v30.0.0` |
| `eth_chainId` | Returns configured chain_id |
| `eth_blockNumber` | Latest committed block height |
| `eth_getBalance` | Balance from MemDb |
| `eth_getTransactionCount` | Nonce from MemDb |
| `eth_sendRawTransaction` | Decode + execute + mine |
| `eth_getTransactionByHash` | From tx map |
| `eth_getTransactionReceipt` | From receipts map |
| `eth_getBlockByNumber` | By height or "latest"/"pending" |
| `eth_getBlockByHash` | By block hash |
| `eth_call` | Read-only EVM call |
| `eth_estimateGas` | EVM gas estimation |
| `eth_gasPrice` | Current base fee |
| `net_version` | Chain ID as string |
| `net_peerCount` | P2P peer count |

### Useful (implemented)
| Method | Notes |
|--------|-------|
| `eth_getLogs` | Full filter support |
| `eth_feeHistory` | Last N blocks fee history |
| `eth_getCode` | Contract bytecode |
| `eth_getStorageAt` | Storage slot read |
| `eth_getProof` | Account + storage proofs |

### Stubs (not critical for testnet)
- WebSocket subscriptions
- `debug_traceTransaction`
- Uncle/ommer support
- Full archive behavior

---

## Restart / Recovery

On restart, each node:
1. Loads `data/state_snapshot.json` → restores `EthRpcState`
2. Loads `data/evm_accounts.json` → restores `MemDb`
3. Loads `data/head.json` → logs resume height
4. Reconnects to peers and re-syncs any missed blocks

```bash
# Test restart recovery
kill -SIGTERM $(pidof iona-node-node1)
sleep 2
iona-node --config testnet/local4/node1/config.toml &
# Node should resume from last persisted height, not from 0
```

---

## Networking

- **P2P**: libp2p gossipsub + kad DHT, static peer dialing, mDNS disabled for internet
- **Reconnect**: disconnected peers re-dialed every 30s
- **Peer scoring**: per-peer rate limiting (60 msg/s, 4 MB/s), score-based ban
- **Max message size**: 16 MiB
- **Gossip heartbeat**: 100ms (enables sub-second block propagation)

---

## Security Defaults

All configs generated with:
- `rpc.listen = "127.0.0.1:PORT"` — loopback only
- `admin.listen = "127.0.0.1:PORT"` — loopback only  
- `cors_allow_all = false`
- `enable_faucet = true` — safe for testnet, **set false for mainnet**

---

## Known Limitations (v30 testnet)

1. **State trie**: Without `state_trie` feature, `stateRoot` is a deterministic keccak of all account RLPs, not a real MPT. Enable with `cargo build --features state_trie` for production.
2. **Transaction pool**: In-memory only, cleared on restart. Persistence is stub.
3. **EVM execution**: Full EVM via revm, but no archive (no historical state queries).
4. **Sync**: New nodes sync via request-response protocol, not optimistic sync.
