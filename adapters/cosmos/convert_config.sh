#!/usr/bin/env bash
# convert_config.sh — CometBFT config.toml → IONA config.toml mapping guide
#
# This script reads a CometBFT config.toml, extracts the relevant settings,
# and generates an IONA config.toml with equivalent values where a direct
# mapping exists.
#
# SCOPE OF THIS TOOL
# ------------------
# This tool handles the MECHANICAL mapping of settings (ports, timeouts,
# peer addresses) where the two systems share semantics.  It does NOT:
#   - Migrate consensus state or signing history
#   - Guarantee identical behaviour under all conditions
#   - Handle CometBFT-specific modules that have no IONA equivalent
#     (e.g., Tendermint mempool v1 reactor, ABCI++)
#
# Always review the generated config before running IONA.
#
# USAGE
# -----
#   ./convert_config.sh <cometbft-config.toml> [output-file]
#
# REQUIREMENTS
# ------------
#   bash, grep, sed, awk, cat
#
# OUTPUT
# ------
#   Writes IONA config.toml to <output-file> (default: iona_config.toml)
#   Prints a summary of mapped and unmapped settings.

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Args ──────────────────────────────────────────────────────────────────
INPUT="${1:-}"
OUTPUT="${2:-iona_config.toml}"

if [[ -z "$INPUT" ]]; then
    echo "Usage: $0 <cometbft-config.toml> [output-file]"
    echo "Example: $0 ~/.gaiad/config/config.toml iona_config.toml"
    exit 1
fi
if [[ ! -f "$INPUT" ]]; then
    err "Input file not found: $INPUT"
    exit 1
fi

info "Reading CometBFT config: $INPUT"
info "Output IONA config:      $OUTPUT"
echo ""

# ── Helper: extract a TOML value by key ──────────────────────────────────
# Returns the raw value (without quotes) or a default.
toml_get() {
    local file="$1" key="$2" default="${3:-}"
    local val
    val=$(grep -E "^\s*${key}\s*=" "$file" | head -1 | \
          sed -E 's/^\s*[^=]+=\s*//' | \
          sed -E 's/\s*#.*//' | \
          tr -d '"' | tr -d "'" | \
          xargs)
    echo "${val:-$default}"
}

# ── Extract CometBFT values ───────────────────────────────────────────────
info "Extracting CometBFT settings..."

# [p2p]
P2P_LADDR=$(toml_get "$INPUT" "laddr" "tcp://0.0.0.0:26656")
P2P_SEEDS=$(toml_get "$INPUT" "seeds" "")
P2P_PERSISTENT_PEERS=$(toml_get "$INPUT" "persistent_peers" "")
P2P_MAX_PEERS=$(toml_get "$INPUT" "max_num_outbound_peers" "10")
P2P_HANDSHAKE_TIMEOUT=$(toml_get "$INPUT" "handshake_timeout" "20s")

# [rpc]
RPC_LADDR=$(toml_get "$INPUT" "laddr" "tcp://127.0.0.1:26657")

# [mempool]
MEMPOOL_SIZE=$(toml_get "$INPUT" "size" "5000")
MEMPOOL_MAX_TX=$(toml_get "$INPUT" "max_tx_bytes" "1048576")

# [consensus]
TIMEOUT_PROPOSE=$(toml_get "$INPUT" "timeout_propose" "3s")
TIMEOUT_PREVOTE=$(toml_get "$INPUT" "timeout_prevote" "1s")
TIMEOUT_PRECOMMIT=$(toml_get "$INPUT" "timeout_precommit" "1s")
TIMEOUT_COMMIT=$(toml_get "$INPUT" "timeout_commit" "5s")

# ── Convert P2P listen address ────────────────────────────────────────────
# CometBFT: tcp://0.0.0.0:26656  →  IONA: 0.0.0.0:7001
P2P_PORT=$(echo "$P2P_LADDR" | grep -oE '[0-9]+$' || echo "26656")
IONA_P2P_LISTEN="0.0.0.0:7001"
if echo "$P2P_LADDR" | grep -q "127\.0\.0\.1"; then
    IONA_P2P_LISTEN="127.0.0.1:7001"
fi

# ── Convert RPC listen address ────────────────────────────────────────────
# Always default to loopback for security
IONA_RPC_LISTEN="127.0.0.1:9001"
if echo "$RPC_LADDR" | grep -q "0\.0\.0\.0"; then
    warn "CometBFT RPC was bound to 0.0.0.0. Defaulting IONA RPC to 127.0.0.1 (safer)."
    warn "Use --unsafe-rpc-public if you need public RPC."
fi

# ── Convert peer addresses ────────────────────────────────────────────────
# CometBFT: nodeID@host:26656  →  IONA: /ip4/<host>/tcp/7001
convert_peers() {
    local peers="$1"
    local result=""
    IFS=',' read -ra peer_list <<< "$peers"
    for peer in "${peer_list[@]}"; do
        peer=$(echo "$peer" | xargs) # trim whitespace
        [[ -z "$peer" ]] && continue
        # Extract host and port
        local host_port
        host_port=$(echo "$peer" | sed 's/^[^@]*@//')
        local host
        local port
        host=$(echo "$host_port" | cut -d: -f1)
        port=$(echo "$host_port" | cut -d: -f2)
        # Convert port to IONA default if using standard CometBFT port
        [[ "$port" == "26656" ]] && port="7001"
        if [[ -n "$result" ]]; then result+=", "; fi
        result+="\"${host}:${port}\""
    done
    echo "$result"
}

IONA_PEERS=$(convert_peers "${P2P_PERSISTENT_PEERS},${P2P_SEEDS}")

# ── Convert timeouts (remove 's' suffix, convert to ms) ──────────────────
to_ms() {
    local val="$1"
    if echo "$val" | grep -qE '[0-9]+s$'; then
        echo "$((${val%s} * 1000))"
    elif echo "$val" | grep -qE '[0-9]+ms$'; then
        echo "${val%ms}"
    else
        echo "1000"  # default fallback
    fi
}

IONA_PROPOSE_MS=$(to_ms "$TIMEOUT_PROPOSE")
IONA_PREVOTE_MS=$(to_ms "$TIMEOUT_PREVOTE")
IONA_PRECOMMIT_MS=$(to_ms "$TIMEOUT_PRECOMMIT")

# ── Write IONA config ─────────────────────────────────────────────────────
info "Writing IONA config to: $OUTPUT"

cat > "$OUTPUT" << TOML
# IONA config.toml — generated by adapters/cosmos/convert_config.sh
# Source: ${INPUT}
# Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
# REVIEW THIS FILE before starting IONA.
# Not all CometBFT settings have direct equivalents; see UNMAPPED section
# at the bottom of this file for settings that require manual attention.

[node]
data_dir    = "./data"
keystore    = "encrypted"
seed        = 0          # unused when keystore=encrypted
chain_id    = 6126151    # CHANGE THIS to your chain ID

[network]
listen   = "${IONA_P2P_LISTEN}"
# Converted from CometBFT source port ${P2P_PORT} → IONA default 7001
# Update peer addresses in your discovery config (peering via bootnodes / static peers)
$([ -n "$IONA_PEERS" ] && echo "peers    = [${IONA_PEERS}]" || echo "peers    = []")
bootnodes = []
enable_mdns = false
enable_kad  = true

# Eclipse resistance (not in CometBFT; IONA-specific)
# "mainnet" = stricter peer diversity; "testnet" = relaxed
eclipse_profile = "mainnet"

[rpc]
listen = "${IONA_RPC_LISTEN}"
# NOTE: CometBFT RPC was at port ${P2P_PORT:-26657}
# IONA default is 127.0.0.1:9001 (loopback only for security)
# If you need public RPC, start with: iona-node --unsafe-rpc-public

cors_allow_all  = false
max_body_bytes  = ${MEMPOOL_MAX_TX:-1048576}
enable_faucet   = false

[admin]
listen         = "127.0.0.1:9002"
require_mtls   = true
rbac_path      = "./rbac.toml"
tls_cert_pem   = "./tls/admin-server.crt.pem"
tls_key_pem    = "./tls/admin-server.key.pem"
tls_ca_cert_pem = "./tls/ca.crt.pem"
audit_log_path = "./data/audit.log"

[consensus]
# Converted from CometBFT timeouts (ms):
propose_timeout_ms    = ${IONA_PROPOSE_MS}
prevote_timeout_ms    = ${IONA_PREVOTE_MS}
precommit_timeout_ms  = ${IONA_PRECOMMIT_MS}
# NOTE: timeout_commit (${TIMEOUT_COMMIT}) controls block interval in CometBFT.
# In IONA this is managed by the proposer; set max_txs_per_block instead.
max_txs_per_block     = 4096
gas_target            = 30000000

[mempool]
# CometBFT mempool.size = ${MEMPOOL_SIZE}
# IONA uses a priority queue; capacity is in entries
capacity = ${MEMPOOL_SIZE}

[storage]
enable_snapshots        = true
snapshot_every_n_blocks = 500
snapshot_keep           = 5
snapshot_zstd_level     = 3

# ── Port mapping reference ─────────────────────────────────────────────────
# CometBFT 26656 (P2P)  → IONA 7001
# CometBFT 26657 (RPC)  → IONA 9001
# CometBFT 9090  (gRPC) → IONA 9090 (metrics)
# CometBFT 9091  (REST) → IONA 9001 (same RPC)

# ── UNMAPPED SETTINGS ──────────────────────────────────────────────────────
# The following CometBFT settings have no direct IONA equivalent.
# Review each one manually:
#
# [p2p].pex                    → IONA uses libp2p Kademlia DHT (enable_kad)
# [p2p].addr_book_strict       → No equivalent; IONA uses eclipse scoring
# [p2p].flush_throttle_timeout → No equivalent
# [p2p].send_rate / recv_rate  → No equivalent (use OS-level tc/iptables)
# [mempool].cache_size         → No equivalent; IONA deduplicates by hash
# [mempool].version            → IONA uses a single priority-queue mempool
# [consensus].create_empty_blocks → IONA always creates empty blocks on schedule
# [consensus].double_sign_check_height → IONA DoubleSignGuard covers this
# [statesync].*                → Use iona backup/restore instead
# [instrumentation].prometheus  → IONA always exposes /metrics on port 9090
# [fastsync] / [blocksync].*   → IONA uses P2P state sync automatically
TOML

echo ""
info "Conversion complete: $OUTPUT"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Mapped settings:"
echo "    ✓  P2P listen     ${P2P_LADDR} → ${IONA_P2P_LISTEN}"
echo "    ✓  RPC listen     (loopback)  → ${IONA_RPC_LISTEN}"
echo "    ✓  Peer addresses (${P2P_MAX_PEERS} max) → converted"
echo "    ✓  Timeouts       propose/prevote/precommit"
echo "    ✓  Mempool size   ${MEMPOOL_SIZE} entries"
echo ""
echo "  Requires manual review (see UNMAPPED section in $OUTPUT):"
warn "    ⚠  pex / addr_book settings"
warn "    ⚠  statesync configuration"
warn "    ⚠  chain_id — update [node].chain_id"
warn "    ⚠  Peer addresses — verify multiaddr format was converted"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Next steps:"
echo "  1. Review $OUTPUT — especially chain_id and peer addresses"
echo "  2. Run: iona keys check ./data"
echo "  3. Run: iona-node --check-compat --config $OUTPUT"
echo "  4. Test on IONA testnet before mainnet"
echo "  5. See adapters/cosmos/migrate_validator.md for full procedure"
echo ""
