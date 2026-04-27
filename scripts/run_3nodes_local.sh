#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IONA Local 3-Node Testnet                                                  ║
# ║                                                                             ║
# ║  Starts a 3‑node IONA network locally (no Docker).                          ║
║  Each node gets its own data directory and RPC port.                         ║
║                                                                             ║
║  Usage:                                                                     ║
║    ./scripts/run_3nodes_local.sh [OPTIONS]                                  ║
║                                                                             ║
║  Options:                                                                   ║
║    --binary PATH    Path to iona-node binary (default: build if missing)    ║
║    --build          Force rebuild before starting                           ║
║    --keep-logs      Keep log files after exit (default: remove)             ║
║    --verbose        Show detailed output                                    ║
║    --help           Show this help                                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

# ── Configuration ────────────────────────────────────────────────────────────

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY=""
FORCE_BUILD=false
KEEP_LOGS=false
VERBOSE=false

# Colors for better readability (if terminal supports)
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

# ── Helper functions ─────────────────────────────────────────────────────────

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
section() { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}"; }

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "[DEBUG] $*"
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ── Parse arguments ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)      BINARY="$2"; shift 2 ;;
        --binary=*)    BINARY="${1#*=}"; shift ;;
        --build)       FORCE_BUILD=true; shift ;;
        --keep-logs)   KEEP_LOGS=true; shift ;;
        --verbose)     VERBOSE=true; shift ;;
        --help|-h)     sed -n '/^# Usage:/,/^# ╚══/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             warn "Unknown option: $1"; shift ;;
    esac
done

# ── Dependency checks ────────────────────────────────────────────────────────

section "Checking dependencies"

if ! command_exists cargo; then
    die "cargo not found. Please install Rust: https://rustup.rs/"
fi
ok "cargo available"

# ── Ensure binary exists / build ─────────────────────────────────────────────

if [[ -z "$BINARY" ]]; then
    BINARY="$ROOT_DIR/target/release/iona-node"
fi

if [[ ! -f "$BINARY" ]] || [[ "$FORCE_BUILD" == true ]]; then
    info "Building iona-node release binary..."
    (cd "$ROOT_DIR" && cargo build --release --locked --bin iona-node) || die "Build failed"
    ok "Binary built at $BINARY"
else
    ok "Binary found at $BINARY"
fi

if [[ ! -x "$BINARY" ]]; then
    die "Binary $BINARY is not executable"
fi

# ── Clean old data (optional) ───────────────────────────────────────────────

section "Preparing data directories"

for i in 1 2 3; do
    DATA_DIR="$ROOT_DIR/data/node$i"
    if [[ -d "$DATA_DIR" ]]; then
        log_verbose "Removing old data in $DATA_DIR"
        rm -rf "$DATA_DIR"
    fi
    mkdir -p "$DATA_DIR"
    ok "Directory created: $DATA_DIR"
done

# ── Generate configuration files ────────────────────────────────────────────

section "Generating configuration files"

# Node 1 config
cat > "$ROOT_DIR/data/node1/config.toml" <<'TOML'
# IONA node configuration — node 1 (local testnet)
[node]
data_dir  = "./data/node1"
seed      = 1
chain_id  = 6126151
log_level = "info"
keystore  = "plain"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = true
validator_seeds      = [1, 2, 3]

[network]
listen = "/ip4/0.0.0.0/tcp/7001"
peers  = ["/ip4/127.0.0.1/tcp/7002", "/ip4/127.0.0.1/tcp/7003"]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:9001"
enable_faucet = false
cors_allow_all = false

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
TOML

# Node 2 config
cat > "$ROOT_DIR/data/node2/config.toml" <<'TOML'
[node]
data_dir  = "./data/node2"
seed      = 2
chain_id  = 6126151
log_level = "info"
keystore  = "plain"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = true
validator_seeds      = [1, 2, 3]

[network]
listen = "/ip4/0.0.0.0/tcp/7002"
peers  = ["/ip4/127.0.0.1/tcp/7001", "/ip4/127.0.0.1/tcp/7003"]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:9002"
enable_faucet = false
cors_allow_all = false

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
TOML

# Node 3 config
cat > "$ROOT_DIR/data/node3/config.toml" <<'TOML'
[node]
data_dir  = "./data/node3"
seed      = 3
chain_id  = 6126151
log_level = "info"
keystore  = "plain"

[consensus]
propose_timeout_ms   = 300
prevote_timeout_ms   = 200
precommit_timeout_ms = 200
max_txs_per_block    = 4096
gas_target           = 43000000
fast_quorum          = true
initial_base_fee     = 1
stake_each           = 1000
simple_producer      = true
validator_seeds      = [1, 2, 3]

[network]
listen = "/ip4/0.0.0.0/tcp/7003"
peers  = ["/ip4/127.0.0.1/tcp/7001", "/ip4/127.0.0.1/tcp/7002"]
bootnodes = []
enable_mdns = false
enable_kad  = true
reconnect_s = 10

[mempool]
capacity = 200000

[rpc]
listen        = "127.0.0.1:9003"
enable_faucet = false
cors_allow_all = false

[storage]
enable_snapshots = true
snapshot_every_n_blocks = 500
snapshot_keep = 10
snapshot_zstd_level = 3
TOML

ok "Configuration files created"

# ── Start nodes ──────────────────────────────────────────────────────────────

section "Starting nodes"

LOG_DIR="$ROOT_DIR/logs"
if [[ "$KEEP_LOGS" == true ]]; then
    mkdir -p "$LOG_DIR"
    info "Logs will be saved to $LOG_DIR"
fi

PIDS=()
cleanup() {
    echo ""
    info "Shutting down nodes..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [[ "$KEEP_LOGS" != true ]]; then
        rm -rf "$LOG_DIR" 2>/dev/null || true
        for i in 1 2 3; do
            rm -rf "$ROOT_DIR/data/node$i" 2>/dev/null || true
        done
    fi
    ok "Cleanup completed"
}
trap cleanup EXIT INT TERM

start_node() {
    local i=$1
    local data_dir="$ROOT_DIR/data/node$i"
    local log_file="$LOG_DIR/node$i.log"
    local cmd="$BINARY --config $data_dir/config.toml"

    if [[ "$KEEP_LOGS" == true ]]; then
        mkdir -p "$(dirname "$log_file")"
        $cmd >> "$log_file" 2>&1 &
    else
        $cmd > /dev/null 2>&1 &
    fi
    local pid=$!
    PIDS+=($pid)
    echo -n "  Node $i (PID $pid)"

    # Wait for health endpoint
    local rpc_port=$((9000 + i))
    local health_url="http://127.0.0.1:$rpc_port/health"
    for _ in {1..20}; do
        if curl -s -f -o /dev/null "$health_url" 2>/dev/null; then
            echo -e " ${GREEN}✓ healthy${NC}"
            return 0
        fi
        sleep 0.5
    done
    echo -e " ${RED}✗ failed to become healthy${NC}"
    return 1
}

for i in 1 2 3; do
    start_node $i || warn "Node $i may not be fully functional"
done

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
section "Testnet running"
echo -e "  ${BOLD}RPC endpoints:${NC}"
for i in 1 2 3; do
    echo "    http://127.0.0.1:$((9000 + i))/health"
done
echo ""
echo "  Logs: $LOG_DIR/node*.log"
echo ""
echo "  Press ${BOLD}Ctrl+C${NC} to stop all nodes."

# ── Wait for all background processes ────────────────────────────────────────

wait
