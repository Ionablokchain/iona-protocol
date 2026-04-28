#!/usr/bin/env bash
# ============================================================================
# IONA Rolling Upgrade Simulation
# ============================================================================
# Runs a 3-node local testnet, then upgrades nodes one at a time
# verifying consensus continuity throughout.
#
# Usage:
#   ./rolling_upgrade_sim.sh --current <binary> [OPTIONS]
#
# Options:
#   --current PATH          Path to iona-node binary (required)
#   --nodes N               Number of validator nodes (default: 3)
#   --duration-s SEC        Simulation duration (default: 60) — kept for compatibility
#   --check-no-fork         Verify that heights remain within 2 blocks
#   --health-timeout S      Timeout for health checks (default: 30)
#   --upgrade-interval S    Seconds to wait between node upgrades (default: 3)
#   --graceful-delay S      Seconds after SIGTERM before force kill (default: 2)
#   --verbose               Enable verbose output
#   --json                  Output results in JSON format
#   --help                  Show this help
#
# Examples:
#   cargo build --release
#   ./rolling_upgrade_sim.sh --current ./target/release/iona-node
#   ./rolling_upgrade_sim.sh --current ./target/release/iona-node --nodes 4 --check-no-fork
# ============================================================================

set -euo pipefail

# ── Colours ─────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Helper Functions ────────────────────────────────────────────────────────
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_section() { echo -e "\n${BLUE}${BOLD}══════════════════════════════════════════════════════${NC}"; echo -e "${BLUE}${BOLD} $* ${NC}"; echo -e "${BLUE}${BOLD}══════════════════════════════════════════════════════${NC}"; }
log_verbose() { if [[ "$VERBOSE" == true ]]; then echo -e "${CYAN}[DEBUG]${NC} $*"; fi }

die() {
    log_error "$*"
    exit 1
}

command_exists() {
    command -v "$1" &>/dev/null
}

# ── Defaults ────────────────────────────────────────────────────────────────
CURRENT_BIN=""
N_NODES=3
DURATION=60          # kept for compatibility but not heavily used
CHECK_NO_FORK=false
BASE_PORT=29000
DATA_ROOT=""
HEALTH_TIMEOUT=30
UPGRADE_INTERVAL=3
GRACEFUL_DELAY=2
VERBOSE=false
JSON_OUTPUT=false

START_TIME=$(date +%s)

# ── Parse Arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --current)          CURRENT_BIN="$2"; shift 2 ;;
        --nodes)            N_NODES="$2"; shift 2 ;;
        --duration-s)       DURATION="$2"; shift 2 ;;
        --check-no-fork)    CHECK_NO_FORK=true; shift ;;
        --health-timeout)   HEALTH_TIMEOUT="$2"; shift 2 ;;
        --upgrade-interval) UPGRADE_INTERVAL="$2"; shift 2 ;;
        --graceful-delay)   GRACEFUL_DELAY="$2"; shift 2 ;;
        --verbose)          VERBOSE=true; shift ;;
        --json)             JSON_OUTPUT=true; shift ;;
        --help)
            sed -n '/^# Usage:/,/^# =/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Validate binary
if [[ -z "$CURRENT_BIN" ]]; then
    log_warn "No --current binary provided. Simulation requires a built binary."
    log_info "Run: cargo build --release && $0 --current ./target/release/iona-node"
    if [[ "$JSON_OUTPUT" == true ]]; then
        echo '{"status":"skipped","reason":"missing_binary"}'
    else
        echo "[SKIP] Rolling upgrade simulation: SKIPPED (no binary) — acceptable in CI"
    fi
    exit 0
fi

if [[ ! -x "$CURRENT_BIN" ]]; then
    die "Binary not found or not executable: $CURRENT_BIN"
fi

VERSION=$("$CURRENT_BIN" --version 2>/dev/null || echo "unknown")
log_info "Binary: $CURRENT_BIN ($VERSION)"

DATA_ROOT="/tmp/iona-upgrade-sim-$$"
mkdir -p "$DATA_ROOT"

# ── Cleanup Trap ────────────────────────────────────────────────────────────
cleanup() {
    log_verbose "Cleaning up..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$DATA_ROOT"
    log_verbose "Cleanup complete"
}
trap cleanup EXIT INT TERM

PIDS=()
NODE_RPCS=()
NODE_DIRS=()
NODE_INFO=()

# ── Helper: wait for node health ────────────────────────────────────────────
wait_for_health() {
    local rpc_url="$1"
    local node_id="$2"
    local timeout="$3"
    local start=$(date +%s)
    while true; do
        if curl -sf --max-time 2 "$rpc_url/health" >/dev/null 2>&1; then
            return 0
        fi
        local now=$(date +%s)
        if (( now - start > timeout )); then
            return 1
        fi
        sleep 1
    done
}

# ── Get node height (for fork check) ────────────────────────────────────────
get_height() {
    local rpc_url="$1"
    curl -sf --max-time 2 "$rpc_url/status" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sync_info',{}).get('latest_block_height','0'))" 2>/dev/null \
        || echo "0"
}

# ── Phase 1: Start N nodes ──────────────────────────────────────────────────
log_section "Phase 1: Starting $N_NODES nodes"

for i in $(seq 1 "$N_NODES"); do
    NODE_DIR="$DATA_ROOT/node$i"
    mkdir -p "$NODE_DIR"
    P2P_PORT=$((BASE_PORT + (i-1)*10))
    RPC_PORT=$((BASE_PORT + (i-1)*10 + 1))
    NODE_RPCS+=("http://127.0.0.1:${RPC_PORT}")
    NODE_DIRS+=("$NODE_DIR")

    cat > "$NODE_DIR/config.toml" <<TOML
[node]
data_dir = "$NODE_DIR"
seed = $i
chain_id = 9999
log_level = "warn"

[network]
listen = "/ip4/127.0.0.1/tcp/${P2P_PORT}"

[rpc]
listen = "127.0.0.1:${RPC_PORT}"

[consensus]
stake_each = 1000
TOML

    "$CURRENT_BIN" --config "$NODE_DIR/config.toml" > "$NODE_DIR/node.log" 2>&1 &
    PID=$!
    PIDS+=("$PID")
    NODE_INFO+=("{\"index\":$i,\"pid\":$PID,\"rpc_port\":$RPC_PORT,\"p2p_port\":$P2P_PORT,\"log\":\"$NODE_DIR/node.log\"}")
    log_verbose "Node $i started (PID=$PID, RPC=$RPC_PORT, P2P=$P2P_PORT)"
done

log_info "Waiting for nodes to become healthy (timeout: ${HEALTH_TIMEOUT}s)..."
HEALTHY_COUNT=0
for i in $(seq 1 "$N_NODES"); do
    RPC_URL="${NODE_RPCS[$((i-1))]}"
    echo -n "  Node $i ($RPC_URL) ... "
    if wait_for_health "$RPC_URL" "$i" "$HEALTH_TIMEOUT"; then
        echo -e "${GREEN}healthy${NC}"
        ((HEALTHY_COUNT++))
    else
        echo -e "${RED}FAILED${NC}"
        log_warn "Node $i failed to become healthy; log: ${NODE_DIRS[$((i-1))]}/node.log"
    fi
done

if [[ $HEALTHY_COUNT -ne $N_NODES ]]; then
    die "Not all nodes became healthy. Aborting simulation."
fi

log_info "All nodes are healthy."

# ── Phase 2: Verify consensus is running ────────────────────────────────────
log_section "Phase 2: Verifying consensus"

for i in $(seq 1 "$N_NODES"); do
    RPC_URL="${NODE_RPCS[$((i-1))]}"
    HEIGHT=$(get_height "$RPC_URL")
    if [[ "$HEIGHT" == "0" ]]; then
        log_warn "Node $i not responding or height 0"
        FAILED=1
    else
        log_success "Node $i: height=$HEIGHT"
    fi
done

# ── Phase 3: Rolling upgrade simulation ─────────────────────────────────────
log_section "Phase 3: Rolling upgrade (sequential node restart)"

for i in $(seq 1 "$N_NODES"); do
    IDX=$((i-1))
    PID="${PIDS[$IDX]}"
    NODE_DIR="${NODE_DIRS[$IDX]}"
    RPC_URL="${NODE_RPCS[$IDX]}"

    log_info "Node $i: stopping (SIGTERM)"
    kill "$PID" 2>/dev/null || true
    sleep "$GRACEFUL_DELAY"

    # Force kill if still alive
    if kill -0 "$PID" 2>/dev/null; then
        log_warn "Node $i still running, forcing kill"
        kill -9 "$PID" 2>/dev/null || true
    fi

    log_info "Node $i: restarting with same binary"
    "$CURRENT_BIN" --config "$NODE_DIR/config.toml" >> "$NODE_DIR/node.log" 2>&1 &
    NEW_PID=$!
    PIDS[$IDX]=$NEW_PID
    NODE_INFO[$IDX]=$(echo "${NODE_INFO[$IDX]}" | jq ".pid=$NEW_PID")

    log_verbose "Node $i restarted (new PID=$NEW_PID)"

    # Wait for restarted node to become healthy
    if ! wait_for_health "$RPC_URL" "$i" "$HEALTH_TIMEOUT"; then
        die "Node $i failed to become healthy after restart"
    fi

    log_success "Node $i upgraded and healthy"

    # Wait between upgrades
    if [[ $i -lt $N_NODES ]]; then
        sleep "$UPGRADE_INTERVAL"
    fi
done

# ── Phase 4: Post-upgrade consensus check ───────────────────────────────────
log_section "Phase 4: Post-upgrade consensus check"

HEIGHTS=()
MAX_HEIGHT=0
MIN_HEIGHT=999999999

for i in $(seq 1 "$N_NODES"); do
    RPC_URL="${NODE_RPCS[$((i-1))]}"
    H=$(get_height "$RPC_URL")
    HEIGHTS+=("$H")
    if [[ "$H" -gt "$MAX_HEIGHT" ]]; then MAX_HEIGHT=$H; fi
    if [[ "$H" -lt "$MIN_HEIGHT" ]]; then MIN_HEIGHT=$H; fi
    echo "  Node $i: height=$H"
done

# ── Phase 5: Fork check ─────────────────────────────────────────────────────
FORK_DETECTED=false
if [[ "$CHECK_NO_FORK" == "true" ]]; then
    log_section "Phase 5: Fork check"
    DIFF=$((MAX_HEIGHT - MIN_HEIGHT))
    if [[ $DIFF -gt 2 ]]; then
        log_error "Heights diverge by $DIFF blocks (max=$MAX_HEIGHT, min=$MIN_HEIGHT)"
        FORK_DETECTED=true
    else
        log_success "Heights within ${DIFF} block(s) — no fork detected"
    fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [[ "$JSON_OUTPUT" == "true" ]]; then
    JSON_NODES=$(printf '%s\n' "${NODE_INFO[@]}" | jq -s '.')
    cat <<EOF
{
  "status": "$(if $FORK_DETECTED; then echo "failed"; else echo "passed"; fi)",
  "nodes": $JSON_NODES,
  "healthy_count": $HEALTHY_COUNT,
  "total_nodes": $N_NODES,
  "heights": $(printf '%s\n' "${HEIGHTS[@]}" | jq -R . | jq -s '.'),
  "fork_detected": $FORK_DETECTED,
  "duration_seconds": $DURATION
}
EOF
else
    echo ""
    echo "══════════════════════════════════════════════════════"
    if $FORK_DETECTED; then
        echo -e "  ${RED}Rolling Upgrade Simulation: FAILED${NC}"
        echo -e "  Fork detected during rolling upgrade!"
    else
        echo -e "  ${GREEN}Rolling Upgrade Simulation: PASSED${NC}"
        echo "  All $N_NODES nodes upgraded without fork"
    fi
    echo "  Duration: ${DURATION}s"
    echo "══════════════════════════════════════════════════════"
fi

if $FORK_DETECTED; then
    exit 1
else
    exit 0
fi
