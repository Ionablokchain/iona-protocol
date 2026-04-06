#!/usr/bin/env bash
# Start 4-node IONA testnet locally
# Usage: bash run_testnet.sh
set -euo pipefail

BINARY="${1:-iona-node}"
BASE="$(cd "$(dirname "$0")" && pwd)"
PIDS=()

cleanup() {
    echo "Stopping testnet..."
    kill "${PIDS[@]}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for i in $(seq 1 4); do
    "$BINARY" --config "$BASE/node$i/config.toml" \
        > "$BASE/node$i/node.log" 2>&1 &
    PIDS+=($!)
    echo "Node $i started (PID=${PIDS[-1]}, log=$BASE/node$i/node.log)"
    sleep 0.3
done

echo ""
echo "Testnet running. RPC endpoints:"
for i in $(seq 1 4); do
    echo "  node$i: http://127.0.0.1:$((8540+i))"
done
echo ""
echo "Press Ctrl+C to stop all nodes."
wait
