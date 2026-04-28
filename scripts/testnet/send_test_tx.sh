#!/usr/bin/env bash
# ============================================================================
# IONA Testnet — Send Test Transactions (fixed)
# ============================================================================
# Sends test transactions to the testnet via custom RPC method 'iona_submitCommand'
# or via standard 'eth_sendRawTransaction' if a private key is provided.
#
# Usage:
#   ./scripts/testnet/send_test_tx.sh [OPTIONS]
#
# Options:
#   --rpc URL          RPC endpoint (default: http://127.0.0.1:19001)
#   --count N          Number of transactions to send (default: 10)
#   --delay MS         Delay between transactions in ms (default: 100)
#   --payload CMD      Transaction payload (default: "set testkey testvalue")
#   --key HEX          Private key to sign transactions (requires 'cast' in PATH)
#   --to ADDRESS       Recipient address (for value transfers, default: none)
#   --value WEI        Amount to send in wei (default: 0)
# ============================================================================

set -euo pipefail

RPC_URL="http://127.0.0.1:19001"
TX_COUNT=10
DELAY_MS=100
PAYLOAD="set testkey testvalue"
PRIVATE_KEY=""
TO_ADDRESS=""
VALUE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --rpc)     RPC_URL="$2"; shift 2 ;;
        --count)   TX_COUNT="$2"; shift 2 ;;
        --delay)   DELAY_MS="$2"; shift 2 ;;
        --payload) PAYLOAD="$2"; shift 2 ;;
        --key)     PRIVATE_KEY="$2"; shift 2 ;;
        --to)      TO_ADDRESS="$2"; shift 2 ;;
        --value)   VALUE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo "============================================"
echo " IONA Testnet — Send Test Transactions"
echo "============================================"
echo " RPC:     $RPC_URL"
echo " Count:   $TX_COUNT"
echo " Delay:   ${DELAY_MS}ms"
echo " Payload: $PAYLOAD"
[[ -n "$PRIVATE_KEY" ]] && echo " Signing: enabled (using cast)"
[[ -n "$TO_ADDRESS" ]] && echo " To:      $TO_ADDRESS"
[[ $VALUE -gt 0 ]] && echo " Value:   $VALUE wei"
echo "============================================"
echo ""

# Helper: JSON-RPC call
json_rpc() {
    local method="$1"
    local params="$2"
    local id="$3"
    curl -s -m 5 -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":$id}"
}

# Check node health
echo "Checking node health..."
if ! curl -s -m 2 "$RPC_URL/health" >/dev/null 2>&1; then
    echo "Error: Node at $RPC_URL is not responding"
    exit 1
fi
echo "  Node is healthy"

# Get block number to confirm RPC works
BLOCK_HEX=$(json_rpc "eth_blockNumber" "[]" 1 | (jq -r '.result' 2>/dev/null || python3 -c "import sys,json; print(json.load(sys.stdin).get('result','0x0'))") 2>/dev/null)
if [[ "$BLOCK_HEX" =~ ^0x[0-9a-f]+$ ]]; then
    echo "  Block height: $((BLOCK_HEX)) ($BLOCK_HEX)"
else
    echo "  Warning: Cannot fetch block height"
fi
echo ""

# Determine how to send a transaction
USE_CAST=0
if [[ -n "$PRIVATE_KEY" ]] && command -v cast >/dev/null 2>&1; then
    USE_CAST=1
    echo "Using 'cast send' for signed transactions"
elif [[ -n "$PRIVATE_KEY" ]] && ! command -v cast >/dev/null 2>&1; then
    echo "Error: --key provided but 'cast' not found in PATH. Please install Foundry."
    exit 1
fi

# Send transactions
SUCCESSES=0
FAILURES=0

for i in $(seq 1 "$TX_COUNT"); do
    # Unique payload
    if date +%s%N 2>/dev/null | grep -q 'N'; then
        UNIQ=$(date +%s%N)
    elif [[ -n "$EPOCHREALTIME" ]]; then
        UNIQ=$(echo "$EPOCHREALTIME" | tr -d '.')
    else
        UNIQ="${i}${RANDOM}$(date +%s)"
    fi
    TX_PAYLOAD="${PAYLOAD} ${UNIQ}"

    if [[ $USE_CAST -eq 1 ]]; then
        # Real signed transaction via cast
        if [[ -n "$TO_ADDRESS" ]]; then
            CMD="cast send --rpc-url \"$RPC_URL\" --private-key \"$PRIVATE_KEY\" \"$TO_ADDRESS\" --value \"$VALUE\""
        else
            # For custom payload, we need to call a contract or use a custom method
            # Here we assume the node accepts a method 'iona_submitCommand'
            CMD="cast rpc --rpc-url \"$RPC_URL\" iona_submitCommand \"$TX_PAYLOAD\""
        fi
        if output=$(eval "$CMD" 2>&1); then
            echo "  [$i/$TX_COUNT] OK (tx hash: ${output:0:66})"
            SUCCESSES=$((SUCCESSES + 1))
        else
            echo "  [$i/$TX_COUNT] FAIL: $output"
            FAILURES=$((FAILURES + 1))
        fi
    else
        # Unsigned command via custom RPC method (assumed)
        RESP=$(json_rpc "iona_submitCommand" "[\"$TX_PAYLOAD\"]" "$i")
        if echo "$RESP" | grep -q '"error"'; then
            ERROR=$(echo "$RESP" | (jq -r '.error.message' 2>/dev/null || python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',{}).get('message','unknown'))") 2>/dev/null)
            echo "  [$i/$TX_COUNT] ERROR: $ERROR"
            FAILURES=$((FAILURES + 1))
        else
            echo "  [$i/$TX_COUNT] OK"
            SUCCESSES=$((SUCCESSES + 1))
        fi
    fi

    # Delay
    if [[ $i -lt $TX_COUNT ]] && [[ $DELAY_MS -gt 0 ]]; then
        sleep "$(awk "BEGIN {printf \"%.3f\", $DELAY_MS/1000}")"
    fi
done

echo ""
echo "============================================"
echo " Results: $SUCCESSES/$TX_COUNT succeeded, $FAILURES failed"
echo "============================================"
echo ""
echo "Final block height:"
json_rpc "eth_blockNumber" "[]" 2 | (jq -r '.result' 2>/dev/null || python3 -c "import sys,json; print(json.load(sys.stdin).get('result','N/A'))") 2>/dev/null | while read -r hex; do
    if [[ "$hex" =~ ^0x[0-9a-f]+$ ]]; then
        echo "  Height: $((hex)) ($hex)"
    else
        echo "  Height: $hex"
    fi
done
