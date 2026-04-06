#!/bin/bash
set -e

# Setup script for IONA testnet
# Creates directories, generates keys, and initializes genesis state

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
CONFIGS_DIR="$SCRIPT_DIR/configs"

echo "=========================================="
echo "IONA Testnet v28.7.0 Setup"
echo "=========================================="
echo ""

# Verify configuration files exist
if [ ! -f "$CONFIGS_DIR/genesis.json" ]; then
  echo "ERROR: genesis.json not found at $CONFIGS_DIR/genesis.json"
  exit 1
fi

for i in 1 2 3 4; do
  if [ ! -f "$CONFIGS_DIR/validator-$i.toml" ]; then
    echo "ERROR: validator-$i.toml not found"
    exit 1
  fi
done

echo "Creating data directories..."
mkdir -p "$DATA_DIR/validator-1"
mkdir -p "$DATA_DIR/validator-2"
mkdir -p "$DATA_DIR/validator-3"
mkdir -p "$DATA_DIR/validator-4"

echo "Initializing genesis files..."
for i in 1 2 3 4; do
  cp "$CONFIGS_DIR/genesis.json" "$DATA_DIR/validator-$i/genesis.json"
  chmod 644 "$DATA_DIR/validator-$i/genesis.json"
  echo "  Copied genesis to validator-$i"
done

echo ""
echo "Generating validator keys..."

# Try using iona-cli if available, otherwise generate with openssl
if command -v iona-cli >/dev/null 2>&1; then
  echo "Using iona-cli keygen..."
  for i in 1 2 3 4; do
    if [ ! -f "$DATA_DIR/validator-$i/validator_key.json" ]; then
      iona-cli keygen --seed "$((1000 + i))" --output "$DATA_DIR/validator-$i/validator_key.json"
      echo "  Generated key for validator-$i"
    fi
  done
elif command -v openssl >/dev/null 2>&1; then
  echo "Using openssl for key generation..."
  for i in 1 2 3 4; do
    if [ ! -f "$DATA_DIR/validator-$i/validator_key.pem" ]; then
      openssl genrsa -out "$DATA_DIR/validator-$i/validator_key.pem" 2048 2>/dev/null
      openssl rsa -in "$DATA_DIR/validator-$i/validator_key.pem" -pubout -out "$DATA_DIR/validator-$i/validator_key.pub" 2>/dev/null
      echo "  Generated key for validator-$i"
    fi
  done
else
  echo "WARNING: Neither iona-cli nor openssl found. Keys must be generated manually."
  echo "Skipping key generation. You can generate them later with:"
  echo "  iona-cli keygen --seed 1001 --output $DATA_DIR/validator-1/validator_key.json"
fi

echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""

echo "Quick Start:"
echo "  1. Start the testnet:"
echo "     cd $SCRIPT_DIR && docker-compose up -d"
echo ""
echo "  2. Wait ~15 seconds for consensus to start"
echo ""
echo "  3. Check health of validators:"
echo "     curl http://localhost:9001/health"
echo "     curl http://localhost:9011/health"
echo "     curl http://localhost:9021/health"
echo "     curl http://localhost:9031/health"
echo ""
echo "  4. Get chain status:"
echo "     curl http://localhost:9001/status | jq '.result.sync_info'"
echo ""
echo "  5. View logs:"
echo "     docker-compose logs -f validator-1"
echo ""
echo "  6. Access Prometheus dashboard:"
echo "     http://localhost:9090"
echo ""
echo "  7. Stop the testnet:"
echo "     docker-compose down"
echo ""
echo "  8. Reset chain data and start fresh:"
echo "     docker-compose down && rm -rf $DATA_DIR && ./setup.sh && docker-compose up -d"
echo ""

echo "Testnet Configuration:"
echo "  Chain ID: iona-testnet-1"
echo "  Validators: 4 (full BFT consensus)"
echo "  Block Time: 1000ms (1 block/second)"
echo "  RPC Ports: 9001, 9011, 9021, 9031 (localhost)"
echo "  P2P Ports: 7001, 7011, 7021, 7031 (localhost)"
echo "  Metrics: Prometheus at http://localhost:9090"
echo ""
