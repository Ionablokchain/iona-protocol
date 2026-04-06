# IONA Testnet v28.4.0

A fully reproducible 4-validator Byzantine Fault Tolerant testnet for local development, testing, and demonstrations of IONA blockchain consensus.

## Overview

This testnet spins up 4 IONA validators in Docker containers, each running the full BFT consensus protocol:

- **Validator-1**: RPC on 9001, P2P on 7001, Metrics on 6001
- **Validator-2**: RPC on 9011, P2P on 7011, Metrics on 6011
- **Validator-3**: RPC on 9021, P2P on 7021, Metrics on 6021
- **Validator-4**: RPC on 9031, P2P on 7031, Metrics on 6031

All validators are configured for full mesh P2P connectivity and produce blocks every ~1 second.

## Features

- 4 validators with equal stake (1M tokens each)
- Full Byzantine Fault Tolerant consensus (3+ honest validators required)
- Cosmos-compatible key management
- Enterprise-grade RBAC and audit logging
- Prometheus metrics endpoint on each validator
- Centralized Prometheus at http://localhost:9090
- Health checks on each container
- Auto-restart on failure

## Prerequisites

- **Docker**: 24.0 or later
- **Docker Compose**: v2.0 or later
- **RAM**: 4 GB minimum (2 GB for validators, 1 GB for Prometheus, 1 GB buffer)
- **Disk Space**: 10 GB
- **Network**: Ports 9001-9031 (RPC), 7001-7031 (P2P), 9090 (Prometheus) available

Check installed versions:
```bash
docker --version
docker-compose --version
```

## Quick Start

### 1. Setup (5 seconds)

```bash
cd testnet
./setup.sh
```

This creates:
- Data directories for each validator
- Genesis configuration for all validators
- Validator keys (if iona-cli or openssl available)

### 2. Start Testnet (10 seconds)

```bash
docker-compose up -d
```

### 3. Verify All Validators Are Running

Wait ~10 seconds for consensus to catch up, then check:

```bash
# Check health status
curl http://localhost:9001/health
curl http://localhost:9011/health
curl http://localhost:9021/health
curl http://localhost:9031/health

# Expected output: {"status": "healthy"}
```

### 4. Get Chain Status

```bash
curl http://localhost:9001/status | jq '.result.sync_info'
```

Expected output:
```json
{
  "latest_block_height": 45,
  "latest_block_time": "2024-01-01T00:00:45Z",
  "catching_up": false
}
```

### 5. View Logs

```bash
# View logs for a specific validator
docker-compose logs -f validator-1

# View all logs
docker-compose logs -f

# View last 50 lines
docker-compose logs --tail 50
```

### 6. Access Prometheus Dashboard

Open browser at http://localhost:9090

### 7. Stop Testnet

```bash
docker-compose down
```

## Architecture Diagram

```
                    IONA Testnet (iona-testnet-1)
                    Chain ID: iona-testnet-1
                    Consensus: BFT (4 validators)
                    Block Time: 1000ms

┌─────────────────────────────────────────────────────┐
│                 Docker Network (Bridge)              │
│                  172.20.0.0/24                       │
├─────────────────────────────────────────────────────┤
│                                                       │
│  Validator-1 (172.20.0.11)  ←→  Validator-2        │
│     RPC: 9001                    RPC: 9011           │
│     P2P: 7001                    P2P: 7011           │
│        ↑                            ↑                │
│        └─────────────────┬──────────┘                │
│                          │                           │
│  Validator-3 (172.20.0.13)  ←→  Validator-4        │
│     RPC: 9021                    RPC: 9031           │
│     P2P: 7021                    P2P: 7031           │
│        ↑                            ↑                │
│        └─────────────────┬──────────┘                │
│                          │                           │
│                   Prometheus (Port 9090)             │
│                   Scrapes all metrics                │
│                                                       │
└─────────────────────────────────────────────────────┘
```

## Using the Testnet

### Submit a Test Transaction

```bash
# Get an account address (from genesis)
ADDRESS="iona1q9m5lsruqrsx4lqm9j8xqu8rza5hfqz7e8r6c5"

# Get nonce
curl http://localhost:9001/account/$ADDRESS | jq '.result.nonce'

# Submit transaction
curl -X POST http://localhost:9001/tx \
  -H "Content-Type: application/json" \
  -d '{
    "from": "'$ADDRESS'",
    "to": "iona1q9m5lsruqrsx4lqm9j8xqu8rza5hfqz7e9s7d6",
    "amount": 100,
    "nonce": 0
  }'
```

### Query Validator Set

```bash
curl http://localhost:9001/validators | jq '.result.validators'
```

Expected: 4 validators with equal power (1000000 each)

### Query Account Balance

```bash
curl http://localhost:9001/account/iona1q9m5lsruqrsx4lqm9j8xqu8rza5hfqz7e8r6c5 | jq '.result.balance'
```

### Get Block by Height

```bash
# Latest block
curl http://localhost:9001/block | jq '.result.block.header'

# Specific height
curl http://localhost:9001/block/10 | jq '.result.block.header'
```

### Monitor Metrics with Prometheus

Access http://localhost:9090

Example queries:
```
# Blocks produced per minute
rate(iona_blocks_total[1m])

# Consensus round durations (milliseconds)
iona_consensus_round_duration_ms

# Network peers connected per validator
iona_network_peers_total

# RPC request latency (milliseconds)
histogram_quantile(0.95, rate(iona_rpc_request_duration_ms_bucket[5m]))
```

## Troubleshooting

### Validators Won't Start

**Check Docker images**:
```bash
docker images | grep iona
```

If `iona/iona-node:28.4.0` is missing, build it:
```bash
cd ..
docker build -t iona/iona-node:28.4.0 .
cd testnet
docker-compose up -d
```

**Check logs**:
```bash
docker-compose logs validator-1
```

Common errors:
- Port already in use: `sudo ss -tlnp | grep -E ':9[0-3][0-9][0-9]|:7[0-3][0-9][0-9]'`
- Insufficient memory: `free -h`
- Docker daemon not running: `sudo systemctl start docker`

### Consensus Stuck / No Blocks

**Wait longer** (up to 30 seconds for initial sync)

**Check peer connectivity**:
```bash
curl http://localhost:9001/peers | jq '.result.peers'
```

Should show 3 peers for validator-1. If empty, check Docker network:
```bash
docker network inspect testnet_iona-testnet
```

All 4 validators should be connected to the network.

**Check system time**:
```bash
date
timedatectl
```

All containers must have synchronized system time. If skewed, restart Docker:
```bash
docker-compose restart
```

### High CPU/Memory Usage

Check which container:
```bash
docker stats
```

If specific validator is high:
- Restart that validator: `docker-compose restart validator-1`
- Check for large blocks: `curl http://localhost:9001/block | jq '.result.block | length'`
- Reduce block time in config (if needed for testing)

### Network Timeouts

If seeing connection timeouts in logs:

1. Check Docker network is isolated:
   ```bash
   docker network ls
   docker network inspect testnet_iona-testnet
   ```

2. Check firewall isn't blocking localhost:
   ```bash
   netstat -tlnp | grep -E ':9[0-3][0-9][0-9]|:7[0-3][0-9][0-9]'
   ```

3. Restart all containers:
   ```bash
   docker-compose restart
   ```

### Reset Chain Data

To start fresh with a clean chain:

```bash
# Stop all containers
docker-compose down

# Remove all data
rm -rf data/

# Regenerate genesis
./setup.sh

# Start fresh
docker-compose up -d
```

## Configuration Details

### Genesis Configuration

File: `configs/genesis.json`

- **chain_id**: `iona-testnet-1`
- **validators**: 4 validators with equal stake
- **block_time_ms**: 1000 (1 block per second)
- **max_block_gas**: 10,000,000
- **min_gas_price**: 1
- **initial_balances**: 4 validators + 1 faucet account

### Validator Configuration

Files: `configs/validator-1.toml` through `configs/validator-4.toml`

Each validator has:
- **node.chain_id**: `iona-testnet-1`
- **node.profile**: `prod`
- **network.listen**: `0.0.0.0:7001` (inside container)
- **network.peers**: Other 3 validators by container name
- **rpc.listen**: `0.0.0.0:9001` (inside container)
- **rpc.cors_allowed_origins**: `["*"]` (allow all for testing)
- **consensus timeouts**: 1000ms (1 second blocks)
- **security.rbac_enabled**: `true`
- **security.audit_logging_enabled**: `true`

### Docker Compose Configuration

File: `docker-compose.yml`

- **Image**: `iona/iona-node:28.4.0`
- **Network**: `iona-testnet` (bridge mode, 172.20.0.0/24)
- **Healthchecks**: Every 10 seconds on RPC `/health` endpoint
- **Restart**: `unless-stopped` (auto-restart on crash)
- **Resource limits**: 
  - File descriptors: 65536
  - Memory: Default system limits (can be configured)

### Prometheus Configuration

File: `prometheus/prometheus.yml`

- **Scrape interval**: 15 seconds
- **Evaluation interval**: 15 seconds
- **Targets**: All 4 validators on metrics port 6001
- **Labels**: `network=iona-testnet-1`

## Production Considerations

This testnet is for **development and testing only**. For production:

1. **Security**:
   - Change default keys and seeds
   - Enable firewall rules (restrict P2P/RPC access)
   - Use HSM/KMS for validator keys (via iona-remote-signer)
   - Enable TLS on RPC endpoints

2. **Performance**:
   - Increase block time for lower network load
   - Adjust consensus timeouts based on network latency
   - Use dedicated hardware for validators
   - Monitor with Prometheus + Grafana

3. **Monitoring**:
   - Set up alerting rules for missed blocks
   - Monitor validator voting power changes
   - Track chain halt conditions
   - Log all security events

4. **Backups**:
   - Regularly backup `/var/lib/iona` (chain state)
   - Backup `/etc/iona/config.toml` (validator config)
   - Backup validator keys securely
   - Test restore procedures

## Advanced Usage

### Custom Genesis

Modify `configs/genesis.json` before running `./setup.sh`:

```json
{
  "chain_id": "my-custom-testnet",
  "validators": [
    {
      "pubkey": "...",
      "power": 1000000,
      "address": "..."
    }
  ],
  ...
}
```

### Modify Block Time

Edit `configs/validator-*.toml`, change:
```toml
[node]
block_time_ms = 5000  # 5 second blocks instead of 1 second
```

Then restart:
```bash
docker-compose restart
```

### Enable Debug Logging

```bash
# View with debug logging
RUST_LOG=debug docker-compose up validator-1
```

### Attach to Running Container

```bash
docker exec -it iona-validator-1 /bin/bash
```

View logs from inside:
```bash
tail -f /var/log/iona/audit.log
tail -f /var/log/iona/*.log
```

### Performance Testing

With testnet running:
```bash
# Send 100 transactions per second for 60 seconds
for i in {1..6000}; do
  curl -X POST http://localhost:9001/tx \
    -H "Content-Type: application/json" \
    -d '{"from":"iona1...", "to":"iona2...", "amount":1, "nonce":'$i'}' &
  if [ $((i % 100)) -eq 0 ]; then sleep 1; fi
done
wait
```

Monitor with Prometheus: `iona_blocks_total` should stay steady despite load.

## Cleanup

### Stop and Keep Data

```bash
docker-compose down
```

Data persists in `./data/`

### Full Cleanup

```bash
docker-compose down
rm -rf data/ .env
```

## Support

- **Repository**: https://github.com/iona/iona
- **Documentation**: https://docs.iona.network
- **Issues**: https://github.com/iona/iona/issues
- **Discord**: https://discord.gg/iona

## License

IONA is licensed under Apache License 2.0. See LICENSE in the repository.
