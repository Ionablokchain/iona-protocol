# Migrating a Cosmos Validator to IONA

**Step-by-step guide for moving a running CometBFT validator to IONA**

---

## WARNING

> ⚠️ **CRITICAL**: Never run two validator instances with the same key simultaneously. This will result in double-signing, slashing, and permanent loss of stake.
>
> You must shut down the CometBFT validator BEFORE starting the IONA validator.

---

## Prerequisites

Before you start, ensure you have:

- **IONA v28.3 or later** (build from source or download binary)
- **jq** (JSON parser) — install via apt/brew/dnf
- **openssl** (usually pre-installed)
- **Existing CometBFT validator** with `~/.cosmos/config/priv_validator_key.json` accessible
- **Backup of your keys** (encrypted, offline)
- **Testnet experience** (have you run a validator on testnet? Do that first!)

Check IONA is installed:

```bash
iona --version
# Should output: iona v28.3.x
```

---

## Step 1: Export Your Keys

On your live CometBFT validator machine:

### Option A: Securely Copy to Migration Machine

If your validator is on a different machine:

```bash
# From your laptop/secure machine
scp -i ~/.ssh/validator.key validator@cosmos-node:~/.cosmos/config/priv_validator_key.json .
scp -i ~/.ssh/validator.key validator@cosmos-node:~/.cosmos/config/node_key.json .
```

### Option B: Manual Export (Air-Gapped)

If your validator is air-gapped, use a USB stick or secure channel.

Copy these files to a migration machine (not your live validator):
- `~/.cosmos/config/priv_validator_key.json` (the signing key)
- `~/.cosmos/config/node_key.json` (the P2P identity)
- `~/.cosmos/config/config.toml` (the configuration)

---

## Step 2: Convert Key Format

On the migration machine, use the IONA adapter:

```bash
cd iona/adapters/cosmos

# Verify the script exists and is executable
ls -la key_import.sh
# -rwxr-xr-x key_import.sh

# Run the converter
./key_import.sh priv_validator_key.json
```

### What the Script Does

1. Parses the base64-encoded ed25519 private key from the JSON
2. Displays the public key in hex format (for verification)
3. Shows you the next steps for encryption

**Example output**:

```
--- IONA Cosmos Adapter: Key Import ---

✓ File exists: priv_validator_key.json
✓ jq installed

[+] Parsing private key...
Private key (base64): OTeO7BhS...a2F1dXhU  [truncated]

[+] Converting to hex...
Public key (hex): 5A7B3E9C2D1F4A6B8E0C9D2F1A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A

[+] Next steps:
1. Copy the public key hex above
2. Run: iona keys import priv_validator_key.json --output keys.enc
3. You will be prompted for a passphrase (use a strong passphrase!)

[+] Verification:
Run this on your IONA node to verify the key:
  iona keys check keys.enc
  iona keys show keys.enc --public-only
```

---

## Step 3: Encrypt the Key with IONA

Using the IONA binary, encrypt the key:

```bash
# On the migration machine (or your soon-to-be IONA validator)
iona keys import priv_validator_key.json --output keys.enc

# You'll be prompted:
# Enter passphrase:
# Confirm passphrase:
```

**Important**: Choose a strong passphrase (20+ characters, mixed case, symbols).

### Verify the Encryption

```bash
iona keys check keys.enc
# Should output:
# ✓ Validator signing key (data/keys.enc) — valid, encrypted

iona keys show keys.enc --public-only
# Should show your public key in hex
```

---

## Step 4: Convert Configuration

Convert your CometBFT config to IONA format:

```bash
cd iona/adapters/cosmos

./convert_config.sh ~/.cosmos/config/config.toml > iona_config.toml
```

Review the generated `iona_config.toml`:

```bash
# Check peer addresses are in multiaddr format
grep "persistent_peers" iona_config.toml
# Should look like: /ip4/1.2.3.4/tcp/7001/p2p/Qm...

# Check ports (adjust if needed)
grep -E "^\[rpc\]|^\[networking" iona_config.toml
```

Port mapping table (update if needed):

| Service | CometBFT | IONA | Your Setting |
|---------|----------|------|---|
| P2P | 26656 | 7001 | ??? |
| RPC | 26657 | 9001 | ??? |

If you use non-standard ports, manually edit `iona_config.toml` after conversion.

---

## Step 5: Test on IONA Testnet First

**DO NOT skip this step.** Test your key import on testnet before touching mainnet.

### 5a. Initialize IONA Testnet Node

```bash
# Create a fresh testnet directory
mkdir -p ~/.iona-testnet
cd ~/.iona-testnet

# Initialize with testnet config
iona init --chain-id iona-testnet-1 --home ~/.iona-testnet

# Copy your imported key
cp keys.enc ~/.iona-testnet/data/
```

### 5b. Start IONA Testnet Validator

```bash
iona node \
  --home ~/.iona-testnet \
  --chain-id iona-testnet-1 \
  --rpc.laddr "tcp://127.0.0.1:9001"

# Watch for logs indicating successful signing
# Look for lines like:
# [INFO] consensus: signed block height=1234
```

### 5c. Verify Signing

In another terminal:

```bash
# Check if blocks are being signed
iona query block -H 127.0.0.1:9001 | jq '.block.header.height'

# Should increase every ~5 seconds (one block per 5s on testnet)
```

Monitor for at least 10 blocks (~50 seconds). If signing stops, check logs:

```bash
grep ERROR ~/.iona-testnet/iona.log
# Look for any signing errors or key issues
```

### 5d. Verify with iona doctor

```bash
iona doctor --home ~/.iona-testnet
# Should report:
# ✓ Signing is healthy
# ✓ Peer connectivity: N peers
# ✓ RPC is accessible
```

If everything passes, you're ready for mainnet.

---

## Step 6: Coordinated Cutover

Now move to your live validator. Timing is critical.

### 6a. Plan Downtime Window

Coordinate with the IONA community (if this is a public mainnet):
- Pick a time when network load is low
- Notify other validators you're rotating keys (if relevant)
- Estimate downtime: 2-5 minutes (stop CometBFT, start IONA)

### 6b. Stop CometBFT Validator

```bash
# SSH into your live validator
ssh validator@cosmos-node

# Stop the validator gracefully
systemctl stop cosmostend  # Or whatever your service is named
# OR: pkill -TERM cosmos  # (if running manually)

# Verify it stopped
ps aux | grep cosmos
# Should show no running instances

# Wait 10 seconds for graceful shutdown of any pending blocks
sleep 10
```

### 6c. Backup Your Current Keys

Before deploying IONA, back up your CometBFT keys (just in case):

```bash
tar czf cosmos-validator-backup-$(date +%s).tar.gz ~/.cosmos/config/
cp cosmos-validator-backup-*.tar.gz /secure/offline/backup/
```

### 6d. Deploy IONA Node

Copy the converted key and config to your validator machine:

```bash
# From migration machine
scp -i ~/.ssh/validator.key keys.enc validator@cosmos-node:~/iona-migration/
scp -i ~/.ssh/validator.key iona_config.toml validator@cosmos-node:~/iona-migration/

# On the validator machine, set up IONA
mkdir -p ~/.iona/data
cp ~/iona-migration/keys.enc ~/.iona/data/
cp ~/iona-migration/iona_config.toml ~/.iona/config.toml

# Verify key is readable
iona keys check ~/.iona/data/keys.enc
```

### 6e. Start IONA Validator

```bash
# Start IONA as a service (recommended)
systemctl start iona

# Or manually (for testing):
iona node --home ~/.iona --chain-id iona-mainnet-1

# Watch logs for successful signing
# Should see: "[INFO] consensus: signed block height=1234567"
```

### 6f. Verify Signing Within 1 Block

Within 30 seconds, IONA should sign at least one block. Check:

```bash
# In another terminal
iona query block --home ~/.iona | jq '.block.proposed_by'
# Should show your validator address

# Or check the chain explorer
# Your validator address should have signing activity
```

If signing succeeds, you're done! Monitor for the next 10 blocks (~50s) to ensure stability.

---

## Step 7: Monitor for Missed Blocks

After cutover, monitor your validator's performance for 1 hour:

```bash
# Check signing rate
iona query validator-signing-info $(iona keys show mykey -a)

# Healthy: 0 missed blocks after starting
# Bad: > 5 missed blocks indicates signing issues
```

If missed blocks spike, proceed to Rollback Plan (below).

---

## Rollback Plan

If IONA fails to sign after 2 minutes, you have a quick rollback:

### Immediate Rollback

```bash
# Stop IONA
systemctl stop iona

# Restart CometBFT with old key
systemctl start cosmostend

# Verify it signs within 30s
ps aux | grep cosmos  # Should show running
```

### Why Rollback Works

- IONA's signing WAL is separate from CometBFT's WAL
- No conflict between the two systems
- CometBFT will resume from where it left off (no re-initialization needed)

### Long-Term Recovery

If rollback is needed:

1. Check why IONA failed (logs, key permissions, disk space)
2. Fix the issue on a testnet validator first
3. Retry cutover at a later time

---

## Success Criteria

You have successfully migrated when:

- [ ] Key import succeeded (iona keys check passed)
- [ ] Testnet validator signed 10+ blocks without errors
- [ ] Mainnet cutover completed (CometBFT stopped, IONA started)
- [ ] IONA signed at least 1 block on mainnet within 30 seconds
- [ ] No missed blocks reported after 1 hour
- [ ] Validator remains in active set (check chain explorer)

---

## Post-Migration

Once stable, you can:

- Remove the CometBFT binary to free space
- Rotate your node key (optional, improves privacy)
- Set up remote signer for additional security
- Configure HSM/KMS if Enterprise subscriber

See `../../docs/VALIDATOR_KEYS.md` for next steps.

---

## Troubleshooting

### Signing Doesn't Start

**Symptom**: IONA starts but no blocks are signed

**Check**:
1. Is the key file readable? `ls -la ~/.iona/data/keys.enc` should be 0600
2. Is IONA connected to peers? `iona query peers` should show > 0
3. Check logs: `journalctl -u iona -f` for errors

**Fix**:
```bash
# Verify key format
iona keys check ~/.iona/data/keys.enc

# Restart with verbose logging
iona node --home ~/.iona --log-level debug

# Check if you're in the validator set
iona query validators | jq '.validators[] | select(.address == "YOUR_ADDRESS")'
```

### Config Conversion Errors

**Symptom**: `convert_config.sh` crashes or produces invalid TOML

**Fix**:
```bash
# Validate the output manually
toml-cli check iona_config.toml

# Or convert key values manually by comparing:
diff <(jq -S . ~/.cosmos/config/config.json) <(jq -S . iona_config.toml)
```

### Key Permission Issues

**Symptom**: "Permission denied" when reading keys.enc

**Fix**:
```bash
# Set correct permissions
chmod 0600 ~/.iona/data/keys.enc

# Verify
ls -la ~/.iona/data/keys.enc
# Should show: -rw------- (0600)
```

---

## Getting Help

- **Cosmos validator questions**: Ask in the IONA community Slack
- **Key migration issues**: Contact security@example.invalid
- **Production support**: Email enterprise@example.invalid
