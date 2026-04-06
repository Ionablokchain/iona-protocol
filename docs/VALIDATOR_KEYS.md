# IONA Validator Key Management

**Validator-grade key security practices for IONA operators**

---

## Key Types

IONA uses multiple key types, each with specific security requirements. Below is a summary:

| Key Type | File | Purpose | Required Permissions | Encryption |
|----------|------|---------|----------------------|------------|
| Validator signing key | `data/keys.enc` | Block proposals & votes (consensus) | 0600 (owner only) | AES-256-GCM |
| Node P2P identity key | `data/node_key.json` | libp2p peer identity | 0600 | None (JSON) |
| Admin TLS key (private) | `tls/admin.key.pem` | mTLS client authentication | 0600 | Optional (PEM-encrypted) |
| Admin TLS cert (public) | `tls/admin.crt.pem` | mTLS certificate | 0644 | No |
| RBAC CA certificate | `tls/ca.crt.pem` | mTLS CA verification | 0644 | No |

### Validator Signing Key (data/keys.enc)

The most critical file. Loss or compromise leads to validator removal or slashing.

- **Format**: AES-256-GCM encrypted ed25519 keypair
- **Permissions**: Must be 0600 (readable/writable by owner only)
- **Location**: Should be on persistent storage (not /tmp or tmpfs)
- **Backup**: Create offline encrypted copy, test restore on testnet before production
- **Rotation**: Supported via `iona keys rotate` (see Key Rotation Procedure below)

### Node P2P Identity Key (data/node_key.json)

Identifies the node on the P2P network. Less critical than signing key, but enables Sybil attacks if leaked.

- **Format**: ed25519 public/private keypair (JSON)
- **Permissions**: Must be 0600
- **Location**: Persistent storage (co-located with validator signing key)
- **Rotation**: Can be rotated without governance approval; changes node identity on network

### Admin TLS Keys (tls/)

Used for administrative API authentication (mTLS). Protect like SSH keys.

- **admin.key.pem**: Private key (0600)
- **admin.crt.pem**: Public certificate (0644)
- **ca.crt.pem**: CA certificate for verification (0644)
- **Expiry**: Automatically tracked in Prometheus metrics
- **Rotation**: `iona admin cert-rotate` command (Enterprise Pack)

---

## iona keys check

IONA provides a command to validate key setup before starting the node.

### Usage

```bash
iona keys check [--strict]
```

### What It Checks

1. **File existence**: Are all required keys present?
2. **File permissions**: Validator/node/admin keys have 0600?
3. **Key validity**: Can keys be parsed and decrypted?
4. **Certificate expiry**: Do admin TLS certs have > 30 days remaining?
5. **Signing WAL**: Is the double-sign guard WAL file readable?

### Example Output (Pass)

```
✓ Validator signing key (data/keys.enc) — valid, encrypted
✓ Node P2P key (data/node_key.json) — valid
✓ Admin TLS key (tls/admin.key.pem) — valid, expires in 180 days
✓ Admin TLS cert (tls/admin.crt.pem) — valid, expires in 180 days
✓ Signing WAL (data/signing.wal) — healthy, 1024 entries
✓ All checks passed
```

### Example Output (Fail)

```
✗ Validator signing key (data/keys.enc) — MISSING (critical)
✗ Node P2P key (data/node_key.json) — permissions 0644 (should be 0600)
⚠ Admin TLS cert (tls/admin.crt.pem) — expires in 5 days (warn)
✗ 2 critical issues, 1 warning
```

### Strict Mode

With `--strict`, the command exits non-zero on any warning (not just errors). Useful in CI/CD pipelines to ensure production readiness.

---

## Double-Sign Protection

IONA prevents validator double-signing through a persistent, WAL-backed guard.

### How It Works

Before signing any block, IONA checks the **signing WAL** (Write-Ahead Log) stored in `data/signing.wal`.

- **WAL Entry Format**: height | round | time_lock | signature_hash
- **Check**: "Have I already signed a block at this height/round?"
- **Action**: If yes, refuse to sign (panic and exit, not a degraded state)
- **Safety**: WAL is persisted to disk before returning block signature to consensus

### The Signing WAL File

**Location**: `data/signing.wal`  
**Format**: Binary log (not human-readable; use `iona doctor` to inspect)  
**Size**: ~64 bytes per entry; a 1-year validator produces ~1.3M blocks ≈ 83 MB

**Never delete this file.** It's the only protection against double-signing. Even brief loss of the WAL can lead to slashing.

### If the WAL Is Corrupted

If you see errors like `WAL corruption detected` or `Failed to load signing.wal`:

1. **STOP the validator immediately**
2. **DO NOT skip the WAL check** (no --unsafe-skip-wal-check flag)
3. **Contact IONA support** at security@example.invalid with:
   - The error message
   - Your validator address
   - Last 5 blocks signed (from blockchain explorer)
4. We will help determine if slashing is likely and advise recovery steps

**Why strict?** Double-signing is unrecoverable and results in permanent loss of stake.

---

## Key Rotation Procedure

Validator signing keys can be rotated without stopping the validator, but requires governance coordination.

### Step-by-Step Rotation

#### Step 1: Generate New Key

On a secure, offline machine:

```bash
iona keys gen-validator --output new_key.enc
# Encrypted AES-256-GCM. You'll be prompted for passphrase.
```

Verify the new key:

```bash
iona keys show new_key.enc --public-only
# Output: validator_key_<hash>
```

#### Step 2: Register with Governance

Submit an on-chain governance proposal to activate the new key at a target height.

```bash
iona tx governance propose \
  --key-rotation \
  --new-key validator_key_<hash> \
  --effective-height 1000000 \
  --from your_validator_address
```

Voting period: standard governance voting window (e.g., 7 days).

#### Step 3: Activate at Target Height

The chain activates the new key automatically at the effective height. IONA will:
1. Stop using old key for signing
2. Accept signatures from new key
3. Broadcast `KeyRotation` event to peers

No manual intervention needed.

#### Step 4: Archive Old Key

Once the network has moved 100 blocks past the rotation height:

```bash
iona keys archive old_key.enc --backup /secure/offline/backup/
```

The old key is encrypted and stored offline. Keep for 1+ years for audit/forensics.

#### Step 5: Verify Signing Works

Monitor your validator for the next 10 blocks. Check:

```bash
iona doctor --check signing
# Output: ✓ Signing with rotated key (2 blocks since rotation)
```

If signing stops, rollback to old key:

```bash
iona keys activate old_key.enc
iona node --resume  # Restart signing with old key
```

### Key Rotation Timeline

| Step | Duration | Action |
|------|----------|--------|
| Generate new key | 1 minute | Offline, local |
| Governance proposal | 7 days | On-chain voting |
| Activation | 1 block | Automatic at effective height |
| Archive old key | 1 hour | Move to offline backup |
| Verification | 5 minutes | Monitor signing with `iona doctor` |
| **Total** | **~7 days** | |

---

## Remote Signer Setup

For maximum security, IONA supports signing on a separate air-gapped machine via the `iona-remote-signer` binary.

### Use Case

Validator machine runs on the internet (P2P, RPC open). Signing machine is air-gapped and only receives signing requests over a secure channel (mTLS, ssh tunnel, etc.).

- Validator never has private key in memory
- Even if validator is compromised, attacker cannot sign without the remote signer machine
- Signing machine can run on hardware with minimal attack surface (bare metal, no cloud)

### Configuration

In the validator node's `config.toml`:

```toml
[signing]
mode = "remote"
remote_signer_address = "https://signer.internal:7778"
remote_signer_cert = "tls/signer_client.crt.pem"
remote_signer_key = "tls/signer_client.key.pem"
remote_signer_ca = "tls/signer_ca.crt.pem"
```

### Remote Signer Binary

On the air-gapped machine:

```bash
# Copy keys.enc to signer machine (via secure channel)
scp -i key.pem data/keys.enc signer@air-gapped-machine:/var/lib/iona/

# Start the remote signer
iona-remote-signer \
  --keys-file /var/lib/iona/keys.enc \
  --listen 0.0.0.0:7778 \
  --tls-cert tls/signer.crt.pem \
  --tls-key tls/signer.key.pem
```

The remote signer listens for signing requests and responds with signatures. It does NOT participate in consensus or validation; purely a signing service.

### Security Benefits

1. **Isolation**: Signing keys never exposed to internet-facing validator
2. **Atomicity**: Each signing request is atomic (either succeeds or fails completely)
3. **Auditability**: Remote signer logs all signing requests with timestamps
4. **Hardware**: Can run on minimal hardware (Raspberry Pi, bare metal, HSM-backed)

---

## HSM / KMS Integration (Enterprise)

IONA's signing interface is pluggable, allowing integration with hardware security modules and key management services.

### Pluggable Signer Trait

The core trait is defined in `src/crypto/signer.rs`:

```rust
pub trait Signer {
    fn public_key(&self) -> PublicKey;
    fn sign(&mut self, msg: &[u8]) -> Result<Signature>;
}
```

Any implementation satisfying this trait can be used as a validator's signer.

### Vault Transit (HashiCorp Vault)

Example integration (Enterprise Pack includes full implementation):

```toml
[signing]
mode = "vault"
vault_addr = "https://vault.internal:8200"
vault_token = "s.XXXXXXXXXXXXX"
vault_key_name = "iona-validator-key"
```

Benefits:
- Keys never leave Vault
- Audit logs of all signing operations
- Key versioning and rotation
- HA Vault cluster for availability

### AWS KMS

Example config:

```toml
[signing]
mode = "aws-kms"
kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
aws_region = "us-east-1"
```

Benefits:
- AWS CloudTrail logs all signing requests
- Keys protected by AWS hardware
- Automatic key rotation (KMS managed)
- Cost: ~$1/month per key + $0.03 per signing operation

### GCP Cloud KMS

Example config:

```toml
[signing]
mode = "gcp-kms"
gcp_project = "my-project"
gcp_location = "us-central1"
gcp_keyring = "iona-validators"
gcp_key = "validator-key-1"
```

Benefits:
- Google Cloud Audit Logs
- Multi-region replication available
- CMEK (Customer Managed Encryption Keys) for compliance

### PKCS#11 (Hardware HSMs)

For YubiHSM, Thales, or other PKCS#11-compatible devices:

```toml
[signing]
mode = "pkcs11"
pkcs11_library = "/usr/lib/libykcs11.so"
pkcs11_slot = 0
pkcs11_pin = "1234"
pkcs11_label = "IONA Validator Key"
```

Benefits:
- Hardware-backed keys (never in software)
- Tamper-evident if device is opened
- Offline key generation possible
- High-security deployments (institutional)

---

## Disaster Recovery

### If Keys Are Lost

If your `data/keys.enc` is permanently lost, your validator is removed from the set at the next governance epoch.

- No slashing (keys were lost, not compromised)
- Delegators' stakes are returned
- You must regenerate keys and re-register to re-join the validator set

### Backup Policy

Recommended backup strategy:

1. **Offline Encrypted Backup**: Create a copy of `data/keys.enc` on encrypted external storage
   ```bash
   gpg --symmetric data/keys.enc  # Creates keys.enc.gpg
   cp keys.enc.gpg /mnt/secure-backup/
   ```

2. **Verify Restore Works**: On a testnet machine, decrypt and verify:
   ```bash
   gpg --output keys.enc.restored data/keys.enc.gpg
   iona keys check keys.enc.restored  # Should pass
   ```

3. **Split Backup**: For very high-value validators, split the backup across 2 trusted parties using Shamir secret sharing:
   ```bash
   ssss-split -t 2 -n 3 < data/keys.enc  # 2-of-3 threshold
   # Distribute shares to 3 trusted parties, any 2 can reconstruct
   ```

4. **Never Store Backup on Same Machine**: If your validator machine is compromised, offline backup is the only recovery.

### Key Loss Mitigation

- Use remote signer (keys on air-gapped machine)
- Use HSM (keys in hardware)
- Regular offline backup tests on testnet
- Multiple independent backup copies

---

## Checklist Before Going Live

Before running a mainnet IONA validator, complete all items:

- [ ] `iona keys check` passes all checks (no warnings with --strict)
- [ ] Signing WAL (`data/signing.wal`) is on persistent storage (not tmpfs)
- [ ] Remote signer configured and tested (recommended for mainnet)
- [ ] Offline encrypted backup of `data/keys.enc` created
- [ ] Backup restore tested on testnet validator (you recovered and signed blocks)
- [ ] Key rotation procedure understood and practiced on testnet
- [ ] mTLS admin certificates generated and installed
- [ ] RBAC policy defined (`config/rbac.toml`)
- [ ] `iona doctor` reports no issues
- [ ] Monitoring stack connected (Prometheus + Grafana)
- [ ] Runbooks reviewed (ops/runbooks/*)
- [ ] Disaster recovery tabletop exercise completed (with team)
- [ ] Support tier selected (Community/Professional/Enterprise)

Once all items are checked, you're ready to join the network.

---

## Further Reading

- **Security Posture**: See `../SECURITY_POSTURE.md` for details on audit logging and consensus safety
- **Monitoring**: See `../ops/monitoring-quickstart.md` for setting up alerts and SLO dashboards
- **Enterprise Features**: See `../ENTERPRISE.md` for HSM/KMS, managed upgrades, and support contracts
- **Cosmos Validator Migration**: See `../adapters/cosmos/migrate_validator.md` if migrating from CometBFT
