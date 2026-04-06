# IONA Node Debian Package

Production-grade Debian package for IONA v28.4.0 blockchain node with Byzantine Fault Tolerant consensus.

## Contents

This package includes:
- `iona-node`: Main consensus and networking daemon
- `iona-cli`: Command-line management tool
- `iona-remote-signer`: HSM/KMS remote signing proxy
- `iona-node.service`: Systemd service for automatic startup
- Default configuration at `/etc/iona/config.toml.default`

## Building the Package

### Prerequisites

On Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y build-essential devscripts debhelper cargo rustc libssl-dev pkg-config
```

Or use `fpm` (recommended for faster builds):
```bash
sudo apt-get install -y ruby ruby-dev
sudo gem install fpm
```

### Build

From the repository root:

```bash
./packaging/deb/build-deb.sh
```

This will:
1. Check for required tools (dpkg-buildpackage or fpm)
2. Run `cargo build --release`
3. Strip binaries for smaller package size
4. Create `iona-node_28.4.0_amd64.deb`
5. Optionally sign if `$GPG_KEY` is set and `dpkg-sig` is available

Output will be placed in the repository root:
```
iona-node_28.4.0_amd64.deb
```

## Installation

### Clean Install

```bash
sudo dpkg -i iona-node_28.4.0_amd64.deb
sudo apt-get install -f  # Install any missing dependencies
```

Post-installation:
- System user `iona` is created
- Directories `/var/lib/iona`, `/var/log/iona`, `/etc/iona` are initialized
- Service is enabled and started automatically
- Configuration available at `/etc/iona/config.toml.default`

### Configuration

Copy the default configuration and edit as needed:

```bash
sudo cp /etc/iona/config.toml.default /etc/iona/config.toml
sudo nano /etc/iona/config.toml
```

Key configuration sections:
- `[node]`: Chain ID, data directory, profile (dev/prod)
- `[network]`: Listen address, peer configuration
- `[rpc]`: RPC server bind address and port
- `[consensus]`: Timeout and gas parameters
- `[security]`: RBAC, audit logging configuration

### Starting the Service

```bash
# Start the service
sudo systemctl start iona-node

# Check status
sudo systemctl status iona-node

# View logs (last 50 lines, follow mode)
sudo journalctl -u iona-node -n 50 -f

# Check node health
iona-cli doctor
```

### Verification

Once running, verify the node is producing blocks:

```bash
# Get chain status
iona-cli --rpc http://localhost:8545 status

# Get current height
iona-cli --rpc http://localhost:8545 block | jq '.height'

# Get validator info
iona-cli --rpc http://localhost:8545 validators
```

## Upgrading

To upgrade to a newer version:

```bash
sudo dpkg -i iona-node_28.4.1_amd64.deb
```

The service will automatically restart with the new version. Chain data in `/var/lib/iona` is preserved.

To monitor the upgrade:
```bash
sudo journalctl -u iona-node -n 100 -f
```

## Removal

### Remove Package (Keep Chain Data)

```bash
sudo dpkg -r iona-node
```

This removes the binaries and service but preserves:
- `/var/lib/iona/` - chain state and validator keys
- `/etc/iona/config.toml` - your configuration

### Complete Removal (Including Chain Data)

```bash
sudo dpkg -r iona-node
sudo rm -rf /var/lib/iona
sudo rm -rf /etc/iona
sudo userdel iona
```

## Repository Installation (Future)

Once published to the IONA package repository, installation will be as simple as:

```bash
curl -sL https://packages.iona.network/apt/install.sh | sudo bash
sudo apt-get install iona-node
sudo apt-get upgrade iona-node  # For future updates
```

## Service Management

### Systemd Unit File

The service is defined in `/lib/systemd/system/iona-node.service` with:
- User: `iona` (unprivileged system user)
- Auto-restart on failure (RestartSec=5)
- Security hardening: ProtectSystem=strict, NoNewPrivileges=true, etc.
- Resource limits: 65536 file descriptors, 2GB memory
- Logging: Direct to systemd journal

### Enable at Boot

```bash
sudo systemctl enable iona-node.service
```

### Disable at Boot

```bash
sudo systemctl disable iona-node.service
```

## Troubleshooting

### Service Fails to Start

Check the logs:
```bash
sudo journalctl -u iona-node -n 100 -e
```

Common issues:
- Port already in use (check `ss -tlnp | grep iona-node`)
- Permission denied on `/var/lib/iona` (check ownership: `ls -ld /var/lib/iona`)
- Missing configuration file (ensure `/etc/iona/config.toml` exists)

### Service Running but No Blocks

Wait up to 30 seconds for consensus to catch up. Check:
```bash
iona-cli --rpc http://localhost:8545 status
iona-cli --rpc http://localhost:8545 peers
```

If peers are empty, check network configuration and firewall.

### High Memory Usage

Set memory limit in systemd or in the node configuration. Default is 2GB. To adjust:

```bash
sudo systemctl edit iona-node
# Add/modify: MemoryLimit=4G
# Save and exit, then reload
sudo systemctl daemon-reload
sudo systemctl restart iona-node
```

### Disk Space Issues

Check usage:
```bash
du -sh /var/lib/iona
```

Consider pruning old state (requires custom implementation) or running a state snapshot.

## Performance Tuning

For production validators, optimize your system:

```bash
# Increase file descriptors
echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.conf
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Optimize network
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf

sudo sysctl -p
```

## Security Considerations

- The `iona` user runs with minimal privileges (no login shell)
- All binaries are stripped and verified before packaging
- Systemd hardening: ProtectSystem=strict, MemoryDenyWriteExecute=true, etc.
- Configuration file permissions: mode 0640 (readable by iona user only)
- Data directory permissions: mode 0750 (accessible by iona user only)
- Audit logging enabled for all security-relevant operations

## Support

For issues, questions, or contributions:
- Repository: https://github.com/iona/iona
- Issues: https://github.com/iona/iona/issues
- Documentation: https://docs.iona.network
- Community: https://discord.gg/iona

## License

IONA is licensed under the Apache License 2.0. See LICENSE in the repository.
