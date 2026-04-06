# IONA APT Repository

This directory contains tooling for publishing IONA as an installable APT package.

## For end users

### Install via the official APT repository (recommended)

```bash
# 1. Import the GPG signing key
curl -fsSL https://packages.iona.network/apt/iona-archive-keyring.gpg \
  | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/iona.gpg

# 2. Add the repository
echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/iona.gpg] \
  https://packages.iona.network/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/iona.list

# 3. Update and install
sudo apt-get update
sudo apt-get install iona-node

# 4. Verify installation
iona-node --version
systemctl status iona-node
```

### Supported releases

| Codename | Debian Equivalent | Ubuntu Equivalent | Status |
|----------|------------------|------------------|--------|
| `stable` | Debian 12 Bookworm | Ubuntu 22.04 LTS | ✅ Active |
| `testing` | Debian 13 Trixie | Ubuntu 24.04 LTS | ✅ Active |
| `oldstable` | Debian 11 Bullseye | Ubuntu 20.04 LTS | ⚠️ Security patches only |

For ARM64 systems, replace `arch=amd64` with `arch=arm64`.

---

## For repository maintainers

### Building the APT repository

```bash
# Prerequisites
sudo apt-get install dpkg-dev apt-utils gnupg

# Build packages first
cd ../..
./packaging/deb/build-deb.sh

# Set up the repo
cd packaging/apt-repo
./setup-apt-repo.sh \
  --debs ../../dist \
  --output ./repo \
  --sign-key YOUR_GPG_KEY_ID

# The repo is now at ./repo/ — publish it to your web server
rsync -av ./repo/ user@example.invalid:/var/www/apt/
```

### GitHub Actions integration

The release workflow (`.github/workflows/release.yml`) automatically builds the `.deb` package. To publish it to the APT repository, add a deploy step:

```yaml
- name: Publish to APT repo
  env:
    APT_REPO_SSH_KEY: ${{ secrets.APT_REPO_SSH_KEY }}
  run: |
    ./packaging/apt-repo/setup-apt-repo.sh \
      --debs dist \
      --output apt-repo \
      --sign-key "${{ vars.GPG_KEY_ID }}"
    rsync -e "ssh -i ${APT_REPO_SSH_KEY}" \
      -av apt-repo/ \
      packages@example.invalid:/var/www/apt/
```

### Repository structure

```
apt-repo/
├── pool/
│   └── main/
│       └── iona-node_28.5.0_amd64.deb
└── dists/
    └── stable/
        ├── Release          (signed by GPG)
        ├── InRelease        (clearsigned)
        ├── Release.gpg      (detached signature)
        └── main/
            └── binary-amd64/
                ├── Packages
                ├── Packages.gz
                └── Packages.bz2
```

### Signing key rotation

When rotating the GPG signing key:

1. Generate a new key: `gpg --full-generate-key`
2. Publish the new public key alongside the old one temporarily
3. Sign the repository with both keys for one release cycle
4. Remove the old key from `Release.gpg` after all clients have updated
5. Update the key fingerprint at https://iona.network/security

---

## For developers: local install from .deb

```bash
# Build and install locally
./packaging/deb/build-deb.sh
sudo dpkg -i iona-node_*.deb

# Or install with apt to resolve dependencies automatically
sudo apt-get install ./iona-node_*.deb
```
