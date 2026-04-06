# IONA Official Releases

This directory documents the release artefact structure for IONA v28.x.

## Release Artefacts (per version)

Every official release at https://github.com/iona/iona/releases includes:

```
releases/
  iona-node-vX.Y.Z-x86_64-linux.tar.gz       # Linux binary tarball (x86_64)
  iona-node-vX.Y.Z-aarch64-linux.tar.gz       # Linux binary tarball (ARM64)
  iona-node-vX.Y.Z-x86_64-darwin.tar.gz       # macOS binary tarball (Intel)
  iona-node-vX.Y.Z-aarch64-darwin.tar.gz      # macOS binary tarball (Apple Silicon)
  iona-node_X.Y.Z_amd64.deb                   # Debian/Ubuntu package (x86_64)
  iona-node_X.Y.Z_arm64.deb                   # Debian/Ubuntu package (ARM64)
  SHA256SUMS                                   # SHA-256 checksums for all artefacts
  SHA512SUMS                                   # SHA-512 checksums for all artefacts
  SHA256SUMS.asc                               # GPG detached signature over SHA256SUMS
  SHA512SUMS.asc                               # GPG detached signature over SHA512SUMS
  sbom.json                                    # CycloneDX 1.4 SBOM
  sbom.json.sig                                # cosign signature for SBOM
  cosign.pub                                   # cosign public key
  iona-release-signing-key.asc                 # GPG public key for release verification
  install.sh                                   # Official installer script
```

## Tarball Contents

Each `.tar.gz` tarball extracts to:

```
iona-vX.Y.Z-<arch>-<os>/
  iona-node              # Main validator/node binary
  iona-cli               # CLI management tool
  iona-remote-signer     # Remote signer binary
  config.toml.default    # Default configuration template
  LICENSE
  CHANGELOG.md
  VERIFY.md              # Verification guide (this file)
```

## How to Verify

See `dist/VERIFY.md` for full verification instructions (SHA256, GPG, cosign).

Quick start:
```bash
VERSION=v28.6.0
curl -LO https://github.com/iona/iona/releases/download/${VERSION}/iona-node-${VERSION}-x86_64-linux.tar.gz
curl -LO https://github.com/iona/iona/releases/download/${VERSION}/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

## Signing Infrastructure

- **GPG key**: `packages@example.invalid` — fingerprint published at https://iona.network/security
- **cosign**: Sigstore-based signing; public key in each release as `cosign.pub`
- **SBOM**: CycloneDX 1.4 JSON format, covering all Rust crate dependencies
- **Transparency log**: All releases logged to Sigstore Rekor public log

## Release Cadence

| Type    | Frequency         | Example       | Notes                         |
|---------|-------------------|---------------|-------------------------------|
| Patch   | As needed         | v28.6.1       | Bug/security fixes only       |
| Minor   | Every 2-3 months  | v28.7.0       | New features, non-breaking    |
| LTS     | Every 12-18 months| v28.6.0 (LTS) | 21-month security support     |
| Major   | Annually          | v29.0.0       | Consensus/breaking changes    |

Current LTS: **v28.6.0** — supported through **2027-09-04**
